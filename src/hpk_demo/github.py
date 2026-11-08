"""Pinned, credential-isolated GitHub REST driver for the synthetic test repo."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .fixture import ORIGINAL, PATH
from .files import atomic, read


_REPOSITORY = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}"
)
_BRANCH = re.compile(r"hpk-handoff-[0-9a-f]{12}")


def validate_target(repo, branch):
    if not _REPOSITORY.fullmatch(repo) or not _BRANCH.fullmatch(branch):
        raise ValueError(
            "Use an owner/name GitHub repository and a generated fixture branch"
        )


class GitHubError(Exception):
    def __init__(self, status, endpoint):
        super().__init__(f"GitHub HTTP {status} for {endpoint}")
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, token, repo, branch, audit_path=None):
        validate_target(repo, branch)
        if not token.startswith("github_pat_"):
            raise ValueError("Use a repository-scoped, fine-grained GitHub token")
        self.repo = repo
        self.branch = branch
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())
        self.audit_path = audit_path

    def audit(self, method, endpoint, status, body):
        if self.audit_path is None:
            return
        with self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "method": method,
                        "endpoint": endpoint,
                        "status": status,
                        "branch": (body or {}).get("branch"),
                        "head": (body or {}).get("head"),
                    }
                )
                + "\n"
            )

    def call(self, method, endpoint="", body=None, query=None):
        url = f"https://api.github.com/repos/{self.repo}" + endpoint
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": "Happy-Proof-Kernel-Isolated-MCP-Test",
            },
        )
        try:
            with self.opener.open(req, timeout=12) as reply:
                self.audit(method, endpoint, reply.status, body)
                return json.load(reply)
        except urllib.error.HTTPError as error:
            self.audit(method, endpoint, error.code, body)
            raise GitHubError(error.code, endpoint) from None

    def optional(self, endpoint, query=None):
        try:
            return self.call("GET", endpoint, query=query)
        except GitHubError as error:
            if error.status == 404:
                return None
            raise

    def validate_repo(self):
        result = self.call("GET")
        if (
            result.get("full_name") != self.repo
            or not result.get("private")
            or result.get("default_branch") != "main"
        ):
            raise ValueError(
                "GitHub repository privacy, identity or default branch differs"
            )
        return result

    def head(self, branch):
        ref = self.optional("/git/ref/heads/" + branch)
        return ref["object"]["sha"] if ref else None

    def file(self, ref):
        item = self.optional("/contents/" + PATH, {"ref": ref})
        return (
            (item["sha"], base64.b64decode(item["content"])) if item else (None, None)
        )

    def seed(self):
        self.validate_repo()
        files = self.call("GET", "/contents", query={"ref": "main"})
        if (
            not isinstance(files, list)
            or any(
                item.get("type") != "file"
                or item.get("name") not in {"README.md", PATH}
                for item in files
            )
            or not any(item.get("name") == "README.md" for item in files)
        ):
            raise ValueError(
                "Use a dedicated private repository initialized with only a README"
            )
        _, content = self.file("main")
        if content is None:
            self.call(
                "PUT",
                "/contents/" + PATH,
                {
                    "branch": "main",
                    "message": "Add synthetic slug fixture",
                    "content": base64.b64encode(ORIGINAL).decode(),
                },
            )
        elif content != ORIGINAL:
            raise ValueError("Main contains an unexpected fixture")
        return {"repo": self.repo, "base_sha": self.head("main"), "branch": self.branch}

    def matching_prs(self):
        return self.call(
            "GET",
            "/pulls",
            query={
                "state": "all",
                "head": self.repo.split("/")[0] + ":" + self.branch,
                "base": "main",
                "per_page": 100,
            },
        )

    def observe(self, base, number=None):
        prs = self.matching_prs()
        if len(prs) != 1:
            raise ValueError(f"Expected one matching GitHub PR; found {len(prs)}")
        pr_number = prs[0]["number"]
        if number is not None and number != pr_number:
            raise ValueError("PR number changed")
        pr = self.call("GET", f"/pulls/{pr_number}")
        if (
            pr["state"] != "open"
            or pr["base"]["sha"] != base
            or pr["head"]["ref"] != self.branch
            or pr["head"]["repo"]["full_name"] != self.repo
            or pr["base"]["repo"]["full_name"] != self.repo
        ):
            raise ValueError("PR does not bind to the exact fixture branch and base")
        head = pr["head"]["sha"]
        if self.head(self.branch) != head:
            raise ValueError("Remote branch and PR head differ")
        commits = self.call("GET", f"/pulls/{pr_number}/commits")
        if (
            len(commits) != 1
            or commits[0]["sha"] != head
            or [p["sha"] for p in commits[0]["parents"]] != [base]
        ):
            raise ValueError("PR does not contain exactly one direct child commit")
        files = self.call("GET", f"/pulls/{pr_number}/files")
        if [entry["filename"] for entry in files] != [PATH]:
            raise ValueError("Unexpected changed files")
        _, content = self.file(head)
        return {
            "repo": self.repo,
            "pr_number": pr_number,
            "url": pr["html_url"],
            "head_sha": head,
            "base_sha": base,
            "branch": self.branch,
            "pr_count": len(prs),
            "commit_count": len(commits),
            "replacement_sha256": hashlib.sha256(content).hexdigest(),
        }

    def publish(self, base, replacement):
        self.validate_repo()
        if self.head("main") != base:
            raise ValueError("The GitHub base advanced")
        head = self.head(self.branch)
        if head is None:
            try:
                self.call(
                    "POST",
                    "/git/refs",
                    {"ref": "refs/heads/" + self.branch, "sha": base},
                )
            except GitHubError as error:
                if error.status != 422 or self.head(self.branch) is None:
                    raise
            head = self.head(self.branch)
        digest, current = self.file(head)
        if head == base and current == ORIGINAL:
            self.call(
                "PUT",
                "/contents/" + PATH,
                {
                    "branch": self.branch,
                    "sha": digest,
                    "message": "Fix slug normalization via HPK",
                    "content": base64.b64encode(replacement).decode(),
                },
            )
        elif current != replacement:
            raise ValueError("Refusing to overwrite a different remote commit")
        prs = self.matching_prs()
        if not prs:
            try:
                self.call(
                    "POST",
                    "/pulls",
                    {
                        "base": "main",
                        "head": self.branch,
                        "title": "Fix slug normalization (HPK MCP test)",
                        "body": "Synthetic, isolated MCP handoff verification fixture.",
                    },
                )
            except GitHubError as error:
                if error.status != 422 or not self.matching_prs():
                    raise
        observed = self.observe(base)
        if observed["replacement_sha256"] != hashlib.sha256(replacement).hexdigest():
            raise ValueError("Remote replacement differs from authorized bytes")
        return observed


def service_requests(root, api, base):
    """Process only the two supported operations through a local one-run queue."""
    for request in sorted((root / "queue").glob("*.request.json")):
        response = request.with_name(
            request.name.replace(".request.json", ".response.json")
        )
        if response.exists():
            continue
        message = read(request)
        payload = message["payload"]
        try:
            if message["operation"] == "publish":
                value = api.publish(base, payload["replacement"].encode())
            elif message["operation"] == "observe":
                value = api.observe(base, payload["pr_number"])
            else:
                raise ValueError("Unknown bridge operation")
            result = {"ok": True, "value": value}
        except (GitHubError, ValueError, OSError) as error:
            result = {"ok": False, "error": str(error)}
        atomic(response, result)


def main():
    import argparse
    import sys
    import time

    parser = argparse.ArgumentParser()
    parser.add_argument("state_dir", type=Path)
    args = parser.parse_args()
    target = read(args.state_dir / "repo.json")
    token = sys.stdin.readline().strip()
    api = GitHub(
        token,
        target["repo"],
        target["branch"],
        args.state_dir / "github-api-events.jsonl",
    )
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        service_requests(args.state_dir, api, target["base_sha"])
        time.sleep(0.25)


if __name__ == "__main__":
    main()
