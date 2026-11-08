"""Pinned, credential-isolated GitHub REST driver for the synthetic test repo."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import json
import re
import time
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


class ManualReviewRequired(ValueError):
    """A write cannot safely be repeated without operator reconciliation."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, token, repo, branch, audit_path=None, state_path=None):
        validate_target(repo, branch)
        if not token.startswith("github_pat_"):
            raise ValueError("Use a repository-scoped, fine-grained GitHub token")
        self.repo = repo
        self.branch = branch
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())
        self.audit_path = audit_path
        self.state_path = state_path
        self.state = read(state_path) if state_path and state_path.exists() else {}

    def remember(self, **values):
        self.state.update(values)
        if self.state_path is not None:
            atomic(self.state_path, self.state)

    def write_confirmed(self, method, endpoint, body, confirm):
        # Persist intent before dispatch so a restarted bridge only reads it back.
        self.remember(pending={"method": method, "endpoint": endpoint})
        try:
            self.call(method, endpoint, body)
        except (GitHubError, OSError, http.client.HTTPException, json.JSONDecodeError):
            # An independent read must establish the result of an ambiguous write.
            pass
        return self.confirm_write(confirm)

    def confirm_write(self, confirm):
        endpoint = self.state["pending"]["endpoint"]
        try:
            result = confirm()
            if not result:
                raise ValueError("Remote write outcome is not established")
        except (
            GitHubError, ValueError, OSError, http.client.HTTPException, LookupError, TypeError
        ) as error:
            self.remember(status="manual_review_required", reason=type(error).__name__)
            raise ManualReviewRequired(
                "manual_review_required: unresolved GitHub write at " + endpoint
            ) from None
        self.remember(pending=None, status="reconciled", reason=None)
        return result

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
        attempts = 3 if method == "GET" else 1
        for attempt in range(attempts):
            try:
                with self.opener.open(req, timeout=4) as reply:
                    self.audit(method, endpoint, reply.status, body)
                    return json.load(reply)
            except urllib.error.HTTPError as error:
                self.audit(method, endpoint, error.code, body)
                if (
                    method != "GET"
                    or error.code not in {502, 503, 504}
                    or attempt + 1 == attempts
                ):
                    raise GitHubError(error.code, endpoint) from None
            except (OSError, http.client.HTTPException, json.JSONDecodeError):
                self.audit(method, endpoint, "transport_error", body)
                if attempt + 1 == attempts:
                    raise
            time.sleep(0.2 * (attempt + 1))

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
        if self.state.get("pr_number") is not None and pr_number != self.state["pr_number"]:
            raise ValueError("Recorded PR number changed")
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
        if self.state.get("head_sha") and head != self.state["head_sha"]:
            raise ValueError("Recorded PR head SHA changed")
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
        if content is None:
            raise ValueError("Remote fixture file is missing")
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

    def candidate_head(self, base, replacement):
        head = self.head(self.branch)
        if not head or head == base:
            return None
        pinned = self.state.get("head_sha")
        if pinned and pinned != head:
            raise ValueError("Remote candidate SHA changed")
        commit = self.call("GET", "/commits/" + head)
        if commit["sha"] != head or [p["sha"] for p in commit["parents"]] != [base]:
            raise ValueError("Candidate is not one direct child of the pinned base")
        files = [(entry["filename"], entry["status"]) for entry in commit.get("files", [])]
        if files != [(PATH, "modified")]:
            raise ValueError("Candidate changes files outside the authorized edit")
        _, current = self.file(head)
        if current != replacement:
            raise ValueError("Refusing to overwrite a different remote commit")
        self.remember(head_sha=head)
        return head

    def validate_base(self, base):
        self.validate_repo()
        if self.head("main") != base:
            raise ValueError("The GitHub base advanced")

    def confirm_branch(self, base):
        if self.head(self.branch) != base:
            return False
        self.remember(branch_confirmed=True)
        return True

    def confirm_pr(self, base, replacement_digest):
        if not self.state.get("head_sha"):
            raise ValueError("Missing pinned candidate SHA")
        observed = self.observe(base)
        if observed["replacement_sha256"] != replacement_digest:
            raise ValueError("Remote replacement differs from authorized bytes")
        self.remember(pr_number=observed["pr_number"])
        return observed

    def publish(self, base, replacement):
        digest = hashlib.sha256(replacement).hexdigest()
        plan = {"repo": self.repo, "branch": self.branch, "base": base, "sha256": digest}
        if self.state.get("plan", plan) != plan:
            raise ValueError("Refusing to overwrite a different publication plan")

        pending = self.state.get("pending")
        if pending:
            def confirm_pending():
                self.validate_base(base)
                if pending == {"method": "POST", "endpoint": "/git/refs"}:
                    return self.confirm_branch(base)
                if pending == {"method": "PUT", "endpoint": "/contents/" + PATH}:
                    return self.candidate_head(base, replacement)
                if pending == {"method": "POST", "endpoint": "/pulls"}:
                    return self.confirm_pr(base, digest)
                raise ValueError("Unrecognized pending write")

            result = self.confirm_write(confirm_pending)
            if "plan" not in self.state:
                self.remember(plan=plan)
            if pending["endpoint"] == "/pulls":
                return result
        else:
            self.validate_base(base)
            if "plan" not in self.state:
                self.remember(plan=plan)

        head = self.head(self.branch)
        if self.state.get("head_sha") and head != self.state["head_sha"]:
            raise ValueError("Remote candidate SHA changed")
        if self.state.get("pr_number") is not None:
            return self.confirm_pr(base, digest)
        if head is None:
            if self.state.get("branch_confirmed"):
                raise ValueError("The confirmed GitHub branch is missing")
            self.write_confirmed(
                "POST", "/git/refs",
                {"ref": "refs/heads/" + self.branch, "sha": base},
                lambda: self.confirm_branch(base),
            )
            head = base
        blob_sha, current = self.file(head)
        if head == base and current == ORIGINAL:
            self.write_confirmed(
                "PUT", "/contents/" + PATH,
                {
                    "branch": self.branch, "sha": blob_sha,
                    "message": "Fix slug normalization via HPK",
                    "content": base64.b64encode(replacement).decode(),
                },
                lambda: self.candidate_head(base, replacement),
            )
        elif not self.candidate_head(base, replacement):
            raise ValueError("Refusing to overwrite a different remote commit")
        prs = self.matching_prs()
        if not prs:
            if self.head(self.branch) != self.state["head_sha"] or self.head("main") != base:
                raise ValueError("Remote branch changed before PR creation")
            return self.write_confirmed(
                "POST", "/pulls",
                {
                    "base": "main", "head": self.branch,
                    "title": "Fix slug normalization (HPK MCP test)",
                    "body": "Synthetic, isolated MCP handoff verification fixture.",
                },
                lambda: self.confirm_pr(base, digest),
            )
        return self.confirm_pr(base, digest)


def service_requests(root, api, base):
    """Process only the two supported operations through a local one-run queue."""
    if api.state_path is None:
        api.state_path = root / "github-write-state.json"
    # All workers sharing this run must refresh state while holding the same lock.
    with (root / "github-bridge.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        api.state = read(api.state_path) if api.state_path.exists() else {}
        service_locked_queue(root, api, base)


def service_locked_queue(root, api, base):
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
        except (GitHubError, ValueError, OSError, http.client.HTTPException) as error:
            result = {
                "ok": False, "error": str(error),
                "status": "manual_review_required" if api.state.get("pending") else "blocked",
                "code": "github_manual_review_required" if api.state.get("pending") else "github_blocked",
                "endpoint": (api.state.get("pending") or {}).get("endpoint"),
            }
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
        state_path=args.state_dir / "github-write-state.json",
    )
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        service_requests(args.state_dir, api, target["base_sha"])
        time.sleep(0.25)


if __name__ == "__main__":
    main()
