import base64
import hashlib
import json
import threading

import pytest
from starlette.testclient import TestClient

from happylm.ledger import SQLiteWorkLedger
from hpk_demo import fixture
from hpk_demo.files import atomic
from hpk_demo.github import GitHub, GitHubError, service_requests, validate_target
from hpk_demo.server import build


BASE = "https://preview.example.invalid"
REPO = "fixture-owner/hpk-test"
BRANCH = "hpk-handoff-0123456789ab"
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
REPLACEMENT = (
    'def slugify(value):\n    return value.strip().lower().replace(" ", "-")\n'
)
ROLE_SECRETS = {
    fixture.CLIENT_A: "publisher-fixture-secret",
    fixture.CLIENT_B: "verifier-fixture-secret",
}


class MemoryGitHub(GitHub):
    """Exercise the real GitHub adapter against a tiny deterministic REST double."""

    def __init__(self):
        super().__init__("github_pat_fixture", REPO, BRANCH)
        self.refs = {"main": BASE_SHA}
        self.blobs = {BASE_SHA: fixture.ORIGINAL}
        self.opened = False
        self.writes = []
        self.private = True
        self.parents = [BASE_SHA]
        self.paths = [fixture.PATH]
        self.other_files = []

    def call(self, method, endpoint="", body=None, query=None):
        if method != "GET":
            self.writes.append((method, endpoint))
        if (method, endpoint) == ("GET", ""):
            return {
                "full_name": self.repo,
                "private": self.private,
                "default_branch": "main",
            }
        if (method, endpoint) == ("GET", "/contents"):
            return [
                {"name": name, "type": "file"}
                for name in ["README.md", fixture.PATH, *self.other_files]
            ]
        if endpoint.startswith("/git/ref/heads/"):
            ref = endpoint.removeprefix("/git/ref/heads/")
            if ref not in self.refs:
                raise GitHubError(404, endpoint)
            return {"object": {"sha": self.refs[ref]}}
        if (method, endpoint) == ("POST", "/git/refs"):
            assert body == {"ref": "refs/heads/" + self.branch, "sha": BASE_SHA}
            self.refs[self.branch] = BASE_SHA
            return {}
        if (method, endpoint) == ("GET", "/contents/" + fixture.PATH):
            ref = query["ref"]
            content = self.blobs[self.refs.get(ref, ref)]
            return {
                "sha": hashlib.sha1(content).hexdigest(),
                "content": base64.b64encode(content).decode(),
            }
        if (method, endpoint) == ("PUT", "/contents/" + fixture.PATH):
            assert body["branch"] == self.branch
            assert body["sha"] == hashlib.sha1(fixture.ORIGINAL).hexdigest()
            assert self.refs[self.branch] == BASE_SHA
            self.blobs[HEAD_SHA] = base64.b64decode(body["content"])
            self.refs[self.branch] = HEAD_SHA
            return {}
        if (method, endpoint) == ("GET", "/pulls"):
            assert (
                query["state"] == "all"
                and query["head"] == "fixture-owner:" + self.branch
            )
            return [{"number": 1}] if self.opened else []
        if (method, endpoint) == ("POST", "/pulls"):
            assert body["head"] == self.branch and not self.opened
            self.opened = True
            return {"number": 1}
        if endpoint == "/pulls/1":
            return {
                "state": "open",
                "html_url": "https://github.com/" + self.repo + "/pull/1",
                "base": {"sha": BASE_SHA, "repo": {"full_name": self.repo}},
                "head": {
                    "sha": HEAD_SHA,
                    "ref": self.branch,
                    "repo": {"full_name": self.repo},
                },
            }
        if endpoint == "/pulls/1/commits":
            return [
                {"sha": HEAD_SHA, "parents": [{"sha": sha} for sha in self.parents]}
            ]
        if endpoint == "/pulls/1/files":
            return [{"filename": path} for path in self.paths]
        raise AssertionError((method, endpoint))


@pytest.mark.parametrize(
    "repo,branch",
    [
        ("https://github.com/owner/repo", BRANCH),
        ("owner/..", BRANCH),
        (REPO, "main"),
    ],
)
def test_reject_unsafe_github_targets(repo, branch):
    with pytest.raises(ValueError):
        validate_target(repo, branch)


def test_repo_must_be_private_and_dedicated():
    api = MemoryGitHub()
    api.private = False
    with pytest.raises(ValueError, match="privacy"):
        api.seed()
    api.private = True
    api.other_files.append("customer-data.py")
    with pytest.raises(ValueError, match="dedicated"):
        api.seed()
    assert api.writes == []


def test_github_publish_retry_reconciles_without_extra_writes():
    api = MemoryGitHub()
    assert api.seed()["base_sha"] == BASE_SHA
    first = api.publish(BASE_SHA, REPLACEMENT.encode())
    assert api.publish(BASE_SHA, REPLACEMENT.encode()) == first
    assert first["commit_count"] == first["pr_count"] == 1
    assert api.writes == [
        ("POST", "/git/refs"),
        ("PUT", "/contents/" + fixture.PATH),
        ("POST", "/pulls"),
    ]
    with pytest.raises(ValueError, match="overwrite"):
        api.publish(BASE_SHA, b"changed")
    api.parents.append("c" * 40)
    with pytest.raises(ValueError, match="one direct child"):
        api.observe(BASE_SHA)


@pytest.mark.parametrize(
    "source",
    [
        "import os\ndef slugify(value): return value",
        "def slugify(value): return open(value)",
        "def slugify(value): return value.strip(unsafe=True)",
        "def slugify(value): return value.replace('a', 'b')",
    ],
)
def test_model_code_is_limited_to_safe_fixture_expression(source):
    with pytest.raises(ValueError):
        fixture.limit_edit(source)


def issue(client, role, *, scope=None, resource=None, secret=None):
    permission = "hpk:publish" if role == fixture.CLIENT_A else "hpk:verify"
    return client.post(
        "/oauth/token",
        auth=(role, secret or ROLE_SECRETS[role]),
        data={
            "grant_type": "client_credentials",
            "resource": resource or BASE + "/mcp",
            "scope": scope or "happy:mcp " + permission,
        },
    )


def rpc(client, name, arguments=None, token=None):
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )


def payload(response):
    assert response.status_code == 200
    result = response.json()["result"]
    assert not result.get("isError")
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


def test_oauth_mcp_handoff_and_retries_without_network(tmp_path):
    root = tmp_path / "run"
    fixture.init(root)
    (root / "queue").mkdir()
    api = MemoryGitHub()
    atomic(root / "clients.json", ROLE_SECRETS)
    atomic(root / "repo.json", api.seed())
    shutdown = threading.Event()

    def bridge():
        while not shutdown.is_set():
            service_requests(root, api, BASE_SHA)
            shutdown.wait(0.02)

    thread = threading.Thread(target=bridge, daemon=True)
    thread.start()
    try:
        with TestClient(
            build(root, BASE, 18769).streamable_http_app(), base_url=BASE
        ) as client:
            discovery = client.get("/.well-known/oauth-protected-resource/mcp").json()
            issuer = client.get("/.well-known/oauth-authorization-server").json()
            assert discovery["resource"] == BASE + "/mcp"
            assert discovery["authorization_servers"] == [issuer["issuer"]]
            assert client.get("/jwks.json").json()["keys"][0]["alg"] == "RS256"
            assert rpc(client, "oauth_identity").status_code == 401
            assert rpc(client, "oauth_identity", token="not.a.token").status_code == 401
            assert (
                issue(client, fixture.CLIENT_A, secret="incorrect").status_code == 401
            )
            assert (
                issue(
                    client, fixture.CLIENT_B, scope="happy:mcp hpk:publish"
                ).status_code
                == 400
            )
            assert (
                issue(client, fixture.CLIENT_A, resource=BASE + "/other").status_code
                == 400
            )
            a = issue(client, fixture.CLIENT_A).json()["access_token"]
            b = issue(client, fixture.CLIENT_B).json()["access_token"]
            assert (
                payload(rpc(client, "get_git_task", token=a))["base_commit"] == BASE_SHA
            )
            edit = {"base_commit": BASE_SHA, "replacement": REPLACEMENT}
            wrong_role = rpc(client, "publish_git_pr", edit, b).json()["result"]
            assert wrong_role["isError"] is True and not api.writes
            failed = rpc(client, "publish_git_pr", edit, a).json()["result"]
            assert failed["isError"] is True and "Injected reply loss" in json.dumps(
                failed
            )
            published = payload(rpc(client, "publish_git_pr", edit, a))
            assert published["status"] == "already_published"
            handoff = payload(rpc(client, "get_github_handoff", token=b))
            assert handoff["method"]["status"] == "verification_pending"
            verify = {
                "pr_number": handoff["github"]["pr_number"],
                "head_sha": handoff["github"]["head_sha"],
                "checkpoint_digest": handoff["method"]["evidence_digest"],
            }
            assert rpc(
                client, "verify_github_pr", {**verify, "head_sha": BASE_SHA}, b
            ).json()["result"]["isError"]
            assert (
                payload(rpc(client, "verify_github_pr", verify, b))["status"]
                == "verified"
            )
            assert (
                payload(rpc(client, "verify_github_pr", verify, b))["status"]
                == "already_verified"
            )
    finally:
        shutdown.set()
        thread.join(timeout=3)
    assert api.observe(BASE_SHA)["head_sha"] == HEAD_SHA
    assert api.writes == [
        ("POST", "/git/refs"),
        ("PUT", "/contents/" + fixture.PATH),
        ("POST", "/pulls"),
    ]
    with SQLiteWorkLedger(root / "work.sqlite") as ledger:
        actions = [
            a
            for op in ledger.snapshot(fixture.WORK)["operations"]
            for a in op["actions"]
        ]
        assert len(actions) == 2
        for action in actions:
            assert action["status"] == "verified"
            events = ledger.events_for("action", action["action_id"])
            assert sum(event.event_type == "dispatch.started" for event in events) == 1
