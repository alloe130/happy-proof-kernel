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
        if endpoint.startswith("/commits/"):
            return {"sha": endpoint.rsplit("/", 1)[1],
                    "parents": [{"sha": sha} for sha in self.parents],
                    "files": [{"filename": path, "status": "modified"} for path in self.paths]}
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
            # Both publisher and verifier must reject changed remote heads,
            # even after a successful protected check was already recorded.
            api.refs[BRANCH] = 'c' * 40
            assert rpc(client, "publish_git_pr", edit, a).json()["result"]["isError"]
            assert rpc(client, "verify_github_pr", verify, b).json()["result"]["isError"]
            api.refs[BRANCH] = HEAD_SHA
            original_call = api.call

            def moved_pr(method, endpoint="", body=None, query=None):
                value = original_call(method, endpoint, body, query)
                if endpoint == "/pulls/1":
                    value["head"]["sha"] = 'c' * 40
                return value

            api.call = moved_pr
            assert rpc(client, "publish_git_pr", edit, a).json()["result"]["isError"]
            assert rpc(client, "verify_github_pr", verify, b).json()["result"]["isError"]
            api.call = original_call
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

@pytest.mark.parametrize('endpoint', ['/git/refs', '/contents/' + fixture.PATH, '/pulls'])
@pytest.mark.parametrize('failure', ['timeout', 'server_error', 'invalid_json'])
def test_lost_write_reply_reads_back_without_duplicate_write(endpoint, failure):
    api = MemoryGitHub()
    original = api.call
    lost = False

    def call(method, path='', body=None, query=None):
        nonlocal lost
        result = original(method, path, body, query)
        if method != 'GET' and path == endpoint and not lost:
            lost = True
            if failure == 'server_error':
                raise GitHubError(503, path)
            if failure == 'invalid_json':
                raise json.JSONDecodeError('truncated reply', '', 0)
            raise TimeoutError('lost response')
        return result

    api.call = call
    observed = api.publish(BASE_SHA, REPLACEMENT.encode())
    assert observed['pr_number'] == 1 and observed['head_sha'] == HEAD_SHA
    assert api.publish(BASE_SHA, REPLACEMENT.encode()) == observed
    assert len(api.writes) == 3


def test_uncertain_write_persists_manual_review_and_blocks_replay(tmp_path):
    from hpk_demo.files import read

    api = MemoryGitHub()
    original = api.call

    def call(method, path='', body=None, query=None):
        if method == 'POST' and path == '/git/refs':
            api.writes.append((method, path))
            raise TimeoutError('request outcome unknown')
        return original(method, path, body, query)

    api.call = call
    queue = tmp_path / 'queue'
    queue.mkdir()
    request = {'operation': 'publish', 'payload': {'replacement': REPLACEMENT}}
    atomic(queue / '1.request.json', request)
    service_requests(tmp_path, api, BASE_SHA)
    result = read(queue / '1.response.json')
    assert result['code'] == 'github_manual_review_required'
    assert result['endpoint'] == '/git/refs'
    # A new bridge object simulates loss of all in-memory state.
    restarted = MemoryGitHub()
    atomic(queue / '2.request.json', request)
    service_requests(tmp_path, restarted, BASE_SHA)
    assert read(queue / '2.response.json')['code'] == result['code']
    assert len(api.writes) == 1 and restarted.writes == []


@pytest.mark.parametrize('stage', ['file', 'pr'])
def test_unreadable_write_reconciliation_requires_review(stage):
    from hpk_demo.github import ManualReviewRequired

    api = MemoryGitHub()
    original = api.call
    uncertain = False
    target = '/contents/' + fixture.PATH if stage == 'file' else '/pulls'

    def call(method, path='', body=None, query=None):
        nonlocal uncertain
        if uncertain and method == 'GET':
            raise TimeoutError('read-back unavailable')
        result = original(method, path, body, query)
        if method != 'GET' and path == target:
            uncertain = True
            raise TimeoutError('reply unavailable')
        return result

    api.call = call
    with pytest.raises(ManualReviewRequired):
        api.publish(BASE_SHA, REPLACEMENT.encode())
    assert len(api.writes) == (2 if stage == 'file' else 3)


@pytest.mark.parametrize('failure', ['timeout', 'server_error', 'incomplete', 'invalid_json'])
@pytest.mark.parametrize('recover', [True, False])
def test_real_http_read_retry_is_bounded(monkeypatch, failure, recover):
    import http.client
    import io
    import urllib.error
    from hpk_demo import github as module

    api = GitHub('github_pat_fixture', REPO, BRANCH)
    attempts = []
    pauses = []

    class Reply(io.StringIO):
        status = 200

    def open_request(request, timeout):
        attempts.append((request.method, timeout))
        if recover and len(attempts) == 3:
            return Reply('{"private": true}')
        if failure == 'server_error':
            raise urllib.error.HTTPError(request.full_url, 503, 'Unavailable', {}, None)
        if failure == 'incomplete':
            raise http.client.IncompleteRead(b'partial')
        if failure == 'invalid_json':
            return Reply('{')
        raise TimeoutError('read timed out')

    monkeypatch.setattr(api.opener, 'open', open_request)
    monkeypatch.setattr(module.time, 'sleep', pauses.append)
    if recover:
        assert api.call('GET') == {'private': True}
    else:
        with pytest.raises((TimeoutError, GitHubError, http.client.IncompleteRead, json.JSONDecodeError)):
            api.call('GET')
    assert attempts == [('GET', 4)] * 3
    assert pauses == [0.2, 0.4]


def test_real_http_never_retries_write_or_permanent_read_error(monkeypatch):
    import urllib.error
    api = GitHub('github_pat_fixture', REPO, BRANCH)
    calls = []

    def open_request(request, timeout):
        calls.append(request.method)
        if request.method == 'POST':
            raise TimeoutError('ambiguous write')
        raise urllib.error.HTTPError(request.full_url, 403, 'Forbidden', {}, None)

    monkeypatch.setattr(api.opener, 'open', open_request)
    with pytest.raises(TimeoutError):
        api.call('POST', '/pulls', {})
    with pytest.raises(GitHubError):
        api.call('GET')
    assert calls == ['POST', 'GET']


def test_changed_candidate_ancestry_is_rejected_before_pr_creation():
    api = MemoryGitHub()
    api.refs[BRANCH] = HEAD_SHA
    api.blobs[HEAD_SHA] = REPLACEMENT.encode()
    api.parents = ['c' * 40]
    with pytest.raises(ValueError, match='one direct child'):
        api.publish(BASE_SHA, REPLACEMENT.encode())
    assert api.writes == []


def test_same_bytes_at_different_sha_are_not_an_authorized_replay():
    api = MemoryGitHub()
    api.publish(BASE_SHA, REPLACEMENT.encode())
    api.refs[BRANCH] = 'c' * 40
    api.blobs['c' * 40] = REPLACEMENT.encode()
    before = list(api.writes)
    with pytest.raises(ValueError, match='SHA changed'):
        api.publish(BASE_SHA, REPLACEMENT.encode())
    assert api.writes == before


def test_process_interruption_leaves_persistent_write_gate(tmp_path):
    api = MemoryGitHub()
    api.state_path = tmp_path / 'write-state.json'
    original = api.call

    class ProcessStopped(BaseException):
        pass

    def call(method, path='', body=None, query=None):
        value = original(method, path, body, query)
        if method == 'POST':
            raise ProcessStopped()
        return value

    api.call = call
    with pytest.raises(ProcessStopped):
        api.publish(BASE_SHA, REPLACEMENT.encode())
    from hpk_demo.files import read
    restarted = MemoryGitHub()
    restarted.state = read(api.state_path)
    with pytest.raises(ValueError, match='manual_review_required'):
        restarted.publish(BASE_SHA, REPLACEMENT.encode())
    assert restarted.writes == []


@pytest.mark.parametrize("endpoint", ["/git/refs", "/contents/" + fixture.PATH, "/pulls"])
def test_restart_confirms_existing_remote_write_without_resending(tmp_path, endpoint):
    from hpk_demo.files import read

    api = MemoryGitHub()
    api.state_path = tmp_path / "write-state.json"
    original = api.call

    class ProcessStopped(BaseException):
        pass

    def call(method, path="", body=None, query=None):
        result = original(method, path, body, query)
        if method != "GET" and path == endpoint:
            raise ProcessStopped()
        return result

    api.call = call
    with pytest.raises(ProcessStopped):
        api.publish(BASE_SHA, REPLACEMENT.encode())

    # Keep the remote double, but reload the bridge state from disk.
    api.call = original
    api.state = read(api.state_path)
    assert api.state["pending"]["endpoint"] == endpoint
    observed = api.publish(BASE_SHA, REPLACEMENT.encode())
    assert observed["head_sha"] == HEAD_SHA and observed["pr_number"] == 1
    assert api.state["pending"] is None
    assert api.writes == [
        ("POST", "/git/refs"), ("PUT", "/contents/" + fixture.PATH), ("POST", "/pulls"),
    ]


def test_legacy_pending_pr_requires_the_pinned_head_and_replacement():
    from hpk_demo.github import ManualReviewRequired

    api = MemoryGitHub()
    api.publish(BASE_SHA, REPLACEMENT.encode())
    api.state = {"pending": {"method": "POST", "endpoint": "/pulls"}, "head_sha": HEAD_SHA}
    api.writes.clear()
    with pytest.raises(ManualReviewRequired):
        api.publish(BASE_SHA, b"different replacement")
    assert api.state["pending"]["endpoint"] == "/pulls"
    assert api.publish(BASE_SHA, REPLACEMENT.encode())["pr_number"] == 1
    assert api.state["pending"] is None and api.writes == []


def test_pending_content_with_an_extra_changed_file_never_opens_pr():
    from hpk_demo.github import ManualReviewRequired

    api = MemoryGitHub()
    api.refs[BRANCH] = HEAD_SHA
    api.blobs[HEAD_SHA] = REPLACEMENT.encode()
    api.paths.append("unrelated.txt")
    pending = {"method": "PUT", "endpoint": "/contents/" + fixture.PATH}
    api.state = {"pending": pending}

    with pytest.raises(ManualReviewRequired):
        api.publish(BASE_SHA, REPLACEMENT.encode())

    assert api.state["pending"] == pending
    assert api.writes == []


def test_pr_number_change_is_rejected_without_writes():
    api = MemoryGitHub()
    api.publish(BASE_SHA, REPLACEMENT.encode())
    original = api.call

    def call(method, path='', body=None, query=None):
        if (method, path) == ('GET', '/pulls'):
            return [{'number': 2}]
        return original(method, path, body, query)

    api.call = call
    with pytest.raises(ValueError, match='PR number changed'):
        api.publish(BASE_SHA, REPLACEMENT.encode())
    assert len(api.writes) == 3
