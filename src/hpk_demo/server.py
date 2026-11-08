"""One-run HTTPS OAuth MCP fixture. Only synthetic slug.py data leaves the workspace."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import socket
import time
import uuid
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import jwt
import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import fixture as demo
from .files import atomic, read
from happylm.development import (
    GIT_DEVELOPMENT_ADAPTER_DIGEST,
    ContributionKind,
    EditInstruction,
)
from happylm.development_runner import (
    GIT_HANDOFF_VERIFY_ADAPTER_DIGEST,
    GIT_HANDOFF_VERIFY_OPERATION,
    DevelopmentActionSpec,
)
from happylm.identity import AuthenticationError, OIDCBearerVerifier
from happylm.ledger import SQLiteWorkLedger
from happylm.mcp_work import SQLiteMCPJournal
from happylm.policy import ActionRequest, SideEffect
from happylm.work import ActionStatus


BASE_SCOPE = "happy:mcp"
SCOPES = {demo.CLIENT_A: "hpk:publish", demo.CLIENT_B: "hpk:verify"}
KID = "hpk-remote-fixture"


class Signature:
    def __init__(self, key):
        self.key = key

    def verify(self, *, algorithm, key_id, signing_input, signature):
        if algorithm != "RS256" or key_id != KID:
            return False
        try:
            self.key.verify(
                signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True


class OAuth:
    def __init__(self, base: str, root: Path):
        self.issuer = base + "/"
        self.audience = base + "/mcp"
        self.root = root
        self.clients = read(root / "clients.json")
        self.signing_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        key = self.signing_key.public_key()
        self.jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key, as_dict=True)
        self.jwk.update(kid=KID, alg="RS256", use="sig")
        self.verifier = OIDCBearerVerifier(
            issuer=self.issuer,
            audience=self.audience,
            signature_verifier=Signature(key),
            leeway_seconds=0,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            principal = self.verifier.verify_authorization(f"Bearer {token}")
        except AuthenticationError:
            return None
        if principal.subject not in SCOPES or set(principal.scopes) != {
            BASE_SCOPE,
            SCOPES[principal.subject],
        }:
            return None
        return AccessToken(
            token=token,
            client_id=principal.subject,
            scopes=list(principal.scopes),
            resource=self.audience,
            expires_at=principal.expires_at,
        )

    async def token(self, request: Request) -> JSONResponse:
        def reject(code, status=400):
            return JSONResponse(
                {"error": code},
                status_code=status,
                headers={"Cache-Control": "no-store"},
            )

        try:
            prefix, credential = request.headers.get("authorization", "").split(" ", 1)
            client, secret = (
                base64.b64decode(credential, validate=True)
                .decode("ascii")
                .split(":", 1)
            )
        except (ValueError, UnicodeError):
            return reject("invalid_client", 401)
        if (
            prefix.lower() != "basic"
            or client not in self.clients
            or not hmac.compare_digest(self.clients[client], secret)
        ):
            return reject("invalid_client", 401)
        length = request.headers.get("content-length", "")
        if not length.isdecimal() or int(length) > 2048:
            return reject("invalid_request")
        form = await request.form()
        if form.get("grant_type") != "client_credentials":
            return reject("unsupported_grant_type")
        if form.get("resource") != self.audience:
            return reject("invalid_target")
        if set(str(form.get("scope", "")).split()) != {BASE_SCOPE, SCOPES[client]}:
            return reject("invalid_scope")
        now = int(time.time())
        ttl = 600
        signed = jwt.encode(
            {
                "iss": self.issuer,
                "aud": self.audience,
                "sub": client,
                "iat": now,
                "exp": now + ttl,
                "jti": uuid.uuid4().hex,
                "scope": f"{BASE_SCOPE} {SCOPES[client]}",
                "tenant_id": demo.TENANT,
                "roles": ["work.contributor"],
                "work_ids": [demo.WORK],
            },
            self.signing_key,
            algorithm="RS256",
            headers={"kid": KID, "typ": "at+jwt"},
        )
        demo.log(self.root, "oauth_token_issued", client=client, scope=SCOPES[client])
        return JSONResponse(
            {"access_token": signed, "token_type": "Bearer", "expires_in": ttl},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )


def require(role: str) -> None:
    token = get_access_token()
    if token is None or token.client_id != role or SCOPES[role] not in token.scopes:
        raise ValueError("This OAuth client does not have the required scope")


def bind_repo(root: Path) -> dict:
    path = root / "repo.json"
    if not path.is_file():
        raise ValueError("A private GitHub fixture has not been bound")
    return read(path)


async def github(root: Path, operation: str, payload: dict) -> dict:
    call_id = uuid.uuid4().hex
    atomic(
        root / "queue" / f"{call_id}.request.json",
        {"operation": operation, "payload": payload},
    )
    response = root / "queue" / f"{call_id}.response.json"
    until = time.monotonic() + 65
    while time.monotonic() < until:
        if response.exists():
            value = read(response)
            if not value.get("ok"):
                raise ValueError(
                    "GitHub test bridge failed: " + value.get("error", "unknown")
                )
            return value["value"]
        await asyncio.sleep(0.25)
    raise TimeoutError("GitHub test bridge did not respond")


def stage(root: Path, code: bytes):
    with SQLiteWorkLedger(root / "work.sqlite") as ledger:
        runner, registration, check, artifacts = demo.fixture(
            root, ledger, demo.CLIENT_A
        )
        if ledger.snapshot(demo.WORK)["operations"]:
            raise ValueError(
                "Staging already started without a usable checkpoint; inspect the run state"
            )
        base = demo.git(root / "repo", "rev-parse", "HEAD")
        spec = DevelopmentActionSpec(
            demo.REPO,
            registration.digest,
            base,
            demo.WORKSPACE,
            "Fix slug normalization",
            (
                EditInstruction(
                    demo.PATH,
                    hashlib.sha256(demo.ORIGINAL).hexdigest(),
                    artifacts.put_bytes(code),
                    ContributionKind.AI,
                    demo.CLIENT_A,
                ),
            ),
            (check.digest,),
        )
        contract = demo.contract(demo.EDIT_OPERATION, SideEffect.WRITE)
        action = demo.prepare(
            ledger,
            ledger.get_grant(demo.A_GRANT),
            contract,
            ActionRequest(
                "remote.gpt.publish",
                "git-development",
                demo.EDIT_OPERATION,
                demo.REPO,
                spec.to_dict(),
                0,
            ),
            GIT_DEVELOPMENT_ADAPTER_DIGEST,
        )
        permit = ledger.issue_dispatch_permit(
            action.action_id, worker_id=demo.CLIENT_A, ttl=timedelta(minutes=1)
        )
        candidate = runner.stage_for_handoff(permit)
        return {
            "action_id": action.action_id,
            "local_candidate": candidate.candidate_commit,
            "checkpoint_digest": candidate.checkpoint_digest,
            "replacement_sha256": hashlib.sha256(code).hexdigest(),
        }


def build(root: Path, base: str, port: int) -> FastMCP:
    oauth = OAuth(base, root)
    host = urlsplit(base).netloc
    server = FastMCP(
        "hpk-remote-oauth-fixture",
        host="127.0.0.1",
        port=port,
        json_response=True,
        stateless_http=True,
        token_verifier=oauth,
        auth=AuthSettings(
            issuer_url=base,
            resource_server_url=oauth.audience,
            required_scopes=[BASE_SCOPE],
            validate_token_resource=True,
        ),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[host, f"127.0.0.1:{port}"],
            allowed_origins=[base],
        ),
    )
    lock = asyncio.Lock()

    @server.custom_route("/health", methods=["GET"])
    async def health(request):
        return JSONResponse(
            {"service": "hpk-isolated-mcp-fixture", "auth": "OAuth required for MCP"}
        )

    @server.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def metadata(request):
        return JSONResponse(
            {
                "issuer": oauth.issuer,
                "token_endpoint": base + "/oauth/token",
                "jwks_uri": base + "/jwks.json",
                "grant_types_supported": ["client_credentials"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                "scopes_supported": [BASE_SCOPE, *SCOPES.values()],
                "response_types_supported": [],
            }
        )

    @server.custom_route("/jwks.json", methods=["GET"])
    async def jwks(request):
        return JSONResponse({"keys": [oauth.jwk]})

    @server.custom_route("/oauth/token", methods=["POST"])
    async def token(request):
        return await oauth.token(request)

    @server.tool()
    def oauth_identity() -> dict:
        """Return the authenticated test client and the scope in this MCP session."""
        access = get_access_token()
        demo.log(root, "oauth_mcp_identity", client=access.client_id)
        return {"client": access.client_id, "scopes": access.scopes}

    @server.tool()
    def get_git_task() -> dict:
        """Read the synthetic GitHub task and its exact base revision."""
        require(demo.CLIENT_A)
        repo = bind_repo(root)
        demo.log(root, "gpt_get_git_task")
        return {
            "repository": repo["repo"],
            "base_commit": repo["base_sha"],
            "path": demo.PATH,
            "source": demo.ORIGINAL.decode(),
            "objective": demo.OBJECTIVE,
        }

    @server.tool()
    async def publish_git_pr(base_commit: str, replacement: str) -> dict:
        """Publish the authorized slug.py change as one test PR. Retry with identical arguments after a lost reply."""
        require(demo.CLIENT_A)
        repo = bind_repo(root)
        if base_commit != repo["base_sha"]:
            raise ValueError("The supplied base commit is stale")
        code = demo.limit_edit(replacement)
        async with lock:
            plan_path = root / "publish-plan.json"
            if not plan_path.exists():
                atomic(plan_path, stage(root, code))
            plan = read(plan_path)
            if hashlib.sha256(code).hexdigest() != plan["replacement_sha256"]:
                raise ValueError("The previously authorized replacement is different")
            committed = root / "published.json"
            if committed.exists():
                recorded = read(committed)
                observed = await github(root, "observe", recorded["github"])
                if observed != recorded["github"]:
                    raise ValueError("GitHub changed since publication")
                demo.log(root, "gpt_publish_replayed", **observed)
                return {"status": "already_published", **observed}
            observed = await github(root, "publish", {"replacement": code.decode()})
            demo.enable_b(root)
            atomic(committed, {"plan": plan, "github": observed})
            demo.log(root, "gpt_published_reply_lost", **observed)
            raise ValueError(
                "Injected reply loss after durable GitHub publication. Retry with identical arguments."
            )

    @server.tool()
    async def get_github_handoff() -> dict:
        """Read the stored GitHub PR handoff in a fresh verifier session."""
        require(demo.CLIENT_B)
        published = read(root / "published.json")
        with (
            SQLiteWorkLedger(root / "work.sqlite") as ledger,
            SQLiteMCPJournal(root / "work.sqlite") as journal,
        ):
            _, _, _, artifacts = demo.fixture(root, ledger, demo.CLIENT_B)
            packet = demo.handoff(ledger, journal, artifacts)
        if not packet["complete"]:
            raise ValueError("Handoff is incomplete")
        (method,) = packet["execution_method"]
        demo.log(
            root,
            "claude_handoff_read",
            status=method["status"],
            pr_number=published["github"]["pr_number"],
        )
        return {
            "objective": packet["work"]["objective"],
            "github": published["github"],
            "method": method,
        }

    @server.tool()
    async def verify_github_pr(
        pr_number: int, head_sha: str, checkpoint_digest: str
    ) -> dict:
        """Verify the exact PR and GitHub head in the handoff; repeats never publish or create commits."""
        require(demo.CLIENT_B)
        async with lock:
            published = read(root / "published.json")
            pinned = published["github"]
            plan = published["plan"]
            if (pr_number, head_sha, checkpoint_digest) != (
                pinned["pr_number"],
                pinned["head_sha"],
                plan["checkpoint_digest"],
            ):
                raise ValueError(
                    "The requested PR or checkpoint differs from the handoff"
                )
            observed = await github(root, "observe", pinned)
            if (
                observed != pinned
                or observed["replacement_sha256"] != plan["replacement_sha256"]
            ):
                raise ValueError("GitHub PR or file content changed")
            with SQLiteWorkLedger(root / "work.sqlite") as ledger:
                if ledger.get_action(plan["action_id"]).status is ActionStatus.VERIFIED:
                    demo.log(
                        root,
                        "claude_verify_replayed",
                        pr_number=pr_number,
                        head_sha=head_sha,
                    )
                    return {"status": "already_verified", **observed}
                runner, _, _, _ = demo.fixture(root, ledger, demo.CLIENT_B)
                contract = demo.contract(GIT_HANDOFF_VERIFY_OPERATION, SideEffect.READ)
                request = ActionRequest(
                    "remote.claude.verify",
                    "git-development",
                    GIT_HANDOFF_VERIFY_OPERATION,
                    demo.REPO,
                    {
                        "source_action_id": plan["action_id"],
                        "checkpoint_digest": checkpoint_digest,
                    },
                    0,
                )
                action = demo.prepare(
                    ledger,
                    ledger.get_grant(demo.B_GRANT),
                    contract,
                    request,
                    GIT_HANDOFF_VERIFY_ADAPTER_DIGEST,
                )
                permit = ledger.issue_dispatch_permit(
                    action.action_id, worker_id=demo.CLIENT_B, ttl=timedelta(minutes=1)
                )
                status = runner.verify_handoff(permit)
                demo.log(
                    root,
                    "claude_verified_pr",
                    status=status.value,
                    pr_number=pr_number,
                    head_sha=head_sha,
                )
                return {"status": status.value, **observed}

    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state_dir", type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--fd", type=int, required=True)
    args = parser.parse_args()
    with socket.socket(fileno=args.fd) as listener:
        host, port = listener.getsockname()
        if host != "127.0.0.1":
            raise ValueError("The fixture requires a prebound IPv4 loopback socket")
        app = build(args.state_dir, args.base, port).streamable_http_app()
        config = uvicorn.Config(app, access_log=False, proxy_headers=False)
        uvicorn.Server(config).run(sockets=[listener])


if __name__ == "__main__":
    main()
