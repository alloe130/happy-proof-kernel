"""A tiny synthetic repository and the trusted kernel grants for the demo."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import secrets
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from happylm.development import (
    ContentAddressedArtifactStore,
    ProtectedCheckDefinition,
    ProtectedCheckRegistry,
    RepositoryRegistration,
    RepositoryRegistry,
)
from happylm.development_runner import (
    DurableGitDevelopmentRunner,
    GIT_HANDOFF_VERIFY_OPERATION,
)
from happylm.identity import AuthenticatedPrincipal
from happylm.ledger import LedgerError, SQLiteWorkLedger
from happylm.mcp_work import HappyMCPWorkService, MCP_REQUIRED_SCOPE, SQLiteMCPJournal
from happylm.policy import ApprovalMode, CapabilityContract, RiskLevel, SideEffect
from happylm.policy_profiles import policy_for
from happylm.work import ActionStatus, DelegationGrant, PolicyProfile

TENANT = "tenant.handoff-demo"
WORK = "work.git-handoff-demo"
REPO = "repo://demo/slugger"
WORKSPACE = "slug-fix"
OWNER = "owner.demo"
CLIENT_A = "client.ai-a"
CLIENT_B = "client.ai-b"
AUDIENCE = "https://handoff.example.invalid/mcp"
EDIT_OPERATION = "prepare_reviewable_change"


def fixture(root: Path, ledger: SQLiteWorkLedger, actor: str):
    artifacts = ContentAddressedArtifactStore(root / "artifacts")
    repository = RepositoryRegistration(REPO, str(root / "repo"))
    script = Path(__file__).with_name("slug_check.py").resolve()
    interpreter = Path(sys.executable).resolve()
    check = ProtectedCheckDefinition(
        "slug.behavior",
        "1",
        (str(interpreter), str(script), "slug.py"),
        timeout_seconds=10,
        implementation_files=tuple(
            (str(path), hashlib.sha256(path.read_bytes()).hexdigest())
            for path in (script, interpreter)
        ),
    )
    runner = DurableGitDevelopmentRunner(
        ledger=ledger,
        repositories=RepositoryRegistry((repository,)),
        checks=ProtectedCheckRegistry((check,)),
        artifacts=artifacts,
        workspace_root=root / "workspaces",
        worker_id=actor,
        attestation_key=secrets.token_bytes(32),
        attestation_key_id="demo.ephemeral.hmac",
    )
    return runner, repository, check, artifacts


def contract(operation: str, effect: SideEffect) -> CapabilityContract:
    return CapabilityContract(
        id=f"demo.git.{operation}",
        version="1",
        tool_name="git-development",
        operations=(operation,),
        resource_scopes=(REPO,),
        side_effects=(effect,),
        risk_level=RiskLevel.MODERATE if effect is SideEffect.WRITE else RiskLevel.LOW,
        approval_mode=ApprovalMode.NONE,
        max_cost_usd=1.0,
        idempotent=effect is SideEffect.READ,
        reversible=False,
    )


def grant(
    ledger: SQLiteWorkLedger,
    actor: str,
    capability: CapabilityContract,
    check_digest: str,
) -> DelegationGrant:
    now = datetime.now(UTC)
    profile = PolicyProfile.PRODUCTIVITY_STANDARD
    allowed_actions = capability.operations
    if actor == CLIENT_B:
        allowed_actions += ("happy-mcp.draft_handoff",)
    delegation = DelegationGrant(
        grant_id=f"grant.{actor}",
        issuer_principal=OWNER,
        subject_principal=actor,
        tenant_id=TENANT,
        work_id=WORK,
        policy_profile=profile,
        policy_ref=policy_for(profile).ref,
        contract_digests=(capability.digest,),
        allowed_actions=allowed_actions,
        allowed_side_effects=capability.side_effects,
        resource_scopes=(REPO,),
        destinations=(AUDIENCE,),
        max_actions=1,
        max_cost_micros=1_000_000,
        exclusions=("push", "deploy"),
        required_checks=(check_digest,),
        valid_from=(now - timedelta(seconds=5)).isoformat(),
        valid_until=(now + timedelta(hours=1)).isoformat(),
    )
    return ledger.issue_grant(delegation)


def prepare(ledger, delegation, capability, request, adapter_digest):
    operation, _ = ledger.accept_operation(
        tenant_id=TENANT,
        work_id=WORK,
        caller_request_id=request.id,
        intent={"operation": request.operation, "request_digest": request.digest},
    )
    return ledger.prepare_action(
        operation_id=operation.operation_id,
        grant_id=delegation.grant_id,
        subject_principal=delegation.subject_principal,
        request=request,
        contract=capability,
        adapter_digest=adapter_digest,
    )[0]


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ("git", *args),
        cwd=cwd,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_NAME": "A2 Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@invalid",
            "GIT_COMMITTER_NAME": "A2 Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@invalid",
        },
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


ORIGINAL = b"def slugify(value):\n    return value.lower()\n"
PATH = "slug.py"
A_GRANT = f"grant.{CLIENT_A}"
B_GRANT = f"grant.{CLIENT_B}"
OBJECTIVE = "Fix slugify: trim surrounding whitespace, lowercase, and replace spaces with hyphens."


def log(root: Path, event: str, **fields) -> None:
    with (root / "mcp-events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"event": event, **fields}, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def init(root: Path) -> None:
    root.mkdir(mode=0o700)
    repo = root / "repo"
    repo.mkdir()
    (repo / PATH).write_bytes(ORIGINAL)
    git(repo, "init", "--quiet")
    git(repo, "add", "--", PATH)
    git(
        repo,
        "-c",
        "commit.gpgSign=false",
        "commit",
        "--quiet",
        "-m",
        "Initialize slug fixture",
    )
    with SQLiteWorkLedger(root / "work.sqlite") as ledger:
        _, _, check, _ = fixture(root, ledger, CLIENT_A)
        ledger.create_work(
            tenant_id=TENANT,
            work_id=WORK,
            owner_principals=(OWNER,),
            objective=OBJECTIVE,
            acceptance_criteria=("One Git candidate", "Protected check passes"),
        )
        grant(
            ledger, CLIENT_A, contract(EDIT_OPERATION, SideEffect.WRITE), check.digest
        )


def limit_edit(replacement: str) -> bytes:
    """Allow only a one-expression fixture transformation before running Python."""
    if len(replacement) > 1024:
        raise ValueError("The fixture replacement is too long")
    body = ast.parse(replacement).body
    if len(body) != 1 or not isinstance(body[0], ast.FunctionDef):
        raise ValueError("Submit a single slugify function")
    fn = body[0]
    if (
        fn.name != "slugify"
        or fn.decorator_list
        or fn.returns is not None
        or ast.dump(fn.args)
        != ast.dump(ast.parse("def slugify(value): pass").body[0].args)
        or len(fn.body) != 1
        or not isinstance(fn.body[0], ast.Return)
    ):
        raise ValueError("Use def slugify(value) with one return expression")
    expr = fn.body[0].value
    while isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        method = expr.func.attr
        args = [
            item.value
            if isinstance(item, ast.Constant) and type(item.value) is str
            else None
            for item in expr.args
        ]
        if expr.keywords or not (
            (method in ("strip", "lower") and args == [])
            or (method == "replace" and args == [" ", "-"])
        ):
            raise ValueError(
                "The fixture permits only strip(), lower(), and replacement of spaces with hyphens"
            )
        expr = expr.func.value
    if not isinstance(expr, ast.Name) or expr.id != "value":
        raise ValueError("Only the input string may be used")
    return (replacement.rstrip() + "\n").encode()


def enable_b(root: Path) -> None:
    with SQLiteWorkLedger(root / "work.sqlite") as ledger:
        try:
            ledger.get_grant(B_GRANT)
        except LedgerError as error:
            if error.code != "grant_not_found":
                raise
        else:
            return
        actions = [
            item for op in ledger.snapshot(WORK)["operations"] for item in op["actions"]
        ]
        if (
            len(actions) != 1
            or actions[0]["status"] != ActionStatus.VERIFICATION_PENDING.value
        ):
            raise ValueError("Claude requires exactly one staged action from GPT")
        _, _, check, _ = fixture(root, ledger, CLIENT_B)
        if ledger.get_grant_state(A_GRANT)[1].value != "revoked":
            ledger.revoke_grant(
                A_GRANT,
                reason="Git candidate staged; verification is separately scoped",
            )
        grant(
            ledger,
            CLIENT_B,
            contract(GIT_HANDOFF_VERIFY_OPERATION, SideEffect.READ),
            check.digest,
        )


def handoff(ledger: SQLiteWorkLedger, journal: SQLiteMCPJournal, artifacts) -> dict:
    principal = AuthenticatedPrincipal(
        subject=CLIENT_B,
        tenant_id=TENANT,
        roles=("work.contributor",),
        work_ids=(WORK,),
        issuer="https://local-mcp-fixture.invalid",
        audience=AUDIENCE,
        token_id="claude-oauth-demo",
        expires_at=int(datetime.now(UTC).timestamp()) + 300,
        scopes=(MCP_REQUIRED_SCOPE,),
    )
    return HappyMCPWorkService(
        ledger=ledger, journal=journal, artifacts=artifacts
    ).draft_handoff(principal=principal, work_id=WORK, grant_id=B_GRANT)
