"""Durable A2 dispatcher joining the Git workflow to the A1 ledger."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, cast

from .attestation import ActionAttestation, SignedAttestation
from .development import (
    GIT_DEVELOPMENT_ADAPTER_DIGEST,
    ContentAddressedArtifactStore,
    DevelopmentError,
    DevelopmentReview,
    EditInstruction,
    GitDevelopmentWorkspace,
    ProtectedCheckDefinition,
    ProtectedCheckReceipt,
    ProtectedCheckRegistry,
    RepositoryRegistry,
    build_development_review,
)
from .integrity import is_sha256_digest, sha256_json
from .ledger import SQLiteWorkLedger
from .work import ActionRecord, ActionStatus, AttemptStatus, DispatchPermit


GIT_HANDOFF_VERIFY_OPERATION = "verify_staged_candidate"
GIT_HANDOFF_VERIFY_ADAPTER_DIGEST = sha256_json(
    {"id": "happy.git-handoff-verifier", "version": "1", "operation": GIT_HANDOFF_VERIFY_OPERATION}
)
GIT_CANDIDATE_SCHEMA = "happy-development-candidate/v1"


def git_candidate_checkpoint(
    ledger: SQLiteWorkLedger,
    artifacts: ContentAddressedArtifactStore,
    action: ActionRecord,
) -> tuple[dict[str, Any], str] | None:
    """Read a committed runner artifact by its ledger-bound digest."""
    if action.adapter_digest != GIT_DEVELOPMENT_ADAPTER_DIGEST:
        return None
    operation = ledger.get_operation(action.operation_id)
    for event in reversed(ledger.events_for("action", action.action_id)):
        if event.event_type != "dispatch.acknowledged":
            continue
        digest = event.payload.get("result_digest")
        if not isinstance(digest, str) or not is_sha256_digest(digest):
            return None
        try:
            artifact = artifacts.get_json(digest)
        except (OSError, ValueError, DevelopmentError):
            return None
        if (
            artifact.get("schema_version") not in (GIT_CANDIDATE_SCHEMA, "happy-development-review/v1")
            or artifact.get("action_id") != action.action_id
            or artifact.get("operation_id") != operation.operation_id
            or artifact.get("work_id") != operation.work_id
            or artifact.get("repository_uri") != action.request.resource
            or artifact.get("base_commit") != action.request.arguments.get("base_commit")
            or not isinstance(artifact.get("candidate_commit"), str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", artifact["candidate_commit"])
            or not isinstance(artifact.get("diff_digest"), str)
            or not is_sha256_digest(artifact["diff_digest"])
        ):
            return None
        if artifact["schema_version"] == GIT_CANDIDATE_SCHEMA and artifact.get("request_digest") != action.request.digest:
            return None
        return artifact, digest
    return None


@dataclass(frozen=True, slots=True)
class DevelopmentActionSpec:
    repository_uri: str
    repository_registration_digest: str
    base_commit: str
    workspace_id: str
    commit_message: str
    edits: tuple[EditInstruction, ...]
    protected_check_digests: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DevelopmentActionSpec":
        expected = {
            "repository_uri",
            "repository_registration_digest",
            "base_commit",
            "workspace_id",
            "commit_message",
            "edits",
            "protected_check_digests",
        }
        if set(value) != expected:
            raise DevelopmentError(
                "development_spec_invalid", "development action fields are not exact"
            )
        raw_edits = value["edits"]
        raw_checks = value["protected_check_digests"]
        if not isinstance(raw_edits, list) or not raw_edits:
            raise DevelopmentError("development_spec_invalid", "at least one edit is required")
        if not isinstance(raw_checks, list) or not raw_checks:
            raise DevelopmentError(
                "development_spec_invalid", "at least one protected check is required"
            )
        for field in (
            "repository_uri",
            "repository_registration_digest",
            "base_commit",
            "workspace_id",
            "commit_message",
        ):
            if not isinstance(value[field], str):
                raise DevelopmentError(
                    "development_spec_invalid", f"{field} must be a string"
                )
        edits: list[EditInstruction] = []
        for raw in raw_edits:
            if not isinstance(raw, dict):
                raise DevelopmentError("development_spec_invalid", "edit must be an object")
            if set(raw) != {
                "relative_path",
                "expected_before_digest",
                "replacement_artifact_digest",
                "contributor_kind",
                "contributor_principal",
            }:
                raise DevelopmentError("development_spec_invalid", "edit fields are not exact")
            if any(not isinstance(raw[field], str) for field in raw):
                raise DevelopmentError(
                    "development_spec_invalid", "edit fields must be strings"
                )
            from .development import ContributionKind

            edits.append(
                EditInstruction(
                    relative_path=raw["relative_path"],
                    expected_before_digest=raw["expected_before_digest"],
                    replacement_artifact_digest=raw["replacement_artifact_digest"],
                    contributor_kind=ContributionKind(raw["contributor_kind"]),
                    contributor_principal=raw["contributor_principal"],
                )
            )
        if any(not isinstance(item, str) for item in raw_checks):
            raise DevelopmentError("development_spec_invalid", "check digests must be strings")
        if len(raw_checks) != len(set(raw_checks)):
            raise DevelopmentError("development_spec_invalid", "check digests must be unique")
        return cls(
            repository_uri=value["repository_uri"],
            repository_registration_digest=value["repository_registration_digest"],
            base_commit=value["base_commit"],
            workspace_id=value["workspace_id"],
            commit_message=value["commit_message"],
            edits=tuple(edits),
            protected_check_digests=tuple(raw_checks),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_uri": self.repository_uri,
            "repository_registration_digest": self.repository_registration_digest,
            "base_commit": self.base_commit,
            "workspace_id": self.workspace_id,
            "commit_message": self.commit_message,
            "edits": [item.to_dict() for item in self.edits],
            "protected_check_digests": list(self.protected_check_digests),
        }


@dataclass(frozen=True, slots=True)
class DevelopmentRunResult:
    review: DevelopmentReview
    review_artifact_digest: str
    attestation_artifact_digest: str
    action_status: ActionStatus
    workspace_path: str


@dataclass(frozen=True, slots=True)
class StagedDevelopmentCandidate:
    candidate_commit: str
    checkpoint_digest: str


class DurableGitDevelopmentRunner:
    """Consume one dispatch permit and produce one immutable Git review."""

    def __init__(
        self,
        *,
        ledger: SQLiteWorkLedger,
        repositories: RepositoryRegistry,
        checks: ProtectedCheckRegistry,
        artifacts: ContentAddressedArtifactStore,
        workspace_root: str | Path,
        worker_id: str,
        attestation_key: bytes,
        attestation_key_id: str,
        sandbox_profiles: Any | None = None,
        sandbox_runner: Any | None = None,
    ) -> None:
        if not worker_id.strip():
            raise ValueError("worker id must not be empty")
        self.ledger = ledger
        self.repositories = repositories
        self.checks = checks
        self.artifacts = artifacts
        self.workspace_root = Path(workspace_root)
        self.worker_id = worker_id
        self.sandbox_profiles = sandbox_profiles
        self.sandbox_runner = sandbox_runner
        if len(attestation_key) < 32 or not attestation_key_id.strip():
            raise ValueError("runner requires a valid attestation signing key")
        self._attestation_key = attestation_key
        self._attestation_key_id = attestation_key_id

    def _sign_attestation(
        self,
        *,
        request_digest: str,
        contract_digest: str,
        evidence_digest: str,
        execution_status: str,
        output_digest: str,
        verification_checks: tuple[str, ...],
        started_at: str,
        finished_at: str,
        metadata: Mapping[str, Any],
    ) -> tuple[SignedAttestation, str]:
        attestation = ActionAttestation(
            schema_version="happy-development-attestation/v1",
            request_digest=request_digest,
            contract_digest=contract_digest,
            evidence_digest=evidence_digest,
            policy_decision="allow",
            policy_reasons=(),
            execution_status=execution_status,
            output_digest=output_digest,
            verification_checks=verification_checks,
            compensation_status=None,
            started_at=started_at,
            finished_at=finished_at,
            metadata=metadata,
        )
        signed = attestation.sign(
            self._attestation_key,
            key_id=self._attestation_key_id,
        )
        artifact_digest = self.artifacts.put_json(
            {
                "payload_json": signed.payload_json,
                "digest": signed.digest,
                "key_id": signed.key_id,
                "signature": signed.signature,
            }
        )
        return signed, artifact_digest

    def dispatch(self, permit: DispatchPermit) -> DevelopmentRunResult:
        return cast(DevelopmentRunResult, self._dispatch(permit, stage_only=False))

    def stage_for_handoff(self, permit: DispatchPermit) -> StagedDevelopmentCandidate:
        """Apply the authorized edits once and persist the candidate before returning."""
        return cast(StagedDevelopmentCandidate, self._dispatch(permit, stage_only=True))

    def _dispatch(
        self, permit: DispatchPermit, *, stage_only: bool
    ) -> DevelopmentRunResult | StagedDevelopmentCandidate:
        action = self.ledger.get_action(permit.action_id)
        operation = self.ledger.get_operation(action.operation_id)
        if action.adapter_digest != GIT_DEVELOPMENT_ADAPTER_DIGEST:
            raise DevelopmentError("adapter_mismatch", "action is bound to another adapter")
        if (
            action.request.tool_name != "git-development"
            or action.request.operation != "prepare_reviewable_change"
        ):
            raise DevelopmentError("action_mismatch", "action is not a Git development action")
        spec = DevelopmentActionSpec.from_mapping(action.request.arguments)
        if action.request.resource != spec.repository_uri:
            raise DevelopmentError("repository_binding_mismatch", "request resource differs")
        repository = self.repositories.resolve(
            spec.repository_uri,
            spec.repository_registration_digest,
        )
        grant = self.ledger.get_grant(action.grant_id)
        missing_required_checks = set(grant.required_checks) - set(
            spec.protected_check_digests
        )
        if missing_required_checks:
            raise DevelopmentError(
                "required_check_missing",
                "development action omits a delegation-required check",
            )
        definitions = tuple(
            self.checks.resolve(digest) for digest in spec.protected_check_digests
        )
        replacements = tuple(
            self.artifacts.get_bytes(
                item.replacement_artifact_digest,
                max_bytes=1_048_576,
            )
            for item in spec.edits
        )

        self.ledger.consume_dispatch_permit(
            permit.token,
            worker_id=self.worker_id,
            action_id=permit.action_id,
            attempt_id=permit.attempt_id,
        )
        started_at = datetime.now(UTC).isoformat()
        try:
            workspace = GitDevelopmentWorkspace.create(
                repository=repository,
                base_commit=spec.base_commit,
                workspace_root=self.workspace_root,
                workspace_id=spec.workspace_id,
            )
            for instruction, replacement in zip(spec.edits, replacements, strict=True):
                workspace.apply_edit(instruction, replacement)
            candidate, diff = workspace.freeze_candidate(spec.commit_message)
            if stage_only:
                checkpoint_digest = self.artifacts.put_json({
                    "schema_version": GIT_CANDIDATE_SCHEMA,
                    "work_id": operation.work_id,
                    "operation_id": operation.operation_id,
                    "action_id": action.action_id,
                    "request_digest": action.request.digest,
                    "repository_uri": spec.repository_uri,
                    "base_commit": spec.base_commit,
                    "candidate_commit": candidate,
                    "diff_digest": self.artifacts.put_bytes(diff),
                    "contributions": [item.to_dict() for item in workspace.contributions],
                })
            else:
                receipts = self._run_checks(workspace, definitions)
                unresolved = () if all(item.passed for item in receipts) else (
                    "one or more protected checks failed",
                )
                review, review_digest = build_development_review(
                    work_id=operation.work_id,
                    operation_id=operation.operation_id,
                    action_id=action.action_id,
                    workspace=workspace,
                    candidate_commit=candidate,
                    diff=diff,
                    checks=receipts,
                    artifacts=self.artifacts,
                    unresolved_items=unresolved,
                )
        except Exception as error:
            failure = {
                "schema_version": "happy-development-runner-failure/v1",
                "work_id": operation.work_id,
                "operation_id": operation.operation_id,
                "action_id": action.action_id,
                "error_type": type(error).__name__,
                "error_code": getattr(error, "code", "unexpected_failure"),
                "recorded_at": datetime.now(UTC).isoformat(),
            }
            failure_digest = self.artifacts.put_json(failure)
            _, failure_attestation_digest = self._sign_attestation(
                request_digest=action.request.digest,
                contract_digest=action.contract_digest,
                evidence_digest=failure_digest,
                execution_status="verification_failed",
                output_digest=failure_digest,
                verification_checks=(),
                started_at=started_at,
                finished_at=datetime.now(UTC).isoformat(),
                metadata={
                    "work_id": operation.work_id,
                    "operation_id": operation.operation_id,
                    "action_id": action.action_id,
                    "failure_artifact_digest": failure_digest,
                },
            )
            self.ledger.record_dispatch_outcome(
                permit.attempt_id,
                outcome=AttemptStatus.ACKNOWLEDGED,
                result_digest=failure_digest,
            )
            self.ledger.record_verification(
                action.action_id,
                passed=False,
                verifier_receipt_digest=failure_attestation_digest,
            )
            raise

        if stage_only:
            self.ledger.record_dispatch_outcome(
                permit.attempt_id, outcome=AttemptStatus.ACKNOWLEDGED, result_digest=checkpoint_digest
            )
            return StagedDevelopmentCandidate(candidate, checkpoint_digest)

        _, attestation_digest = self._sign_attestation(
            request_digest=action.request.digest,
            contract_digest=action.contract_digest,
            evidence_digest=review.diff_digest,
            execution_status="verified" if review.verified else "verification_failed",
            output_digest=review_digest,
            verification_checks=tuple(item.digest for item in review.checks),
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            metadata={
                "work_id": operation.work_id,
                "operation_id": operation.operation_id,
                "action_id": action.action_id,
                "review_artifact_digest": review_digest,
                "base_commit": review.base_commit,
                "candidate_commit": review.candidate_commit,
                "adapter_digest": action.adapter_digest,
            },
        )
        self.ledger.record_dispatch_outcome(
            permit.attempt_id,
            outcome=AttemptStatus.ACKNOWLEDGED,
            result_digest=review_digest,
        )
        status = self.ledger.record_verification(
            action.action_id,
            passed=review.verified,
            verifier_receipt_digest=attestation_digest,
        )
        return DevelopmentRunResult(
            review=review,
            review_artifact_digest=review_digest,
            attestation_artifact_digest=attestation_digest,
            action_status=status,
            workspace_path=str(workspace.root),
        )

    def _run_checks(
        self, workspace: GitDevelopmentWorkspace, definitions: tuple[ProtectedCheckDefinition, ...]
    ) -> tuple[ProtectedCheckReceipt, ...]:
        return workspace.run_protected_checks(
            definitions,
            self.artifacts,
            sandbox_profiles=self.sandbox_profiles,
            sandbox_runner=self.sandbox_runner,
        )

    def verify_handoff(self, permit: DispatchPermit) -> ActionStatus:
        """Verify the staged Git action with a fresh permit for the receiving worker."""
        follow_up = self.ledger.get_action(permit.action_id)
        request = follow_up.request
        grant = self.ledger.get_grant(follow_up.grant_id)
        if (
            follow_up.adapter_digest != GIT_HANDOFF_VERIFY_ADAPTER_DIGEST
            or request.tool_name != "git-development"
            or request.operation != GIT_HANDOFF_VERIFY_OPERATION
            or set(request.arguments) != {"source_action_id", "checkpoint_digest"}
            or any(not isinstance(value, str) for value in request.arguments.values())
            or grant.subject_principal != self.worker_id
        ):
            raise DevelopmentError("handoff_action_invalid", "follow-up requires its own verifier grant and action")
        source = self.ledger.get_action(request.arguments["source_action_id"])
        source_operation = self.ledger.get_operation(source.operation_id)
        follow_up_operation = self.ledger.get_operation(follow_up.operation_id)
        source_grant = self.ledger.get_grant(source.grant_id)
        if (
            source.operation_id == follow_up.operation_id
            or source_operation.work_id != follow_up_operation.work_id
            or source_operation.tenant_id != follow_up_operation.tenant_id
            or source.request.resource != request.resource
            or source_grant.subject_principal == self.worker_id
            or source.status is not ActionStatus.VERIFICATION_PENDING
        ):
            raise DevelopmentError("handoff_source_invalid", "source must be another worker's staged action on this work")
        checkpoint = git_candidate_checkpoint(self.ledger, self.artifacts, source)
        if (
            checkpoint is None
            or checkpoint[0]["schema_version"] != GIT_CANDIDATE_SCHEMA
            or checkpoint[1] != request.arguments["checkpoint_digest"]
        ):
            raise DevelopmentError("handoff_checkpoint_invalid", "checkpoint must match the ledger")
        candidate, checkpoint_digest = checkpoint
        spec = DevelopmentActionSpec.from_mapping(source.request.arguments)
        if set(grant.required_checks) - set(spec.protected_check_digests):
            raise DevelopmentError("required_check_missing", "handoff omits a verifier-required check")
        repository = self.repositories.resolve(spec.repository_uri, spec.repository_registration_digest)
        definitions = tuple(self.checks.resolve(digest) for digest in spec.protected_check_digests)
        self.ledger.consume_dispatch_permit(
            permit.token, worker_id=self.worker_id, action_id=follow_up.action_id, attempt_id=permit.attempt_id,
            verification_source_action_id=source.action_id,
        )
        started_at = datetime.now(UTC).isoformat()
        try:
            workspace = GitDevelopmentWorkspace.reopen_candidate(
                repository=repository,
                base_commit=spec.base_commit,
                workspace_root=self.workspace_root,
                workspace_id=spec.workspace_id,
                candidate_commit=candidate["candidate_commit"],
                diff_digest=candidate["diff_digest"],
            )
            checks = self._run_checks(workspace, definitions)
        except (DevelopmentError, OSError) as error:
            checks = ()
            error_code = getattr(error, "code", "workspace_unavailable")
        else:
            error_code = None
        passed = bool(checks) and all(item.passed for item in checks)
        observation = self.artifacts.put_json({
            "schema_version": "happy-development-handoff-verification/v1",
            "source_action_id": source.action_id,
            "verification_action_id": follow_up.action_id,
            "checkpoint_digest": checkpoint_digest,
            "candidate_commit": candidate["candidate_commit"],
            "checks": [item.to_dict() for item in checks],
            "error_code": error_code,
            "verified": passed,
        })
        _, receipt = self._sign_attestation(
            request_digest=request.digest,
            contract_digest=follow_up.contract_digest,
            evidence_digest=checkpoint_digest,
            execution_status="verified" if passed else "verification_failed",
            output_digest=observation,
            verification_checks=tuple(item.digest for item in checks),
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            metadata={
                "source_action_id": source.action_id,
                "verification_action_id": follow_up.action_id,
                "candidate_commit": candidate["candidate_commit"],
            },
        )
        return self.ledger.record_handoff_verification(
            source_action_id=source.action_id, verification_attempt_id=permit.attempt_id,
            passed=passed, result_digest=observation, verifier_receipt_digest=receipt,
        )
