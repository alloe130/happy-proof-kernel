"""Versioned work, delegation, and durable execution domain records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Mapping

from .integrity import canonical_json, is_sha256_digest, sha256_json
from .policy import (
    ActionRequest,
    CapabilityContract,
    RiskLevel,
    SideEffect,
    contract_denial_reasons,
    resource_in_scope,
)


def parse_utc(value: str) -> datetime:
    resolved = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if resolved.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return resolved.astimezone(UTC)


def utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC).isoformat()


def _nonempty(value: str, name: str) -> str:
    if not value.strip():
        raise ValueError(f"{name} must not be empty")
    return value


class PolicyProfile(StrEnum):
    PRODUCTIVITY_STANDARD = "productivity_standard"
    STRICT_LEGACY = "strict_legacy"


class WorkStatus(StrEnum):
    OPEN = "open"
    BLOCKED = "blocked"
    COMPLETED = "completed"


class OperationStatus(StrEnum):
    RECEIVED = "received"
    EXECUTION_PENDING = "execution_pending"
    DISPATCHING = "dispatching"
    EXECUTION_OUTCOME_UNKNOWN = "execution_outcome_unknown"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED = "verified"
    FAILED_NO_EFFECT = "failed_no_effect"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class ActionStatus(StrEnum):
    PREPARED = "prepared"
    DISPATCHING = "dispatching"
    EXECUTION_OUTCOME_UNKNOWN = "execution_outcome_unknown"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED = "verified"
    FAILED_NO_EFFECT = "failed_no_effect"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class AttemptStatus(StrEnum):
    PREPARED = "prepared"
    AUTHORIZED = "authorized"
    DISPATCHING = "dispatching"
    EXECUTION_OUTCOME_UNKNOWN = "execution_outcome_unknown"
    ACKNOWLEDGED = "acknowledged"
    FAILED_NO_EFFECT = "failed_no_effect"


class ReconcileOutcome(StrEnum):
    EFFECT_CONFIRMED = "effect_confirmed"
    NO_EFFECT_CONFIRMED = "no_effect_confirmed"
    INCONCLUSIVE = "inconclusive"


class GrantStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class PolicyRef:
    id: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        _nonempty(self.id, "policy id")
        _nonempty(self.version, "policy version")
        if not is_sha256_digest(self.digest):
            raise ValueError("policy reference requires a SHA-256 digest")

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "version": self.version, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class WorkObject:
    work_id: str
    tenant_id: str
    revision: int
    objective: str
    acceptance_criteria: tuple[str, ...]
    owner_principals: tuple[str, ...]
    status: WorkStatus
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        for name, value in (
            ("work id", self.work_id),
            ("tenant id", self.tenant_id),
            ("objective", self.objective),
        ):
            _nonempty(value, name)
        if self.revision < 1:
            raise ValueError("work revision must be positive")
        if not self.acceptance_criteria or any(
            not item.strip() for item in self.acceptance_criteria
        ):
            raise ValueError("work requires non-empty acceptance criteria")
        if not self.owner_principals or len(self.owner_principals) != len(
            set(self.owner_principals)
        ):
            raise ValueError("work owners must be non-empty and unique")
        parse_utc(self.created_at)
        parse_utc(self.updated_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "work_id": self.work_id,
            "tenant_id": self.tenant_id,
            "revision": self.revision,
            "objective": self.objective,
            "acceptance_criteria": list(self.acceptance_criteria),
            "owner_principals": list(self.owner_principals),
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class DelegationGrant:
    grant_id: str
    issuer_principal: str
    subject_principal: str
    tenant_id: str
    work_id: str
    policy_profile: PolicyProfile
    policy_ref: PolicyRef
    contract_digests: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    allowed_side_effects: tuple[SideEffect, ...]
    resource_scopes: tuple[str, ...]
    destinations: tuple[str, ...]
    max_actions: int
    max_cost_micros: int
    exclusions: tuple[str, ...]
    required_checks: tuple[str, ...]
    valid_from: str
    valid_until: str

    def __post_init__(self) -> None:
        for name, value in (
            ("grant id", self.grant_id),
            ("issuer principal", self.issuer_principal),
            ("subject principal", self.subject_principal),
            ("tenant id", self.tenant_id),
            ("work id", self.work_id),
        ):
            _nonempty(value, name)
        if not self.contract_digests or any(
            not is_sha256_digest(item) for item in self.contract_digests
        ):
            raise ValueError("grant requires contract SHA-256 digests")
        if not self.allowed_actions or len(self.allowed_actions) != len(
            set(self.allowed_actions)
        ):
            raise ValueError("allowed actions must be non-empty and unique")
        if not self.allowed_side_effects or len(self.allowed_side_effects) != len(
            set(self.allowed_side_effects)
        ):
            raise ValueError("allowed side effects must be non-empty and unique")
        if not self.resource_scopes or len(self.resource_scopes) != len(
            set(self.resource_scopes)
        ):
            raise ValueError("resource scopes must be non-empty and unique")
        # Reuse ActionRequest validation without accepting an actual action.
        for scope in self.resource_scopes:
            ActionRequest("scope.check", "scope", "check", scope, {})
        if self.max_actions < 1 or self.max_cost_micros < 0:
            raise ValueError("grant limits must be non-negative and actions positive")
        if len(self.destinations) != len(set(self.destinations)):
            raise ValueError("destinations must be unique")
        if len(self.exclusions) != len(set(self.exclusions)):
            raise ValueError("exclusions must be unique")
        if any(not item.strip() for item in (*self.required_checks, *self.exclusions)):
            raise ValueError("grant checks and exclusions must not be blank")
        if parse_utc(self.valid_until) <= parse_utc(self.valid_from):
            raise ValueError("grant expiry must follow its start")
        canonical_json(self.to_dict())

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "issuer_principal": self.issuer_principal,
            "subject_principal": self.subject_principal,
            "tenant_id": self.tenant_id,
            "work_id": self.work_id,
            "policy_profile": self.policy_profile.value,
            "policy_ref": self.policy_ref.to_dict(),
            "contract_digests": list(self.contract_digests),
            "allowed_actions": list(self.allowed_actions),
            "allowed_side_effects": [item.value for item in self.allowed_side_effects],
            "resource_scopes": list(self.resource_scopes),
            "destinations": list(self.destinations),
            "max_actions": self.max_actions,
            "max_cost_micros": self.max_cost_micros,
            "exclusions": list(self.exclusions),
            "required_checks": list(self.required_checks),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }


@dataclass(frozen=True, slots=True)
class DelegationDecision:
    allowed: bool
    reason_codes: tuple[str, ...]
    required_approvers: int


@dataclass(frozen=True, slots=True)
class ActionApprovalRecord:
    approval_id: str
    tenant_id: str
    work_id: str
    operation_id: str
    request_digest: str
    contract_digest: str
    adapter_digest: str
    policy_ref: PolicyRef
    resource: str
    destination: str | None
    approvers: tuple[str, ...]
    approved_at: str
    valid_until: str

    def __post_init__(self) -> None:
        for name, value in (
            ("approval id", self.approval_id),
            ("tenant id", self.tenant_id),
            ("work id", self.work_id),
            ("operation id", self.operation_id),
            ("resource", self.resource),
        ):
            _nonempty(value, name)
        for digest in (
            self.request_digest,
            self.contract_digest,
            self.adapter_digest,
        ):
            if not is_sha256_digest(digest):
                raise ValueError("approval commitments must be SHA-256 digests")
        ActionRequest("approval.scope", "scope", "check", self.resource, {})
        if self.destination is not None and not self.destination.strip():
            raise ValueError("approval destination must not be blank")
        if not self.approvers or len(self.approvers) != len(set(self.approvers)):
            raise ValueError("approval requires unique, non-empty approvers")
        if any(not item.strip() for item in self.approvers):
            raise ValueError("approval requires unique, non-empty approvers")
        if parse_utc(self.valid_until) <= parse_utc(self.approved_at):
            raise ValueError("approval expiry must follow approval time")
        canonical_json(self.to_dict())

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "tenant_id": self.tenant_id,
            "work_id": self.work_id,
            "operation_id": self.operation_id,
            "request_digest": self.request_digest,
            "contract_digest": self.contract_digest,
            "adapter_digest": self.adapter_digest,
            "policy_ref": self.policy_ref.to_dict(),
            "resource": self.resource,
            "destination": self.destination,
            "approvers": list(self.approvers),
            "approved_at": self.approved_at,
            "valid_until": self.valid_until,
        }


def evaluate_delegation(
    grant: DelegationGrant,
    request: ActionRequest,
    contract: CapabilityContract,
    *,
    subject_principal: str,
    now: datetime,
    destination: str | None,
    action_approver_count: int,
) -> DelegationDecision:
    """Evaluate a proposed action without allowing a grant to expand itself."""

    reasons: list[str] = []
    reasons.extend(contract_denial_reasons(request, contract))
    current = now.astimezone(UTC)
    if subject_principal != grant.subject_principal:
        reasons.append("grant_subject_mismatch")
    if not (parse_utc(grant.valid_from) <= current < parse_utc(grant.valid_until)):
        reasons.append("grant_not_current")
    if contract.digest not in grant.contract_digests:
        reasons.append("contract_not_delegated")
    if request.operation not in grant.allowed_actions:
        reasons.append("action_not_delegated")
    if request.operation in grant.exclusions:
        reasons.append("action_explicitly_excluded")
    if not set(contract.side_effects).issubset(set(grant.allowed_side_effects)):
        reasons.append("side_effect_not_delegated")
    try:
        in_scope = any(
            resource_in_scope(request.resource, scope) for scope in grant.resource_scopes
        )
    except ValueError:
        in_scope = False
    if not in_scope:
        reasons.append("resource_outside_delegation")
    if SideEffect.EXTERNAL in contract.side_effects:
        if destination is None or destination not in grant.destinations:
            reasons.append("destination_not_delegated")

    required = 0
    if grant.policy_profile is PolicyProfile.STRICT_LEGACY:
        if set(contract.side_effects) & {SideEffect.WRITE, SideEffect.EXTERNAL}:
            required = max(required, 1)
        if set(contract.side_effects) & {SideEffect.DESTRUCTIVE, SideEffect.FINANCIAL}:
            required = max(required, 2)
        if contract.risk_level is RiskLevel.CRITICAL:
            required = max(required, 2)
    else:
        # productivity_standard delegates scoped read/write work, but never the
        # MVP's protected effects or critical actions.
        if set(contract.side_effects) & {SideEffect.DESTRUCTIVE, SideEffect.FINANCIAL}:
            required = max(required, 2)
        if contract.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            required = max(required, 1 if contract.risk_level is RiskLevel.HIGH else 2)
    if action_approver_count < required:
        reasons.append("action_approval_floor_not_met")
    return DelegationDecision(not reasons, tuple(reasons), required)


@dataclass(frozen=True, slots=True)
class OperationRecord:
    operation_id: str
    tenant_id: str
    work_id: str
    caller_request_id: str
    intent_digest: str
    status: OperationStatus
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class ActionRecord:
    action_id: str
    operation_id: str
    grant_id: str
    request: ActionRequest
    contract_digest: str
    adapter_digest: str
    approval_digest: str | None
    status: ActionStatus
    reserved_cost_micros: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    attempt_id: str
    action_id: str
    attempt_number: int
    status: AttemptStatus
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class DispatchPermit:
    permit_id: str
    action_id: str
    attempt_id: str
    worker_id: str
    registry_revision: int
    expires_at: str
    token: str


@dataclass(frozen=True, slots=True)
class LedgerEvent:
    event_id: str
    tenant_id: str
    aggregate_type: str
    aggregate_id: str
    sequence: int
    event_type: str
    payload: Mapping[str, Any]
    payload_digest: str
    occurred_at: str
