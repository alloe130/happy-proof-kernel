"""Capability contracts and fail-closed policy evaluation."""

from __future__ import annotations

import math
import posixpath
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

from .integrity import sha256_json


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class SideEffect(str, Enum):
    READ = "read"
    WRITE = "write"
    EXTERNAL = "external"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"


class ApprovalMode(str, Enum):
    NONE = "none"
    USER = "user"
    TWO_PERSON = "two_person"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


def _parse_utc(value: str) -> datetime:
    resolved = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if resolved.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return resolved.astimezone(UTC)


def _normalized_resource(value: str) -> tuple[str, str, str]:
    if not value.strip() or "\\" in value:
        raise ValueError("resource must be a non-empty canonical path or URI")
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment:
        raise ValueError("resource must not contain a query or fragment")
    decoded_path = unquote(parsed.path)
    if decoded_path != parsed.path:
        raise ValueError("resource path must not use percent encoding")
    if ".." in PurePosixPath(decoded_path).parts:
        raise ValueError("resource must not contain parent traversal")

    if parsed.scheme:
        if not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("resource URI must have a host and no user info")
        host = (parsed.hostname or "").lower()
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        path = posixpath.normpath(decoded_path or "/")
        return parsed.scheme.lower(), host, path

    if not value.startswith("/"):
        raise ValueError("local resource must be an absolute path")
    return "file", "", posixpath.normpath(decoded_path)


def _resource_in_scope(resource: str, scope: str) -> bool:
    resource_scheme, resource_host, resource_path = _normalized_resource(resource)
    scope_scheme, scope_host, scope_path = _normalized_resource(scope)
    if (resource_scheme, resource_host) != (scope_scheme, scope_host):
        return False
    if resource_path == scope_path:
        return True
    boundary = scope_path.rstrip("/") + "/"
    return resource_path.startswith(boundary)


def resource_in_scope(resource: str, scope: str) -> bool:
    """Return whether a canonical resource is inside a canonical scope.

    This public wrapper lets the durable delegation layer reuse exactly the
    same path-component boundary rules as capability contracts.
    """

    return _resource_in_scope(resource, scope)


def contract_denial_reasons(
    request: "ActionRequest", contract: "CapabilityContract"
) -> tuple[str, ...]:
    """Validate immutable request bounds without applying an approval profile."""

    reasons: list[str] = []
    if request.tool_name != contract.tool_name:
        reasons.append("tool_mismatch")
    if request.operation not in contract.operations:
        reasons.append("operation_not_allowed")
    try:
        in_scope = any(
            _resource_in_scope(request.resource, scope)
            for scope in contract.resource_scopes
        )
    except ValueError:
        in_scope = False
    if not in_scope:
        reasons.append("resource_out_of_scope")
    if (
        contract.max_cost_usd is not None
        and request.expected_cost_usd > contract.max_cost_usd
    ):
        reasons.append("cost_limit_exceeded")
    return tuple(reasons)


@dataclass(frozen=True, slots=True)
class CapabilityContract:
    id: str
    version: str
    tool_name: str
    operations: tuple[str, ...]
    resource_scopes: tuple[str, ...]
    side_effects: tuple[SideEffect, ...]
    risk_level: RiskLevel
    approval_mode: ApprovalMode
    max_cost_usd: float | None
    idempotent: bool
    reversible: bool
    preconditions: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ()
    compensating_action: str | None = None

    def __post_init__(self) -> None:
        if not all(item.strip() for item in (self.id, self.version, self.tool_name)):
            raise ValueError("contract identity fields must not be empty")
        if not self.operations or len(self.operations) != len(set(self.operations)):
            raise ValueError("contract operations must be non-empty and unique")
        if any(not item.strip() for item in self.operations):
            raise ValueError("contract operations must not be blank")
        if not self.resource_scopes or len(self.resource_scopes) != len(
            set(self.resource_scopes)
        ):
            raise ValueError("resource scopes must be non-empty and unique")
        for scope in self.resource_scopes:
            _normalized_resource(scope)
        if not self.side_effects or len(self.side_effects) != len(set(self.side_effects)):
            raise ValueError("side effects must be non-empty and unique")
        if self.max_cost_usd is not None and (
            not math.isfinite(self.max_cost_usd) or self.max_cost_usd < 0
        ):
            raise ValueError("maximum cost must be finite and non-negative")
        if self.reversible and not self.compensating_action:
            raise ValueError("reversible contracts require a compensating action")
        if not self.reversible and self.compensating_action is not None:
            raise ValueError("irreversible contracts cannot name a compensating action")
        sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "tool_name": self.tool_name,
            "operations": list(self.operations),
            "resource_scopes": list(self.resource_scopes),
            "side_effects": [item.value for item in self.side_effects],
            "risk_level": self.risk_level.value,
            "approval_mode": self.approval_mode.value,
            "max_cost_usd": self.max_cost_usd,
            "idempotent": self.idempotent,
            "reversible": self.reversible,
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "compensating_action": self.compensating_action,
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class ActionRequest:
    id: str
    tool_name: str
    operation: str
    resource: str
    arguments: Mapping[str, Any]
    expected_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if not all(item.strip() for item in (self.id, self.tool_name, self.operation)):
            raise ValueError("request identity fields must not be empty")
        _normalized_resource(self.resource)
        if not math.isfinite(self.expected_cost_usd) or self.expected_cost_usd < 0:
            raise ValueError("expected cost must be finite and non-negative")
        sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "resource": self.resource,
            "arguments": dict(self.arguments),
            "expected_cost_usd": self.expected_cost_usd,
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class Approval:
    request_digest: str
    contract_digest: str
    approvers: tuple[str, ...]
    approved_at: str
    valid_until: str

    def __post_init__(self) -> None:
        if len(self.approvers) != len(set(self.approvers)) or any(
            not item.strip() for item in self.approvers
        ):
            raise ValueError("approvers must be unique and non-empty")
        if _parse_utc(self.valid_until) <= _parse_utc(self.approved_at):
            raise ValueError("approval expiry must follow approval time")


@dataclass(frozen=True, slots=True)
class PolicyResult:
    decision: PolicyDecision
    reason_codes: tuple[str, ...]
    required_approvers: int
    request_digest: str
    contract_digest: str


class CapabilityPolicy:
    """Evaluate a request without allowing a contract to weaken safety floors."""

    def evaluate(
        self,
        request: ActionRequest,
        contract: CapabilityContract,
        *,
        approval: Approval | None = None,
        now: datetime | None = None,
    ) -> PolicyResult:
        denial_reasons = list(contract_denial_reasons(request, contract))

        required = {
            ApprovalMode.NONE: 0,
            ApprovalMode.USER: 1,
            ApprovalMode.TWO_PERSON: 2,
        }[contract.approval_mode]
        if contract.risk_level is RiskLevel.HIGH:
            required = max(required, 1)
        elif contract.risk_level is RiskLevel.CRITICAL:
            required = max(required, 2)
        if set(contract.side_effects) & {SideEffect.WRITE, SideEffect.EXTERNAL}:
            required = max(required, 1)
        if set(contract.side_effects) & {SideEffect.DESTRUCTIVE, SideEffect.FINANCIAL}:
            required = max(required, 2)

        if denial_reasons:
            return PolicyResult(
                PolicyDecision.DENY,
                tuple(denial_reasons),
                required,
                request.digest,
                contract.digest,
            )

        if required:
            if approval is None:
                return PolicyResult(
                    PolicyDecision.REQUIRE_APPROVAL,
                    ("approval_missing",),
                    required,
                    request.digest,
                    contract.digest,
                )
            binding_errors: list[str] = []
            if approval.request_digest != request.digest:
                binding_errors.append("approval_request_mismatch")
            if approval.contract_digest != contract.digest:
                binding_errors.append("approval_contract_mismatch")
            current = (now or datetime.now(UTC)).astimezone(UTC)
            if not (_parse_utc(approval.approved_at) <= current < _parse_utc(approval.valid_until)):
                binding_errors.append("approval_expired_or_not_yet_valid")
            if len(approval.approvers) < required:
                binding_errors.append("insufficient_approvers")
            if binding_errors:
                return PolicyResult(
                    PolicyDecision.DENY,
                    tuple(binding_errors),
                    required,
                    request.digest,
                    contract.digest,
                )

        return PolicyResult(
            PolicyDecision.ALLOW,
            (),
            required,
            request.digest,
            contract.digest,
        )
