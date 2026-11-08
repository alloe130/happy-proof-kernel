"""Versioned built-in Happy Proof Kernel policy profiles.

These definitions are data, not ambient authority.  A delegation grant pins the
exact policy reference and the ledger still evaluates the concrete action at
dispatch time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .integrity import sha256_json
from .work import PolicyProfile, PolicyRef


@dataclass(frozen=True, slots=True)
class PolicyDefinition:
    id: str
    version: str
    profile: PolicyProfile
    rules: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "profile": self.profile.value,
            "rules": list(self.rules),
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())

    @property
    def ref(self) -> PolicyRef:
        return PolicyRef(self.id, self.version, self.digest)


PRODUCTIVITY_STANDARD_V1 = PolicyDefinition(
    id="happy.policy.productivity_standard",
    version="1",
    profile=PolicyProfile.PRODUCTIVITY_STANDARD,
    rules=(
        "scoped_read_write_may_use_delegation",
        "high_risk_requires_one_action_approver",
        "critical_destructive_financial_require_two_action_approvers",
        "policy_delegation_and_required_checks_are_not_self_modifiable",
    ),
)


STRICT_LEGACY_V1 = PolicyDefinition(
    id="happy.policy.strict_legacy",
    version="1",
    profile=PolicyProfile.STRICT_LEGACY,
    rules=(
        "write_or_external_requires_one_action_approver",
        "critical_destructive_financial_require_two_action_approvers",
        "policy_delegation_and_required_checks_are_not_self_modifiable",
    ),
)


BUILTIN_POLICY_PROFILES = {
    PRODUCTIVITY_STANDARD_V1.profile: PRODUCTIVITY_STANDARD_V1,
    STRICT_LEGACY_V1.profile: STRICT_LEGACY_V1,
}


def policy_for(profile: PolicyProfile) -> PolicyDefinition:
    return BUILTIN_POLICY_PROFILES[profile]
