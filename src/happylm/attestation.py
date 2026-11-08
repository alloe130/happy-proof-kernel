"""Tamper-evident Happy action attestations with symmetric signatures."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .integrity import canonical_json


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(item in "0123456789abcdef" for item in value)


@dataclass(frozen=True, slots=True)
class ActionAttestation:
    schema_version: str
    request_digest: str
    contract_digest: str
    evidence_digest: str
    policy_decision: str
    policy_reasons: tuple[str, ...]
    execution_status: str
    output_digest: str | None
    verification_checks: tuple[str, ...]
    compensation_status: str | None
    started_at: str
    finished_at: str
    previous_attestation_digest: str | None = None
    metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        required_digests = (
            self.request_digest,
            self.contract_digest,
            self.evidence_digest,
        )
        if not all(_is_sha256(item) for item in required_digests):
            raise ValueError("attestation requires valid request, contract, and evidence digests")
        if self.output_digest is not None and not _is_sha256(self.output_digest):
            raise ValueError("attestation output digest must be SHA-256")
        if (
            self.previous_attestation_digest is not None
            and not _is_sha256(self.previous_attestation_digest)
        ):
            raise ValueError("previous attestation digest must be SHA-256")
        canonical_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_digest": self.request_digest,
            "contract_digest": self.contract_digest,
            "evidence_digest": self.evidence_digest,
            "policy_decision": self.policy_decision,
            "policy_reasons": list(self.policy_reasons),
            "execution_status": self.execution_status,
            "output_digest": self.output_digest,
            "verification_checks": list(self.verification_checks),
            "compensation_status": self.compensation_status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "previous_attestation_digest": self.previous_attestation_digest,
            "metadata": dict(self.metadata or {}),
        }

    def sign(self, key: bytes, *, key_id: str) -> "SignedAttestation":
        if len(key) < 32:
            raise ValueError("attestation signing key must be at least 32 bytes")
        if not key_id.strip():
            raise ValueError("attestation key id must not be empty")
        payload_json = canonical_json(self.to_dict())
        digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        signature = hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        return SignedAttestation(payload_json, digest, key_id, signature)


@dataclass(frozen=True, slots=True)
class KernelAdmissionAttestation:
    """Signed denial emitted before an action enters the Proof Loop."""

    schema_version: str
    request_digest: str
    contract_id: str
    contract_version: str
    contract_digest: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    admission_decision: str
    reason_codes: tuple[str, ...]
    occurred_at: str
    previous_attestation_digest: str | None = None
    metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not _is_sha256(self.request_digest):
            raise ValueError("admission attestation request digest must be SHA-256")
        if not _is_sha256(self.contract_digest) or not _is_sha256(self.adapter_digest):
            raise ValueError("admission attestation references require SHA-256 digests")
        identities = (
            self.contract_id,
            self.contract_version,
            self.adapter_id,
            self.adapter_version,
        )
        if any(not value.strip() for value in identities):
            raise ValueError("admission attestation reference identity must not be empty")
        if self.admission_decision != "deny":
            raise ValueError("kernel admission attestation must record a denial")
        if not self.reason_codes or any(not code.strip() for code in self.reason_codes):
            raise ValueError("kernel admission denial requires reason codes")
        if (
            self.previous_attestation_digest is not None
            and not _is_sha256(self.previous_attestation_digest)
        ):
            raise ValueError("previous attestation digest must be SHA-256")
        canonical_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_digest": self.request_digest,
            "contract_ref": {
                "id": self.contract_id,
                "version": self.contract_version,
                "digest": self.contract_digest,
            },
            "adapter_ref": {
                "id": self.adapter_id,
                "version": self.adapter_version,
                "digest": self.adapter_digest,
            },
            "admission_decision": self.admission_decision,
            "reason_codes": list(self.reason_codes),
            "occurred_at": self.occurred_at,
            "previous_attestation_digest": self.previous_attestation_digest,
            "metadata": dict(self.metadata or {}),
        }

    def sign(self, key: bytes, *, key_id: str) -> "SignedAttestation":
        if len(key) < 32:
            raise ValueError("attestation signing key must be at least 32 bytes")
        if not key_id.strip():
            raise ValueError("attestation key id must not be empty")
        payload_json = canonical_json(self.to_dict())
        digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        signature = hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        return SignedAttestation(payload_json, digest, key_id, signature)


@dataclass(frozen=True, slots=True)
class SignedAttestation:
    payload_json: str
    digest: str
    key_id: str
    signature: str

    @property
    def payload(self) -> dict[str, Any]:
        value = json.loads(self.payload_json)
        if not isinstance(value, dict):
            raise ValueError("attestation payload must be a JSON object")
        return value

    def verify(self, key: bytes) -> bool:
        if len(key) < 32:
            return False
        try:
            value = self.payload
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if canonical_json(value) != self.payload_json:
            return False
        expected_digest = hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected_digest, self.digest):
            return False
        expected_signature = hmac.new(
            key, self.digest.encode("ascii"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_signature, self.signature)
