from dataclasses import replace

from happylm.attestation import ActionAttestation, KernelAdmissionAttestation


KEY = b"a" * 32


def attestation() -> ActionAttestation:
    return ActionAttestation(
        schema_version="happy-proof-attestation/v1",
        request_digest="1" * 64,
        contract_digest="2" * 64,
        evidence_digest="3" * 64,
        policy_decision="allow",
        policy_reasons=(),
        execution_status="verified",
        output_digest="4" * 64,
        verification_checks=("http_200",),
        compensation_status=None,
        started_at="2026-10-31T06:00:00+00:00",
        finished_at="2026-10-31T06:00:01+00:00",
    )


def test_signed_attestation_verifies_with_bound_key() -> None:
    signed = attestation().sign(KEY, key_id="dev-key-1")

    assert signed.verify(KEY)
    assert not signed.verify(b"b" * 32)
    assert signed.payload["execution_status"] == "verified"


def test_tampered_attestation_payload_is_detected() -> None:
    signed = attestation().sign(KEY, key_id="dev-key-1")
    tampered = replace(
        signed,
        payload_json=signed.payload_json.replace("verified", "failed", 1),
    )

    assert not tampered.verify(KEY)


def test_signed_kernel_admission_denial_binds_exact_references() -> None:
    signed = KernelAdmissionAttestation(
        schema_version="happy-proof-kernel-admission/v1",
        request_digest="1" * 64,
        contract_id="filesystem.read",
        contract_version="1",
        contract_digest="2" * 64,
        adapter_id="filesystem.local",
        adapter_version="3",
        adapter_digest="3" * 64,
        admission_decision="deny",
        reason_codes=("contract_revoked",),
        occurred_at="2026-10-31T06:00:00+00:00",
    ).sign(KEY, key_id="dev-key-1")

    assert signed.verify(KEY)
    assert signed.payload["contract_ref"]["version"] == "1"
    assert signed.payload["adapter_ref"]["version"] == "3"
    assert signed.payload["reason_codes"] == ["contract_revoked"]
