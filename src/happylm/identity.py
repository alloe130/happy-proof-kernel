"""Provider-neutral OIDC bearer-token validation and tenant RBAC claims."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Protocol


class AuthenticationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _decode_segment(value: str) -> bytes:
    if not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise ValueError("JWT segment is not canonical base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise ValueError("JWT segment is not canonical base64url")
    return decoded


def _json_segment(value: str) -> dict[str, Any]:
    decoded = json.loads(
        _decode_segment(value).decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(decoded, dict):
        raise ValueError("JWT segment must be a JSON object")
    return decoded


class JWTSignatureVerifier(Protocol):
    def verify(
        self,
        *,
        algorithm: str,
        key_id: str,
        signing_input: bytes,
        signature: bytes,
    ) -> bool: ...


class HMACJWTSignatureVerifier:
    """Closed-deployment/test signature verifier; production OIDC should use JWKS."""

    def __init__(self, keys: Mapping[str, bytes]) -> None:
        if not keys or any(not key_id or len(key) < 32 for key_id, key in keys.items()):
            raise ValueError("HMAC JWT keys must be named and at least 32 bytes")
        self._keys = dict(keys)

    def verify(
        self,
        *,
        algorithm: str,
        key_id: str,
        signing_input: bytes,
        signature: bytes,
    ) -> bool:
        if algorithm != "HS256" or key_id not in self._keys:
            return False
        expected = hmac.new(self._keys[key_id], signing_input, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected)


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    subject: str
    tenant_id: str
    roles: tuple[str, ...]
    work_ids: tuple[str, ...]
    issuer: str
    audience: str
    token_id: str | None
    expires_at: int
    scopes: tuple[str, ...] = ()

    def has_role(self, *roles: str) -> bool:
        return bool(set(self.roles).intersection(roles))

    def may_read_work(self, work_id: str) -> bool:
        return "*" in self.work_ids or work_id in self.work_ids


class OIDCBearerVerifier:
    """Validate signed OIDC-style JWT claims without owning provider credentials.

    The signature verifier is injected so production deployments can bind this
    claim validation to an asymmetric JWKS/KMS implementation.  The included
    HMAC verifier is intentionally limited to closed reference deployments.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        signature_verifier: JWTSignatureVerifier,
        allowed_algorithms: tuple[str, ...] = ("RS256",),
        clock: Callable[[], datetime] | None = None,
        leeway_seconds: int = 30,
        max_token_bytes: int = 16_384,
    ) -> None:
        if not issuer or not audience or not allowed_algorithms:
            raise ValueError("OIDC issuer, audience, and algorithms are required")
        if "none" in {item.lower() for item in allowed_algorithms}:
            raise ValueError("unsigned JWTs are forbidden")
        if not 0 <= leeway_seconds <= 300 or max_token_bytes < 1024:
            raise ValueError("OIDC verifier limits are invalid")
        self.issuer = issuer
        self.audience = audience
        self.signature_verifier = signature_verifier
        self.allowed_algorithms = allowed_algorithms
        self.clock = clock or (lambda: datetime.now(UTC))
        self.leeway_seconds = leeway_seconds
        self.max_token_bytes = max_token_bytes

    def verify_authorization(self, authorization: str) -> AuthenticatedPrincipal:
        if not authorization.startswith("Bearer "):
            raise AuthenticationError("bearer_required", "Bearer authorization is required")
        token = authorization[7:]
        if not token or len(token.encode("ascii", errors="ignore")) > self.max_token_bytes:
            raise AuthenticationError("token_invalid", "Bearer token is missing or oversized")
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthenticationError("token_invalid", "JWT must contain three segments")
        try:
            header = _json_segment(parts[0])
            claims = _json_segment(parts[1])
            signature = _decode_segment(parts[2])
        except (ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise AuthenticationError("token_invalid", "JWT encoding is invalid") from error
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if not isinstance(algorithm, str) or algorithm not in self.allowed_algorithms:
            raise AuthenticationError("algorithm_denied", "JWT algorithm is not allowed")
        if not isinstance(key_id, str) or not key_id:
            raise AuthenticationError("key_id_missing", "JWT key id is required")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        if not self.signature_verifier.verify(
            algorithm=algorithm,
            key_id=key_id,
            signing_input=signing_input,
            signature=signature,
        ):
            raise AuthenticationError("signature_invalid", "JWT signature is invalid")
        return self._claims_to_principal(claims)

    def _claims_to_principal(self, claims: Mapping[str, Any]) -> AuthenticatedPrincipal:
        issuer = claims.get("iss")
        subject = claims.get("sub")
        tenant_id = claims.get("tenant_id")
        roles = claims.get("roles")
        work_ids = claims.get("work_ids")
        token_id = claims.get("jti")
        scope_claim = claims.get("scope", "")
        if issuer != self.issuer:
            raise AuthenticationError("issuer_mismatch", "JWT issuer does not match")
        audience_claim = claims.get("aud")
        audiences = (
            (audience_claim,)
            if isinstance(audience_claim, str)
            else tuple(audience_claim) if isinstance(audience_claim, list) else ()
        )
        if any(not isinstance(item, str) or not item for item in audiences):
            raise AuthenticationError("audience_invalid", "JWT audience is invalid")
        if self.audience not in audiences:
            raise AuthenticationError("audience_mismatch", "JWT audience does not match")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("subject_missing", "JWT subject is required")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise AuthenticationError("tenant_missing", "JWT tenant is required")
        if (
            not isinstance(roles, list)
            or not roles
            or any(not isinstance(item, str) or not item for item in roles)
            or any(len(item) > 128 for item in roles)
            or len(roles) != len(set(roles))
        ):
            raise AuthenticationError("roles_invalid", "JWT roles are invalid")
        if (
            not isinstance(work_ids, list)
            or any(not isinstance(item, str) or not item for item in work_ids)
            or any(len(item) > 128 for item in work_ids)
            or len(work_ids) != len(set(work_ids))
        ):
            raise AuthenticationError("work_scope_invalid", "JWT work scope is invalid")
        if token_id is not None and (not isinstance(token_id, str) or not token_id):
            raise AuthenticationError("token_id_invalid", "JWT token id is invalid")
        if not isinstance(scope_claim, str):
            raise AuthenticationError("scope_invalid", "JWT scope must be a string")
        scopes = tuple(item for item in scope_claim.split(" ") if item)
        if (
            any(len(item) > 128 for item in scopes)
            or len(scopes) != len(set(scopes))
        ):
            raise AuthenticationError("scope_invalid", "JWT scope is invalid")
        now = self.clock()
        if now.tzinfo is None:
            raise ValueError("OIDC verifier clock must be timezone-aware")
        current = now.astimezone(UTC).timestamp()
        exp = claims.get("exp")
        nbf = claims.get("nbf", claims.get("iat", 0))
        if not isinstance(exp, (int, float)) or not math.isfinite(float(exp)):
            raise AuthenticationError("expiry_missing", "JWT expiry is required")
        if not isinstance(nbf, (int, float)) or not math.isfinite(float(nbf)):
            raise AuthenticationError("not_before_invalid", "JWT not-before is invalid")
        if current >= float(exp) + self.leeway_seconds:
            raise AuthenticationError("token_expired", "JWT has expired")
        if current + self.leeway_seconds < float(nbf):
            raise AuthenticationError("token_not_yet_valid", "JWT is not active")
        return AuthenticatedPrincipal(
            subject=subject,
            tenant_id=tenant_id,
            roles=tuple(roles),
            work_ids=tuple(work_ids),
            issuer=self.issuer,
            audience=self.audience,
            token_id=token_id,
            expires_at=int(exp),
            scopes=scopes,
        )
