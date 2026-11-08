"""SQLite append-only ledger and durable A1 execution projections."""

from __future__ import annotations

import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .integrity import canonical_json, is_sha256_digest, sha256_json
from .policy import ActionRequest, CapabilityContract, SideEffect
from .policy_profiles import policy_for
from .work import (
    ActionApprovalRecord,
    ActionRecord,
    ActionStatus,
    AttemptRecord,
    AttemptStatus,
    DelegationGrant,
    DispatchPermit,
    GrantStatus,
    LedgerEvent,
    OperationRecord,
    OperationStatus,
    ReconcileOutcome,
    WorkObject,
    WorkStatus,
    evaluate_delegation,
    parse_utc,
    utc_text,
)


class LedgerError(RuntimeError):
    """Machine-readable durable-workflow failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _cost_micros(value: float) -> int:
    return int(
        (Decimal(str(value)) * Decimal("1000000")).quantize(
            Decimal("1"), rounding=ROUND_HALF_UP
        )
    )


class SQLiteWorkLedger:
    """Single-worker reference ledger with atomic event/projection updates."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.path = str(path)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._id_factory = id_factory or _new_id
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        # MCP sync tools execute in a bounded worker thread.  The A1 reference
        # still uses one serialized worker, but its connection must be movable
        # across that thread boundary.
        self._db = sqlite3.connect(
            self.path, isolation_level=None, check_same_thread=False
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = FULL")
        self._migrate()

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "SQLiteWorkLedger":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield self._db
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        else:
            self._db.execute("COMMIT")

    def _migrate(self) -> None:
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS ledger_meta (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO ledger_meta(key, value)
            VALUES ('registry_revision', 0);

            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                aggregate_type TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                UNIQUE(tenant_id, aggregate_type, aggregate_id, sequence)
            );
            CREATE TRIGGER IF NOT EXISTS events_no_update
            BEFORE UPDATE ON events BEGIN
                SELECT RAISE(ABORT, 'events are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete
            BEFORE DELETE ON events BEGIN
                SELECT RAISE(ABORT, 'events are append-only');
            END;

            CREATE TABLE IF NOT EXISTS work_objects (
                work_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                objective TEXT NOT NULL,
                acceptance_json TEXT NOT NULL,
                owners_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(tenant_id, work_id)
            );

            CREATE TABLE IF NOT EXISTS delegation_grants (
                grant_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                work_id TEXT NOT NULL REFERENCES work_objects(work_id),
                grant_json TEXT NOT NULL,
                grant_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                used_actions INTEGER NOT NULL DEFAULT 0,
                reserved_actions INTEGER NOT NULL DEFAULT 0,
                used_cost_micros INTEGER NOT NULL DEFAULT 0,
                reserved_cost_micros INTEGER NOT NULL DEFAULT 0,
                issued_at TEXT NOT NULL,
                revoked_at TEXT,
                revocation_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                work_id TEXT NOT NULL REFERENCES work_objects(work_id),
                caller_request_id TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(tenant_id, caller_request_id)
            );

            CREATE TABLE IF NOT EXISTS actions (
                action_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                grant_id TEXT NOT NULL REFERENCES delegation_grants(grant_id),
                request_json TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                resource TEXT NOT NULL,
                side_effects_json TEXT NOT NULL,
                contract_digest TEXT NOT NULL,
                adapter_digest TEXT NOT NULL,
                approval_digest TEXT,
                status TEXT NOT NULL,
                reserved_cost_micros INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(operation_id, request_digest)
            );

            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL REFERENCES actions(action_id),
                attempt_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(action_id, attempt_number)
            );

            CREATE TABLE IF NOT EXISTS dispatch_permits (
                permit_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL REFERENCES actions(action_id),
                attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
                grant_id TEXT NOT NULL REFERENCES delegation_grants(grant_id),
                worker_id TEXT NOT NULL,
                token_digest TEXT NOT NULL UNIQUE,
                registry_revision INTEGER NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                UNIQUE(action_id, attempt_id)
            );
            """
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("ledger clock must return timezone-aware timestamps")
        return value.astimezone(UTC)

    def _append_event(
        self,
        db: sqlite3.Connection,
        *,
        tenant_id: str,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        occurred_at: str,
    ) -> LedgerEvent:
        payload_json = canonical_json(dict(payload))
        payload_digest = sha256_json(dict(payload))
        row = db.execute(
            """SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence
               FROM events
               WHERE tenant_id=? AND aggregate_type=? AND aggregate_id=?""",
            (tenant_id, aggregate_type, aggregate_id),
        ).fetchone()
        sequence = int(row["next_sequence"])
        # A caller-provided ID factory may lose its in-memory counter after a
        # process restart.  Build event IDs from the durable aggregate sequence
        # and event content so restart recovery cannot collide with old rows.
        event_id = "evt_" + sha256_json(
            {
                "tenant_id": tenant_id,
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "sequence": sequence,
                "event_type": event_type,
                "payload_digest": payload_digest,
            }
        )[:32]
        db.execute(
            """INSERT INTO events(
                   event_id, tenant_id, aggregate_type, aggregate_id, sequence,
                   event_type, payload_json, payload_digest, occurred_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                tenant_id,
                aggregate_type,
                aggregate_id,
                sequence,
                event_type,
                payload_json,
                payload_digest,
                occurred_at,
            ),
        )
        return LedgerEvent(
            event_id,
            tenant_id,
            aggregate_type,
            aggregate_id,
            sequence,
            event_type,
            dict(payload),
            payload_digest,
            occurred_at,
        )

    def registry_revision(self) -> int:
        row = self._db.execute(
            "SELECT value FROM ledger_meta WHERE key='registry_revision'"
        ).fetchone()
        return int(row["value"])

    def _bump_registry_revision(self, db: sqlite3.Connection) -> int:
        db.execute(
            "UPDATE ledger_meta SET value=value+1 WHERE key='registry_revision'"
        )
        row = db.execute(
            "SELECT value FROM ledger_meta WHERE key='registry_revision'"
        ).fetchone()
        return int(row["value"])

    def create_work(
        self,
        *,
        tenant_id: str,
        objective: str,
        acceptance_criteria: tuple[str, ...],
        owner_principals: tuple[str, ...],
        work_id: str | None = None,
    ) -> WorkObject:
        now = utc_text(self._now())
        work = WorkObject(
            work_id or self._id_factory("work"),
            tenant_id,
            1,
            objective,
            acceptance_criteria,
            owner_principals,
            WorkStatus.OPEN,
            now,
            now,
        )
        with self._transaction() as db:
            try:
                db.execute(
                    """INSERT INTO work_objects VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        work.work_id,
                        work.tenant_id,
                        work.revision,
                        work.objective,
                        canonical_json(list(work.acceptance_criteria)),
                        canonical_json(list(work.owner_principals)),
                        work.status.value,
                        work.created_at,
                        work.updated_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise LedgerError("work_exists", "work id already exists") from error
            self._append_event(
                db,
                tenant_id=work.tenant_id,
                aggregate_type="work",
                aggregate_id=work.work_id,
                event_type="work.created",
                payload=work.to_dict(),
                occurred_at=now,
            )
        return work

    def get_work(self, work_id: str) -> WorkObject:
        row = self._db.execute(
            "SELECT * FROM work_objects WHERE work_id=?", (work_id,)
        ).fetchone()
        if row is None:
            raise LedgerError("work_not_found", f"work {work_id!r} was not found")
        return WorkObject(
            row["work_id"],
            row["tenant_id"],
            row["revision"],
            row["objective"],
            tuple(json.loads(row["acceptance_json"])),
            tuple(json.loads(row["owners_json"])),
            WorkStatus(row["status"]),
            row["created_at"],
            row["updated_at"],
        )

    def get_grant(self, grant_id: str) -> DelegationGrant:
        row = self._db.execute(
            "SELECT * FROM delegation_grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
        if row is None:
            raise LedgerError("grant_not_found", "delegation grant was not found")
        return self._grant_from_row(row)

    def get_grant_state(
        self, grant_id: str
    ) -> tuple[DelegationGrant, GrantStatus, dict[str, int]]:
        """Return an immutable grant plus its current durable projection state."""

        row = self._db.execute(
            "SELECT * FROM delegation_grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
        if row is None:
            raise LedgerError("grant_not_found", "delegation grant was not found")
        counters = {
            "used_actions": int(row["used_actions"]),
            "reserved_actions": int(row["reserved_actions"]),
            "used_cost_micros": int(row["used_cost_micros"]),
            "reserved_cost_micros": int(row["reserved_cost_micros"]),
        }
        return self._grant_from_row(row), GrantStatus(row["status"]), counters

    def issue_grant(self, grant: DelegationGrant) -> DelegationGrant:
        work = self.get_work(grant.work_id)
        if work.tenant_id != grant.tenant_id:
            raise LedgerError("tenant_mismatch", "grant tenant does not own the work")
        if grant.policy_ref != policy_for(grant.policy_profile).ref:
            raise LedgerError(
                "policy_reference_mismatch",
                "grant profile is not pinned to the supported policy version",
            )
        now = utc_text(self._now())
        with self._transaction() as db:
            try:
                db.execute(
                    """INSERT INTO delegation_grants(
                           grant_id, tenant_id, work_id, grant_json, grant_digest,
                           status, issued_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        grant.grant_id,
                        grant.tenant_id,
                        grant.work_id,
                        canonical_json(grant.to_dict()),
                        grant.digest,
                        GrantStatus.ACTIVE.value,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise LedgerError("grant_exists", "grant id already exists") from error
            revision = self._bump_registry_revision(db)
            self._append_event(
                db,
                tenant_id=grant.tenant_id,
                aggregate_type="grant",
                aggregate_id=grant.grant_id,
                event_type="grant.issued",
                payload={"grant": grant.to_dict(), "registry_revision": revision},
                occurred_at=now,
            )
        return grant

    def revoke_grant(self, grant_id: str, *, reason: str) -> int:
        if not reason.strip():
            raise ValueError("grant revocation requires a reason")
        now = utc_text(self._now())
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM delegation_grants WHERE grant_id=?", (grant_id,)
            ).fetchone()
            if row is None:
                raise LedgerError("grant_not_found", "grant was not found")
            if row["status"] != GrantStatus.ACTIVE.value:
                raise LedgerError("grant_not_active", "grant is not active")
            db.execute(
                """UPDATE delegation_grants
                   SET status=?, revoked_at=?, revocation_reason=? WHERE grant_id=?""",
                (GrantStatus.REVOKED.value, now, reason, grant_id),
            )
            revision = self._bump_registry_revision(db)
            self._append_event(
                db,
                tenant_id=row["tenant_id"],
                aggregate_type="grant",
                aggregate_id=grant_id,
                event_type="grant.revoked",
                payload={"reason": reason, "registry_revision": revision},
                occurred_at=now,
            )
        return revision

    def accept_operation(
        self,
        *,
        tenant_id: str,
        work_id: str,
        caller_request_id: str,
        intent: Mapping[str, Any],
    ) -> tuple[OperationRecord, bool]:
        if not caller_request_id.strip():
            raise ValueError("caller request id must not be empty")
        work = self.get_work(work_id)
        if work.tenant_id != tenant_id:
            raise LedgerError("tenant_mismatch", "tenant does not own the work")
        intent_json = canonical_json(dict(intent))
        digest = sha256_json(dict(intent))
        now = utc_text(self._now())
        with self._transaction() as db:
            existing = db.execute(
                """SELECT * FROM operations
                   WHERE tenant_id=? AND caller_request_id=?""",
                (tenant_id, caller_request_id),
            ).fetchone()
            if existing is not None:
                if existing["intent_digest"] != digest or existing["work_id"] != work_id:
                    raise LedgerError(
                        "caller_request_conflict",
                        "caller request id is already bound to another intent",
                    )
                return self._operation_from_row(existing), False
            operation_id = self._id_factory("op")
            db.execute(
                """INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    operation_id,
                    tenant_id,
                    work_id,
                    caller_request_id,
                    intent_json,
                    digest,
                    OperationStatus.RECEIVED.value,
                    now,
                    now,
                ),
            )
            self._append_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="operation",
                aggregate_id=operation_id,
                event_type="operation.accepted",
                payload={
                    "work_id": work_id,
                    "caller_request_id": caller_request_id,
                    "intent_digest": digest,
                },
                occurred_at=now,
            )
            row = db.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            return self._operation_from_row(row), True

    def prepare_action(
        self,
        *,
        operation_id: str,
        grant_id: str,
        subject_principal: str,
        request: ActionRequest,
        contract: CapabilityContract,
        adapter_digest: str,
        destination: str | None = None,
        action_approval: ActionApprovalRecord | None = None,
    ) -> tuple[ActionRecord, AttemptRecord]:
        if not is_sha256_digest(adapter_digest):
            raise ValueError("adapter digest must be SHA-256")
        now_dt = self._now()
        now = utc_text(now_dt)
        cost = _cost_micros(request.expected_cost_usd)
        with self._transaction() as db:
            operation = db.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if operation is None:
                raise LedgerError("operation_not_found", "operation was not found")
            existing = db.execute(
                """SELECT * FROM actions
                   WHERE operation_id=? AND request_digest=?""",
                (operation_id, request.digest),
            ).fetchone()
            if existing is not None:
                attempt = db.execute(
                    """SELECT * FROM attempts WHERE action_id=?
                       ORDER BY attempt_number DESC LIMIT 1""",
                    (existing["action_id"],),
                ).fetchone()
                return self._action_from_row(existing), self._attempt_from_row(attempt)
            grant_row = db.execute(
                "SELECT * FROM delegation_grants WHERE grant_id=?", (grant_id,)
            ).fetchone()
            if grant_row is None:
                raise LedgerError("grant_not_found", "delegation grant was not found")
            grant = self._grant_from_row(grant_row)
            if grant_row["status"] != GrantStatus.ACTIVE.value:
                raise LedgerError("grant_not_active", "delegation grant is not active")
            if operation["tenant_id"] != grant.tenant_id or operation["work_id"] != grant.work_id:
                raise LedgerError("grant_scope_mismatch", "grant is bound to another work")
            action_approver_count = 0
            approval_digest: str | None = None
            if action_approval is not None:
                expected = {
                    "tenant_id": operation["tenant_id"],
                    "work_id": operation["work_id"],
                    "operation_id": operation_id,
                    "request_digest": request.digest,
                    "contract_digest": contract.digest,
                    "adapter_digest": adapter_digest,
                    "policy_ref": grant.policy_ref,
                    "resource": request.resource,
                    "destination": destination,
                }
                actual = {
                    "tenant_id": action_approval.tenant_id,
                    "work_id": action_approval.work_id,
                    "operation_id": action_approval.operation_id,
                    "request_digest": action_approval.request_digest,
                    "contract_digest": action_approval.contract_digest,
                    "adapter_digest": action_approval.adapter_digest,
                    "policy_ref": action_approval.policy_ref,
                    "resource": action_approval.resource,
                    "destination": action_approval.destination,
                }
                if actual != expected:
                    raise LedgerError(
                        "action_approval_mismatch",
                        "approval is bound to another action context",
                    )
                if not (
                    parse_utc(action_approval.approved_at)
                    <= now_dt
                    < parse_utc(action_approval.valid_until)
                ):
                    raise LedgerError(
                        "action_approval_expired",
                        "approval is expired or not yet valid",
                    )
                action_approver_count = len(action_approval.approvers)
                approval_digest = action_approval.digest
            decision = evaluate_delegation(
                grant,
                request,
                contract,
                subject_principal=subject_principal,
                now=now_dt,
                destination=destination,
                action_approver_count=action_approver_count,
            )
            if not decision.allowed:
                raise LedgerError(
                    "delegation_denied", ",".join(decision.reason_codes)
                )
            if grant_row["reserved_actions"] + grant_row["used_actions"] >= grant.max_actions:
                raise LedgerError("grant_action_limit", "delegation action limit exhausted")
            if (
                grant_row["reserved_cost_micros"]
                + grant_row["used_cost_micros"]
                + cost
                > grant.max_cost_micros
            ):
                raise LedgerError("grant_cost_limit", "delegation cost limit exceeded")
            if set(contract.side_effects) & {
                SideEffect.WRITE,
                SideEffect.EXTERNAL,
                SideEffect.DESTRUCTIVE,
                SideEffect.FINANCIAL,
            }:
                hold = db.execute(
                    """SELECT actions.action_id
                       FROM actions
                       JOIN operations USING (operation_id)
                       WHERE operations.tenant_id=? AND actions.resource=?
                         AND actions.status=?
                       LIMIT 1""",
                    (
                        operation["tenant_id"],
                        request.resource,
                        ActionStatus.EXECUTION_OUTCOME_UNKNOWN.value,
                    ),
                ).fetchone()
                if hold is not None:
                    raise LedgerError(
                        "scope_hold_active",
                        "a related action has an unknown execution outcome",
                    )
            action_id = self._id_factory("act")
            attempt_id = self._id_factory("try")
            db.execute(
                """INSERT INTO actions(
                       action_id, operation_id, grant_id, request_json,
                       request_digest, resource, side_effects_json,
                       contract_digest, adapter_digest, approval_digest, status,
                       reserved_cost_micros, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action_id,
                    operation_id,
                    grant_id,
                    canonical_json(request.to_dict()),
                    request.digest,
                    request.resource,
                    canonical_json([item.value for item in contract.side_effects]),
                    contract.digest,
                    adapter_digest,
                    approval_digest,
                    ActionStatus.PREPARED.value,
                    cost,
                    now,
                    now,
                ),
            )
            db.execute(
                "INSERT INTO attempts VALUES (?, ?, 1, ?, ?, ?)",
                (attempt_id, action_id, AttemptStatus.PREPARED.value, now, now),
            )
            db.execute(
                """UPDATE delegation_grants
                   SET reserved_actions=reserved_actions+1,
                       reserved_cost_micros=reserved_cost_micros+?
                   WHERE grant_id=?""",
                (cost, grant_id),
            )
            db.execute(
                "UPDATE operations SET status=?, updated_at=? WHERE operation_id=?",
                (OperationStatus.EXECUTION_PENDING.value, now, operation_id),
            )
            self._append_event(
                db,
                tenant_id=operation["tenant_id"],
                aggregate_type="action",
                aggregate_id=action_id,
                event_type="action.prepared",
                payload={
                    "operation_id": operation_id,
                    "attempt_id": attempt_id,
                    "grant_id": grant_id,
                    "request_digest": request.digest,
                    "contract_digest": contract.digest,
                    "adapter_digest": adapter_digest,
                    "approval_digest": approval_digest,
                    "approver_count": action_approver_count,
                    "reserved_cost_micros": cost,
                },
                occurred_at=now,
            )
            action = db.execute(
                "SELECT * FROM actions WHERE action_id=?", (action_id,)
            ).fetchone()
            attempt = db.execute(
                "SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            return self._action_from_row(action), self._attempt_from_row(attempt)

    def issue_dispatch_permit(
        self,
        action_id: str,
        *,
        worker_id: str,
        ttl: timedelta,
    ) -> DispatchPermit:
        if not worker_id.strip() or ttl <= timedelta(0):
            raise ValueError("dispatch permit requires a worker and positive TTL")
        now_dt = self._now()
        now = utc_text(now_dt)
        with self._transaction() as db:
            action = db.execute(
                "SELECT * FROM actions WHERE action_id=?", (action_id,)
            ).fetchone()
            if action is None:
                raise LedgerError("action_not_found", "action was not found")
            if action["status"] != ActionStatus.PREPARED.value:
                raise LedgerError("action_not_prepared", "action is not dispatchable")
            attempt = db.execute(
                """SELECT * FROM attempts WHERE action_id=?
                   ORDER BY attempt_number DESC LIMIT 1""",
                (action_id,),
            ).fetchone()
            grant_row = db.execute(
                "SELECT * FROM delegation_grants WHERE grant_id=?", (action["grant_id"],)
            ).fetchone()
            grant = self._grant_from_row(grant_row)
            if grant_row["status"] != GrantStatus.ACTIVE.value:
                raise LedgerError("grant_not_active", "grant is not active")
            expires_dt = min(now_dt + ttl, parse_utc(grant.valid_until))
            if expires_dt <= now_dt:
                raise LedgerError("grant_expired", "grant is expired")
            token = self._token_factory()
            if not token or len(token) < 32:
                raise ValueError("dispatch token must contain at least 32 characters")
            permit_id = self._id_factory("permit")
            revision = self.registry_revision()
            expires_at = utc_text(expires_dt)
            try:
                db.execute(
                    """INSERT INTO dispatch_permits VALUES (
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
                       )""",
                    (
                        permit_id,
                        action_id,
                        attempt["attempt_id"],
                        action["grant_id"],
                        worker_id,
                        sha256_json(token),
                        revision,
                        now,
                        expires_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise LedgerError(
                    "dispatch_permit_exists", "attempt already has a dispatch permit"
                ) from error
            db.execute(
                "UPDATE attempts SET status=?, updated_at=? WHERE attempt_id=?",
                (AttemptStatus.AUTHORIZED.value, now, attempt["attempt_id"]),
            )
            operation = db.execute(
                "SELECT * FROM operations WHERE operation_id=?", (action["operation_id"],)
            ).fetchone()
            self._append_event(
                db,
                tenant_id=operation["tenant_id"],
                aggregate_type="action",
                aggregate_id=action_id,
                event_type="dispatch.authorized",
                payload={
                    "permit_id": permit_id,
                    "attempt_id": attempt["attempt_id"],
                    "worker_id": worker_id,
                    "registry_revision": revision,
                    "expires_at": expires_at,
                },
                occurred_at=now,
            )
            return DispatchPermit(
                permit_id,
                action_id,
                attempt["attempt_id"],
                worker_id,
                revision,
                expires_at,
                token,
            )

    def consume_dispatch_permit(
        self,
        token: str,
        *,
        worker_id: str,
        action_id: str,
        attempt_id: str,
        verification_source_action_id: str | None = None,
    ) -> None:
        token_digest = sha256_json(token)
        with self._transaction() as db:
            permit = db.execute(
                "SELECT * FROM dispatch_permits WHERE token_digest=?", (token_digest,)
            ).fetchone()
            if permit is None:
                raise LedgerError("dispatch_permit_invalid", "permit was not found")
            if permit["consumed_at"] is not None:
                raise LedgerError("dispatch_permit_consumed", "permit is single-use")
            if (
                permit["worker_id"] != worker_id
                or permit["action_id"] != action_id
                or permit["attempt_id"] != attempt_id
            ):
                raise LedgerError("dispatch_binding_mismatch", "permit binding mismatch")
            revision = self.registry_revision()
            if permit["registry_revision"] != revision:
                raise LedgerError(
                    "registry_revision_changed", "registry changed after permit issuance"
                )
            grant = db.execute(
                "SELECT * FROM delegation_grants WHERE grant_id=?", (permit["grant_id"],)
            ).fetchone()
            if grant["status"] != GrantStatus.ACTIVE.value:
                raise LedgerError("grant_not_active", "grant is not active")
            grant_value = self._grant_from_row(grant)
            action = db.execute(
                "SELECT * FROM actions WHERE action_id=?", (action_id,)
            ).fetchone()
            attempt = db.execute(
                "SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if action["status"] != ActionStatus.PREPARED.value or attempt[
                "status"
            ] != AttemptStatus.AUTHORIZED.value:
                raise LedgerError("dispatch_state_changed", "action is no longer dispatchable")
            operation = db.execute(
                "SELECT * FROM operations WHERE operation_id=?", (action["operation_id"],)
            ).fetchone()
            if verification_source_action_id is not None:
                source = self.get_action(verification_source_action_id)
                source_operation = self.get_operation(source.operation_id)
                if (
                    source.status is not ActionStatus.VERIFICATION_PENDING
                    or source_operation.work_id != operation["work_id"]
                    or source.operation_id == action["operation_id"]
                    or self._action_from_row(action).request.arguments.get("source_action_id")
                    != source.action_id
                ):
                    raise LedgerError("handoff_source_invalid", "source is not a pending action on this work")
                claim = db.execute(
                    """SELECT 1 FROM events WHERE aggregate_type='action' AND aggregate_id=?
                       AND event_type='handoff.verification_started'""",
                    (source.action_id,),
                ).fetchone()
                if claim is not None:
                    raise LedgerError("handoff_verification_claimed", "verification is already assigned")
            now_dt = self._now()
            if parse_utc(permit["expires_at"]) <= now_dt:
                raise LedgerError("dispatch_permit_expired", "permit is expired")
            if parse_utc(grant_value.valid_until) <= now_dt:
                raise LedgerError("grant_expired", "grant is expired")
            now = utc_text(now_dt)
            db.execute(
                "UPDATE dispatch_permits SET consumed_at=? WHERE permit_id=?",
                (now, permit["permit_id"]),
            )
            db.execute(
                "UPDATE actions SET status=?, updated_at=? WHERE action_id=?",
                (ActionStatus.DISPATCHING.value, now, action_id),
            )
            db.execute(
                "UPDATE attempts SET status=?, updated_at=? WHERE attempt_id=?",
                (AttemptStatus.DISPATCHING.value, now, attempt_id),
            )
            db.execute(
                "UPDATE operations SET status=?, updated_at=? WHERE operation_id=?",
                (OperationStatus.DISPATCHING.value, now, action["operation_id"]),
            )
            if verification_source_action_id is not None:
                self._append_event(
                    db,
                    tenant_id=operation["tenant_id"],
                    aggregate_type="action",
                    aggregate_id=verification_source_action_id,
                    event_type="handoff.verification_started",
                    payload={"verification_action_id": action_id, "attempt_id": attempt_id},
                    occurred_at=now,
                )
            self._append_event(
                db,
                tenant_id=operation["tenant_id"],
                aggregate_type="action",
                aggregate_id=action_id,
                event_type="dispatch.started",
                payload={
                    "permit_id": permit["permit_id"],
                    "attempt_id": attempt_id,
                    "worker_id": worker_id,
                },
                occurred_at=now,
            )

    def record_dispatch_outcome(
        self,
        attempt_id: str,
        *,
        outcome: AttemptStatus,
        result_digest: str | None = None,
    ) -> ActionStatus:
        if outcome not in {
            AttemptStatus.ACKNOWLEDGED,
            AttemptStatus.EXECUTION_OUTCOME_UNKNOWN,
            AttemptStatus.FAILED_NO_EFFECT,
        }:
            raise ValueError("unsupported dispatch outcome")
        if result_digest is not None and not is_sha256_digest(result_digest):
            raise ValueError("result digest must be SHA-256")
        now = utc_text(self._now())
        with self._transaction() as db:
            return self._record_dispatch_outcome(db, attempt_id, outcome, result_digest, now)

    def _record_dispatch_outcome(
        self, db: sqlite3.Connection, attempt_id: str, outcome: AttemptStatus,
        result_digest: str | None, now: str
    ) -> ActionStatus:
        attempt = db.execute(
            "SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if attempt is None:
            raise LedgerError("attempt_not_found", "attempt was not found")
        if attempt["status"] != AttemptStatus.DISPATCHING.value:
            raise LedgerError("attempt_not_dispatching", "attempt is not dispatching")
        action = db.execute(
            "SELECT * FROM actions WHERE action_id=?", (attempt["action_id"],)
        ).fetchone()
        if outcome is AttemptStatus.ACKNOWLEDGED:
            action_status = ActionStatus.VERIFICATION_PENDING
            operation_status = OperationStatus.VERIFICATION_PENDING
        elif outcome is AttemptStatus.EXECUTION_OUTCOME_UNKNOWN:
            action_status = ActionStatus.EXECUTION_OUTCOME_UNKNOWN
            operation_status = OperationStatus.EXECUTION_OUTCOME_UNKNOWN
        else:
            action_status = ActionStatus.FAILED_NO_EFFECT
            operation_status = OperationStatus.FAILED_NO_EFFECT
            self._settle_reservation(db, action, used=False)
        db.execute(
            "UPDATE attempts SET status=?, updated_at=? WHERE attempt_id=?",
            (outcome.value, now, attempt_id),
        )
        db.execute(
            "UPDATE actions SET status=?, updated_at=? WHERE action_id=?",
            (action_status.value, now, action["action_id"]),
        )
        db.execute(
            "UPDATE operations SET status=?, updated_at=? WHERE operation_id=?",
            (operation_status.value, now, action["operation_id"]),
        )
        operation = db.execute(
            "SELECT * FROM operations WHERE operation_id=?", (action["operation_id"],)
        ).fetchone()
        self._append_event(
            db,
            tenant_id=operation["tenant_id"],
            aggregate_type="action",
            aggregate_id=action["action_id"],
            event_type=f"dispatch.{outcome.value}",
            payload={
                "attempt_id": attempt_id,
                "result_digest": result_digest,
            },
            occurred_at=now,
        )
        return action_status

    def reconcile_action(
        self,
        action_id: str,
        *,
        outcome: ReconcileOutcome,
        observation_digest: str,
    ) -> ActionStatus:
        if not is_sha256_digest(observation_digest):
            raise ValueError("observation digest must be SHA-256")
        now = utc_text(self._now())
        with self._transaction() as db:
            action = db.execute(
                "SELECT * FROM actions WHERE action_id=?", (action_id,)
            ).fetchone()
            if action is None:
                raise LedgerError("action_not_found", "action was not found")
            if action["status"] != ActionStatus.EXECUTION_OUTCOME_UNKNOWN.value:
                raise LedgerError("action_not_unknown", "action does not require reconciliation")
            if outcome is ReconcileOutcome.EFFECT_CONFIRMED:
                status = ActionStatus.VERIFICATION_PENDING
                operation_status = OperationStatus.VERIFICATION_PENDING
            elif outcome is ReconcileOutcome.NO_EFFECT_CONFIRMED:
                status = ActionStatus.FAILED_NO_EFFECT
                operation_status = OperationStatus.FAILED_NO_EFFECT
                self._settle_reservation(db, action, used=False)
            else:
                status = ActionStatus.EXECUTION_OUTCOME_UNKNOWN
                operation_status = OperationStatus.EXECUTION_OUTCOME_UNKNOWN
            db.execute(
                "UPDATE actions SET status=?, updated_at=? WHERE action_id=?",
                (status.value, now, action_id),
            )
            db.execute(
                "UPDATE operations SET status=?, updated_at=? WHERE operation_id=?",
                (operation_status.value, now, action["operation_id"]),
            )
            operation = db.execute(
                "SELECT * FROM operations WHERE operation_id=?", (action["operation_id"],)
            ).fetchone()
            self._append_event(
                db,
                tenant_id=operation["tenant_id"],
                aggregate_type="action",
                aggregate_id=action_id,
                event_type=f"reconcile.{outcome.value}",
                payload={"observation_digest": observation_digest},
                occurred_at=now,
            )
            return status

    def record_verification(
        self,
        action_id: str,
        *,
        passed: bool,
        verifier_receipt_digest: str,
    ) -> ActionStatus:
        if not is_sha256_digest(verifier_receipt_digest):
            raise ValueError("verifier receipt digest must be SHA-256")
        now = utc_text(self._now())
        with self._transaction() as db:
            return self._record_verification(db, action_id, passed, verifier_receipt_digest, now)

    def _record_verification(
        self, db: sqlite3.Connection, action_id: str, passed: bool,
        verifier_receipt_digest: str, now: str
    ) -> ActionStatus:
        action = db.execute(
            "SELECT * FROM actions WHERE action_id=?", (action_id,)
        ).fetchone()
        if action is None:
            raise LedgerError("action_not_found", "action was not found")
        if action["status"] != ActionStatus.VERIFICATION_PENDING.value:
            raise LedgerError("verification_not_pending", "action is not awaiting verification")
        if passed:
            status = ActionStatus.VERIFIED
            operation_status = OperationStatus.VERIFIED
            self._settle_reservation(db, action, used=True)
        else:
            status = ActionStatus.MANUAL_INTERVENTION_REQUIRED
            operation_status = OperationStatus.MANUAL_INTERVENTION_REQUIRED
            # Keep the reservation while the effect exists but verification failed.
        db.execute(
            "UPDATE actions SET status=?, updated_at=? WHERE action_id=?",
            (status.value, now, action_id),
        )
        db.execute(
            "UPDATE operations SET status=?, updated_at=? WHERE operation_id=?",
            (operation_status.value, now, action["operation_id"]),
        )
        operation = db.execute(
            "SELECT * FROM operations WHERE operation_id=?", (action["operation_id"],)
        ).fetchone()
        self._append_event(
            db,
            tenant_id=operation["tenant_id"],
            aggregate_type="action",
            aggregate_id=action_id,
            event_type="verification.passed" if passed else "verification.failed",
            payload={"verifier_receipt_digest": verifier_receipt_digest},
            occurred_at=now,
        )
        return status

    def record_handoff_verification(
        self,
        *,
        source_action_id: str,
        verification_attempt_id: str,
        passed: bool,
        result_digest: str,
        verifier_receipt_digest: str,
    ) -> ActionStatus:
        """Finalize the receiving action and its source in one transaction."""
        if not all(is_sha256_digest(value) for value in (result_digest, verifier_receipt_digest)):
            raise ValueError("handoff results and receipts require SHA-256")
        with self._transaction() as db:
            attempt = db.execute(
                "SELECT * FROM attempts WHERE attempt_id=?", (verification_attempt_id,)
            ).fetchone()
            if attempt is None:
                raise LedgerError("attempt_not_found", "attempt was not found")
            verification_id = attempt["action_id"]
            claim = db.execute(
                """SELECT payload_json FROM events WHERE aggregate_type='action' AND aggregate_id=?
                   AND event_type='handoff.verification_started'""",
                (source_action_id,),
            ).fetchone()
            expected = {"verification_action_id": verification_id, "attempt_id": verification_attempt_id}
            if claim is None or json.loads(claim["payload_json"]) != expected:
                raise LedgerError("handoff_action_invalid", "verification attempt does not own the handoff")
            now = utc_text(self._now())
            status = self._record_verification(db, source_action_id, passed, verifier_receipt_digest, now)
            self._record_dispatch_outcome(db, verification_attempt_id, AttemptStatus.ACKNOWLEDGED, result_digest, now)
            self._record_verification(db, verification_id, passed, verifier_receipt_digest, now)
            return status

    def pending_reconciliation(self) -> tuple[ActionRecord, ...]:
        rows = self._db.execute(
            "SELECT * FROM actions WHERE status=? ORDER BY created_at, action_id",
            (ActionStatus.EXECUTION_OUTCOME_UNKNOWN.value,),
        ).fetchall()
        return tuple(self._action_from_row(row) for row in rows)

    def get_operation(self, operation_id: str) -> OperationRecord:
        row = self._db.execute(
            "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None:
            raise LedgerError("operation_not_found", "operation was not found")
        return self._operation_from_row(row)

    def get_action(self, action_id: str) -> ActionRecord:
        row = self._db.execute(
            "SELECT * FROM actions WHERE action_id=?", (action_id,)
        ).fetchone()
        if row is None:
            raise LedgerError("action_not_found", "action was not found")
        return self._action_from_row(row)

    def events_for(self, aggregate_type: str, aggregate_id: str) -> tuple[LedgerEvent, ...]:
        rows = self._db.execute(
            """SELECT * FROM events WHERE aggregate_type=? AND aggregate_id=?
               ORDER BY sequence""",
            (aggregate_type, aggregate_id),
        ).fetchall()
        return tuple(
            LedgerEvent(
                row["event_id"],
                row["tenant_id"],
                row["aggregate_type"],
                row["aggregate_id"],
                row["sequence"],
                row["event_type"],
                json.loads(row["payload_json"]),
                row["payload_digest"],
                row["occurred_at"],
            )
            for row in rows
        )

    def snapshot(self, work_id: str) -> dict[str, Any]:
        """Return a read-only console/API projection without granting authority."""

        work = self.get_work(work_id)
        grants = self._db.execute(
            """SELECT grant_id, status, used_actions, reserved_actions,
                      used_cost_micros, reserved_cost_micros
               FROM delegation_grants WHERE work_id=? ORDER BY issued_at""",
            (work_id,),
        ).fetchall()
        operations = self._db.execute(
            "SELECT * FROM operations WHERE work_id=? ORDER BY created_at", (work_id,)
        ).fetchall()
        operation_values: list[dict[str, Any]] = []
        for operation in operations:
            actions = self._db.execute(
                "SELECT * FROM actions WHERE operation_id=? ORDER BY created_at",
                (operation["operation_id"],),
            ).fetchall()
            action_values: list[dict[str, Any]] = []
            for item in actions:
                verification = self._db.execute(
                    """SELECT payload_json FROM events
                       WHERE aggregate_type='action' AND aggregate_id=?
                         AND event_type IN ('verification.passed', 'verification.failed')
                       ORDER BY sequence DESC LIMIT 1""",
                    (item["action_id"],),
                ).fetchone()
                receipt_digest = None
                if verification is not None:
                    receipt_digest = json.loads(verification["payload_json"])[
                        "verifier_receipt_digest"
                    ]
                action_values.append(
                    {
                        "action_id": item["action_id"],
                        "request_digest": item["request_digest"],
                        "resource": item["resource"],
                        "status": item["status"],
                        "verification_receipt_digest": receipt_digest,
                    }
                )
            operation_values.append(
                {
                    **asdict(self._operation_from_row(operation)),
                    "status": operation["status"],
                    "actions": action_values,
                }
            )
        return {
            "schema_version": "happy-work-snapshot/v1",
            "work": work.to_dict(),
            "grants": [dict(row) for row in grants],
            "operations": operation_values,
            "registry_revision": self.registry_revision(),
        }

    def _settle_reservation(
        self, db: sqlite3.Connection, action: sqlite3.Row, *, used: bool
    ) -> None:
        if used:
            db.execute(
                """UPDATE delegation_grants
                   SET reserved_actions=reserved_actions-1,
                       reserved_cost_micros=reserved_cost_micros-?,
                       used_actions=used_actions+1,
                       used_cost_micros=used_cost_micros+?
                   WHERE grant_id=?""",
                (
                    action["reserved_cost_micros"],
                    action["reserved_cost_micros"],
                    action["grant_id"],
                ),
            )
        else:
            db.execute(
                """UPDATE delegation_grants
                   SET reserved_actions=reserved_actions-1,
                       reserved_cost_micros=reserved_cost_micros-?
                   WHERE grant_id=?""",
                (action["reserved_cost_micros"], action["grant_id"]),
            )

    def _grant_from_row(self, row: sqlite3.Row) -> DelegationGrant:
        from .work import PolicyProfile, PolicyRef

        value = json.loads(row["grant_json"])
        policy = value["policy_ref"]
        return DelegationGrant(
            value["grant_id"],
            value["issuer_principal"],
            value["subject_principal"],
            value["tenant_id"],
            value["work_id"],
            PolicyProfile(value["policy_profile"]),
            PolicyRef(policy["id"], policy["version"], policy["digest"]),
            tuple(value["contract_digests"]),
            tuple(value["allowed_actions"]),
            tuple(SideEffect(item) for item in value["allowed_side_effects"]),
            tuple(value["resource_scopes"]),
            tuple(value["destinations"]),
            value["max_actions"],
            value["max_cost_micros"],
            tuple(value["exclusions"]),
            tuple(value["required_checks"]),
            value["valid_from"],
            value["valid_until"],
        )

    def _operation_from_row(self, row: sqlite3.Row) -> OperationRecord:
        return OperationRecord(
            row["operation_id"],
            row["tenant_id"],
            row["work_id"],
            row["caller_request_id"],
            row["intent_digest"],
            OperationStatus(row["status"]),
            row["created_at"],
            row["updated_at"],
        )

    def _action_from_row(self, row: sqlite3.Row) -> ActionRecord:
        value = json.loads(row["request_json"])
        request = ActionRequest(
            value["id"],
            value["tool_name"],
            value["operation"],
            value["resource"],
            value["arguments"],
            value["expected_cost_usd"],
        )
        return ActionRecord(
            row["action_id"],
            row["operation_id"],
            row["grant_id"],
            request,
            row["contract_digest"],
            row["adapter_digest"],
            row["approval_digest"],
            ActionStatus(row["status"]),
            row["reserved_cost_micros"],
            row["created_at"],
            row["updated_at"],
        )

    def _attempt_from_row(self, row: sqlite3.Row) -> AttemptRecord:
        return AttemptRecord(
            row["attempt_id"],
            row["action_id"],
            row["attempt_number"],
            AttemptStatus(row["status"]),
            row["created_at"],
            row["updated_at"],
        )
