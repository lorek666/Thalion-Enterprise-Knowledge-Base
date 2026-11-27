from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from psycopg import Connection, Error, OperationalError
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from enterprise_kb.database import rehearsal_marker

from .effectivity import StopKind


@dataclass(frozen=True)
class RuleRestriction:
    generation: int
    decision_ref: UUID
    space_ref: UUID
    version_ref: UUID
    approver_ref: UUID
    contract_revision: int
    kind: StopKind | Literal["deletion_blocked"]
    basis_ref: UUID
    recorded_at: datetime

    def payload(self):
        return {
            "schema_revision": 1,
            "space_ref": str(self.space_ref),
            "version_ref": str(self.version_ref),
            "approver_ref": str(self.approver_ref),
            "contract_revision": self.contract_revision,
            "kind": self.kind,
            "basis_ref": str(self.basis_ref),
            "recorded_at": self.recorded_at.astimezone(UTC).isoformat(),
        }


@dataclass(frozen=True)
class LogDelivery:
    status: Literal["ok", "unavailable", "not_independent", "conflict"]
    confirmed: tuple[UUID, ...] = ()


@dataclass(frozen=True)
class ReplayInput:
    status: Literal["closed", "verified"]
    entries: tuple[RuleRestriction, ...] = ()
    stream_ref: UUID | None = None
    log_ref: UUID | None = None


@dataclass(frozen=True)
class RehearsalReplay:
    status: Literal["closed", "replayed"]
    applied: tuple[UUID, ...] = ()
    generation: int | None = None


class _LogConflict(Exception):
    pass


_RECORD_COLUMNS = """
    record.generation, record.decision_ref, record.space_ref, record.version_ref, record.approver_ref,
    record.contract_revision, record.kind, record.basis_ref, record.recorded_at
"""


def _require_idle(connection: Connection):
    if connection.closed:
        raise OperationalError("Restriction log database is closed.")
    if not connection.autocommit or connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Restriction log operations require idle autocommit connections.")


def _log_ref(connection: Connection, *, lock: bool = False) -> UUID:
    query = "SELECT log_ref FROM thalion.rule_log_endpoint WHERE singleton"
    row = connection.execute(query + (" FOR UPDATE" if lock else "")).fetchone()
    if row is None:
        raise OperationalError("Restriction log identity is missing.")
    return row[0]


def _log_head(log, stream_ref):
    return log.execute(
        "SELECT coalesce(max(generation), 0) FROM thalion.rule_log_entry WHERE stream_ref = %s",
        (stream_ref,),
    ).fetchone()[0]


def _append_entries(log, stream_ref, entries, head):
    for entry in entries:
        payload = entry.payload()
        if entry.generation <= head:
            matches = log.execute(
                """
                SELECT 1 FROM thalion.rule_log_entry
                WHERE stream_ref = %s AND generation = %s AND decision_ref = %s AND payload = %s
                """,
                (stream_ref, entry.generation, entry.decision_ref, Jsonb(payload)),
            ).fetchone()
            if matches is None:
                raise _LogConflict
            continue
        if entry.generation != head + 1:
            raise _LogConflict
        log.execute(
            """
            INSERT INTO thalion.rule_log_entry (stream_ref, generation, decision_ref, payload)
            VALUES (%s, %s, %s, %s)
            """,
            (stream_ref, entry.generation, entry.decision_ref, Jsonb(payload)),
        )
        head = entry.generation


def _append_batch(log: Connection, stream_ref: UUID, entries: tuple[RuleRestriction, ...]):
    with log.transaction():
        log.execute("SET LOCAL synchronous_commit = on")
        _log_ref(log, lock=True)
        _append_entries(log, stream_ref, entries, _log_head(log, stream_ref))


def deliver_pending(
    source: Connection, log: Connection | None, org_id: int, *, limit: int = 100,
) -> LogDelivery:
    """Confirm only entries committed in a separately initialized synthetic log database."""
    if not 1 <= limit <= 500:
        raise ValueError("The restriction delivery limit must be between 1 and 500.")
    _require_idle(source)
    if log is None:
        return LogDelivery("unavailable")
    try:
        _require_idle(log)
        if rehearsal_marker(source) is not None or rehearsal_marker(log) is not None:
            return LogDelivery("unavailable")
        log_ref = _log_ref(log)
    except Error:
        return LogDelivery("unavailable")
    if _log_ref(source) == log_ref:
        return LogDelivery("not_independent")
    stream = source.execute(
        "SELECT stream_ref FROM thalion.rule_restriction_stream WHERE org_id = %s", (org_id,),
    ).fetchone()
    if stream is None:
        return LogDelivery("ok")
    stream_ref, = stream
    rows = source.execute(
        f"""
        SELECT {_RECORD_COLUMNS}
        FROM thalion.rule_restriction_record AS record
        WHERE record.org_id = %s AND NOT EXISTS (
            SELECT 1 FROM thalion.rule_log_confirmation AS confirmation
            WHERE confirmation.decision_ref = record.decision_ref AND confirmation.log_ref = %s
        )
        ORDER BY record.generation LIMIT %s
        """,
        (org_id, log_ref, limit),
    ).fetchall()
    entries = tuple(RuleRestriction(*row) for row in rows)
    if not entries:
        return LogDelivery("ok")
    try:
        _append_batch(log, stream_ref, entries)
    except _LogConflict:
        return LogDelivery("conflict")
    except Error:
        return LogDelivery("unavailable")

    confirmed = tuple(entry.decision_ref for entry in entries)
    source.execute(
        """
        INSERT INTO thalion.rule_log_confirmation (decision_ref, log_ref)
        SELECT decision_ref, %s FROM unnest(%s::uuid[]) AS decisions (decision_ref)
        ON CONFLICT (decision_ref, log_ref) DO NOTHING
        """,
        (log_ref, list(confirmed)),
    )
    return LogDelivery("ok", confirmed)


def _read_restrictions(connection: Connection, org_id: int, limit: int) -> tuple[RuleRestriction, ...]:
    rows = connection.execute(
        f"""
        SELECT {_RECORD_COLUMNS} FROM thalion.rule_restriction_record AS record
        WHERE record.org_id = %s ORDER BY record.generation LIMIT %s
        """, (org_id, limit),
    ).fetchall()
    return tuple(RuleRestriction(*row) for row in rows)


def _log_matches(log, stream_ref, entries):
    generation = len(entries)
    exact = log.execute(
        """
        SELECT count(*), count(expected.generation)
        FROM (
            SELECT generation, decision_ref, payload FROM thalion.rule_log_entry
            WHERE stream_ref = %s ORDER BY generation LIMIT %s
        ) AS logged
        LEFT JOIN unnest(%s::bigint[], %s::uuid[], %s::jsonb[])
             AS expected (generation, decision_ref, payload)
          ON (logged.generation, logged.decision_ref, logged.payload)
           = (expected.generation, expected.decision_ref, expected.payload)
        """,
        (
            stream_ref, generation + 1,
            [entry.generation for entry in entries], [entry.decision_ref for entry in entries],
            [Jsonb(entry.payload()) for entry in entries],
        ),
    ).fetchone()
    return exact == (generation, generation)


def _check_replay_input(authority: Connection, log: Connection, org_id: int) -> ReplayInput:
    closed = ReplayInput("closed")
    if rehearsal_marker(authority) is not None or rehearsal_marker(log) is not None:
        return closed
    log_ref = _log_ref(log)
    if _log_ref(authority) == log_ref:
        return closed
    head = authority.execute(
        """
        SELECT stream_ref, generation FROM thalion.rule_restriction_stream
        WHERE org_id = %s FOR SHARE
        """, (org_id,),
    ).fetchone()
    if head is None or head[1] > 1000:
        return closed
    stream_ref, generation = head
    entries = _read_restrictions(authority, org_id, generation + 1)
    if len(entries) != generation or any(
        entry.generation != position for position, entry in enumerate(entries, 1)
    ):
        return closed
    return ReplayInput("verified", entries, stream_ref, log_ref) if _log_matches(log, stream_ref, entries) else closed


def verify_replay_input(
    authority: Connection | None, log: Connection | None, org_id: int,
) -> ReplayInput:
    """Verify a bounded rule-stop snapshot, without authorizing reads or promoting a restore."""
    if authority is not None and log is not None:
        try:
            _require_idle(authority)
            _require_idle(log)
            with authority.transaction():
                return _check_replay_input(authority, log, org_id)
        except Error:
            pass
    return ReplayInput("closed")


@contextmanager
def pinned_replay_input(
    authority: Connection | None, log: Connection | None, org_id: int, *, authority_ref: UUID, log_ref: UUID,
):
    """Hold the current synthetic restriction head while an isolated operation uses it."""
    closed = ReplayInput("closed")
    if authority is None or log is None or authority_ref == log_ref:
        yield closed
        return
    try:
        for connection in (authority, log):
            _require_idle(connection)
            if connection.info.hostaddr not in {"127.0.0.1", "::1"}:
                raise _LogConflict
    except (Error, RuntimeError, _LogConflict):
        yield closed
        return
    with authority.transaction():
        authority.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        authority.execute("SET LOCAL lock_timeout = '3s'")
        if _log_ref(authority) != authority_ref or _log_ref(log) != log_ref:
            yield closed
            return
        yield _check_replay_input(authority, log, org_id)


def _apply_restriction(target: Connection, org_id: int, entry: RuleRestriction, log_ref: UUID):
    inserted = target.execute(
        """
        INSERT INTO thalion.rule_use_stop
            (decision_ref, org_id, space_id, source_id, document_id, version_id,
             contract_revision, decided_by, kind, basis_ref, recorded_at, replay_log_ref)
        SELECT %s, version.org_id, version.space_id, version.source_id, version.document_id, version.version_id,
               contract.revision, actor.object_id, %s, %s, %s, %s
        FROM thalion.object_identity AS version_ref
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id)
           = (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id)
        JOIN thalion.object_identity AS space
          ON (space.org_id, space.object_type, space.object_id) = (version.org_id, 'space', version.space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id)
           = (version.org_id, version.space_id, version.source_id)
        JOIN thalion.object_identity AS actor
          ON (actor.org_id, actor.object_type, actor.object_id) = (contract.org_id, 'principal', contract.approver_id)
        WHERE version.org_id = %s AND space.public_id = %s AND version_ref.public_id = %s
          AND actor.public_id = %s AND contract.revision = %s AND contract.admission IN ('synthetic_only', 'production_approved')
        RETURNING decision_ref
        """,
        (
            entry.decision_ref, entry.kind, entry.basis_ref, entry.recorded_at,
            log_ref if entry.kind == "deletion_blocked" else None,
            org_id, entry.space_ref, entry.version_ref, entry.approver_ref, entry.contract_revision,
        ),
    ).fetchone()
    if inserted != (entry.decision_ref,):
        raise _LogConflict


def _apply_replay(target: Connection, org_id: int, checked: ReplayInput) -> RehearsalReplay:
    head = target.execute(
        """
        SELECT stream_ref, generation FROM thalion.rule_restriction_stream WHERE org_id = %s FOR UPDATE
        """, (org_id,),
    ).fetchone()
    prefix = head[1] if head is not None else 0
    generation = len(checked.entries)
    if prefix > generation or (head is not None and head[0] != checked.stream_ref):
        raise _LogConflict
    if _read_restrictions(target, org_id, generation + 1) != checked.entries[:prefix]:
        raise _LogConflict
    pending = checked.entries[prefix:]
    for entry in pending:
        _apply_restriction(target, org_id, entry, checked.log_ref)
    if head is None:
        target.execute(
            "UPDATE thalion.rule_restriction_stream SET stream_ref = %s WHERE org_id = %s",
            (checked.stream_ref, org_id),
        )
    if _read_restrictions(target, org_id, generation + 1) != checked.entries:
        raise _LogConflict
    return RehearsalReplay("replayed", tuple(entry.decision_ref for entry in pending), generation)


def rehearse_replay(
    authority: Connection | None, log: Connection | None, target: Connection, org_id: int,
) -> RehearsalReplay:
    """Apply exact synthetic stops to a fenced local clone; never permit it to serve."""
    closed = RehearsalReplay("closed")
    if authority is None or log is None:
        return closed
    try:
        for connection in (authority, log, target):
            _require_idle(connection)
            if connection.info.hostaddr not in {"127.0.0.1", "::1"}:
                return closed
        if target.info.dbname == authority.info.dbname or rehearsal_marker(target) != target.info.dbname:
            return closed
        with authority.transaction():
            checked = _check_replay_input(authority, log, org_id)
            if checked.status != "verified":
                return closed
            with target.transaction():
                if _log_ref(target, lock=True) != _log_ref(authority):
                    return closed
                return _apply_replay(target, org_id, checked)
    except (Error, _LogConflict):
        return closed
