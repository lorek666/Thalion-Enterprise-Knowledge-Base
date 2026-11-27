from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from psycopg import Connection, Error
from psycopg.pq import TransactionStatus

from enterprise_kb.database import rehearsal_marker
from enterprise_kb.modules.sources.restriction_log import (
    LogDelivery, RehearsalReplay, _LogConflict, _append_entries, _log_head, _log_matches, _log_ref, _require_idle,
)


MAX_QUALITY_HISTORY = 1000


@dataclass(frozen=True)
class _QualityBaseline:
    decision_ref: UUID
    authority_ref: UUID
    generation: int = field(init=False, default=1)

    def payload(self):
        return {"schema_revision": 1, "kind": "quality_baseline", "authority_ref": str(self.authority_ref)}


@dataclass(frozen=True)
class _QualityRecord:
    generation: int
    decision_ref: UUID
    space_ref: UUID
    version_ref: UUID
    run_ref: UUID
    configuration_revision: int
    manifest_digest: bytes
    recorded_at: datetime

    def _payload(self, kind):
        return {
            "schema_revision": 1,
            "kind": kind,
            "space_ref": str(self.space_ref),
            "version_ref": str(self.version_ref),
            "run_ref": str(self.run_ref),
            "configuration_revision": self.configuration_revision,
            "manifest_sha256": self.manifest_digest.hex(),
            "recorded_at": self.recorded_at.astimezone(UTC).isoformat(),
        }


@dataclass(frozen=True)
class _QualityRestriction(_QualityRecord):
    reviewer_ref: UUID
    basis_ref: UUID

    def payload(self):
        return self._payload("quality_quarantine") | {"reviewer_ref": str(self.reviewer_ref), "basis_ref": str(self.basis_ref)}


@dataclass(frozen=True)
class PdfProcessingQuarantine(_QualityRecord):
    reason: str
    page_count: int

    def payload(self):
        return self._payload("pdf_processing_quarantine") | {"reason": self.reason, "page_count": self.page_count}


@dataclass(frozen=True)
class QualityHistory:
    stream_ref: UUID
    entries: tuple[_QualityBaseline | _QualityRestriction | PdfProcessingQuarantine, ...] = field(repr=False)

    @property
    def generation(self):
        return len(self.entries)

    @property
    def quarantines(self):
        return tuple(entry for entry in self.entries if isinstance(entry, _QualityRecord))

    @property
    def blocked_versions(self):
        return frozenset(entry.version_ref for entry in self.quarantines)


def _read_history(authority, org_id, authority_ref, *, for_update=False):
    head = authority.execute(
        "SELECT stream_ref, generation FROM thalion.quality_restriction_stream WHERE org_id = %s "
        + ("FOR UPDATE" if for_update else "FOR SHARE"),
        (org_id,),
    ).fetchone()
    if head is None or not 1 <= head[1] <= MAX_QUALITY_HISTORY:
        return None
    stream_ref, generation = head
    rows = authority.execute("""
        WITH items AS (SELECT * FROM thalion.quality_restriction_item WHERE org_id = %s)
        SELECT item.generation, item.decision_ref, material.space_ref, material.version_ref, material.run_ref,
               material.configuration_revision, material.manifest_digest, material.recorded_at,
               material.reviewer_ref, material.basis_ref, NULL::text, NULL::integer
        FROM items AS item JOIN thalion.quality_restriction_material AS material
          ON (item.org_id, item.review_decision_ref) = (material.org_id, material.decision_ref)
        UNION ALL
        SELECT item.generation, item.decision_ref, material.space_ref, material.version_ref, material.run_ref,
               material.configuration_revision, material.manifest_digest, material.recorded_at,
               NULL::uuid, NULL::uuid, material.reason, material.pdf_page_count
        FROM items AS item JOIN thalion.pdf_processing_restriction_material AS material
          ON (item.org_id, item.processing_run_ref) = (material.org_id, material.run_ref)
        ORDER BY generation LIMIT %s
        """, (org_id, generation)).fetchall()
    if len(rows) != generation - 1 or any(row[0] != offset for offset, row in enumerate(rows, 2)):
        return None
    restrictions = tuple(
        _QualityRestriction(*binding, reviewer_ref, basis_ref) if page_count is None
        else PdfProcessingQuarantine(*binding, reason, page_count)
        for *binding, reviewer_ref, basis_ref, reason, page_count in rows
    )
    return QualityHistory(stream_ref, (_QualityBaseline(stream_ref, authority_ref), *restrictions))


def deliver_pending(
    authority: Connection, log: Connection | None, org_id: int, *, limit: int = 100,
) -> LogDelivery:
    """Append an exact quality prefix to the separate local log and report confirmed decision or run references."""
    if not 1 <= limit <= 500:
        raise ValueError("The quality delivery limit must be between 1 and 500.")
    if log is None:
        return LogDelivery("unavailable")
    try:
        for connection in (authority, log):
            _require_idle(connection)
            if connection.info.hostaddr not in {"127.0.0.1", "::1"} or rehearsal_marker(connection) is not None:
                return LogDelivery("unavailable")
        authority_ref, log_ref = _log_ref(authority), _log_ref(log)
        if authority_ref == log_ref:
            return LogDelivery("not_independent")
        with authority.transaction():
            authority.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            authority.execute("SET LOCAL lock_timeout = '3s'")
            history = _read_history(authority, org_id, authority_ref)
            if history is None:
                return LogDelivery("conflict")
            with log.transaction():
                log.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                log.execute("SET LOCAL synchronous_commit = on")
                _log_ref(log, lock=True)
                head = _log_head(log, history.stream_ref)
                if head > history.generation or not _log_matches(log, history.stream_ref, history.entries[:head]):
                    return LogDelivery("conflict")
                batch = history.entries[head:head + limit]
                _append_entries(log, history.stream_ref, batch, head)
            return LogDelivery("ok", tuple(entry.decision_ref for entry in batch if isinstance(entry, _QualityRecord)))
    except _LogConflict:
        return LogDelivery("conflict")
    except (Error, RuntimeError):
        return LogDelivery("unavailable")


def check_pinned_history(authority: Connection, log: Connection, org_id: int, authority_ref: UUID) -> QualityHistory | None:
    """Use the endpoints verified by the caller and hold the quality head until its authority transaction ends."""
    if authority.info.transaction_status != TransactionStatus.INTRANS:
        raise RuntimeError("Quality history must be pinned within the authority transaction.")
    history = _read_history(authority, org_id, authority_ref)
    return history if history is not None and _log_matches(log, history.stream_ref, history.entries) else None


def _apply_quarantine(target: Connection, org_id: int, entry: _QualityRestriction, log_ref: UUID):
    inserted = target.execute("""
        INSERT INTO thalion.quality_decision (
            decision_ref, org_id, space_id, version_id, run_ref, reviewer_id,
            basis_ref, outcome, recorded_at, replay_log_ref
        )
        SELECT %s, run.org_id, run.space_id, run.version_id, run.run_ref, reviewer.object_id,
               %s, 'quarantined', %s, %s
        FROM thalion.processing_run AS run
        JOIN thalion.object_identity AS version_ref
          ON (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id) =
             (run.org_id, run.space_id, 'document_version', run.version_id)
        JOIN thalion.object_identity AS space
          ON (space.org_id, space.space_id, space.object_type, space.object_id) =
             (run.org_id, run.space_id, 'space', run.space_id)
        JOIN thalion.object_identity AS reviewer
          ON reviewer.org_id = run.org_id AND reviewer.object_type = 'principal'
        WHERE (run.org_id, run.run_ref, run.configuration_revision, run.manifest_digest, run.outcome) =
              (%s, %s, %s, %s, 'pending_review')
          AND (space.public_id, version_ref.public_id, reviewer.public_id) = (%s, %s, %s)
        RETURNING decision_ref
        """, (
            entry.decision_ref, entry.basis_ref, entry.recorded_at, log_ref, org_id, entry.run_ref,
            entry.configuration_revision, entry.manifest_digest, entry.space_ref, entry.version_ref, entry.reviewer_ref,
        )).fetchone()
    if inserted != (entry.decision_ref,):
        raise _LogConflict


def _apply_replay(target, org_id, current, authority_ref, log_ref):
    prefix = _read_history(target, org_id, authority_ref, for_update=True)
    if (
        prefix is None or prefix.stream_ref != current.stream_ref
        or prefix.entries != current.entries[:prefix.generation]
    ):
        raise _LogConflict
    pending = current.entries[prefix.generation:]
    for entry in pending:
        if not isinstance(entry, _QualityRestriction):
            raise _LogConflict
        _apply_quarantine(target, org_id, entry, log_ref)
    if _read_history(target, org_id, authority_ref) != current:
        raise _LogConflict
    return RehearsalReplay("replayed", tuple(entry.decision_ref for entry in pending), current.generation)


def rehearse_replay(
    authority: Connection | None, log: Connection | None, target: Connection, org_id: int,
    *, authority_ref: UUID, log_ref: UUID,
) -> RehearsalReplay:
    """Verify the exact prefix and replay only independently confirmed human decisions onto a fenced clone."""
    closed = RehearsalReplay("closed")
    if authority is None or log is None or authority_ref == log_ref:
        return closed
    try:
        for connection in (authority, log, target):
            _require_idle(connection)
            if connection.info.hostaddr not in {"127.0.0.1", "::1"}:
                return closed
        if (
            target.info.dbname == authority.info.dbname
            or rehearsal_marker(authority) is not None or rehearsal_marker(log) is not None
            or rehearsal_marker(target) != target.info.dbname
        ):
            return closed
        with authority.transaction():
            authority.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            authority.execute("SET LOCAL lock_timeout = '3s'")
            if _log_ref(authority) != authority_ref or _log_ref(log) != log_ref:
                return closed
            current = check_pinned_history(authority, log, org_id, authority_ref)
            if current is None:
                return closed
            with target.transaction():
                target.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                target.execute("SET LOCAL lock_timeout = '3s'")
                target.execute("SET LOCAL synchronous_commit = on")
                if _log_ref(target, lock=True) != authority_ref or rehearsal_marker(target) != target.info.dbname:
                    return closed
                return _apply_replay(target, org_id, current, authority_ref, log_ref)
    except (Error, RuntimeError, _LogConflict):
        return closed
