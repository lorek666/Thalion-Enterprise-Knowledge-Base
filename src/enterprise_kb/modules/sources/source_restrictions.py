from dataclasses import dataclass, field
from datetime import UTC
from typing import Literal
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus

from enterprise_kb.runtime.commands import IdempotencyConflict, execute_command
from enterprise_kb.runtime.events import append_event

from . import registry, sync
from .source_revocations import SourceRevocationAuthority


COMMIT = "acknowledge_source_restriction"
EVENT = "sources.restriction.acknowledged"
RemovalKind = Literal["withdrawn", "deleted"]


class RestrictionConflict(Exception):
    pass


@dataclass(frozen=True)
class Removal:
    event_ref: UUID
    object_key: str = field(repr=False)
    incarnation: str = field(repr=False)
    version_key: str = field(repr=False)
    kind: RemovalKind
    decision_ref: UUID


@dataclass(frozen=True)
class RestrictionReceipt:
    event_ref: UUID
    kind: str
    target_ref: UUID
    decision_ref: UUID
    outbox_ref: UUID
    authority_ref: UUID | None
    authority_generation: int | None


def _require_idle(connection):
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Source restriction acknowledgment requires an independent transaction.")


def _received(connection, scope, event_ref, digest):
    row = connection.execute("""
        SELECT input_digest, kind, target_ref, decision_ref, outbox_ref, authority_ref, authority_generation
        FROM thalion.source_restriction_receipt
        WHERE (org_id, space_id, source_id, event_ref) = (%s, %s, %s, %s)
    """, (*scope[:3], event_ref)).fetchone()
    if row is None:
        return None
    if row[0] != digest:
        raise IdempotencyConflict("The source event already identifies a different restriction.")
    return RestrictionReceipt(event_ref, *row[1:])


def _acknowledge(connection, context, source, event_ref, kind, identity, resolve, *, authority=None):
    digest = registry._digest("acknowledge_source_restriction.v1", source.space_id, str(source.source_ref),
                              str(event_ref), kind, identity)
    command = registry._command(context, COMMIT, source.contract_revision, digest)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        registry._lock_source_content(connection, source.source_ref)
        scope, _ = sync._admit(connection, context, source, COMMIT)

        def apply(transaction):
            if _received(transaction, scope, event_ref, digest) is not None:
                return event_ref
            target_ref, decision_ref = resolve(transaction, scope)
            outbox = append_event(transaction, context.org_id, EVENT, target_ref, space_id=source.space_id)
            transaction.execute("""
                INSERT INTO thalion.source_restriction_receipt (
                    org_id, space_id, source_id, contract_revision, event_ref, kind, target_ref, decision_ref,
                    local_stop_ref, authority_ref, authority_stream_ref, authority_generation, authority_recorded_at,
                    request_id, input_digest, outbox_ref
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (*scope, event_ref, kind, target_ref, decision_ref,
                  None if authority is not None else decision_ref, *(authority or (None,) * 4),
                  context.request_id, digest, outbox.event_id))
            return event_ref

        receipt = execute_command(connection, command, apply)
        result = _received(connection, scope, event_ref, digest)
        if result is None or receipt.result_ref != result.event_ref:
            raise RuntimeError("The source command did not record the expected restriction.")
        return result


def acknowledge_removal(
    connection: Connection, context: registry.SourceWrite, source: sync.SyncSource, event: Removal,
) -> RestrictionReceipt:
    _require_idle(connection)
    registry._validate_keys(event.object_key, event.incarnation, event.version_key)
    if (
        event.kind not in ("withdrawn", "deleted")
        or not isinstance(event.event_ref, UUID) or not isinstance(event.decision_ref, UUID)
    ):
        raise ValueError("A synthetic removal requires a named event and an existing decision.")

    def resolve(transaction, scope):
        row = transaction.execute("""
            SELECT identity.public_id
            FROM thalion.rule_use_stop AS stop
            JOIN thalion.document_version AS version USING (org_id, space_id, source_id, document_id, version_id)
            JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                 (version.org_id, version.space_id, version.identity_type, version.version_id)
            WHERE (stop.org_id, stop.space_id, stop.source_id) = (%s, %s, %s)
              AND (document.source_object_key, document.incarnation, version.source_version_key) = (%s, %s, %s)
              AND (stop.decision_ref, stop.basis_ref, stop.kind) = (%s, %s, %s)
              AND stop.replay_log_ref IS NULL
        """, (*scope[:3], event.object_key, event.incarnation, event.version_key, event.decision_ref, event.event_ref,
              "deletion_blocked" if event.kind == "deleted" else "withdrawn")).fetchone()
        if row is None:
            raise RestrictionConflict("The source event has no exact existing local removal decision.")
        return row[0], event.decision_ref

    identity = (event.object_key, event.incarnation, event.version_key, str(event.decision_ref))
    return _acknowledge(connection, context, source, event.event_ref, event.kind, identity, resolve)


def acknowledge_revocation(
    connection: Connection, context: registry.SourceWrite, source: sync.SyncSource, decision_ref: UUID,
    authority: SourceRevocationAuthority,
) -> RestrictionReceipt:
    _require_idle(connection)
    if not isinstance(decision_ref, UUID):
        raise ValueError("A synthetic permission event requires an opaque authority decision reference.")
    with connection.transaction():
        scope, _ = sync._admit(connection, context, source, COMMIT)
        space_ref, = connection.execute("""
            SELECT public_id FROM thalion.object_identity
            WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'space', %s)
        """, (*scope[:2], source.space_id)).fetchone()
    snapshot = authority.snapshot(space_ref)
    decision = next((entry for entry in snapshot.decisions if entry.decision_ref == decision_ref), None)
    if decision is None:
        raise RestrictionConflict("The source permission event is absent from the independent authority.")

    def resolve(transaction, scope):
        version_id, = transaction.execute("""
            SELECT thalion.source_restriction_version(%s, %s, %s, %s)
        """, (*scope[:3], decision.object_ref)).fetchone()
        if version_id is None or transaction.execute("""
            SELECT 1 FROM thalion.object_identity AS identity
            JOIN thalion.principal AS subject
              ON (subject.org_id, subject.identity_type, subject.principal_id) =
                 (identity.org_id, identity.object_type, identity.object_id)
            WHERE identity.org_id = %s AND identity.public_id = %s AND subject.principal_type = 'employee'
        """, (scope[0], decision.employee_ref)).fetchone() is None:
            raise RestrictionConflict("The permission event does not identify an employee and the active source scope.")
        return decision.object_ref, decision_ref

    identity = (
        str(snapshot.authority_ref), str(snapshot.stream_ref), decision.generation,
        str(decision.employee_ref), str(decision.object_ref), decision.access_use,
        str(decision.basis_ref), decision.recorded_at.astimezone(UTC).isoformat(),
    )
    evidence = (snapshot.authority_ref, snapshot.stream_ref, decision.generation, decision.recorded_at)
    return _acknowledge(
        connection, context, source, decision_ref, "permission_revoked", identity, resolve, authority=evidence,
    )
