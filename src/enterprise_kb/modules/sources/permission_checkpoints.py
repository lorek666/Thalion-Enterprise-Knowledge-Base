from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus

from enterprise_kb.runtime.commands import IdempotencyConflict, execute_command
from enterprise_kb.runtime.events import append_event

from . import registry, sync
from .source_revocations import SourceRevocationAuthority


COMMIT = "record_source_permission_checkpoint"
READ = "read_source_permission_checkpoint"
EVENT = "sources.permission.checkpointed"


class PermissionCheckpointConflict(Exception):
    pass


@dataclass(frozen=True)
class PermissionCheckpointReceipt:
    checkpoint_ref: UUID
    sequence: int
    authority_ref: UUID
    authority_stream_ref: UUID
    authority_generation: int
    acknowledged_count: int
    last_acknowledged_generation: int | None
    outbox_ref: UUID
    committed_at: datetime


def _require_idle(connection: Connection):
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Source permission checkpoints require an independent transaction.")


def _head(connection: Connection, scope: tuple[int, int, int, int]) -> PermissionCheckpointReceipt | None:
    row = connection.execute("""
        SELECT checkpoint_ref, sequence, authority_ref, authority_stream_ref, authority_generation,
               acknowledged_count, last_acknowledged_generation, outbox_ref, committed_at
        FROM thalion.source_permission_checkpoint
        WHERE (org_id, space_id, source_id) = (%s, %s, %s)
        ORDER BY sequence DESC LIMIT 1
    """, scope[:3]).fetchone()
    return None if row is None else PermissionCheckpointReceipt(*row)


def _received(
    connection: Connection, scope: tuple[int, int, int, int], checkpoint_ref: UUID, digest: bytes,
) -> PermissionCheckpointReceipt | None:
    row = connection.execute("""
        SELECT input_digest, sequence, authority_ref, authority_stream_ref, authority_generation,
               acknowledged_count, last_acknowledged_generation, outbox_ref, committed_at
        FROM thalion.source_permission_checkpoint
        WHERE (org_id, space_id, source_id, checkpoint_ref) = (%s, %s, %s, %s)
    """, (*scope[:3], checkpoint_ref)).fetchone()
    if row is None:
        return None
    if row[0] != digest:
        raise IdempotencyConflict("The checkpoint reference already identifies a different permission checkpoint.")
    return PermissionCheckpointReceipt(checkpoint_ref, *row[1:])


def read_permission_checkpoint(
    connection: Connection, context: registry.SourceWrite, source: sync.SyncSource,
) -> PermissionCheckpointReceipt | None:
    with connection.transaction():
        scope, _ = sync._admit(connection, context, source, READ)
        return _head(connection, scope)


def record_permission_checkpoint(
    connection: Connection, context: registry.SourceWrite, source: sync.SyncSource,
    checkpoint_ref: UUID, previous: UUID | None, authority: SourceRevocationAuthority,
) -> PermissionCheckpointReceipt:
    _require_idle(connection)
    if (
        not isinstance(checkpoint_ref, UUID)
        or (previous is not None and not isinstance(previous, UUID))
        or checkpoint_ref == previous
    ):
        raise ValueError("A synthetic permission checkpoint requires distinct opaque checkpoint references.")

    with connection.transaction():
        scope, _ = sync._admit(connection, context, source, COMMIT)
        space_ref, = connection.execute("""
            SELECT public_id FROM thalion.object_identity
            WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'space', %s)
        """, (*scope[:2], source.space_id)).fetchone()

    snapshot = authority.snapshot(space_ref)
    digest = registry._digest(
        "record_source_permission_checkpoint.v1", source.space_id, str(source.source_ref),
        str(checkpoint_ref), str(previous) if previous is not None else None,
        str(snapshot.authority_ref), str(snapshot.stream_ref),
    )
    command = registry._command(context, COMMIT, source.contract_revision, digest)
    decision_refs = [entry.decision_ref for entry in snapshot.decisions]
    object_refs = [entry.object_ref for entry in snapshot.decisions]
    generations = [entry.generation for entry in snapshot.decisions]

    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        registry._lock_source_content(connection, source.source_ref)
        scope, _ = sync._admit(connection, context, source, COMMIT)

        def apply(transaction):
            if _received(transaction, scope, checkpoint_ref, digest) is not None:
                return checkpoint_ref
            current = _head(transaction, scope)
            if current is None:
                if previous is not None:
                    raise PermissionCheckpointConflict("The first permission checkpoint cannot reference a predecessor.")
                sequence = 1
            else:
                if current.checkpoint_ref != previous:
                    raise PermissionCheckpointConflict("The permission checkpoint predecessor does not match the current head.")
                if (
                    (current.authority_ref, current.authority_stream_ref)
                    != (snapshot.authority_ref, snapshot.stream_ref)
                    or snapshot.generation < current.authority_generation
                ):
                    raise PermissionCheckpointConflict("The authority snapshot cannot switch streams or move backward.")
                sequence = current.sequence + 1

            if transaction.execute("""
                SELECT 1 FROM thalion.source_restriction_receipt
                WHERE (org_id, space_id, source_id, kind) = (%s, %s, %s, 'permission_revoked')
                  AND (authority_ref, authority_stream_ref) IS DISTINCT FROM (%s, %s)
                LIMIT 1
            """, (*scope[:3], snapshot.authority_ref, snapshot.stream_ref)).fetchone() is not None:
                raise PermissionCheckpointConflict("Acknowledged source revocations belong to a different authority stream.")

            if decision_refs and transaction.execute("""
                WITH events AS (
                    SELECT * FROM unnest(%s::uuid[], %s::uuid[], %s::bigint[])
                      AS entry(decision_ref, object_ref, generation)
                )
                SELECT 1 FROM events
                WHERE thalion.source_restriction_version(%s, %s, %s, events.object_ref) IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM thalion.source_restriction_receipt AS receipt
                      WHERE (receipt.org_id, receipt.space_id, receipt.source_id, receipt.event_ref) =
                            (%s, %s, %s, events.decision_ref)
                        AND (receipt.kind, receipt.target_ref, receipt.authority_ref,
                             receipt.authority_stream_ref, receipt.authority_generation) =
                            ('permission_revoked', events.object_ref, %s, %s, events.generation)
                  )
                LIMIT 1
            """, (
                decision_refs, object_refs, generations, *scope[:3], *scope[:3],
                snapshot.authority_ref, snapshot.stream_ref,
            )).fetchone() is not None:
                raise PermissionCheckpointConflict("Unacknowledged source revocations must be recorded before checkpointing.")

            acknowledged_count, last_acknowledged_generation = transaction.execute("""
                SELECT count(*)::integer, max(authority_generation)
                FROM thalion.source_restriction_receipt
                WHERE (org_id, space_id, source_id, kind, authority_ref, authority_stream_ref) =
                      (%s, %s, %s, 'permission_revoked', %s, %s)
            """, (*scope[:3], snapshot.authority_ref, snapshot.stream_ref)).fetchone()
            if last_acknowledged_generation is not None and last_acknowledged_generation > snapshot.generation:
                raise PermissionCheckpointConflict("The authority snapshot is behind an acknowledged source revocation.")

            outbox = append_event(transaction, context.org_id, EVENT, source.source_ref, space_id=source.space_id)
            transaction.execute("""
                INSERT INTO thalion.source_permission_checkpoint (
                    org_id, space_id, source_id, contract_revision, sequence, checkpoint_ref,
                    previous_checkpoint_ref, authority_ref, authority_stream_ref, authority_generation,
                    acknowledged_count, last_acknowledged_generation, request_id, input_digest, outbox_ref
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                *scope, sequence, checkpoint_ref, previous,
                snapshot.authority_ref, snapshot.stream_ref, snapshot.generation,
                acknowledged_count, last_acknowledged_generation,
                context.request_id, digest, outbox.event_id,
            ))
            return checkpoint_ref

        receipt = execute_command(connection, command, apply)
        result = _received(connection, scope, checkpoint_ref, digest)
        if result is None or receipt.result_ref != result.checkpoint_ref:
            raise RuntimeError("The source command did not record the expected permission checkpoint.")
        return result
