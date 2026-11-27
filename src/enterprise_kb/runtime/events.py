from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus


@dataclass(frozen=True)
class OutboxEvent:
    org_id: int
    event_id: UUID
    space_id: int | None
    event_type: str
    object_ref: UUID
    schema_revision: int
    occurred_at: datetime


def append_event(
    connection: Connection,
    org_id: int,
    event_type: str,
    object_ref: UUID,
    *,
    space_id: int | None = None,
    schema_revision: int = 1,
) -> OutboxEvent:
    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise RuntimeError("Outbox events require the active business transaction.")
    row = connection.execute(
        """
        WITH target AS (
            SELECT org_id, space_id, public_id FROM thalion.object_identity
            WHERE org_id = %s AND public_id = %s
              AND (%s::bigint IS NULL OR space_id = %s)
        ), written AS (
            INSERT INTO thalion.outbox_event (org_id, event_type, object_ref, schema_revision)
            SELECT org_id, %s, public_id, %s FROM target
            RETURNING org_id, event_id, event_type, object_ref, schema_revision, occurred_at
        )
        SELECT written.org_id, written.event_id, target.space_id, written.event_type,
               written.object_ref, written.schema_revision, written.occurred_at
        FROM written CROSS JOIN target
        """,
        (org_id, object_ref, space_id, space_id, event_type, schema_revision),
    ).fetchone()
    if row is None:
        raise ValueError("The event target is not registered in this scope.")
    return OutboxEvent(*row)


def pending_events(
    connection: Connection, org_id: int, consumer: str, *, limit: int = 100
) -> tuple[OutboxEvent, ...]:
    if not 1 <= limit <= 500:
        raise ValueError("The outbox batch size must be between 1 and 500.")
    rows = connection.execute(
        """
        SELECT event.org_id, event.event_id, identity.space_id, event.event_type,
               event.object_ref, event.schema_revision, event.occurred_at
        FROM thalion.outbox_event AS event
        JOIN thalion.object_identity AS identity
          ON identity.org_id = event.org_id AND identity.public_id = event.object_ref
        WHERE event.org_id = %s AND NOT EXISTS (
            SELECT 1 FROM thalion.event_consumption AS receipt
            WHERE receipt.org_id = event.org_id AND receipt.event_id = event.event_id
              AND receipt.consumer = %s
        )
        ORDER BY event.occurred_at, event.event_id
        LIMIT %s
        """,
        (org_id, consumer, limit),
    ).fetchall()
    return tuple(OutboxEvent(*row) for row in rows)


def consume_event(
    connection: Connection,
    org_id: int,
    event_id: UUID,
    consumer: str,
    apply: Callable[[Connection, OutboxEvent], object],
) -> bool:
    """Commit local effects together with the consumer receipt."""
    with connection.transaction():
        row = connection.execute(
            """
            SELECT event.org_id, event.event_id, identity.space_id, event.event_type,
                   event.object_ref, event.schema_revision, event.occurred_at
            FROM thalion.outbox_event AS event
            JOIN thalion.object_identity AS identity
              ON identity.org_id = event.org_id AND identity.public_id = event.object_ref
            WHERE event.org_id = %s AND event.event_id = %s
            """,
            (org_id, event_id),
        ).fetchone()
        if row is None:
            return False
        claimed = connection.execute(
            """
            INSERT INTO thalion.event_consumption (org_id, event_id, consumer)
            VALUES (%s, %s, %s)
            ON CONFLICT (org_id, event_id, consumer) DO NOTHING
            RETURNING event_id
            """,
            (org_id, event_id, consumer),
        ).fetchone()
        if claimed is None:
            return False
        apply(connection, OutboxEvent(*row))
        return True
