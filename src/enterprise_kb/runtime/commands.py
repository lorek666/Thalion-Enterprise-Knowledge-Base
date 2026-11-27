from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from uuid import UUID

from psycopg import Connection

from .audit import require_open_request


class IdempotencyConflict(Exception):
    pass


@dataclass(frozen=True)
class CommandEnvelope:
    org_id: int
    principal_id: int
    delegated_principal_id: int | None
    request_id: UUID
    operation: str
    idempotency_key: str = field(repr=False)
    input_digest: bytes
    configuration_revision: int
    expected_generation: int | None


@dataclass(frozen=True)
class CommandReceipt:
    receipt_id: UUID
    result_ref: UUID | None
    replayed: bool


def execute_command(
    connection: Connection,
    command: CommandEnvelope,
    apply: Callable[[Connection], UUID | None],
) -> CommandReceipt:
    """Run an already authorized database command; a receipt grants no read rights."""
    key = command.idempotency_key.encode("utf-8")
    if not key or len(key) > 1024:
        raise ValueError("Idempotency keys must be between 1 and 1024 bytes.")
    scope = (
        command.org_id,
        command.principal_id,
        command.delegated_principal_id,
        command.operation,
        sha256(key).digest(),
    )
    preconditions = (
        command.input_digest,
        command.configuration_revision,
        command.expected_generation,
    )
    with connection.transaction():
        require_open_request(
            connection, command.org_id, command.request_id, command.principal_id,
            command.delegated_principal_id, operation=command.operation,
        )
        claimed = connection.execute(
            """
            INSERT INTO thalion.command_receipt (
                org_id, principal_id, delegated_principal_id, operation, key_digest,
                input_digest, configuration_revision, expected_generation, request_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (org_id, principal_id, delegated_principal_id, operation, key_digest)
            DO NOTHING
            RETURNING receipt_id
            """,
            (*scope, *preconditions, command.request_id),
        ).fetchone()
        if claimed is None:
            stored = connection.execute(
                """
                SELECT input_digest, configuration_revision, expected_generation,
                       receipt_id, result_ref, completed_at
                FROM thalion.command_receipt
                WHERE org_id = %s AND principal_id = %s
                  AND delegated_principal_id IS NOT DISTINCT FROM %s
                  AND operation = %s AND key_digest = %s
                """,
                scope,
            ).fetchone()
            if stored is None or stored[5] is None:
                raise RuntimeError("A completed command receipt is not visible.")
            if stored[:3] != preconditions:
                raise IdempotencyConflict("The idempotency key already has different input.")
            _link_command_request(connection, command, stored[3])
            return CommandReceipt(stored[3], stored[4], replayed=True)

        receipt_id = claimed[0]
        result_ref = apply(connection)
        if result_ref is not None and not isinstance(result_ref, UUID):
            raise TypeError("A command result must be an opaque UUID or None.")
        connection.execute(
            """
            UPDATE thalion.command_receipt
            SET result_ref = %s, completed_at = clock_timestamp()
            WHERE receipt_id = %s
            """,
            (result_ref, receipt_id),
        )
        _link_command_request(connection, command, receipt_id)
        return CommandReceipt(receipt_id, result_ref, replayed=False)


def _link_command_request(connection: Connection, command: CommandEnvelope, receipt_id: UUID):
    connection.execute(
        """
        INSERT INTO thalion.request_command (org_id, request_id, receipt_id) VALUES (%s, %s, %s)
        ON CONFLICT (org_id, request_id, receipt_id) DO NOTHING
        """,
        (command.org_id, command.request_id, receipt_id),
    )
