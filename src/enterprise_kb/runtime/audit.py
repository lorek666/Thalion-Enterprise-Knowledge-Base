from dataclasses import dataclass
from datetime import date
from typing import Literal
from uuid import UUID

from psycopg import Connection, errors
from psycopg.pq import TransactionStatus


RequestOutcome = Literal[
    "succeeded", "rejected", "no_evidence", "input_changed", "dependency_unavailable", "failed"
]
RequestIngress = Literal["http", "mcp", "internal"]


class RequestAuditConflict(Exception):
    pass


@dataclass(frozen=True)
class RequestStart:
    org_id: int
    request_id: UUID
    principal_id: int
    delegated_principal_id: int | None
    client_id: str
    operation: str
    destination: str
    business_date: date
    configuration_revision: int
    question_chain_id: UUID | None = None
    space_id: int | None = None
    ingress: RequestIngress | None = None


def require_open_request(
    connection: Connection,
    org_id: int,
    request_id: UUID,
    principal_id: int,
    delegated_principal_id: int | None,
    *,
    operation: str,
):
    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise RuntimeError("Checking an open request requires the active business transaction.")
    request = connection.execute(
        """
        SELECT request_id FROM thalion.request_record
        WHERE org_id = %s AND request_id = %s AND principal_id = %s
          AND delegated_principal_id IS NOT DISTINCT FROM %s AND operation = %s AND outcome IS NULL
        FOR SHARE
        """,
        (org_id, request_id, principal_id, delegated_principal_id, operation),
    ).fetchone()
    if request is None:
        raise RequestAuditConflict("A matching open request is required for this command.")


def _require_independent_transaction(connection: Connection):
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Request audit boundaries must commit outside business transactions.")


def start_request(connection: Connection, request: RequestStart):
    """Persist metadata from trusted ingress, not raw content or authorization."""
    _require_independent_transaction(connection)
    identity = (request.principal_id, request.delegated_principal_id, request.client_id)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        if request.question_chain_id is not None:
            connection.execute(
                """
                INSERT INTO thalion.question_chain (
                    org_id, question_chain_id, principal_id, delegated_principal_id, client_id
                ) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (org_id, question_chain_id) DO NOTHING
                """,
                (request.org_id, request.question_chain_id, *identity),
            )
        try:
            dimensions = tuple(
                (column, value) for column, value in (("scope_space_id", request.space_id), ("ingress", request.ingress))
                if value is not None
            )
            extra_columns = "".join(f", {column}" for column, _ in dimensions)
            connection.execute(
                f"""
                INSERT INTO thalion.request_record (
                    org_id, request_id, principal_id, delegated_principal_id, client_id,
                    operation, destination, business_date, configuration_revision, question_chain_id{extra_columns}
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s{", %s" * len(dimensions)})
                """,
                (
                    request.org_id, request.request_id, *identity, request.operation,
                    request.destination, request.business_date, request.configuration_revision,
                    request.question_chain_id, *(value for _, value in dimensions),
                ),
            )
        except (errors.UniqueViolation, errors.ObjectNotInPrerequisiteState) as error:
            raise RequestAuditConflict("Request ID already exists or question chain differs.") from error


def finish_request(
    connection: Connection,
    org_id: int,
    request_id: UUID,
    outcome: RequestOutcome,
    elapsed_ms: int,
) -> bool:
    _require_independent_transaction(connection)
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        return finish_open_request(connection, org_id, request_id, outcome, elapsed_ms)


def finish_open_request(
    connection: Connection, org_id: int, request_id: UUID, outcome: RequestOutcome, elapsed_ms: int,
) -> bool:
    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise RuntimeError("Finalizing an open request requires an active transaction.")
    changed = connection.execute(
        """
        UPDATE thalion.request_record
        SET outcome = %s, elapsed_ms = %s, completed_at = clock_timestamp()
        WHERE org_id = %s AND request_id = %s AND outcome IS NULL
        RETURNING request_id
        """,
        (outcome, elapsed_ms, org_id, request_id),
    ).fetchone()
    return changed is not None
