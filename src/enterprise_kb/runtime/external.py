from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from uuid import UUID

from psycopg import Connection, errors
from psycopg.pq import TransactionStatus

from .jobs import (
    ExternalCallPending,
    JobLease,
    JobSpec,
    LeaseLost,
    _finish_job,
    _lock_current_job,
    _require_read_committed,
    _retire_external_call,
    enqueue_job,
)


class CallBudgetExceeded(Exception):
    pass


class ExternalCallConflict(Exception):
    pass


@dataclass(frozen=True)
class CallBudget:
    currency: str
    maximum_microunits: int
    maximum_calls: int
    allow_unknown_retry: bool = False


@dataclass(frozen=True)
class CallUsage:
    currency: str
    actual_microunits: int
    reserved_microunits: int
    dispatched_calls: int
    active_reservations: int
    unresolved_calls: int


@dataclass(frozen=True)
class UsageReceipt:
    receipt_id: UUID
    provider_request_id: str = field(repr=False)
    succeeded: bool
    input_tokens: int
    output_tokens: int
    actual_microunits: int
    previous_receipt_id: UUID | None = None


@dataclass(frozen=True)
class CallArtifact:
    ref: UUID
    digest: bytes


@dataclass(frozen=True)
class ConfirmedCall:
    call_id: UUID
    generation: int
    route: str
    provider_namespace: str
    input_digest: bytes
    artifact: CallArtifact


def enqueue_external_job(
    connection: Connection, spec: JobSpec, budget: CallBudget, *, request_id: UUID | None = None
) -> UUID:
    """Make enrollment and the fixed budget visible in the same transaction."""
    with connection.transaction():
        _require_read_committed(connection)
        job_id = enqueue_job(connection, spec, request_id=request_id)
        _configure_call_budget(connection, spec.org_id, job_id, budget)
        return job_id


def _configure_call_budget(
    connection: Connection, org_id: int, job_id: UUID, budget: CallBudget
):
    """Attach a trusted workflow's budget before the job is first claimed."""
    with connection.transaction():
        job = connection.execute(
            """
            SELECT generation FROM thalion.job
            WHERE org_id = %s AND job_id = %s FOR UPDATE
            """,
            (org_id, job_id),
        ).fetchone()
        if job is None:
            raise ExternalCallConflict("Job is not registered in this organization.")
        stored = _get_budget(connection, org_id, job_id)
        if stored == budget:
            return
        if stored is not None or job[0] != 0:
            raise ExternalCallConflict("A started job or a fixed budget cannot be changed.")
        connection.execute(
            """
            INSERT INTO thalion.external_call_budget (
                org_id, job_id, currency, maximum_microunits, maximum_calls, allow_unknown_retry
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                org_id, job_id, budget.currency, budget.maximum_microunits,
                budget.maximum_calls, budget.allow_unknown_retry,
            ),
        )


def _get_budget(connection: Connection, org_id: int, job_id: UUID) -> CallBudget | None:
    row = connection.execute(
        """
        SELECT currency, maximum_microunits, maximum_calls, allow_unknown_retry
        FROM thalion.external_call_budget WHERE org_id = %s AND job_id = %s
        """,
        (org_id, job_id),
    ).fetchone()
    return CallBudget(*row) if row is not None else None


def external_call_usage(connection: Connection, org_id: int, job_id: UUID) -> CallUsage:
    row = connection.execute(
        """
        SELECT currency, actual_microunits, reserved_microunits, dispatched_calls,
               active_reservations, unresolved_calls
        FROM thalion.external_job_ledger WHERE org_id = %s AND job_id = %s
        """,
        (org_id, job_id),
    ).fetchone()
    if row is None:
        raise CallBudgetExceeded("No external call budget is configured.")
    return CallUsage(row[0], int(row[1]), int(row[2]), *row[3:])


def _check_budget(connection: Connection, lease: JobLease, extra_cost: int, extra_calls: int):
    row = connection.execute(
        """
        SELECT maximum_microunits, maximum_calls, allow_unknown_retry,
               actual_microunits + reserved_microunits, dispatched_calls + active_reservations,
               unresolved_calls, artifact_ref
        FROM thalion.external_job_ledger WHERE org_id = %s AND job_id = %s
        """,
        (lease.spec.org_id, lease.job_id),
    ).fetchone()
    if row is None:
        raise CallBudgetExceeded("No external call budget is configured.")
    cost_limit, call_limit, allow_unknown, allocated, calls, unresolved, artifact_ref = row
    if artifact_ref is not None:
        raise ExternalCallPending("Review the confirmed artifact before sending another call.")
    if unresolved and not allow_unknown:
        raise ExternalCallPending("An earlier external call must be reconciled.")
    if allocated + extra_cost > cost_limit or calls + extra_calls > call_limit:
        raise CallBudgetExceeded("External call budget would be exceeded.")


def reserve_external_call(
    connection: Connection,
    lease: JobLease,
    *,
    route: str,
    provider_namespace: str,
    input_digest: bytes,
    maximum_microunits: int,
) -> UUID:
    if maximum_microunits < 0:
        raise ValueError("The external call reservation must be nonnegative.")
    scope = (lease.spec.org_id, lease.job_id, lease.generation)
    parameters = (route, provider_namespace, input_digest, maximum_microunits)
    with connection.transaction():
        _lock_current_job(connection, lease)
        stored = connection.execute(
            """
            SELECT call_id, route, provider_namespace, input_digest, reserved_microunits
            FROM thalion.external_call WHERE org_id = %s AND job_id = %s AND generation = %s
            """,
            scope,
        ).fetchone()
        if stored is not None:
            if stored[1:] != parameters:
                raise ExternalCallConflict("The attempt already reserved a different call.")
            return stored[0]
        _check_budget(connection, lease, maximum_microunits, 1)
        return connection.execute(
            """
            INSERT INTO thalion.external_call (
                org_id, job_id, generation, route, provider_namespace, input_digest,
                reserved_microunits
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING call_id
            """,
            (*scope, *parameters),
        ).fetchone()[0]


def mark_call_sent(
    connection: Connection,
    lease: JobLease,
    call_id: UUID,
    *,
    route: str,
    provider_namespace: str,
    input_digest: bytes,
) -> bool:
    """Return True only to the sender that committed this dispatch intent."""
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Dispatch intent must be committed before external I/O.")
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        return _register_dispatch(connection, lease, call_id, route=route, provider_namespace=provider_namespace,
                                  input_digest=input_digest)


def _register_dispatch(
    connection: Connection, lease: JobLease, call_id: UUID, *, route: str, provider_namespace: str, input_digest: bytes,
) -> bool:
    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise RuntimeError("Dispatch registration requires an active transaction.")
    _lock_current_job(connection, lease)
    scope = (lease.spec.org_id, lease.job_id, lease.generation, call_id)
    stored = connection.execute(
        """
        SELECT route, provider_namespace, input_digest, state, abandoned_at
        FROM thalion.external_call
        WHERE org_id = %s AND job_id = %s AND generation = %s AND call_id = %s
        """,
        scope,
    ).fetchone()
    if stored is None or stored[:3] != (route, provider_namespace, input_digest):
        raise ExternalCallConflict("The dispatch does not match the reserved call.")
    if stored[3:] != ("not_sent", None):
        return False
    _check_budget(connection, lease, 0, 0)
    dispatched = connection.execute(
        """
        UPDATE thalion.external_call AS call
        SET state = 'sent', dispatched_at = clock_timestamp()
        FROM thalion.job AS job
        JOIN thalion.job_attempt AS attempt ON attempt.org_id = job.org_id
          AND attempt.job_id = job.job_id AND attempt.generation = job.generation
        JOIN thalion.principal AS worker ON worker.org_id = attempt.org_id
          AND worker.principal_id = attempt.worker_id
        WHERE call.org_id = %s AND call.job_id = %s AND call.generation = %s
          AND call.call_id = %s AND call.state = 'not_sent' AND call.abandoned_at IS NULL
          AND job.org_id = call.org_id AND job.job_id = call.job_id
          AND job.state = 'running' AND job.generation = call.generation
          AND attempt.attempt_id = %s AND attempt.worker_id = %s
          AND attempt.outcome = 'running' AND attempt.lease_expires_at > clock_timestamp()
          AND worker.principal_type = 'service' AND NOT worker.disabled
        RETURNING call.call_id
        """,
        (*scope, lease.attempt_id, lease.worker_id),
    ).fetchone()
    if dispatched is None:
        raise LeaseLost("The job attempt cannot register dispatch.")
    return True


def _lock_call_job(connection: Connection, org_id: int, call_id: UUID):
    _require_read_committed(connection)
    locked = connection.execute(
        """
        SELECT job.job_id FROM thalion.job AS job
        JOIN thalion.external_call AS attempt ON attempt.org_id = job.org_id
          AND attempt.job_id = job.job_id
        WHERE attempt.org_id = %s AND attempt.call_id = %s
        FOR UPDATE OF job
        """,
        (org_id, call_id),
    ).fetchone()
    if locked is None:
        raise ExternalCallConflict("The external call is not registered in this organization.")


def lock_pending_dispatch(connection: Connection, lease: JobLease, call_id: UUID) -> bool:
    """Hold the current job against retirement or reconciliation during local receipt."""
    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise RuntimeError("Checking dispatch requires the active receipt transaction.")
    _lock_current_job(connection, lease)
    return connection.execute(
        """
        SELECT 1 FROM thalion.external_call
        WHERE (org_id, job_id, generation, call_id) = (%s, %s, %s, %s) AND state = 'sent'
        """,
        (lease.spec.org_id, lease.job_id, lease.generation, call_id),
    ).fetchone() is not None


def mark_call_unknown(connection: Connection, org_id: int, call_id: UUID):
    with connection.transaction():
        _lock_call_job(connection, org_id, call_id)
        connection.execute(
            """
            UPDATE thalion.external_call SET state = 'outcome_unknown'
            WHERE org_id = %s AND call_id = %s AND state = 'sent'
            """,
            (org_id, call_id),
        )


def complete_external_job(
    connection: Connection,
    lease: JobLease,
    accept: Callable[[Connection, ConfirmedCall], UUID],
) -> UUID:
    """Accept only after the owner checks artifact integrity, inputs and current authorization."""
    with connection.transaction():
        _lock_current_job(connection, lease)
        scope = (lease.spec.org_id, lease.job_id)
        row = connection.execute(
            """
            SELECT call_id, generation, route, provider_namespace, input_digest,
                   artifact_ref, artifact_digest
            FROM thalion.external_job_ledger
            WHERE org_id = %s AND job_id = %s AND artifact_ref IS NOT NULL
            """,
            scope,
        ).fetchone()
        if row is None:
            raise ExternalCallPending("The latest dispatch has no confirmed artifact.")
        candidate = ConfirmedCall(*row[:5], CallArtifact(*row[5:]))
        result_ref = accept(connection, candidate)
        _retire_external_call(connection, *scope, lease.generation)
        return _finish_job(connection, lease, result_ref, result_call_id=candidate.call_id)


def record_call_receipt(
    connection: Connection,
    org_id: int,
    call_id: UUID,
    receipt: UsageReceipt,
    *,
    artifact: CallArtifact | None = None,
) -> bool:
    """Persist trusted usage and any durable output pointer, without accepting the job."""
    if artifact is not None and (
        not receipt.succeeded or not isinstance(artifact.ref, UUID) or len(artifact.digest) != 32
    ):
        raise ValueError("Only a successful receipt can bind an artifact UUID and SHA-256 digest.")
    provider_id = receipt.provider_request_id.encode("utf-8")
    if not provider_id or len(provider_id) > 1024:
        raise ValueError("Provider request IDs must be between 1 and 1024 bytes.")
    scope = (org_id, call_id)
    provider_digest = sha256(provider_id).digest()
    outcome = "confirmed_success" if receipt.succeeded else "confirmed_failure"
    values = (
        receipt.previous_receipt_id, receipt.input_tokens, receipt.output_tokens,
        receipt.actual_microunits,
    )
    with connection.transaction():
        _lock_call_job(connection, *scope)
        state, stored_digest, artifact_ref, artifact_digest = connection.execute(
            """
            SELECT state, provider_request_digest, artifact_ref, artifact_digest
            FROM thalion.external_call
            WHERE org_id = %s AND call_id = %s
            """,
            scope,
        ).fetchone()
        if state == "not_sent":
            raise ExternalCallConflict("An unsent call cannot receive usage.")
        if stored_digest is not None and (state, stored_digest) != (outcome, provider_digest):
            raise ExternalCallConflict("A reconciliation cannot change provider identity or outcome.")
        if artifact is not None and artifact_ref is not None and (
            artifact.ref, artifact.digest
        ) != (artifact_ref, artifact_digest):
            raise ExternalCallConflict("A confirmed artifact cannot be replaced.")
        existing = connection.execute(
            """
            SELECT previous_receipt_id, input_tokens, output_tokens, actual_microunits
            FROM thalion.external_call_receipt
            WHERE org_id = %s AND call_id = %s AND receipt_id = %s
            """,
            (*scope, receipt.receipt_id),
        ).fetchone()
        if existing is not None:
            if existing != values:
                raise ExternalCallConflict("Receipt replay does not match previously recorded usage.")
        else:
            _insert_call_receipt(
                connection, scope, receipt.receipt_id, values, outcome, provider_digest,
                first_receipt=stored_digest is None,
            )
        if artifact is not None and artifact_ref is None:
            connection.execute(
                """
                UPDATE thalion.external_call SET artifact_ref = %s, artifact_digest = %s
                WHERE org_id = %s AND call_id = %s
                """,
                (artifact.ref, artifact.digest, *scope),
            )
            return True
        return existing is None


def _insert_call_receipt(
    connection, scope, receipt_id, values, outcome, provider_digest, *, first_receipt
):
    latest = connection.execute(
        """
        SELECT receipt_id FROM thalion.external_call_latest_receipt
        WHERE org_id = %s AND call_id = %s
        """,
        scope,
    ).fetchone()
    if values[0] != (latest[0] if latest else None):
        raise ExternalCallConflict("The reconciliation does not follow the current receipt.")
    if first_receipt:
        try:
            connection.execute(
                """
                UPDATE thalion.external_call SET state = %s, provider_request_digest = %s
                WHERE org_id = %s AND call_id = %s
                """,
                (outcome, provider_digest, *scope),
            )
        except errors.UniqueViolation as error:
            raise ExternalCallConflict("This provider request belongs to another call.") from error
    connection.execute(
        """
        INSERT INTO thalion.external_call_receipt (
            org_id, call_id, receipt_id, previous_receipt_id, input_tokens, output_tokens,
            actual_microunits
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (*scope, receipt_id, *values),
    )
