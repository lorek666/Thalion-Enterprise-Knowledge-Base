from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from psycopg import Connection


class LeaseLost(Exception):
    pass


class ExternalCallPending(Exception):
    pass


def _require_read_committed(connection: Connection):
    if connection.execute("SHOW transaction_isolation").fetchone() != ("read committed",):
        raise RuntimeError("Job lifecycle and external call writes require READ COMMITTED.")


@dataclass(frozen=True)
class JobSpec:
    org_id: int
    space_id: int
    target_ref: UUID
    stage: str
    input_digest: bytes
    configuration_revision: int


@dataclass(frozen=True)
class JobLease:
    job_id: UUID
    attempt_id: UUID
    generation: int
    worker_id: int
    expires_at: datetime
    spec: JobSpec


def enqueue_job(
    connection: Connection, spec: JobSpec, *, request_id: UUID | None = None
) -> UUID:
    identity = (
        spec.org_id, spec.space_id, spec.target_ref, spec.stage,
        spec.input_digest, spec.configuration_revision,
    )
    with connection.transaction():
        row = connection.execute(
            """
            INSERT INTO thalion.job (
                org_id, space_id, target_ref, stage, input_digest, configuration_revision
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (org_id, space_id, target_ref, stage, input_digest, configuration_revision)
            DO NOTHING
            RETURNING job_id
            """,
            identity,
        ).fetchone()
        if row is None:
            row = connection.execute(
                """
                SELECT job_id FROM thalion.job
                WHERE org_id = %s AND space_id = %s AND target_ref = %s AND stage = %s
                  AND input_digest = %s AND configuration_revision = %s
                """,
                identity,
            ).fetchone()
        if row is None:
            raise RuntimeError("The existing job is not visible.")
        if request_id is not None:
            connection.execute(
                """
                INSERT INTO thalion.request_job (org_id, request_id, job_id)
                VALUES (%s, %s, %s) ON CONFLICT (org_id, request_id, job_id) DO NOTHING
                """,
                (spec.org_id, request_id, row[0]),
            )
        return row[0]


def _select_claimable_job(connection: Connection, org_id: int, stage: str, worker_id: int, job_id: UUID | None):
    while True:
        selected = connection.execute(
            """
            SELECT job.job_id, job.generation, job.space_id, job.target_ref,
                   job.input_digest, job.configuration_revision, attempt.attempt_id
            FROM thalion.job AS job
            LEFT JOIN thalion.job_attempt AS attempt
              ON attempt.org_id = job.org_id AND attempt.job_id = job.job_id
              AND attempt.generation = job.generation AND attempt.outcome = 'running'
            WHERE job.org_id = %s AND job.stage = %s AND job.job_id = COALESCE(%s, job.job_id)
              AND EXISTS (
                  SELECT 1 FROM thalion.principal AS worker
                  WHERE worker.org_id = job.org_id AND worker.principal_id = %s
                    AND worker.principal_type = 'service' AND NOT worker.disabled
              )
              AND (
                  (job.state = 'queued' AND (job.generation = 0 OR job.available_at <= clock_timestamp()))
                  OR (job.state = 'running' AND attempt.lease_expires_at <= clock_timestamp())
                  OR (job.state IN ('awaiting_external', 'external_budget_blocked') AND EXISTS (
                      SELECT 1 FROM thalion.external_job_ledger AS ledger
                      WHERE ledger.org_id = job.org_id AND ledger.job_id = job.job_id
                        AND ledger.blocked_state IS NULL
                  ))
              )
            ORDER BY job.available_at, job.job_id
            LIMIT 1
            FOR UPDATE OF job SKIP LOCKED
            """,
            (org_id, stage, job_id, worker_id),
        ).fetchone()
        if selected is None:
            return None
        selected_id, generation, _, _, _, _, expired_id = selected
        if expired_id is not None:
            _retire_external_call(connection, org_id, selected_id, generation)
            connection.execute(
                """
                UPDATE thalion.job_attempt SET outcome = 'expired', finished_at = clock_timestamp()
                WHERE org_id = %s AND attempt_id = %s
                """,
                (org_id, expired_id),
            )
        blocked = connection.execute(
            """
            SELECT blocked_state FROM thalion.external_job_ledger
            WHERE org_id = %s AND job_id = %s AND blocked_state IS NOT NULL
            """,
            (org_id, selected_id),
        ).fetchone()
        if blocked is None:
            return selected[:6]
        connection.execute(
            "UPDATE thalion.job SET state = %s WHERE org_id = %s AND job_id = %s",
            (blocked[0], org_id, selected_id),
        )


def claim_job(
    connection: Connection,
    org_id: int,
    stage: str,
    worker_id: int,
    lease_for: timedelta,
    *,
    job_id: UUID | None = None,
) -> JobLease | None:
    if lease_for <= timedelta(0):
        raise ValueError("A job lease duration must be positive.")
    with connection.transaction():
        _require_read_committed(connection)
        selected = _select_claimable_job(connection, org_id, stage, worker_id, job_id)
        if selected is None:
            return None
        job_id, old_generation, space_id, target_ref, digest, revision = selected
        generation = old_generation + 1
        attempt_id, expires_at = connection.execute(
            """
            WITH timing AS (SELECT clock_timestamp() AS started_at)
            INSERT INTO thalion.job_attempt (
                org_id, job_id, generation, worker_id, started_at, lease_expires_at
            )
            SELECT %s, %s, %s, %s, started_at, started_at + %s FROM timing
            RETURNING attempt_id, lease_expires_at
            """,
            (org_id, job_id, generation, worker_id, lease_for),
        ).fetchone()
        connection.execute(
            """
            UPDATE thalion.job SET state = 'running', generation = %s
            WHERE org_id = %s AND job_id = %s
            """,
            (generation, org_id, job_id),
        )
        spec = JobSpec(org_id, space_id, target_ref, stage, digest, revision)
        return JobLease(job_id, attempt_id, generation, worker_id, expires_at, spec)


def _lock_current_job(connection: Connection, lease: JobLease):
    _require_read_committed(connection)
    org_id = lease.spec.org_id
    row = connection.execute(
        """
        SELECT job.org_id, job.space_id, job.target_ref, job.stage,
               job.input_digest, job.configuration_revision
        FROM thalion.job AS job
        JOIN thalion.job_attempt AS attempt
          ON attempt.org_id = job.org_id AND attempt.job_id = job.job_id
          AND attempt.generation = job.generation
        JOIN thalion.principal AS worker
          ON worker.org_id = job.org_id AND worker.principal_id = attempt.worker_id
        WHERE job.org_id = %s AND job.job_id = %s AND job.state = 'running'
          AND job.generation = %s AND attempt.attempt_id = %s AND attempt.worker_id = %s
          AND attempt.outcome = 'running' AND attempt.lease_expires_at > clock_timestamp()
          AND worker.principal_type = 'service' AND NOT worker.disabled
        FOR UPDATE OF job
        """,
        (org_id, lease.job_id, lease.generation, lease.attempt_id, lease.worker_id),
    ).fetchone()
    if row is None or JobSpec(*row) != lease.spec:
        raise LeaseLost("The job attempt is not current or cannot commit.")


def _close_attempt(connection: Connection, lease: JobLease, outcome: str):
    closed = connection.execute(
        """
        UPDATE thalion.job_attempt AS attempt
        SET outcome = %s, finished_at = clock_timestamp()
        FROM thalion.principal AS worker
        WHERE attempt.org_id = %s AND attempt.attempt_id = %s
          AND attempt.outcome = 'running' AND attempt.lease_expires_at > clock_timestamp()
          AND worker.org_id = attempt.org_id AND worker.principal_id = attempt.worker_id
          AND worker.principal_type = 'service' AND NOT worker.disabled
        RETURNING attempt.attempt_id
        """,
        (outcome, lease.spec.org_id, lease.attempt_id),
    ).fetchone()
    if closed is None:
        raise LeaseLost("The job attempt expired or lost its worker before commit.")


def _retire_external_call(connection: Connection, org_id: int, job_id: UUID, generation: int):
    connection.execute(
        """
        UPDATE thalion.external_call
        SET state = CASE WHEN state = 'sent' THEN 'outcome_unknown' ELSE state END,
            abandoned_at = CASE WHEN state = 'not_sent' THEN clock_timestamp() END
        WHERE org_id = %s AND job_id = %s AND generation = %s
          AND state IN ('not_sent', 'sent') AND abandoned_at IS NULL
        """,
        (org_id, job_id, generation),
    )


def _external_call_state(connection: Connection, lease: JobLease) -> tuple[str | None] | None:
    return connection.execute(
        """
        SELECT attempt.state FROM thalion.external_call_budget AS budget
        LEFT JOIN thalion.external_call AS attempt ON attempt.org_id = budget.org_id
          AND attempt.job_id = budget.job_id AND attempt.generation = %s
        WHERE budget.org_id = %s AND budget.job_id = %s
        """,
        (lease.generation, lease.spec.org_id, lease.job_id),
    ).fetchone()


def complete_job(
    connection: Connection, lease: JobLease, accept: Callable[[Connection], UUID]
) -> UUID:
    """Check the lease and atomically accept result, domain changes and events.

    The owning module checks its current input and safety preconditions in accept.
    External I/O must finish before entering this transaction.
    """
    with connection.transaction():
        _lock_current_job(connection, lease)
        if _external_call_state(connection, lease) is not None:
            raise ExternalCallPending("External jobs must explicitly accept a confirmed artifact.")
        return _finish_job(connection, lease, accept(connection))


def _finish_job(
    connection: Connection, lease: JobLease, result_ref: UUID, *, result_call_id: UUID | None = None
) -> UUID:
    if not isinstance(result_ref, UUID):
        raise TypeError("The accepted result must be an opaque UUID.")
    _close_attempt(connection, lease, "succeeded")
    connection.execute(
        """
        UPDATE thalion.job SET state = 'succeeded', result_ref = %s, result_call_id = %s
        WHERE org_id = %s AND job_id = %s
        """,
        (result_ref, result_call_id, lease.spec.org_id, lease.job_id),
    )
    return result_ref


def retry_job(connection: Connection, lease: JobLease, *, delay: timedelta):
    """Requeue a known retryable local failure, not an unknown external outcome."""
    if delay < timedelta(0):
        raise ValueError("A retry delay cannot be negative.")
    with connection.transaction():
        _lock_current_job(connection, lease)
        call = _external_call_state(connection, lease)
        if call in (("sent",), ("outcome_unknown",)):
            raise ExternalCallPending("A sent attempt cannot be retried as a local failure.")
        _retire_external_call(connection, lease.spec.org_id, lease.job_id, lease.generation)
        _close_attempt(connection, lease, "retry")
        connection.execute(
            """
            UPDATE thalion.job SET state = 'queued', available_at = clock_timestamp() + %s
            WHERE org_id = %s AND job_id = %s
            """,
            (delay, lease.spec.org_id, lease.job_id),
        )
