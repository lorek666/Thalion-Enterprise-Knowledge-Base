from datetime import UTC, datetime

from psycopg import Connection


def _clear_minutes(
    unfinished: int, states: dict[str, int], unknown: int, unresolved_external: bool, net_per_interval: int | None,
) -> int | None:
    if unknown or unresolved_external or states.keys() - {"ready", "leased"}:
        return None
    if net_per_interval is None or net_per_interval <= 0:
        return None
    minutes = (unfinished * 15 + net_per_interval - 1) // net_per_interval
    return minutes if minutes <= 60 else None


def read_job_backlog(
    connection: Connection, org_id: int, space_id: int, observed_at: datetime | None = None,
    *, window: tuple[datetime, datetime] | None = None, visible_stages: tuple[str, ...] | None = None,
    include_estimate: bool = False, source_id: int | None = None,
) -> dict:
    if include_estimate and (window is not None or not visible_stages):
        raise ValueError("A clearance estimate requires the live one-hour window and named stages.")
    start, end = window if window is not None else (None, None)
    rows = connection.execute("""
        WITH snapshot AS NOT MATERIALIZED (
            SELECT coalesce(%(observed_at)s::timestamptz, statement_timestamp()) AS observed_at
        ), bounds AS NOT MATERIALIZED (
            SELECT observed_at,
                   coalesce(%(start)s::timestamptz, observed_at - interval '1 hour') AS start_at,
                   coalesce(%(end)s::timestamptz, observed_at) AS end_at
            FROM snapshot
        ), scoped AS NOT MATERIALIZED (
            SELECT job.org_id, job.job_id, job.state, job.generation, job.enqueued_at, job.available_at,
                   CASE WHEN %(stages)s::text[] IS NULL OR job.stage = ANY(%(stages)s::text[])
                        THEN job.stage ELSE 'other' END AS stage
            FROM thalion.job AS job
            WHERE job.org_id = %(org_id)s AND job.space_id = %(space_id)s
              AND (
                  %(source_id)s::bigint IS NULL
                  OR EXISTS (
                      SELECT 1
                      FROM thalion.object_identity AS target_identity
                      LEFT JOIN thalion.document AS target_document
                        ON target_identity.object_type = 'document'
                       AND (target_document.org_id, target_document.space_id, target_document.document_id)
                         = (target_identity.org_id, target_identity.space_id, target_identity.object_id)
                      LEFT JOIN thalion.passage AS target_passage
                        ON target_identity.object_type = 'passage'
                       AND (target_passage.org_id, target_passage.space_id, target_passage.passage_id)
                         = (target_identity.org_id, target_identity.space_id, target_identity.object_id)
                      LEFT JOIN thalion.document_version AS target_version
                        ON (target_version.org_id, target_version.space_id, target_version.version_id)
                         = (
                             target_identity.org_id, target_identity.space_id,
                             CASE
                                 WHEN target_identity.object_type = 'document_version' THEN target_identity.object_id
                                 WHEN target_identity.object_type = 'passage' THEN target_passage.version_id
                             END
                         )
                      WHERE (target_identity.org_id, target_identity.space_id, target_identity.public_id)
                          = (job.org_id, job.space_id, job.target_ref)
                        AND (
                            (target_identity.object_type = 'source' AND target_identity.object_id = %(source_id)s)
                            OR (target_identity.object_type = 'document' AND target_document.source_id = %(source_id)s)
                            OR (
                                target_identity.object_type IN ('document_version', 'passage')
                                AND target_version.source_id = %(source_id)s
                            )
                        )
                  )
              )
        ), pending AS MATERIALIZED (
            SELECT job.stage, job.available_at,
                   CASE WHEN job.enqueued_at <= snapshot.observed_at THEN job.enqueued_at END AS known_enqueue,
                   CASE WHEN %(estimate)s AND budget.job_id IS NOT NULL THEN EXISTS (
                       SELECT 1 FROM thalion.external_call AS call
                       WHERE (call.org_id, call.job_id) = (budget.org_id, budget.job_id)
                         AND call.state IN ('sent', 'outcome_unknown')
                   ) ELSE false END AS unresolved_external,
                   CASE
                       WHEN job.state = 'running' THEN CASE
                           WHEN attempt.lease_expires_at IS NULL THEN 'inconsistent'
                           WHEN attempt.lease_expires_at <= snapshot.observed_at THEN 'lease_expired'
                           ELSE 'leased'
                       END
                       WHEN job.state = 'queued' AND job.generation > 0 AND job.available_at > snapshot.observed_at
                           THEN 'retry_delayed'
                       ELSE COALESCE(
                           CASE WHEN budget.job_id IS NOT NULL THEN (
                               SELECT COALESCE(ledger.blocked_state, 'ready')
                               FROM thalion.external_job_ledger AS ledger
                               WHERE (ledger.org_id, ledger.job_id) = (budget.org_id, budget.job_id)
                           ) END,
                           CASE WHEN job.state = 'queued' THEN 'ready' ELSE 'inconsistent' END
                       )
                   END AS status
            FROM snapshot CROSS JOIN scoped AS job
            LEFT JOIN thalion.job_attempt AS attempt
              ON (attempt.org_id, attempt.job_id, attempt.generation) = (job.org_id, job.job_id, job.generation)
              AND attempt.outcome = 'running' AND job.state = 'running'
            LEFT JOIN thalion.external_call_budget AS budget
              ON (budget.org_id, budget.job_id) = (job.org_id, job.job_id)
            WHERE job.state <> 'succeeded'
        ), counts AS (
            SELECT stage, status, count(*) AS jobs,
                   count(*) - count(known_enqueue) AS unknown_enqueue_time,
                   min(known_enqueue) AS oldest_enqueue,
                   bool_or(unresolved_external) AS unresolved_external,
                   min(available_at) FILTER (WHERE status = 'retry_delayed') AS next_retry
            FROM pending GROUP BY stage, status
        ), backlog AS (
            SELECT stage, sum(jobs)::bigint AS unfinished, jsonb_object_agg(status, jobs) AS states,
                   sum(unknown_enqueue_time)::bigint AS unknown_enqueue_time, min(oldest_enqueue) AS oldest_enqueue,
                   bool_or(unresolved_external) AS unresolved_external,
                   min(next_retry) AS next_retry FROM counts GROUP BY stage
        ), activity AS (
            SELECT job.stage, true AS arrival, false AS recent_success, false AS unknown_start,
                   CASE WHEN %(estimate)s THEN date_bin('15 minutes', job.enqueued_at, bounds.start_at) END AS bucket
            FROM scoped AS job CROSS JOIN bounds
            WHERE job.enqueued_at >= bounds.start_at AND job.enqueued_at < bounds.end_at
            UNION ALL
            SELECT job.stage, false,
                   %(estimate)s AND attempt.finished_at >= bounds.end_at - interval '5 minutes',
                   %(estimate)s AND (job.enqueued_at IS NULL OR job.enqueued_at > attempt.finished_at),
                   CASE WHEN %(estimate)s THEN date_bin('15 minutes', attempt.finished_at, bounds.start_at) END
            FROM scoped AS job JOIN thalion.job_attempt AS attempt USING (org_id, job_id, generation)
            CROSS JOIN bounds
            WHERE job.state = 'succeeded' AND attempt.outcome = 'succeeded'
              AND attempt.finished_at >= bounds.start_at AND attempt.finished_at < bounds.end_at
        ), interval_activity AS (
            SELECT stage, count(*) FILTER (WHERE arrival) AS enqueued,
                   count(*) FILTER (WHERE NOT arrival) AS succeeded,
                   bucket, bool_or(recent_success) AS recent_success, bool_or(unknown_start) AS unknown_start
            FROM activity GROUP BY stage, bucket
        ), throughput AS (
            SELECT stage, sum(enqueued)::bigint AS enqueued, sum(succeeded)::bigint AS succeeded,
                   CASE WHEN count(bucket) = 4 AND min(succeeded) >= 5
                          AND bool_or(recent_success) AND NOT bool_or(unknown_start)
                        THEN min(succeeded - enqueued) END AS net_per_interval
            FROM interval_activity GROUP BY stage
        )
        SELECT snapshot.observed_at, stage, unfinished, states, next_retry, unknown_enqueue_time,
               floor(extract(epoch FROM (snapshot.observed_at - oldest_enqueue)) * 1000)::bigint,
               enqueued, succeeded, unresolved_external, net_per_interval
        FROM snapshot LEFT JOIN (backlog FULL JOIN throughput USING (stage)) ON true
        ORDER BY stage
    """, {"org_id": org_id, "space_id": space_id, "observed_at": observed_at, "start": start, "end": end,
          "stages": list(visible_stages) if visible_stages is not None else None,
          "estimate": include_estimate, "source_id": source_id}).fetchall()
    backlog, throughput = [], []
    for _, stage, unfinished, states, next_retry, unknown, oldest_age, enqueued, succeeded, unresolved, net in rows:
        if unfinished is not None:
            pending = {
                "stage": stage, "unfinished": unfinished, "states": states,
                "next_retry_at": next_retry.astimezone(UTC).isoformat() if next_retry is not None else None,
                "oldest_known_age_ms": oldest_age, "unknown_enqueue_time": unknown,
            }
            if include_estimate:
                pending["estimated_clear_minutes"] = (
                    _clear_minutes(unfinished, states, unknown, unresolved, net) if stage != "other" else None
                )
            backlog.append(pending)
        if enqueued is not None:
            throughput.append({"stage": stage, "enqueued": enqueued, "succeeded": succeeded})
    return {
        "observed_at": rows[0][0].astimezone(UTC).isoformat(),
        "job_backlog_by_stage": backlog,
        "job_throughput_by_stage": throughput,
    }
