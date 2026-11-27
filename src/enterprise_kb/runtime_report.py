import argparse
from datetime import UTC, datetime, timedelta
import json
import os
import sys
from uuid import UUID

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from sqlalchemy.exc import ArgumentError

from .database import local_connection_factory
from .modules.evidence.processing import count_review_backlogs
from .modules.wiki.management import count_review_backlog
from .runtime.job_backlog import read_job_backlog


def _requests(connection, scope, start, end, observed_at):
    rows = connection.execute("""
        SELECT ingress, operation, destination, COALESCE(outcome, 'unfinished'), count(*),
               percentile_disc(ARRAY[0.50, 0.95, 0.99]) WITHIN GROUP (ORDER BY elapsed_ms)
                   FILTER (WHERE outcome = 'succeeded'),
               floor(extract(epoch FROM (%s - (min(started_at) FILTER (WHERE outcome IS NULL)))) * 1000)::bigint
        FROM thalion.request_record
        WHERE org_id = %s AND scope_space_id = %s AND started_at >= %s AND started_at < %s
        GROUP BY ingress, operation, destination, outcome
        ORDER BY ingress, operation, destination, outcome
    """, (observed_at, *scope, start, end)).fetchall()
    groups = {}
    for ingress, operation, destination, outcome, count, percentiles, oldest_age in rows:
        group = groups.setdefault((ingress, operation, destination), {
            "ingress": ingress, "operation": operation, "destination": destination, "registered": 0, "outcomes": {},
            "success_ledger_elapsed_ms": None, "oldest_unfinished_age_ms": None,
        })
        group["registered"] += count
        group["outcomes"][outcome] = count
        if percentiles is not None:
            group["success_ledger_elapsed_ms"] = dict(zip(("p50", "p95", "p99"), percentiles, strict=True))
        if outcome == "unfinished":
            group["oldest_unfinished_age_ms"] = oldest_age
    return list(groups.values())


def _external_calls(connection, scope, start, end):
    with connection.cursor(row_factory=dict_row) as cursor:
        rows = cursor.execute("""
            SELECT budget.currency, count(*) AS registered,
                   count(call.dispatched_at) AS dispatched, count(receipt.receipt_id) AS settled,
                   count(call.dispatched_at) FILTER (WHERE receipt.receipt_id IS NULL) AS unsettled,
                   count(*) FILTER (WHERE call.state = 'not_sent' AND call.abandoned_at IS NULL) AS open_unsent,
                   COALESCE(sum(call.reserved_microunits) FILTER (
                       WHERE call.state IN ('not_sent', 'sent', 'outcome_unknown') AND call.abandoned_at IS NULL
                   ), 0) AS reserved_microunits,
                   sum(receipt.actual_microunits) AS receipted_microunits,
                   sum(receipt.input_tokens) AS receipted_input_tokens,
                   sum(receipt.output_tokens) AS receipted_output_tokens
            FROM thalion.job AS job
            JOIN thalion.external_call_budget AS budget USING (org_id, job_id)
            JOIN thalion.external_call AS call USING (org_id, job_id)
            LEFT JOIN thalion.external_call_latest_receipt AS receipt USING (org_id, call_id)
            WHERE job.org_id = %s AND job.space_id = %s AND call.reserved_at >= %s AND call.reserved_at < %s
            GROUP BY budget.currency
            ORDER BY budget.currency
        """, (*scope, start, end)).fetchall()
    for row in rows:
        for field in ("reserved_microunits", "receipted_microunits", "receipted_input_tokens", "receipted_output_tokens"):
            if row[field] is not None:
                row[field] = int(row[field])
    return rows


def observe(connection, space_ref: UUID, start: datetime, end: datetime) -> dict:
    if start.utcoffset() is None or end.utcoffset() is None:
        raise ValueError("The observation window requires two timezone-aware timestamps.")
    start, end = start.astimezone(UTC), end.astimezone(UTC)
    if not timedelta(0) < end - start <= timedelta(days=1):
        raise ValueError("The observation window must be positive and no longer than 24 hours.")
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Observation requires an independent read-only transaction.")
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        target = connection.execute("""
            SELECT space.org_id, space.space_id, statement_timestamp()
            FROM thalion.object_identity AS identity
            JOIN thalion.space AS space USING (org_id, space_id)
            WHERE identity.object_type = 'space' AND identity.object_id = space.space_id AND identity.public_id = %s
        """, (space_ref,)).fetchone()
        if target is None:
            raise ValueError("The observation scope is not registered.")
        org_id, space_id, observed_at = target
        if end > observed_at:
            raise ValueError("The observation window cannot end after the snapshot.")
        scope = (org_id, space_id)
        requests = _requests(connection, scope, start, end, observed_at)
        external_calls = _external_calls(connection, scope, start, end)
        jobs = read_job_backlog(connection, *scope, observed_at, window=(start, end))
        quality_pending, ocr_pages_pending = count_review_backlogs(connection, *scope)
        wiki_backlog = count_review_backlog(connection, *scope)
    return {
        "scope": "synthetic_space", "space_id": str(space_ref),
        "start": start.isoformat(), "end": end.isoformat(),
        "registered_requests": sum(group["registered"] for group in requests),
        "unfinished_requests": sum(group["outcomes"].get("unfinished", 0) for group in requests),
        "requests_by_ingress_operation_destination": requests,
        "external_calls_by_currency": external_calls,
        **jobs,
        "quality_review_backlog": {"pending_review": quality_pending},
        "ocr_correction_backlog": {"pending_pages": ocr_pages_pending},
        "wiki_review_backlog": wiki_backlog,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="查看本机合成空间的请求、外部调用、任务和审核积压")
    parser.add_argument("--space-id", type=UUID, required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    arguments = parser.parse_args()
    try:
        start, end = datetime.fromisoformat(arguments.start), datetime.fromisoformat(arguments.end)
        connect = local_connection_factory(os.environ.get("THALION_DATABASE_URL", ""))
        with connect() as connection:
            detail = observe(connection, arguments.space_id, start, end)
    except (ValueError, OverflowError, ArgumentError, psycopg.Error):
        print("FAIL 无法读取运行账本。请核对本机数据库、只读权限、空间和统计窗口。", file=sys.stderr)
        return 1
    print(json.dumps(detail, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
