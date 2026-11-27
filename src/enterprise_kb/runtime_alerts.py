import argparse
import json
import os
import sys
from uuid import UUID

import psycopg
from psycopg.pq import TransactionStatus
from sqlalchemy.exc import ArgumentError

from .database import local_connection_factory
from .runtime.events import append_event
from .runtime.job_backlog import read_job_backlog


BLOCKERS = frozenset({"awaiting_external", "external_budget_blocked", "inconsistent", "lease_expired"})
STALL_AGE_MS = 3_600_000


def _active_reasons(snapshot: dict) -> set[str]:
    succeeded = {row["stage"]: row["succeeded"] for row in snapshot["job_throughput_by_stage"]}
    reasons = set()
    for row in snapshot["job_backlog_by_stage"]:
        reasons.update(BLOCKERS.intersection(row["states"]))
        age = row["oldest_known_age_ms"]
        if age is not None and age >= STALL_AGE_MS and not succeeded.get(row["stage"], 0):
            reasons.add("stalled")
    return reasons


def poll(connection: psycopg.Connection, space_ref: UUID) -> dict:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Polling requires an independent write transaction.")
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        scope = connection.execute("""
            SELECT org_id, space_id FROM thalion.object_identity
            WHERE object_type = 'space' AND public_id = %s
        """, (space_ref,)).fetchone()
        if scope is None:
            raise ValueError("The alert scope is not registered.")
        org_id, space_id = scope
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"thalion.runtime.backlog:{space_ref}",),
        )
        snapshot = read_job_backlog(connection, org_id, space_id)
        active = _active_reasons(snapshot)
        previous = {row[0] for row in connection.execute("""
            SELECT reason FROM thalion.runtime_backlog_alert WHERE (org_id, space_id) = (%s, %s)
        """, scope)}
        raised, cleared = sorted(active - previous), sorted(previous - active)
        for reason in raised:
            connection.execute("""
                INSERT INTO thalion.runtime_backlog_alert (org_id, space_id, reason) VALUES (%s, %s, %s)
            """, (*scope, reason))
            append_event(connection, org_id, f"runtime.backlog.{reason}.raised", space_ref, space_id=space_id)
        if cleared:
            connection.execute("""
                DELETE FROM thalion.runtime_backlog_alert
                WHERE (org_id, space_id) = (%s, %s) AND reason = ANY(%s)
            """, (*scope, cleared))
            for reason in cleared:
                append_event(connection, org_id, f"runtime.backlog.{reason}.cleared", space_ref, space_id=space_id)
    return {
        "scope": "synthetic_space", "space_id": str(space_ref), "observed_at": snapshot["observed_at"],
        "active": sorted(active), "transitions": {"raised": raised, "cleared": cleared},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="巡检本机合成空间，将告警变化写入本地发件箱")
    parser.add_argument("--space-id", type=UUID, required=True)
    parser.add_argument("--synthetic", action="store_true", required=True)
    arguments = parser.parse_args()
    try:
        connect = local_connection_factory(os.environ.get("THALION_DATABASE_URL", ""))
        with connect() as connection:
            detail = poll(connection, arguments.space_id)
    except (ValueError, ArgumentError, psycopg.Error):
        print("FAIL 巡检未确认告警变化。请核对本机数据库、写入权限和空间。", file=sys.stderr)
        return 1
    print(json.dumps(detail, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
