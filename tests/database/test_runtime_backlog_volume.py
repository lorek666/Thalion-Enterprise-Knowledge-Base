from dataclasses import replace
from datetime import timedelta
import json
from math import ceil
from time import perf_counter

import pytest

from enterprise_kb.runtime.job_backlog import read_job_backlog

from test_identity import space
from test_runtime import INPUT, runtime_db


HISTORY = 60_000


def seed_jobs(connection, tenant, count, offset, enqueued_at, *, completed_at=None, stage="parse"):
    with connection.transaction():
        connection.execute("""
            WITH job_seed AS (
                INSERT INTO thalion.job (
                    org_id, space_id, target_ref, stage, input_digest, configuration_revision,
                    enqueued_at, available_at, state, generation, result_ref
                )
                SELECT %(org)s, %(space)s, %(ref)s, %(stage)s, %(digest)s, revision,
                       %(enqueued)s, coalesce(%(enqueued)s::timestamptz, statement_timestamp()),
                       CASE WHEN %(finished)s::timestamptz IS NULL THEN 'queued' ELSE 'succeeded' END,
                       CASE WHEN %(finished)s::timestamptz IS NULL THEN 0 ELSE 1 END,
                       CASE WHEN %(finished)s::timestamptz IS NOT NULL THEN %(ref)s END
                FROM generate_series(%(first)s::integer, %(last)s::integer) AS revision
                RETURNING org_id, job_id, generation
            )
            INSERT INTO thalion.job_attempt (
                org_id, job_id, generation, worker_id, started_at, lease_expires_at, finished_at, outcome
            )
            SELECT org_id, job_id, generation, %(worker)s, %(finished)s::timestamptz - interval '1 second',
                   %(finished)s::timestamptz + interval '1 minute', %(finished)s, 'succeeded'
            FROM job_seed WHERE generation = 1
        """, {"org": tenant.org_id, "space": tenant.space_id, "ref": tenant.space_ref, "digest": INPUT, "stage": stage,
              "first": offset + 1, "last": offset + count, "worker": tenant.worker_id, "enqueued": enqueued_at,
              "finished": completed_at})


def sample(connection, tenant, monkeypatch):
    def read():
        result = read_job_backlog(connection, tenant.org_id, tenant.space_id,
                                  visible_stages=("parse",), include_estimate=True)
        pending, = result["job_backlog_by_stage"]
        assert pending["oldest_known_age_ms"] >= 604_800_000
        return pending, result["job_throughput_by_stage"]

    for _ in range(3):
        read()
    elapsed = []
    for _ in range(20):
        start = perf_counter()
        read()
        elapsed.append((perf_counter() - start) * 1000)

    execute = connection.execute
    plans = []

    def explain(statement, params=None):
        plan, = execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON, TIMING OFF) " + statement, params).fetchone()
        plans.append(plan[0])
        return execute(statement, params)

    with monkeypatch.context() as patch:
        patch.setattr(connection, "execute", explain)
        result = read()

    plan, = plans
    root = plan["Plan"]
    metrics = {
        "shared_blocks": root["Shared Hit Blocks"] + root["Shared Read Blocks"],
        "execution_ms": plan["Execution Time"],
        "roundtrip_p95_ms": round(sorted(elapsed)[ceil(len(elapsed) * 0.95) - 1], 3),
    }
    return result, metrics


def test_runtime_backlog_limits_history_work_in_quiet_space(runtime_db, monkeypatch):
    connection, quiet, _ = runtime_db
    with connection.transaction():
        space_id, space_ref = space(connection, quiet.org_id, quiet.actor_id, "Synthetic bulk")
    bulk = replace(quiet, space_id=space_id, space_ref=space_ref)
    observed, = connection.execute("SELECT statement_timestamp()").fetchone()
    old = observed - timedelta(days=7)
    recent = observed - timedelta(minutes=15)
    for tenant, old_pending, new_pending in ((quiet, 6, 2), (bulk, 9_850, 150)):
        seed_jobs(connection, tenant, HISTORY, 0, old, completed_at=old + timedelta(seconds=2))
        seed_jobs(connection, tenant, 120, HISTORY, recent, completed_at=recent + timedelta(seconds=2))
        seed_jobs(connection, tenant, old_pending, HISTORY + 120, old)
        seed_jobs(connection, tenant, new_pending, HISTORY + 120 + old_pending, recent)
    connection.execute("VACUUM (ANALYZE) thalion.job, thalion.job_attempt")

    measurements = {}
    for label, tenant, pending, new_pending in (("quiet", quiet, 8, 2), ("bulk", bulk, 10_000, 150)):
        (backlog, throughput), measurements[label] = sample(connection, tenant, monkeypatch)
        assert backlog == {
            "stage": "parse", "unfinished": pending, "states": {"ready": pending}, "next_retry_at": None,
            "oldest_known_age_ms": pytest.approx(604_800_000, abs=3_600_000), "unknown_enqueue_time": 0,
            "estimated_clear_minutes": None,
        }
        assert throughput == [{"stage": "parse", "enqueued": 120 + new_pending, "succeeded": 120}]
    print(json.dumps(measurements, sort_keys=True))
    assert measurements["quiet"]["shared_blocks"] < 2_000
    assert measurements["bulk"]["shared_blocks"] < 25_000
