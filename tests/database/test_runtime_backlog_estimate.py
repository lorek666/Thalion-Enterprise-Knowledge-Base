from dataclasses import replace
from datetime import timedelta

import pytest

from enterprise_kb.runtime.external import CallBudget, enqueue_external_job
from enterprise_kb.runtime.job_backlog import read_job_backlog
from enterprise_kb.runtime.jobs import claim_job, complete_job, enqueue_job, retry_job

from test_external_calls import dispatch, expire, reserve
from test_identity import space
from test_runtime import LEASE_FOR, runtime_db, spec_for
from test_runtime_backlog_volume import seed_jobs


STAGES = ("parse", "synthetic_model_excerpts")
STABLE = ((2, 8),) * 4


def seed_estimate_history(connection, tenant, observed, *, samples=STABLE, stage="parse",
                          fresh=True, known_completions=True):
    for index, (arrivals, completions) in enumerate(samples):
        start = observed - timedelta(minutes=60 - index * 15)
        seed_jobs(connection, tenant, arrivals, 20_000 + index * 100, start + timedelta(minutes=3), stage=stage)
        completed = start + timedelta(minutes=13 if fresh else 1)
        enqueued = start - timedelta(hours=2) if known_completions else None
        seed_jobs(connection, tenant, completions, 30_000 + index * 100, enqueued,
                  completed_at=completed, stage=stage)


def stage_snapshot(connection, tenant, observed, stage="parse"):
    snapshot = read_job_backlog(connection, tenant.org_id, tenant.space_id, observed,
                                visible_stages=STAGES, include_estimate=True)
    return next((row for row in snapshot["job_backlog_by_stage"] if row["stage"] == stage), None)


def test_conditional_estimate_matches_stable_held_out_drain(runtime_db):
    connection, tenant, _ = runtime_db
    observed, = connection.execute("SELECT statement_timestamp()").fetchone()
    seed_estimate_history(connection, tenant, observed)
    seed_jobs(connection, tenant, 4, 0, observed - timedelta(hours=2))
    prediction = stage_snapshot(connection, tenant, observed)
    assert prediction["unfinished"] == 12
    assert prediction["estimated_clear_minutes"] == 30

    for tick in (1, 2):
        for revision in (40_000 + tick * 100, 40_001 + tick * 100):
            enqueue_job(connection, replace(spec_for(tenant), configuration_revision=revision))
        for _ in range(8):
            lease = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
            assert lease is not None
            complete_job(connection, lease, lambda tx: tenant.space_ref)
        actual, = connection.execute("""
            SELECT count(*) FROM thalion.job WHERE org_id = %s AND space_id = %s AND state <> 'succeeded'
        """, (tenant.org_id, tenant.space_id)).fetchone()
        assert actual == 12 - tick * 6
    assert tick * 15 == prediction["estimated_clear_minutes"]


def test_estimate_uses_slowest_positive_interval_and_rounds_up(runtime_db):
    connection, tenant, _ = runtime_db
    observed, = connection.execute("SELECT statement_timestamp()").fetchone()
    seed_estimate_history(connection, tenant, observed, samples=((2, 10), (2, 8), (2, 11), (2, 12)))
    seed_jobs(connection, tenant, 5, 0, observed - timedelta(hours=2))
    row = stage_snapshot(connection, tenant, observed)
    assert row["unfinished"] == 13
    assert row["estimated_clear_minutes"] == 33


@pytest.mark.parametrize("case", ["sparse", "growing", "stale", "old_completions", "old_pending", "other",
                                  "long_horizon", "delayed", "other_space", "external", "retryable_external"])
def test_estimate_withheld_when_rates_or_current_readiness_do_not_support_it(runtime_db, case):
    connection, tenant, _ = runtime_db
    observed, = connection.execute("SELECT statement_timestamp()").fetchone()
    if case == "other_space":
        with connection.transaction():
            space_id, space_ref = space(connection, tenant.org_id, tenant.actor_id, "Other forecast space")
        history = replace(tenant, space_id=space_id, space_ref=space_ref)
    else:
        history = tenant
    stage = (
        "synthetic_model_excerpts" if case in {"external", "retryable_external"}
        else "private-stage" if case == "other"
        else "parse"
    )
    samples = {"sparse": ((2, 4), *STABLE[1:]), "growing": (*STABLE[:3], (8, 7))}.get(case, STABLE)
    seed_estimate_history(connection, history, observed, samples=samples, stage=stage, fresh=case != "stale",
                          known_completions=case != "old_completions")
    seed_jobs(connection, tenant, 30 if case == "long_horizon" else 1, 0,
              None if case == "old_pending" else observed - timedelta(hours=2), stage=stage)
    if case == "delayed":
        lease = claim_job(connection, tenant.org_id, stage, tenant.worker_id, LEASE_FOR)
        retry_job(connection, lease, delay=timedelta(hours=1))
    if case in {"external", "retryable_external"}:
        job_id = enqueue_external_job(connection, replace(spec_for(tenant, stage), configuration_revision=100),
                                      CallBudget("CNY", 500, 2, allow_unknown_retry=case == "retryable_external"))
        lease = claim_job(connection, tenant.org_id, stage, tenant.worker_id, LEASE_FOR, job_id=job_id)
        assert dispatch(connection, lease, reserve(connection, lease))
        expire(connection, lease)
        retry = claim_job(connection, tenant.org_id, stage, tenant.worker_id, LEASE_FOR, job_id=job_id)
        assert (retry is not None) == (case == "retryable_external")
    now, = connection.execute("SELECT statement_timestamp()").fetchone()
    row = stage_snapshot(connection, tenant, now, "other" if case == "other" else stage)
    assert row["estimated_clear_minutes"] is None
    if case == "retryable_external":
        assert row["states"]["leased"] == 1
