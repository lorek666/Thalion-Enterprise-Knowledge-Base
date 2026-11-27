from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
import subprocess
import sys
from threading import Barrier
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest

from enterprise_kb.runtime import external
from enterprise_kb.runtime.events import pending_events
from enterprise_kb.runtime.jobs import claim_job, complete_job

from test_external_calls import dispatch, expire, reserve
from test_identity import space
from test_runtime import LEASE_FOR, open_database, register_tenant, runtime_db, spec_for
from test_runtime_report import seed_job


def run_alerts(database_url, space_ref, *, synthetic=True):
    arguments = ["--synthetic"] if synthetic else []
    return subprocess.run([
        sys.executable, "-I", "-m", "enterprise_kb.runtime_alerts", "--space-id", str(space_ref), *arguments,
    ], env=os.environ | {"THALION_DATABASE_URL": database_url}, capture_output=True, text=True, check=False)


def alert_events(connection, tenant):
    return [
        event for event in pending_events(connection, tenant.org_id, "synthetic-runtime-alert-test")
        if event.object_ref == tenant.space_ref and event.event_type.startswith("runtime.backlog.")
    ]


def older_job(connection, tenant, stage="parse", *, age="61 minutes"):
    enqueued_at, = connection.execute(
        "SELECT clock_timestamp() - %s::interval", (age,),
    ).fetchone()
    return seed_job(connection, spec_for(tenant, stage), enqueued_at)


def finish(connection, tenant, job_id, stage="parse"):
    lease = claim_job(connection, tenant.org_id, stage, tenant.worker_id, LEASE_FOR, job_id=job_id)
    assert complete_job(connection, lease, lambda transaction: tenant.space_ref) == tenant.space_ref


def test_cli_records_stall_transitions_without_refreshing_management(runtime_db):
    connection, tenant, url = runtime_db
    old_job = older_job(connection, tenant)
    assert run_alerts(url, tenant.space_ref, synthetic=False).returncode != 0
    assert not alert_events(connection, tenant)

    def poll(expected):
        result = run_alerts(url, tenant.space_ref)
        assert result.returncode == 0 and not result.stderr, result.stderr
        detail = json.loads(result.stdout)
        assert detail["scope"] == "synthetic_space" and detail["space_id"] == str(tenant.space_ref)
        assert detail["transitions"] == expected
        assert str(old_job) not in result.stdout

    poll({"raised": ["stalled"], "cleared": []})
    poll({"raised": [], "cleared": []})
    finish(connection, tenant, old_job)
    poll({"raised": [], "cleared": ["stalled"]})
    older_job(connection, tenant, "rebuild")
    poll({"raised": ["stalled"], "cleared": []})
    events = alert_events(connection, tenant)
    assert [(event.event_type, event.space_id) for event in events] == [
        ("runtime.backlog.stalled.raised", tenant.space_id),
        ("runtime.backlog.stalled.cleared", tenant.space_id),
        ("runtime.backlog.stalled.raised", tenant.space_id),
    ]
    assert len({event.event_id for event in events}) == 3


def test_concurrent_polls_register_one_transition_and_do_not_touch_other_spaces(runtime_db):
    from enterprise_kb.runtime_alerts import poll

    connection, tenant, url = runtime_db
    other = register_tenant(connection, "Other organization")
    with connection.transaction():
        sibling_id, sibling_ref = space(connection, tenant.org_id, tenant.actor_id)
    sibling = replace(tenant, space_id=sibling_id, space_ref=sibling_ref)
    older_job(connection, other)
    older_job(connection, sibling)
    older_job(connection, tenant, age="59 minutes")
    assert poll(connection, tenant.space_ref)["transitions"] == {"raised": [], "cleared": []}
    older_job(connection, tenant, "rebuild")
    barrier = Barrier(2, timeout=5)

    def inspect_once():
        with open_database(url) as tx:
            barrier.wait()
            return poll(tx, tenant.space_ref)["transitions"]["raised"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(inspect_once) for _ in range(2)]
        assert sorted(future.result(timeout=10) for future in futures) == [[], ["stalled"]]
    assert not alert_events(connection, other) and not alert_events(connection, sibling)
    assert len(alert_events(connection, tenant)) == 1
    assert poll(connection, sibling.space_ref)["transitions"] == {"raised": ["stalled"], "cleared": []}
    assert poll(connection, tenant.space_ref)["transitions"] == {"raised": [], "cleared": []}
    assert len(alert_events(connection, sibling)) == 1 and len(alert_events(connection, tenant)) == 1


def test_cli_refuses_unknown_nonlocal_and_restore_rehearsal_scopes(runtime_db):
    connection, tenant, url = runtime_db
    older_job(connection, tenant)
    unknown = uuid4()
    result = run_alerts(url, unknown)
    assert result.returncode == 1 and not result.stdout and str(unknown) not in result.stderr
    nonlocal_url = "postgresql://test:synthetic-dummy-secret@192.0.2.1/test"
    result = run_alerts(nonlocal_url, tenant.space_ref)
    assert result.returncode == 1 and not result.stdout and "synthetic-dummy-secret" not in result.stderr

    connection.execute(sql.SQL("ALTER DATABASE {} SET thalion.restore_rehearsal = 'isolated'").format(
        sql.Identifier(connection.info.dbname),
    ))
    result = run_alerts(url, tenant.space_ref)
    assert result.returncode == 1 and not result.stdout
    assert not alert_events(connection, tenant)


def test_alert_distinguishes_expired_leases_from_missing_attempts(runtime_db):
    from enterprise_kb.runtime_alerts import poll

    connection, tenant, _ = runtime_db
    expired_id = older_job(connection, tenant, age="5 minutes")
    inconsistent_id = older_job(connection, tenant, "rebuild", age="5 minutes")
    expired = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR, job_id=expired_id)
    missing = claim_job(connection, tenant.org_id, "rebuild", tenant.worker_id, LEASE_FOR, job_id=inconsistent_id)
    assert poll(connection, tenant.space_ref)["active"] == []
    expire(connection, expired)
    connection.execute("DELETE FROM thalion.job_attempt WHERE attempt_id = %s", (missing.attempt_id,))
    assert poll(connection, tenant.space_ref)["transitions"] == {
        "raised": ["inconsistent", "lease_expired"], "cleared": [],
    }
    finish(connection, tenant, expired_id)
    assert poll(connection, tenant.space_ref)["transitions"] == {"raised": [], "cleared": ["lease_expired"]}


@pytest.mark.parametrize("maximum_calls", [1, 2])
def test_receipt_settlement_rechecks_current_budget(runtime_db, maximum_calls):
    from enterprise_kb.runtime_alerts import poll

    connection, tenant, _ = runtime_db
    spec = spec_for(tenant, "synthetic_model_excerpts")
    external.enqueue_external_job(connection, spec, external.CallBudget("CNY", 500, maximum_calls))
    lease = claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR)
    unresolved = reserve(connection, lease)
    assert dispatch(connection, lease, unresolved)
    assert poll(connection, tenant.space_ref)["transitions"] == {"raised": [], "cleared": []}
    expire(connection, lease)
    assert claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR) is None
    assert poll(connection, tenant.space_ref)["transitions"] == {"raised": ["awaiting_external"], "cleared": []}

    assert external.record_call_receipt(connection, tenant.org_id, unresolved, external.UsageReceipt(
        uuid4(), "synthetic-reconciled", False, 0, 0, 50,
    ))
    blocked = ["external_budget_blocked"] if maximum_calls == 1 else []
    assert poll(connection, tenant.space_ref)["transitions"] == {"raised": blocked, "cleared": ["awaiting_external"]}
    assert poll(connection, tenant.space_ref)["active"] == blocked
    assert len(alert_events(connection, tenant)) == 2 + len(blocked)


def test_failed_snapshot_then_failed_outbox_write_cannot_clear_alert(runtime_db, monkeypatch):
    from enterprise_kb import runtime_alerts

    connection, tenant, _ = runtime_db
    old_job = older_job(connection, tenant)
    assert runtime_alerts.poll(connection, tenant.space_ref)["active"] == ["stalled"]
    finish(connection, tenant, old_job)
    before = alert_events(connection, tenant)

    def fail_read(tx, *args):
        tx.execute("SELECT 1 / 0")

    with monkeypatch.context() as patches:
        patches.setattr(runtime_alerts, "read_job_backlog", fail_read)
        with pytest.raises(psycopg.errors.DivisionByZero):
            runtime_alerts.poll(connection, tenant.space_ref)
    assert alert_events(connection, tenant) == before

    append = runtime_alerts.append_event

    def fail_after_append(tx, *args, **kwargs):
        append(tx, *args, **kwargs)
        tx.execute("SELECT 1 / 0")

    with monkeypatch.context() as patches:
        patches.setattr(runtime_alerts, "append_event", fail_after_append)
        with pytest.raises(psycopg.errors.DivisionByZero):
            runtime_alerts.poll(connection, tenant.space_ref)
    assert alert_events(connection, tenant) == before
    assert runtime_alerts.poll(connection, tenant.space_ref)["transitions"] == {"raised": [], "cleared": ["stalled"]}
