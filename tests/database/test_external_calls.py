from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.runtime import external
from enterprise_kb.runtime.external import (
    CallBudget,
    CallBudgetExceeded,
    ExternalCallConflict,
    UsageReceipt,
    enqueue_external_job,
    external_call_usage,
    mark_call_sent,
    mark_call_unknown,
    record_call_receipt,
    reserve_external_call,
)
from enterprise_kb.runtime.jobs import (
    ExternalCallPending,
    LeaseLost,
    claim_job,
    complete_job,
    enqueue_job,
    retry_job,
)

from test_identity import migrate_to_revision
from test_runtime import INPUT, LEASE_FOR, open_database, register_tenant, runtime_db, spec_for


ROUTE = "synthetic-model"
PROVIDER = "synthetic-account"


def synthetic_artifact(payload=b"synthetic output"):
    return external.CallArtifact(uuid4(), sha256(payload).digest())


def setup_job(connection, tenant, *, budget=CallBudget("CNY", 400, 2)):
    enqueue_external_job(connection, spec_for(tenant), budget)
    return claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)


def reserve(connection, lease, *, maximum=200, digest=INPUT):
    return reserve_external_call(
        connection, lease, route=ROUTE, provider_namespace=PROVIDER,
        input_digest=digest, maximum_microunits=maximum,
    )


def dispatch(connection, lease, call_id, *, route=ROUTE, namespace=PROVIDER, digest=INPUT):
    return mark_call_sent(
        connection, lease, call_id,
        route=route, provider_namespace=namespace, input_digest=digest,
    )


def expire(connection, lease):
    updated = connection.execute(
        """
        UPDATE thalion.job_attempt
        SET started_at = clock_timestamp() - interval '2 seconds',
            lease_expires_at = clock_timestamp() - interval '1 second'
        WHERE attempt_id = %s
        """,
        (lease.attempt_id,),
    )
    assert updated.rowcount == 1


def test_dispatch_is_committed_before_sending_and_cannot_be_repeated(runtime_db):
    connection, tenant, database_url = runtime_db
    lease = setup_job(connection, tenant)
    call_id = reserve(connection, lease)
    assert reserve(connection, lease) == call_id
    with connection.transaction():
        with pytest.raises(RuntimeError, match="committed"):
            dispatch(connection, lease, call_id)
    assert dispatch(connection, lease, call_id)
    with open_database(database_url) as independent:
        assert independent.execute(
            "SELECT state FROM thalion.external_call WHERE call_id = %s", (call_id,)
        ).fetchone() == ("sent",)
    assert not dispatch(connection, lease, call_id)
    with pytest.raises(ExternalCallPending):
        complete_job(connection, lease, lambda tx: pytest.fail("no confirmed result"))
    with pytest.raises(ExternalCallPending):
        retry_job(connection, lease, delay=LEASE_FOR)


def test_dispatch_rechecks_lease_after_budget_check(runtime_db, monkeypatch):
    connection, tenant, database_url = runtime_db
    lease = setup_job(connection, tenant)
    call_id = reserve(connection, lease)
    check_budget = external._check_budget

    def check_then_expire(transaction, *args):
        check_budget(transaction, *args)
        with open_database(database_url) as independent:
            expire(independent, lease)

    monkeypatch.setattr(external, "_check_budget", check_then_expire)
    with pytest.raises(LeaseLost):
        dispatch(connection, lease, call_id)
    assert connection.execute(
        "SELECT state, dispatched_at FROM thalion.external_call WHERE call_id = %s",
        (call_id,),
    ).fetchone() == ("not_sent", None)


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_budget_writes_reject_stale_transaction_snapshots(runtime_db, isolation):
    connection, tenant, _ = runtime_db
    lease = setup_job(connection, tenant)
    with connection.transaction():
        connection.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
        with pytest.raises(RuntimeError, match="READ COMMITTED"):
            reserve(connection, lease)
    call_id = reserve(connection, lease)
    assert dispatch(connection, lease, call_id)
    with connection.transaction():
        connection.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
        with pytest.raises(RuntimeError, match="READ COMMITTED"):
            record_call_receipt(
                connection, tenant.org_id, call_id,
                UsageReceipt(uuid4(), "synthetic-isolation", True, 1, 2, 50),
            )
        with pytest.raises(RuntimeError, match="READ COMMITTED"):
            claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert external_call_usage(connection, tenant.org_id, lease.job_id).actual_microunits == 0


def test_budget_enrollment_rolls_back_with_job_and_does_not_expand_on_replay(runtime_db):
    connection, tenant, _ = runtime_db
    spec = spec_for(tenant)
    budget = CallBudget("CNY", 100, 1)
    with pytest.raises(ValueError, match="synthetic interruption"):
        with connection.transaction():
            enqueue_external_job(connection, spec, budget)
            raise ValueError("synthetic interruption")
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR) is None

    job_id = enqueue_external_job(connection, spec, budget)
    assert enqueue_external_job(connection, spec, budget) == job_id
    with pytest.raises(ExternalCallConflict):
        enqueue_external_job(connection, spec, replace(budget, maximum_calls=2))
    lease = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
    with pytest.raises(ExternalCallPending):
        complete_job(connection, lease, lambda tx: pytest.fail("external call missing"))


def test_reservation_is_bound_to_payload_and_route(runtime_db):
    connection, tenant, _ = runtime_db
    lease = setup_job(connection, tenant)
    call_id = reserve(connection, lease)
    with pytest.raises(ExternalCallConflict):
        reserve(connection, lease, digest=bytes(32))
    with pytest.raises(ExternalCallConflict):
        reserve_external_call(
            connection, lease, route="other-route", provider_namespace=PROVIDER,
            input_digest=INPUT, maximum_microunits=200,
        )
    with pytest.raises(ExternalCallConflict):
        dispatch(connection, lease, call_id, digest=bytes(32))
    with pytest.raises(ExternalCallConflict):
        dispatch(connection, lease, call_id, route="other-route")
    with pytest.raises(ExternalCallConflict):
        dispatch(connection, lease, call_id, namespace="other-account")
    assert dispatch(connection, lease, call_id)


def test_unknown_call_keeps_reservation_and_late_receipt_never_completes_job(runtime_db):
    connection, tenant, _ = runtime_db
    stale = setup_job(connection, tenant, budget=CallBudget("CNY", 250, 2, True))
    first = reserve(connection, stale, maximum=200)
    assert dispatch(connection, stale, first)
    expire(connection, stale)
    current = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert connection.execute(
        "SELECT state FROM thalion.external_call WHERE call_id = %s", (first,)
    ).fetchone() == ("outcome_unknown",)
    assert external_call_usage(connection, tenant.org_id, stale.job_id).reserved_microunits == 200
    with pytest.raises(CallBudgetExceeded):
        reserve(connection, current, maximum=100)

    receipt = UsageReceipt(uuid4(), "synthetic-provider-first", True, 20, 3, 80)
    assert record_call_receipt(connection, tenant.org_id, first, receipt)
    assert not record_call_receipt(connection, tenant.org_id, first, receipt)
    assert external_call_usage(connection, tenant.org_id, stale.job_id).actual_microunits == 80
    with pytest.raises(LeaseLost):
        complete_job(connection, stale, lambda tx: pytest.fail("late result accepted"))
    second = reserve(connection, current, maximum=100)
    assert second != first
    assert dispatch(connection, current, second)
    assert record_call_receipt(
        connection,
        tenant.org_id,
        second,
        UsageReceipt(uuid4(), "synthetic-provider-second", True, 10, 2, 40),
        artifact=synthetic_artifact(),
    )
    usage = external_call_usage(connection, tenant.org_id, stale.job_id)
    assert (usage.actual_microunits, usage.reserved_microunits, usage.dispatched_calls) == (
        120, 0, 2,
    )
    assert external.complete_external_job(
        connection, current, lambda tx, result: tenant.space_ref
    ) == tenant.space_ref


def test_unknown_call_parks_without_approved_retry_and_skips_to_other_work(runtime_db):
    connection, tenant, _ = runtime_db
    stale = setup_job(connection, tenant)
    first = reserve(connection, stale)
    assert dispatch(connection, stale, first)
    expire(connection, stale)
    other_spec = replace(stale.spec, configuration_revision=2)
    other_job = enqueue_external_job(connection, other_spec, CallBudget("CNY", 100, 1))
    current = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert current.job_id == other_job
    assert claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR) is None
    assert connection.execute(
        "SELECT state, generation FROM thalion.job WHERE job_id = %s", (stale.job_id,),
    ).fetchone() == ("awaiting_external", 1)
    assert connection.execute(
        "SELECT state FROM thalion.external_call WHERE call_id = %s", (first,),
    ).fetchone() == ("outcome_unknown",)
    assert record_call_receipt(
        connection, tenant.org_id, first,
        UsageReceipt(uuid4(), "synthetic-failed-unknown", False, 20, 0, 100),
    )
    resumed = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert (resumed.job_id, resumed.generation) == (stale.job_id, 2)
    assert reserve(connection, resumed)


def test_exhausted_call_count_does_not_burn_new_lease_generations(runtime_db):
    connection, tenant, _ = runtime_db
    stale = setup_job(connection, tenant, budget=CallBudget("CNY", 400, 1))
    first = reserve(connection, stale)
    assert dispatch(connection, stale, first)
    assert record_call_receipt(
        connection, tenant.org_id, first,
        UsageReceipt(uuid4(), "synthetic-failed-known", False, 20, 0, 100),
    )
    expire(connection, stale)
    for _ in range(3):
        assert claim_job(
            connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR
        ) is None
    assert connection.execute(
        "SELECT state, generation FROM thalion.job WHERE job_id = %s", (stale.job_id,),
    ).fetchone() == ("external_budget_blocked", 1)


def test_current_worker_revalidates_previous_durable_artifact_before_accepting(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    stale = setup_job(connection, tenant, budget=CallBudget("CNY", 300, 1))
    call_id = reserve(connection, stale)
    assert dispatch(connection, stale, call_id)
    payload = b"synthetic result bytes"
    artifact = synthetic_artifact(payload)
    path = tmp_path / str(artifact.ref)
    path.write_bytes(payload)
    receipt = UsageReceipt(uuid4(), "synthetic-recoverable", True, 20, 3, 100)
    assert record_call_receipt(connection, tenant.org_id, call_id, receipt)
    with pytest.raises(ExternalCallPending):
        complete_job(connection, stale, lambda tx: pytest.fail("usage is not an artifact"))
    expire(connection, stale)
    assert claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR) is None
    assert record_call_receipt(connection, tenant.org_id, call_id, receipt, artifact=artifact)
    assert not record_call_receipt(connection, tenant.org_id, call_id, receipt, artifact=artifact)
    with pytest.raises(ExternalCallConflict):
        record_call_receipt(connection, tenant.org_id, call_id, receipt, artifact=synthetic_artifact())
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute(
            "UPDATE thalion.external_call SET artifact_ref = %s WHERE call_id = %s",
            (uuid4(), call_id),
        )
    with open_database(database_url) as worker:
        current = claim_job(worker, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
        assert (current.job_id, current.generation) == (stale.job_id, 2)
        with pytest.raises(LeaseLost):
            external.complete_external_job(worker, stale, lambda tx, result: pytest.fail("old lease"))
        with pytest.raises(ExternalCallPending):
            reserve(worker, current)

        def reject_changed_inputs(transaction, candidate):
            assert (candidate.call_id, candidate.generation, candidate.artifact) == (
                call_id, stale.generation, artifact,
            )
            raise ValueError("current authorization denied")

        with pytest.raises(ValueError, match="authorization denied"):
            external.complete_external_job(worker, current, reject_changed_inputs)
        assert worker.execute(
            "SELECT state, result_call_id FROM thalion.job WHERE job_id = %s",
            (current.job_id,),
        ).fetchone() == ("running", None)

        def validate_result(transaction, candidate):
            assert candidate.input_digest == INPUT
            assert candidate.route == ROUTE
            assert candidate.artifact.digest == sha256(
                (tmp_path / str(candidate.artifact.ref)).read_bytes()
            ).digest()
            return tenant.space_ref

        assert external.complete_external_job(worker, current, validate_result) == tenant.space_ref
        with pytest.raises(LeaseLost):
            external.complete_external_job(worker, current, validate_result)
    assert external_call_usage(connection, tenant.org_id, stale.job_id).dispatched_calls == 1
    assert connection.execute(
        "SELECT state, result_call_id FROM thalion.job WHERE job_id = %s", (stale.job_id,),
    ).fetchone() == ("succeeded", call_id)


def test_late_artifact_cannot_replace_a_newer_dispatched_input(runtime_db):
    connection, tenant, _ = runtime_db
    stale = setup_job(connection, tenant, budget=CallBudget("CNY", 400, 2, True))
    first = reserve(connection, stale)
    assert dispatch(connection, stale, first)
    mark_call_unknown(connection, tenant.org_id, first)
    expire(connection, stale)
    current = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    second = reserve(connection, current, digest=bytes(32))
    assert dispatch(connection, current, second, digest=bytes(32))
    assert record_call_receipt(
        connection, tenant.org_id, first,
        UsageReceipt(uuid4(), "synthetic-late-artifact", True, 20, 2, 100),
        artifact=synthetic_artifact(),
    )
    with pytest.raises(ExternalCallPending):
        external.complete_external_job(
            connection, current, lambda tx, result: pytest.fail("superseded call accepted")
        )


def test_forward_migration_preserves_old_usage_without_inventing_a_result(database_url):
    migrate_to_revision(database_url, "0003_external_calls")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Synthetic upgraded tenant")
        job_id = enqueue_job(connection, spec_for(tenant))
        connection.execute(
            """
            UPDATE thalion.job SET state = 'running', generation = 1
            WHERE org_id = %s AND job_id = %s
            """,
            (tenant.org_id, job_id),
        )
        connection.execute(
            """
            INSERT INTO thalion.job_attempt (
                org_id, job_id, generation, worker_id, started_at, lease_expires_at
            ) VALUES (%s, %s, 1, %s, clock_timestamp() - interval '3 seconds',
                      clock_timestamp() - interval '2 seconds')
            """,
            (tenant.org_id, job_id, tenant.worker_id),
        )
        connection.execute(
            """
            INSERT INTO thalion.external_call_budget (
                org_id, job_id, currency, maximum_microunits, maximum_calls, allow_unknown_retry
            ) VALUES (%s, %s, 'CNY', 100, 1, false)
            """,
            (tenant.org_id, job_id),
        )
        call_id = connection.execute(
            """
            INSERT INTO thalion.external_call (
                org_id, job_id, generation, route, provider_namespace, input_digest,
                reserved_microunits, state, dispatched_at, provider_request_digest
            ) VALUES (%s, %s, 1, %s, %s, %s, 100, 'confirmed_success', clock_timestamp(), %s)
            RETURNING call_id
            """,
            (tenant.org_id, job_id, ROUTE, PROVIDER, INPUT, sha256(b"legacy-request").digest()),
        ).fetchone()[0]
        receipt_id = uuid4()
        connection.execute(
            """
            INSERT INTO thalion.external_call_receipt (
                org_id, call_id, receipt_id, input_tokens, output_tokens, actual_microunits
            ) VALUES (%s, %s, %s, 20, 5, 73)
            """,
            (tenant.org_id, call_id, receipt_id),
        )
        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        usage = external_call_usage(connection, tenant.org_id, job_id)
        assert (usage.actual_microunits, usage.dispatched_calls) == (73, 1)
        assert connection.execute(
            "SELECT artifact_ref, artifact_digest FROM thalion.external_call WHERE call_id = %s",
            (call_id,),
        ).fetchone() == (None, None)
        assert connection.execute(
            "SELECT receipt_id FROM thalion.external_call_latest_receipt WHERE call_id = %s",
            (call_id,),
        ).fetchone() == (receipt_id,)
        assert claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR) is None


def test_unsent_expired_reservation_releases_budget_without_provider_cost(runtime_db):
    connection, tenant, _ = runtime_db
    stale = setup_job(connection, tenant, budget=CallBudget("CNY", 100, 1))
    old_call = reserve(connection, stale, maximum=100)
    expire(connection, stale)
    current = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert external_call_usage(connection, tenant.org_id, stale.job_id).reserved_microunits == 0
    with pytest.raises(LeaseLost):
        dispatch(connection, stale, old_call)
    assert reserve(connection, current, maximum=100) != old_call


def test_accounting_captures_overrun_and_deduplicates_concurrent_receipts(runtime_db):
    connection, tenant, database_url = runtime_db
    lease = setup_job(connection, tenant, budget=CallBudget("CNY", 100, 2))
    call_id = reserve(connection, lease, maximum=100)
    assert dispatch(connection, lease, call_id)
    receipt = UsageReceipt(uuid4(), "synthetic-overrun", True, 200, 50, 125)
    barrier = Barrier(2, timeout=5)

    def reconcile():
        with open_database(database_url) as worker:
            barrier.wait()
            return record_call_receipt(worker, tenant.org_id, call_id, receipt)

    with ThreadPoolExecutor(max_workers=2) as executor:
        replies = [executor.submit(reconcile) for _ in range(2)]
        assert sorted(reply.result(timeout=8) for reply in replies) == [False, True]
    with pytest.raises(ExternalCallConflict):
        record_call_receipt(
            connection, tenant.org_id, call_id, replace(receipt, actual_microunits=5)
        )
    adjustment = replace(
        receipt, receipt_id=uuid4(), actual_microunits=135, previous_receipt_id=receipt.receipt_id
    )
    assert record_call_receipt(connection, tenant.org_id, call_id, adjustment)
    assert not record_call_receipt(connection, tenant.org_id, call_id, receipt)
    with pytest.raises(ExternalCallConflict):
        record_call_receipt(
            connection, tenant.org_id, call_id, replace(adjustment, receipt_id=uuid4())
        )
    usage = external_call_usage(connection, tenant.org_id, lease.job_id)
    assert (usage.actual_microunits, usage.reserved_microunits) == (135, 0)
    assert connection.execute(
        "SELECT count(*) FROM thalion.external_call_receipt WHERE call_id = %s", (call_id,)
    ).fetchone() == (2,)


def test_late_usage_can_stop_a_reserved_but_unsent_retry(runtime_db):
    connection, tenant, _ = runtime_db
    stale = setup_job(connection, tenant, budget=CallBudget("CNY", 400, 2, True))
    first = reserve(connection, stale)
    assert dispatch(connection, stale, first)
    expire(connection, stale)
    current = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    second = reserve(connection, current)
    assert record_call_receipt(
        connection, tenant.org_id, first,
        UsageReceipt(uuid4(), "settled-over-budget", True, 200, 10, 350),
    )
    with pytest.raises(CallBudgetExceeded):
        dispatch(connection, current, second)
    assert external_call_usage(connection, tenant.org_id, current.job_id).dispatched_calls == 1


def test_same_provider_identity_cannot_be_billed_through_two_attempts(runtime_db):
    connection, tenant, _ = runtime_db
    stale = setup_job(connection, tenant, budget=CallBudget("CNY", 400, 2, True))
    first = reserve(connection, stale)
    assert dispatch(connection, stale, first)
    expire(connection, stale)
    current = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    second = reserve(connection, current)
    assert dispatch(connection, current, second)
    receipt = UsageReceipt(uuid4(), "same-provider-request", True, 20, 10, 100)
    assert record_call_receipt(connection, tenant.org_id, first, receipt)
    with pytest.raises(ExternalCallConflict):
        record_call_receipt(
            connection, tenant.org_id, second, replace(receipt, receipt_id=uuid4())
        )
    usage = external_call_usage(connection, tenant.org_id, current.job_id)
    assert (usage.actual_microunits, usage.reserved_microunits) == (100, 200)
