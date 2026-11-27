from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import date, timedelta
from hashlib import sha256
from threading import Barrier
from uuid import UUID, uuid4

import psycopg
import pytest

from enterprise_kb.database import upgrade
from enterprise_kb.runtime.audit import RequestStart, start_request
from enterprise_kb.runtime.commands import CommandEnvelope, IdempotencyConflict, execute_command
from enterprise_kb.runtime.events import append_event, consume_event, pending_events
from enterprise_kb.runtime.jobs import (
    JobSpec,
    LeaseLost,
    claim_job,
    complete_job,
    enqueue_job,
    retry_job,
)


INPUT = sha256(b"synthetic travel inputs").digest()
LEASE_FOR = timedelta(minutes=1)


@dataclass(frozen=True)
class Tenant:
    org_id: int
    space_id: int
    space_ref: UUID
    actor_id: int
    other_actor_id: int
    worker_id: int
    other_worker_id: int


def open_database(database_url):
    return psycopg.connect(database_url, autocommit=True, options="-c statement_timeout=5000")


def register_tenant(connection, label):
    with connection.transaction():
        org_id = connection.execute(
            "INSERT INTO thalion.organization (name, business_timezone) "
            "VALUES (%s, 'Asia/Shanghai') RETURNING org_id",
            (label,),
        ).fetchone()[0]
        actors = []
        for role in ("employee", "employee", "service", "service"):
            actor_id = connection.execute(
                "INSERT INTO thalion.principal "
                "(org_id, principal_type, authority_issuer, authority_subject_key) "
                "VALUES (%s, %s, 'https://synthetic.invalid', %s) RETURNING principal_id",
                (org_id, role, str(uuid4())),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO thalion.object_identity (org_id, object_type, object_id) "
                "VALUES (%s, 'principal', %s)",
                (org_id, actor_id),
            )
            actors.append(actor_id)
        space_id = connection.execute(
            "INSERT INTO thalion.space (org_id, name, classification, owner_principal_id) "
            "VALUES (%s, 'Travel', 'internal', %s) RETURNING space_id",
            (org_id, actors[0]),
        ).fetchone()[0]
        space_ref = connection.execute(
            "INSERT INTO thalion.object_identity (org_id, object_type, object_id, space_id) "
            "VALUES (%s, 'space', %s, %s) RETURNING public_id",
            (org_id, space_id, space_id),
        ).fetchone()[0]
    return Tenant(org_id, space_id, space_ref, *actors)


@pytest.fixture
def runtime_db(database_url):
    upgrade(database_url)
    with open_database(database_url) as connection:
        yield connection, register_tenant(connection, "First"), database_url


def command_for(tenant):
    return CommandEnvelope(
        org_id=tenant.org_id,
        principal_id=tenant.actor_id,
        delegated_principal_id=None,
        request_id=uuid4(),
        operation="update_space",
        idempotency_key="synthetic-update-1",
        input_digest=INPUT,
        configuration_revision=1,
        expected_generation=1,
    )


def open_command_request(connection, command):
    start_request(
        connection,
        RequestStart(
            org_id=command.org_id,
            request_id=command.request_id,
            principal_id=command.principal_id,
            delegated_principal_id=command.delegated_principal_id,
            client_id="synthetic-ui",
            operation=command.operation,
            destination="employee",
            business_date=date(2026, 11, 21),
            configuration_revision=command.configuration_revision,
        ),
    )
    return command


def change_space(connection, tenant):
    connection.execute(
        "UPDATE thalion.space SET row_generation = row_generation + 1 "
        "WHERE org_id = %s AND space_id = %s",
        (tenant.org_id, tenant.space_id),
    )
    append_event(
        connection, tenant.org_id, "space.changed", tenant.space_ref, space_id=tenant.space_id
    )
    return tenant.space_ref


def space_generation(connection, tenant):
    return connection.execute(
        "SELECT row_generation FROM thalion.space WHERE space_id = %s",
        (tenant.space_id,),
    ).fetchone()[0]


def spec_for(tenant, stage="parse"):
    return JobSpec(
        org_id=tenant.org_id,
        space_id=tenant.space_id,
        target_ref=tenant.space_ref,
        stage=stage,
        input_digest=INPUT,
        configuration_revision=1,
    )


def test_command_replay_reuses_result_without_writing_twice(runtime_db):
    connection, tenant, _ = runtime_db
    command = open_command_request(connection, command_for(tenant))
    first = execute_command(connection, command, lambda tx: change_space(tx, tenant))
    replayed = execute_command(
        connection,
        open_command_request(connection, replace(command, request_id=uuid4())),
        lambda tx: pytest.fail("replay executed a business mutation"),
    )
    assert first.replayed is False
    assert replayed.replayed is True
    assert first.receipt_id == replayed.receipt_id
    assert replayed.result_ref == tenant.space_ref
    assert space_generation(connection, tenant) == 2
    assert len(pending_events(connection, tenant.org_id, "parse")) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"input_digest": sha256(b"other content").digest()},
        {"configuration_revision": 2},
        {"expected_generation": 2},
    ],
)
def test_command_key_cannot_be_rebound_to_changed_preconditions(runtime_db, change):
    connection, tenant, _ = runtime_db
    command = open_command_request(connection, command_for(tenant))
    execute_command(connection, command, lambda tx: change_space(tx, tenant))
    with pytest.raises(IdempotencyConflict):
        execute_command(
            connection,
            replace(command, **change),
            lambda tx: pytest.fail("conflicting command applied"),
        )
    assert space_generation(connection, tenant) == 2


def test_delegated_scopes_do_not_share_a_receipt(runtime_db):
    connection, tenant, _ = runtime_db
    command = replace(command_for(tenant), principal_id=tenant.worker_id)
    first = execute_command(
        connection,
        open_command_request(connection, replace(command, delegated_principal_id=tenant.actor_id)),
        lambda tx: tenant.space_ref,
    )
    second = execute_command(
        connection,
        open_command_request(
            connection, replace(command, request_id=uuid4(), delegated_principal_id=tenant.other_actor_id)
        ),
        lambda tx: tenant.space_ref,
    )
    assert second.replayed is False
    assert first.receipt_id != second.receipt_id


def test_command_failure_rolls_back_mutation_event_and_claim(runtime_db):
    connection, tenant, _ = runtime_db
    command = open_command_request(connection, command_for(tenant))

    def interrupted(transaction):
        change_space(transaction, tenant)
        raise ValueError("synthetic interruption")

    with connection.transaction():
        with pytest.raises(ValueError, match="synthetic interruption"):
            execute_command(connection, command, interrupted)
        assert space_generation(connection, tenant) == 1
        assert pending_events(connection, tenant.org_id, "parse") == ()
    retried = execute_command(connection, command, lambda tx: change_space(tx, tenant))
    assert retried.replayed is False
    assert space_generation(connection, tenant) == 2


def test_competing_command_writers_commit_only_one_mutation(runtime_db):
    connection, tenant, database_url = runtime_db
    barrier = Barrier(2, timeout=5)
    command = open_command_request(connection, command_for(tenant))

    def run_competing():
        with open_database(database_url) as worker:
            barrier.wait()
            return execute_command(worker, command, lambda tx: change_space(tx, tenant))

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(run_competing)
        second = executor.submit(run_competing)
        receipts = [first.result(timeout=8), second.result(timeout=8)]
    assert receipts[0].receipt_id == receipts[1].receipt_id
    assert sorted(receipt.replayed for receipt in receipts) == [False, True]
    assert space_generation(connection, tenant) == 2
    assert len(pending_events(connection, tenant.org_id, "parse")) == 1


def test_event_consumer_retries_failed_effect_then_deduplicates(runtime_db):
    connection, tenant, _ = runtime_db
    with connection.transaction():
        event = append_event(connection, tenant.org_id, "space.changed", tenant.space_ref)

    def interrupted(transaction, received):
        assert received == event
        enqueue_job(transaction, spec_for(tenant))
        raise ValueError("consumer stopped before commit")

    with pytest.raises(ValueError, match="consumer stopped"):
        consume_event(connection, tenant.org_id, event.event_id, "parse", interrupted)
    assert pending_events(connection, tenant.org_id, "parse") == (event,)
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR) is None
    assert consume_event(
        connection,
        tenant.org_id,
        event.event_id,
        "parse",
        lambda tx, received: enqueue_job(tx, spec_for(tenant)),
    )
    assert not consume_event(
        connection,
        tenant.org_id,
        event.event_id,
        "parse",
        lambda tx, received: pytest.fail("duplicate event effect"),
    )
    assert pending_events(connection, tenant.org_id, "parse") == ()
    assert pending_events(connection, tenant.org_id, "audit") == (event,)
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)


def test_outbox_append_cannot_autocommit_separately(runtime_db):
    connection, tenant, _ = runtime_db
    with pytest.raises(RuntimeError):
        append_event(connection, tenant.org_id, "space.changed", tenant.space_ref)
    assert pending_events(connection, tenant.org_id, "parse") == ()


def test_consumer_cannot_claim_event_under_another_organization(runtime_db):
    connection, tenant, _ = runtime_db
    other = register_tenant(connection, "Second")
    with connection.transaction():
        event = append_event(connection, tenant.org_id, "space.changed", tenant.space_ref)
    assert not consume_event(
        connection,
        other.org_id,
        event.event_id,
        "parse",
        lambda tx, received: pytest.fail("event exposed across organizations"),
    )
    assert pending_events(connection, other.org_id, "parse") == ()
    assert pending_events(connection, tenant.org_id, "parse") == (event,)


def test_event_scope_is_derived_from_its_registered_object(runtime_db):
    connection, tenant, _ = runtime_db
    with connection.transaction():
        event = append_event(connection, tenant.org_id, "space.changed", tenant.space_ref)
    assert event.space_id == tenant.space_id


def test_runtime_does_not_queue_foreign_or_unregistered_object_references(runtime_db):
    connection, tenant, _ = runtime_db
    other = register_tenant(connection, "Second")
    for bad_ref in (other.space_ref, uuid4()):
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            enqueue_job(connection, replace(spec_for(tenant), target_ref=bad_ref))
        with pytest.raises((ValueError, psycopg.errors.ForeignKeyViolation)):
            with connection.transaction():
                append_event(
                    connection, tenant.org_id, "space.changed", bad_ref, space_id=tenant.space_id
                )
    assert pending_events(connection, tenant.org_id, "parse") == ()
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR) is None


def test_job_input_and_configuration_define_deduplication(runtime_db):
    connection, tenant, _ = runtime_db
    spec = spec_for(tenant)
    job_id = enqueue_job(connection, spec)
    assert enqueue_job(connection, spec) == job_id
    assert enqueue_job(connection, replace(spec, configuration_revision=2)) != job_id
    assert enqueue_job(
        connection, replace(spec, input_digest=sha256(b"revised input").digest())
    ) != job_id


def test_initial_claim_ignores_enqueue_clock_skew_but_retry_waits_until_due(runtime_db):
    connection, tenant, _ = runtime_db
    job_id = enqueue_job(connection, spec_for(tenant))
    connection.execute(
        "UPDATE thalion.job SET available_at = clock_timestamp() + interval '1 minute' WHERE job_id = %s",
        (job_id,),
    )
    first = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
    assert first is not None and (first.job_id, first.generation) == (job_id, 1)

    retry_job(connection, first, delay=timedelta(minutes=1))
    assert claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR) is None
    connection.execute(
        "UPDATE thalion.job SET available_at = clock_timestamp() - interval '1 minute' WHERE job_id = %s",
        (job_id,),
    )
    second = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert second is not None and (second.job_id, second.generation) == (job_id, 2)


def test_competing_workers_do_not_share_a_live_lease(runtime_db):
    connection, tenant, database_url = runtime_db
    job_id = enqueue_job(connection, spec_for(tenant))
    barrier = Barrier(2, timeout=5)

    def compete(worker_id):
        with open_database(database_url) as worker:
            barrier.wait()
            return claim_job(worker, tenant.org_id, "parse", worker_id, LEASE_FOR)

    with ThreadPoolExecutor(max_workers=2) as executor:
        leases = list(executor.map(compete, (tenant.worker_id, tenant.other_worker_id)))
    owned = [lease for lease in leases if lease is not None]
    assert len(owned) == 1
    assert owned[0].job_id == job_id
    assert owned[0].generation == 1
    assert owned[0].spec == spec_for(tenant)


def test_expired_execution_cannot_commit_before_or_after_reclaim(runtime_db):
    connection, tenant, _ = runtime_db
    enqueue_job(connection, spec_for(tenant))
    stale = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
    connection.execute(
        "UPDATE thalion.job_attempt SET started_at = clock_timestamp() - interval '2 minutes', "
        "lease_expires_at = clock_timestamp() - interval '1 minute' WHERE attempt_id = %s",
        (stale.attempt_id,),
    )
    with pytest.raises(LeaseLost):
        complete_job(connection, stale, lambda tx: pytest.fail("expired attempt ran"))
    current = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert current.job_id == stale.job_id
    assert current.generation == stale.generation + 1
    with pytest.raises(LeaseLost):
        complete_job(connection, stale, lambda tx: pytest.fail("superseded attempt ran"))
    assert complete_job(connection, current, lambda tx: change_space(tx, tenant)) == tenant.space_ref
    assert space_generation(connection, tenant) == 2
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR) is None
    with pytest.raises(LeaseLost):
        complete_job(connection, current, lambda tx: pytest.fail("completion applied twice"))


def test_job_completion_uses_current_worker_and_input(runtime_db):
    connection, tenant, _ = runtime_db
    enqueue_job(connection, spec_for(tenant))
    lease = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
    for changed in (
        replace(lease, worker_id=tenant.other_worker_id),
        replace(lease, spec=replace(lease.spec, configuration_revision=2)),
    ):
        with pytest.raises(LeaseLost):
            complete_job(connection, changed, lambda tx: pytest.fail("wrong attempt ran"))
    assert complete_job(connection, lease, lambda tx: tenant.space_ref) == tenant.space_ref


def test_lease_expiring_during_acceptance_rolls_back_changes(runtime_db):
    connection, tenant, _ = runtime_db
    enqueue_job(connection, spec_for(tenant))
    lease = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
    entered = []

    def complete_after_expiry(transaction):
        result = change_space(transaction, tenant)
        entered.append(True)
        transaction.execute(
            """
            UPDATE thalion.job_attempt
            SET started_at = clock_timestamp() - interval '2 seconds',
                lease_expires_at = clock_timestamp() - interval '1 second'
            WHERE attempt_id = %s
            """,
            (lease.attempt_id,),
        )
        return result

    with pytest.raises(LeaseLost):
        complete_job(connection, lease, complete_after_expiry)
    assert entered == [True]
    assert space_generation(connection, tenant) == 1
    assert pending_events(connection, tenant.org_id, "parse") == ()
    assert complete_job(connection, lease, lambda tx: change_space(tx, tenant)) == tenant.space_ref


def test_business_rejection_during_completion_does_not_leave_an_event(runtime_db):
    connection, tenant, _ = runtime_db
    enqueue_job(connection, spec_for(tenant))
    lease = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)

    def current_inputs_changed(transaction):
        change_space(transaction, tenant)
        raise ValueError("inputs changed")

    with pytest.raises(ValueError, match="inputs changed"):
        complete_job(connection, lease, current_inputs_changed)
    assert space_generation(connection, tenant) == 1
    assert pending_events(connection, tenant.org_id, "parse") == ()
    retry_job(connection, lease, delay=timedelta(minutes=1))
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR) is None
    with pytest.raises(LeaseLost):
        complete_job(connection, lease, lambda tx: pytest.fail("retried lease committed"))


def test_employee_cannot_claim_service_work(runtime_db):
    connection, tenant, _ = runtime_db
    enqueue_job(connection, spec_for(tenant))
    assert claim_job(connection, tenant.org_id, "parse", tenant.actor_id, LEASE_FOR) is None
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
