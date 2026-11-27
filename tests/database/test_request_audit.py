from dataclasses import replace
from datetime import date
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.runtime import audit
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.jobs import enqueue_job

from test_identity import migrate_to_revision
from test_runtime import (
    change_space,
    command_for,
    open_database,
    register_tenant,
    runtime_db,
    space_generation,
    spec_for,
)


def request_for(tenant, **changes):
    return replace(
        audit.RequestStart(
            org_id=tenant.org_id,
            request_id=uuid4(),
            principal_id=tenant.actor_id,
            delegated_principal_id=None,
            client_id="synthetic-ui",
            operation="update_space",
            destination="employee",
            business_date=date(2026, 11, 21),
            configuration_revision=1,
            question_chain_id=uuid4(),
        ),
        **changes,
    )


def test_request_records_distinct_requests_in_one_chain_and_seals_outcome(runtime_db):
    connection, tenant, database_url = runtime_db
    initial = request_for(tenant)
    followup = replace(initial, request_id=uuid4(), operation="search")
    audit.start_request(connection, initial)
    audit.start_request(connection, followup)
    with open_database(database_url) as independent:
        assert set(independent.execute(
            """
            SELECT request_id, outcome FROM thalion.request_record
            WHERE org_id = %s AND question_chain_id = %s
            """,
            (tenant.org_id, initial.question_chain_id),
        ).fetchall()) == {(initial.request_id, None), (followup.request_id, None)}
    assert audit.finish_request(connection, tenant.org_id, initial.request_id, "succeeded", 42)
    assert not audit.finish_request(connection, tenant.org_id, initial.request_id, "failed", 47)
    assert audit.finish_request(
        connection, tenant.org_id, followup.request_id, "dependency_unavailable", 20
    )
    assert connection.execute(
        """
        SELECT outcome, elapsed_ms, completed_at IS NOT NULL
        FROM thalion.request_record WHERE org_id = %s AND request_id = %s
        """,
        (tenant.org_id, initial.request_id),
    ).fetchone() == ("succeeded", 42, True)


def test_ingress_migration_preserves_history_and_guards_finalization(database_url):
    migrate_to_revision(database_url, "0093_source_audit")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Synthetic organization")
        historical = request_for(tenant, space_id=tenant.space_id)
        audit.start_request(connection, historical)
        assert audit.finish_request(connection, tenant.org_id, historical.request_id, "succeeded", 10)
        upgrade(database_url)
        current = request_for(tenant, space_id=tenant.space_id, ingress="http")
        audit.start_request(connection, current)
        with pytest.raises(errors.CheckViolation):
            audit.start_request(connection, request_for(tenant, ingress="header-value"))
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            connection.execute("""
                UPDATE thalion.request_record
                SET outcome = 'succeeded', elapsed_ms = 11, completed_at = clock_timestamp(), ingress = 'mcp'
                WHERE request_id = %s
            """, (current.request_id,))
        assert audit.finish_request(connection, tenant.org_id, current.request_id, "succeeded", 12)
        assert set(connection.execute("""
            SELECT request_id, ingress, outcome, elapsed_ms FROM thalion.request_record
        """).fetchall()) == {
            (historical.request_id, "unknown", "succeeded", 10),
            (current.request_id, "http", "succeeded", 12),
        }


def test_request_chain_cannot_bind_another_identity_or_client(runtime_db):
    connection, tenant, _ = runtime_db
    first = request_for(tenant)
    audit.start_request(connection, first)
    for changes in (
        {"principal_id": tenant.other_actor_id},
        {"client_id": "other-client"},
        {"delegated_principal_id": tenant.other_actor_id},
    ):
        with pytest.raises(audit.RequestAuditConflict):
            audit.start_request(connection, replace(first, request_id=uuid4(), **changes))
    assert connection.execute(
        "SELECT count(*) FROM thalion.request_record WHERE org_id = %s", (tenant.org_id,),
    ).fetchone() == (1,)
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute(
            "UPDATE thalion.request_record SET principal_id = %s WHERE request_id = %s",
            (tenant.other_actor_id, first.request_id),
        )


def test_audit_survives_rollback_without_linking_failed_effect(runtime_db):
    connection, tenant, _ = runtime_db
    request = request_for(tenant)
    audit.start_request(connection, request)
    command = replace(command_for(tenant), request_id=request.request_id)

    def interrupted(transaction):
        change_space(transaction, tenant)
        enqueue_job(transaction, spec_for(tenant), request_id=request.request_id)
        raise ValueError("synthetic business rollback")

    with pytest.raises(ValueError, match="business rollback"):
        execute_command(connection, command, interrupted)
    assert audit.finish_request(connection, tenant.org_id, request.request_id, "failed", 8)
    assert space_generation(connection, tenant) == 1
    assert connection.execute("SELECT count(*) FROM thalion.request_command").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.request_job").fetchone() == (0,)
    assert connection.execute("SELECT outcome FROM thalion.request_record").fetchone() == ("failed",)


def test_distinct_requests_link_command_replay_and_job_without_repeating_effect(runtime_db):
    connection, tenant, _ = runtime_db
    first = request_for(tenant)
    replay = replace(first, request_id=uuid4())
    audit.start_request(connection, first)
    audit.start_request(connection, replay)
    command = replace(command_for(tenant), request_id=first.request_id)

    def apply(transaction):
        enqueue_job(transaction, spec_for(tenant), request_id=first.request_id)
        return change_space(transaction, tenant)

    applied = execute_command(connection, command, apply)
    replayed = execute_command(
        connection, replace(command, request_id=replay.request_id),
        lambda tx: pytest.fail("replay executed a mutation"),
    )
    assert applied.receipt_id == replayed.receipt_id
    assert set(connection.execute(
        "SELECT request_id, receipt_id FROM thalion.request_command",
    ).fetchall()) == {(first.request_id, applied.receipt_id), (replay.request_id, applied.receipt_id)}
    assert connection.execute("SELECT request_id FROM thalion.request_job").fetchall() == [
        (first.request_id,)
    ]
    assert space_generation(connection, tenant) == 2


def test_foreign_or_unregistered_request_cannot_authorize_a_link(runtime_db):
    connection, tenant, _ = runtime_db
    other = register_tenant(connection, "Synthetic other")
    request = request_for(tenant)
    audit.start_request(connection, request)
    command = replace(command_for(tenant), request_id=request.request_id)
    for unexpected in (
        replace(command, request_id=uuid4()),
        replace(command, principal_id=tenant.other_actor_id),
        replace(command, delegated_principal_id=tenant.other_actor_id),
        replace(command, org_id=other.org_id, principal_id=other.actor_id),
    ):
        with pytest.raises(audit.RequestAuditConflict):
            execute_command(connection, unexpected, lambda tx: pytest.fail("invalid scope ran"))
    assert not audit.finish_request(connection, other.org_id, request.request_id, "failed", 1)
    with pytest.raises(errors.ForeignKeyViolation):
        enqueue_job(connection, spec_for(other), request_id=request.request_id)
    assert connection.execute("SELECT count(*) FROM thalion.job").fetchone() == (0,)
