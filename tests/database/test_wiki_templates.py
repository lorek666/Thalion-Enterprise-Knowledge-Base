from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.wiki import templates
from enterprise_kb.runtime.audit import RequestAuditConflict
from enterprise_kb.runtime.commands import IdempotencyConflict
from enterprise_kb.runtime.events import pending_events

from test_runtime import open_database, register_tenant, runtime_db
from test_sources import request_for


def spec(tenant, **changes):
    return replace(
        templates.TemplateSpec(
            "travel-summary", "Summarize the synthetic rules without dropping exceptions.",
            "synthetic-local", 8192, 1024, tenant.other_actor_id,
        ),
        **changes,
    )


def context(connection, tenant, actor, operation, key=None):
    request = request_for(connection, tenant, actor, key or str(uuid4()), operation)
    return templates.TemplateWrite(
        request.org_id, request.principal_id, request.request_id, request.idempotency_key,
    )


def register(connection, tenant, *, actor=None, key=None, **changes):
    return templates.register_template_revision(
        connection, context(connection, tenant, actor or tenant.actor_id, "register_template_revision", key),
        tenant.space_id, spec(tenant, **changes),
    )


def review(connection, tenant, revision, *, actor=None, decision="approved"):
    templates.decide_template_admission(
        connection, context(connection, tenant, actor or tenant.other_actor_id, "decide_template_admission"),
        tenant.space_id, revision, decision, uuid4(), "checked_synthetic_constraints",
    )


def activate(connection, tenant, revision, *, generation=0, key=None):
    return templates.activate_template_revision(
        connection, context(connection, tenant, tenant.actor_id, "activate_template_revision", key),
        tenant.space_id, revision, generation,
    )


def active(connection, tenant):
    return connection.execute(
        "SELECT revision_ref, generation FROM thalion.active_compile_template "
        "WHERE org_id = %s AND space_id = %s",
        (tenant.org_id, tenant.space_id),
    ).fetchall()


def test_registration_and_approval_do_not_enable_a_template(runtime_db):
    connection, tenant, _ = runtime_db
    first = register(connection, tenant)
    assert active(connection, tenant) == []
    with pytest.raises(templates.TemplateNotAdmitted):
        activate(connection, tenant, first)
    review(connection, tenant, first)
    assert active(connection, tenant) == []
    assert activate(connection, tenant, first) == 1
    second = register(connection, tenant, prompt="Keep business dates in the synthetic summary.")
    assert second != first
    assert active(connection, tenant) == [(first, 1)]
    with pytest.raises(templates.TemplateNotAdmitted):
        activate(connection, tenant, second, generation=1)
    assert [(event.event_type, event.object_ref) for event in pending_events(connection, tenant.org_id, "wiki-test")] == [
        ("wiki.template_activated", tenant.space_ref),
    ]


def test_registration_replay_does_not_overwrite_revision(runtime_db):
    connection, tenant, _ = runtime_db
    first = register(connection, tenant, key="register-one")
    assert register(connection, tenant, key="register-one") == first
    with pytest.raises(IdempotencyConflict):
        register(connection, tenant, key="register-one", prompt="Different synthetic instructions.")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute(
            "UPDATE thalion.compile_template_revision SET prompt = 'Changed' WHERE revision_ref = %s", (first,),
        )
    assert connection.execute("SELECT count(*) FROM thalion.compile_template_revision").fetchone() == (1,)


def test_template_roles_are_independent_current_and_scoped(runtime_db):
    connection, tenant, _ = runtime_db
    other_org = register_tenant(connection, "Another synthetic organization")
    for reviewer in (tenant.actor_id, tenant.worker_id, other_org.actor_id):
        with pytest.raises(templates.TemplateNotAdmitted):
            register(connection, tenant, reviewer_id=reviewer)
    with pytest.raises(templates.TemplateNotAdmitted):
        register(connection, tenant, actor=tenant.other_actor_id, reviewer_id=tenant.actor_id)
    revision = register(connection, tenant)
    for actor in (tenant.actor_id, tenant.worker_id):
        with pytest.raises(templates.TemplateNotAdmitted):
            review(connection, tenant, revision, actor=actor)
    with pytest.raises(templates.TemplateNotAdmitted):
        review(connection, other_org, revision)
    with pytest.raises(templates.TemplateNotAdmitted):
        activate(connection, other_org, revision)
    review(connection, tenant, revision)
    connection.execute("UPDATE thalion.principal SET disabled = true WHERE principal_id = %s", (tenant.other_actor_id,))
    with pytest.raises(templates.TemplateNotAdmitted):
        activate(connection, tenant, revision)


def test_rejected_revision_cannot_be_enabled_or_rewritten(runtime_db):
    connection, tenant, _ = runtime_db
    revision = register(connection, tenant)
    review(connection, tenant, revision, decision="rejected")
    with pytest.raises(templates.TemplateConflict):
        review(connection, tenant, revision)
    with pytest.raises(templates.TemplateNotAdmitted):
        activate(connection, tenant, revision)
    request = context(connection, tenant, tenant.actor_id, "activate_template_revision")
    with pytest.raises(errors.ForeignKeyViolation):
        connection.execute(
            """
            INSERT INTO thalion.compile_template_activation (
                org_id, space_id, template_key, generation, revision_ref, activated_by, request_id
            ) VALUES (%s, %s, 'travel-summary', 1, %s, %s, %s)
            """,
            (tenant.org_id, tenant.space_id, revision, tenant.actor_id, request.request_id),
        )
    assert active(connection, tenant) == []


def test_active_selection_stops_when_reviewer_becomes_ineligible(runtime_db):
    connection, tenant, _ = runtime_db
    revision = register(connection, tenant)
    review(connection, tenant, revision)
    activate(connection, tenant, revision)
    assert active(connection, tenant) == [(revision, 1)]
    connection.execute("UPDATE thalion.principal SET disabled = true WHERE principal_id = %s", (tenant.other_actor_id,))
    assert active(connection, tenant) == []


def test_concurrent_activations_accept_only_one_expected_generation(runtime_db):
    connection, tenant, database_url = runtime_db
    first = register(connection, tenant)
    second = register(connection, tenant, prompt="Include synthetic approval limits.")
    review(connection, tenant, first)
    review(connection, tenant, second)
    barrier = Barrier(2, timeout=5)

    def compete(revision):
        with open_database(database_url) as writer:
            barrier.wait()
            try:
                return activate(writer, tenant, revision)
            except templates.TemplateConflict:
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, (first, second)))
    assert results.count(1) == 1 and results.count(None) == 1
    winner, = active(connection, tenant)
    assert winner[0] in (first, second) and winner[1] == 1
    assert len(pending_events(connection, tenant.org_id, "wiki-test")) == 1


def test_activation_replay_does_not_change_a_newer_selection(runtime_db):
    connection, tenant, _ = runtime_db
    first = register(connection, tenant)
    second = register(connection, tenant, prompt="Distinguish synthetic rail and flight rules.")
    review(connection, tenant, first)
    review(connection, tenant, second)
    assert activate(connection, tenant, first, key="activate-one") == 1
    assert activate(connection, tenant, second, generation=1) == 2
    assert activate(connection, tenant, first, key="activate-one") == 1
    assert active(connection, tenant) == [(second, 2)]
    assert len(pending_events(connection, tenant.org_id, "wiki-test")) == 2


def test_activation_rolls_back_if_it_cannot_append_an_event(runtime_db):
    connection, tenant, _ = runtime_db
    revision = register(connection, tenant)
    review(connection, tenant, revision)
    connection.execute("ALTER TABLE thalion.outbox_event ADD CONSTRAINT no_outbox CHECK (false)")
    with pytest.raises(errors.CheckViolation):
        activate(connection, tenant, revision, key="activate-once")
    assert active(connection, tenant) == []
    assert connection.execute(
        "SELECT count(*) FROM thalion.command_receipt WHERE operation = 'activate_template_revision'",
    ).fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT no_outbox")
    assert activate(connection, tenant, revision, key="activate-once") == 1


def test_review_requires_the_designated_reviewer_and_matching_trusted_request(runtime_db):
    connection, tenant, _ = runtime_db
    revision = register(connection, tenant)
    basis = uuid4()
    author_request = context(connection, tenant, tenant.actor_id, "decide_template_admission")
    claimed_reviewer = replace(author_request, principal_id=tenant.other_actor_id)
    with pytest.raises(RequestAuditConflict):
        templates.decide_template_admission(
            connection, claimed_reviewer, tenant.space_id, revision, "approved", basis, "preserves_exception",
        )
    reviewer_request = context(connection, tenant, tenant.other_actor_id, "decide_template_admission")
    templates.decide_template_admission(
        connection, reviewer_request, tenant.space_id, revision, "approved", basis, "preserves_exception",
    )
    assert connection.execute(
        "SELECT reviewer_id, request_id, basis_ref, reason_code FROM thalion.compile_template_admission",
    ).fetchall() == [(tenant.other_actor_id, reviewer_request.request_id, basis, "preserves_exception")]
