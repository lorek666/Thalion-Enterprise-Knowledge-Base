from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.access import policy, travel
from enterprise_kb.modules.access.delivery import AuthorityDecision, AuthorizationUnavailable, DeliveryContext
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity, registry
from enterprise_kb.runtime.audit import RequestStart, start_request

from test_effectivity import AFTER, BEFORE, BEGIN, SWITCH, approve
from test_evidence import CONTENT, approved, claim, evidence_db, register_markdown, review
from test_runtime import open_database, runtime_db
from test_sources import register, request_for


FIELDS = frozenset({"excerpt"})


@pytest.fixture
def ready(evidence_db):
    connection, tenant, _, _, store = evidence_db
    version = register_markdown(evidence_db)
    run = processing.process_markdown_job(connection, claim(evidence_db), store)
    review(evidence_db, run)
    approve(connection, tenant, version, BEGIN)
    passage, = approved(evidence_db, version)
    return evidence_db, version, passage


def binding(principal_id, *, effect="allow", end=None, passage_ref=None):
    return policy.LocalRule(
        principal_id, "read_passage", effect, "employee_evidence", "employee", FIELDS,
        datetime.now(UTC) - timedelta(days=1), end, passage_ref,
    )


def set_rules(db, *rules, expected=1, actor=None):
    connection, tenant, _, source, _ = db
    context = request_for(
        connection, tenant, actor or tenant.actor_id, str(uuid4()), "replace_local_policy",
    )
    return policy.replace_synthetic_policy(
        connection, context, tenant.space_id, source, expected, tuple(rules), uuid4(),
    )


def ingress(db, employee, business_date, *, operation="read_passage", purpose="employee_evidence", destination="employee",
            space_id=None):
    connection, tenant, *_ = db
    request_id = uuid4()
    context = DeliveryContext(
        request_id, tenant.org_id, employee, "synthetic-ui", operation,
        purpose, destination, datetime.now(UTC) + timedelta(seconds=15),
    )
    start_request(connection, RequestStart(
        tenant.org_id, request_id, employee, None, context.client_id, context.operation,
        context.destination, business_date, 1, space_id=space_id,
    ))
    return context


def authority_for(allowed):
    def check(probe):
        now = datetime.now(UTC)
        return AuthorityDecision(
            probe.check_id, now, now + timedelta(seconds=10), frozenset({probe.context.principal_id}),
            {scope: scope.fields if probe.context.principal_id in allowed else frozenset()
             for scope in probe.scopes}, str(uuid4()),
        )
    return check


def read(db, passage, employee, authority, *, day=BEFORE, context=None):
    connection, tenant, _, _, store = db
    return travel.read_travel_passage(
        connection, context or ingress(db, employee, day), tenant.space_id,
        passage.passage_ref, passage.revision, store,
        region="shanghai", traveler_class="employee", check_authority=authority,
    )


def test_same_passage_requires_both_current_source_and_local_permission(ready):
    db, _, passage = ready
    _, tenant, _, _, _ = db
    assert set_rules(db, binding(tenant.actor_id)) == 2
    authority = authority_for({tenant.actor_id, tenant.other_actor_id})
    allowed = read(db, passage, tenant.actor_id, authority)
    denied = read(db, passage, tenant.other_actor_id, authority)
    assert (allowed.status, allowed.payload) == (
        "succeeded", CONTENT[passage.byte_start:passage.byte_end],
    )
    assert (denied.status, denied.payload) == ("rejected", None)
    assert read(db, passage, tenant.actor_id, authority_for(set())).status == "rejected"


def test_delivery_audit_binds_actual_bytes_and_authority_without_storing_raw_proof(ready):
    db, _, passage = ready
    connection, tenant, *_ = db
    set_rules(db, binding(tenant.actor_id))
    context = ingress(db, tenant.actor_id, BEFORE)

    def check(probe):
        authority = authority_for({tenant.actor_id})(probe)
        return replace(authority, proof_ref="private synthetic proof")

    decision = read(db, passage, tenant.actor_id, check, context=context)
    assert decision.status == "succeeded"
    assert connection.execute(
        """
        SELECT request_id, passage_ref, excerpt_revision, payload_digest, proof_digest,
               policy_revision, source_epoch, checked_at
        FROM thalion.delivery_record JOIN thalion.delivery_dependency USING (check_id, org_id)
        """
    ).fetchall() == [(
        context.request_id, passage.passage_ref, passage.revision, sha256(decision.payload).digest(),
        sha256(b"private synthetic proof").digest(), 2, 2, decision.checked_at,
    )]
    assert read(db, passage, tenant.other_actor_id, authority_for({tenant.other_actor_id})).payload is None
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (1,)


def test_audit_write_failure_stops_content_delivery(ready):
    db, _, passage = ready
    connection, tenant, *_ = db
    set_rules(db, binding(tenant.actor_id))
    connection.execute("ALTER TABLE thalion.delivery_record ADD CHECK (false)")
    decision = read(db, passage, tenant.actor_id, authority_for({tenant.actor_id}))
    assert (decision.status, decision.payload) == ("dependency_unavailable", None)


@pytest.mark.parametrize("expires", ["authority", "local_allow", "scheduled_deny"])
def test_expiry_while_recording_the_decision_never_returns_content(ready, monkeypatch, expires):
    db, _, passage = ready
    connection, tenant, *_ = db
    assessed = datetime.now(UTC)
    cutoff = assessed + timedelta(seconds=5)
    current = assessed
    rules = [binding(tenant.actor_id, end=cutoff if expires == "local_allow" else None)]
    if expires == "scheduled_deny":
        rules.append(replace(binding(tenant.actor_id, effect="deny"), valid_from=cutoff))
    set_rules(db, *rules)
    context = ingress(db, tenant.actor_id, BEFORE)

    def check(probe):
        return AuthorityDecision(
            probe.check_id, assessed, cutoff if expires == "authority" else context.deadline,
            frozenset({tenant.actor_id}), {scope: scope.fields for scope in probe.scopes}, str(uuid4()),
        )

    class Clock:
        @staticmethod
        def now(timezone=UTC):
            return current

    original_record = travel._record_delivery
    original_authorize = travel.authorize_delivery

    def record_then_advance(*args, **kwargs):
        nonlocal current
        recorded = original_record(*args, **kwargs)
        current = cutoff
        return recorded

    monkeypatch.setattr(travel, "datetime", Clock)
    monkeypatch.setattr(
        travel, "authorize_delivery",
        lambda *args, **kwargs: original_authorize(*args, **(kwargs | {"clock": Clock.now})),
    )
    monkeypatch.setattr(travel, "_record_delivery", record_then_advance)
    decision = read(db, passage, tenant.actor_id, check, context=context)
    assert decision.status != "succeeded" and decision.payload is None
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_same_request_cannot_return_a_second_payload(ready):
    db, _, passage = ready
    connection, tenant, *_ = db
    set_rules(db, binding(tenant.actor_id))
    context = ingress(db, tenant.actor_id, BEFORE)
    authority = authority_for({tenant.actor_id})
    assert read(db, passage, tenant.actor_id, authority, context=context).status == "succeeded"
    replay = read(db, passage, tenant.actor_id, authority, context=context)
    assert (replay.status, replay.payload) == ("rejected", None)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (1,)


def test_quality_quarantine_during_authority_check_prevents_disclosure(ready):
    db, _, passage = ready
    connection, tenant, database_url, source, store = db
    set_rules(db, binding(tenant.actor_id))
    run_ref, digest = connection.execute(
        "SELECT run_ref, manifest_digest FROM thalion.processing_run"
    ).fetchone()
    run = processing.ProcessingResult(run_ref, digest, "pending_review", None, 1)
    authority = authority_for({tenant.actor_id})

    def quarantine_then_confirm(probe):
        with open_database(database_url) as other:
            review((other, tenant, database_url, source, store), run, decision="quarantined")
        return authority(probe)

    result = read(db, passage, tenant.actor_id, quarantine_then_confirm)
    assert (result.status, result.payload) == ("rejected", None)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_source_policy_cannot_point_at_a_different_source_passage(ready):
    db, _, passage = ready
    connection, tenant, database_url, _, store = db
    context = request_for(connection, tenant, tenant.actor_id, "other-source", "register_source_contract")
    other_source = registry.register_synthetic_source(
        connection, context, tenant.space_id,
        registry.SyntheticSource("other-source", "other-archive", tenant.worker_id),
    )
    with pytest.raises(policy.PolicyNotAdmitted):
        set_rules((connection, tenant, database_url, other_source, store),
                  binding(tenant.actor_id, passage_ref=passage.passage_ref))
    assert connection.execute("SELECT count(*) FROM thalion.policy_revision").fetchone() == (0,)


def test_explicit_deny_overrides_allow_and_expired_grants_do_not_apply(ready):
    db, _, passage = ready
    _, tenant, *_ = db
    expired = datetime.now(UTC) - timedelta(seconds=1)
    set_rules(
        db, binding(tenant.actor_id), binding(tenant.actor_id, effect="deny", passage_ref=passage.passage_ref),
        binding(tenant.other_actor_id, end=expired),
    )
    authority = authority_for({tenant.actor_id, tenant.other_actor_id})
    for employee in (tenant.actor_id, tenant.other_actor_id):
        assert read(db, passage, employee, authority).status == "rejected"


def test_source_revocation_needs_no_local_policy_sync_and_outage_is_not_no_evidence(ready):
    db, _, passage = ready
    connection, tenant, *_ = db
    set_rules(db, binding(tenant.actor_id), binding(tenant.other_actor_id))
    source_readers = {tenant.actor_id, tenant.other_actor_id}
    authority = authority_for(source_readers)
    assert read(db, passage, tenant.actor_id, authority).status == "succeeded"
    source_readers.remove(tenant.actor_id)
    assert read(db, passage, tenant.actor_id, authority).payload is None
    assert read(db, passage, tenant.other_actor_id, authority).status == "succeeded"
    assert connection.execute("SELECT safety_epoch FROM thalion.source").fetchone() == (2,)

    def unavailable(probe):
        raise AuthorizationUnavailable("synthetic source offline")

    decision = read(db, passage, tenant.other_actor_id, unavailable)
    assert (decision.status, decision.payload) == ("dependency_unavailable", None)


def test_local_policy_replacement_after_candidate_prevents_delivery(ready):
    db, _, passage = ready
    _, tenant, database_url, source, store = db
    set_rules(db, binding(tenant.actor_id), binding(tenant.other_actor_id))
    authority = authority_for({tenant.actor_id, tenant.other_actor_id})

    def replace_then_confirm(probe):
        with open_database(database_url) as other:
            set_rules((other, tenant, database_url, source, store), binding(tenant.other_actor_id), expected=2)
        return authority(probe)

    decision = read(db, passage, tenant.actor_id, replace_then_confirm)
    assert (decision.status, decision.payload) == ("input_changed", None)
    assert read(db, passage, tenant.other_actor_id, authority).status == "succeeded"


def test_a_newer_unparsed_version_does_not_fall_back_and_historical_read_stays_gated(ready):
    db, previous, passage = ready
    connection, tenant, _, source, store = db
    set_rules(db, binding(tenant.actor_id))
    previous_selection = effectivity.select_rule(
        connection, tenant.org_id, tenant.space_id, previous.document_ref, BEFORE,
        region="shanghai", traveler_class="employee",
    )
    newest = b"# Travel\n\nNo exceptions to prior approval.\n"
    replacement = register(
        connection, tenant, source, store, key="replaced-policy", source_version_key="rev-b",
        digest=sha256(newest).digest(), payload=newest, version_label="B",
    )
    approve(connection, tenant, replacement, SWITCH, replaces=previous_selection.decision_ref)
    authority = authority_for({tenant.actor_id})
    assert read(db, passage, tenant.actor_id, authority, day=AFTER).status == "rejected"
    assert read(db, passage, tenant.actor_id, authority, day=BEFORE).status == "succeeded"
    assert read(db, passage, tenant.actor_id, authority_for(set()), day=BEFORE).status == "rejected"


def test_policy_writer_is_scoped_and_old_policy_bindings_cannot_be_modified(ready):
    db, _, passage = ready
    connection, tenant, *_ = db
    with pytest.raises(policy.PolicyNotAdmitted):
        set_rules(db, binding(tenant.other_actor_id), actor=tenant.other_actor_id)
    assert set_rules(db, binding(tenant.actor_id, passage_ref=passage.passage_ref)) == 2
    with pytest.raises(policy.PolicyConflict):
        set_rules(db, binding(tenant.other_actor_id))
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.permission_binding SET effect = 'deny'")


def test_copied_audit_identity_cannot_reuse_another_employees_request(ready):
    db, _, passage = ready
    _, tenant, *_ = db
    set_rules(db, binding(tenant.actor_id))
    context = ingress(db, tenant.other_actor_id, BEFORE)
    result = read(
        db, passage, tenant.actor_id, authority_for({tenant.actor_id}),
        context=replace(context, principal_id=tenant.actor_id),
    )
    assert (result.status, result.payload) == ("rejected", None)
