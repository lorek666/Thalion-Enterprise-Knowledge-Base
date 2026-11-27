from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from threading import Barrier
from uuid import uuid4

import pytest

from enterprise_kb.modules.access import travel
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.runtime import external
from enterprise_kb.runtime.jobs import JobSpec, claim_job

from test_access_policy_transport import replace_policy
from test_docx_delivery import EXCERPT, publish_docx
from test_evidence_transport import bearer, evidence_transport, private_json, transport
from test_external_calls import expire
from test_feedback_work import admit
from test_gaps import command_headers
from test_model_egress_policy import evidence_db, model_policy_path, rule_for
from test_model_source_authority import GRANTS, grant_for, model_probe
from test_pdf_delivery import PAGE_TEXT, publish_pdf
from test_persisted_access import binding, ingress, set_rules
from test_runtime import LEASE_FOR, open_database, runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_travel_search import BEFORE, corpus


def arrange(transport, evidence_transport, revocation_authority, *, local_rules=True):
    client, db, (employee, approver), credentials, _, first, second = transport
    _, _, _, source, _ = db
    profile = revocation_authority[2]
    credential, scope, _ = model_probe(evidence_transport)
    rule = rule_for(credentials[employee].employee_ref, first.passage_ref)
    rule["valid_from"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    rules = [rule] if local_rules else []
    admit(credentials, approver, "read_model_policy", "replace_model_policy")
    updated = client.post(model_policy_path(source), headers=command_headers(approver), json={
        "expected_epoch": 2, "basis_id": str(uuid4()), "rules": rules,
    })
    assert updated.status_code == 200
    private_json(profile.root / GRANTS, [grant_for(credential, scope)])
    return db, profile, credential, first, second, rule


def prepare(db, credential, refs, authority, *, purpose="model_answer", context=None, match_scope=True):
    connection, tenant, _, _, store = db
    if context is None:
        audited = ingress(db, tenant.actor_id, BEFORE, operation=travel.synthetic_model_request_operation(purpose), purpose=purpose,
                          destination="synthetic-gateway", space_id=tenant.space_id if match_scope else None)
        context = replace(audited, operation="send_model_evidence")
    return travel.prepare_synthetic_model_excerpts(
        connection, context, tenant.space_id, refs, store, region=credential.region,
        traveler_class=credential.traveler_class, check_authority=authority,
    )


def test_model_delivery_seals_only_the_verified_excerpt_bytes_and_exact_revision(transport, evidence_transport, revocation_authority):
    db, profile, credential, first, _, _ = arrange(transport, evidence_transport, revocation_authority)
    connection, tenant, *_ = db
    checks = []

    def authorize(probe):
        checks.append(probe)
        return profile.check_model_source(credential, probe)

    result = prepare(db, credential, ((first.passage_ref, first.revision),), authorize)
    assert result.status == "succeeded"
    assert json.loads(result.payload) == {"excerpts": ["上海住宿限额。\n"]}
    assert len(checks) == 2 and result.check == checks[-1]
    assert checks[-1].payload_sha256 == sha256(result.payload).hexdigest()
    assert {scope.revision for scope in checks[-1].scopes} == {first.revision}
    assert connection.execute("""
        SELECT request.operation, request.destination, delivery.payload_digest, dependency.passage_ref,
               dependency.excerpt_revision, dependency.policy_revision
        FROM thalion.delivery_record AS delivery JOIN thalion.request_record AS request USING (org_id, request_id)
        JOIN thalion.delivery_dependency AS dependency USING (org_id, check_id)
        WHERE delivery.check_id = %s
    """, (result.check.check_id,)).fetchone() == (
        "send_model_evidence.model_answer", "synthetic-gateway", sha256(result.payload).digest(), first.passage_ref, first.revision, 3,
    )
    repeated = prepare(db, credential, ((first.passage_ref, first.revision),), authorize, context=result.check.context)
    assert repeated.status == "rejected" and repeated.payload is None
    assert connection.execute("SELECT count(*) FROM thalion.external_call WHERE org_id = %s", (tenant.org_id,)).fetchone() == (0,)


def test_model_delivery_requires_scope_both_local_permissions_and_complete_requested_inputs(transport, evidence_transport, revocation_authority):
    client, db, (owner, approver), credentials, _, first, second = transport
    connection, tenant, _, source, _ = db
    _, profile, credential, _, _, rule = arrange(transport, evidence_transport, revocation_authority, local_rules=False)
    authorize = lambda probe: profile.check_model_source(credential, probe)
    refs = ((first.passage_ref, first.revision),)
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).status_code == 200
    assert prepare(db, credential, refs, authorize).status == "rejected"
    added = client.post(model_policy_path(source), headers=command_headers(approver), json={
        "expected_epoch": 3, "basis_id": str(uuid4()), "rules": [rule],
    })
    assert added.status_code == 200
    mismatched = ingress(db, tenant.actor_id, BEFORE, operation="send_model_evidence.wiki_compilation",
                        purpose="model_answer", destination="synthetic-gateway", space_id=tenant.space_id)
    for denied in (
        prepare(db, credential, refs, authorize, match_scope=False),
        prepare(db, credential, refs, authorize, context=replace(mismatched, operation="send_model_evidence")),
        prepare(db, credential, refs, authorize, purpose="wiki_compilation"),
        prepare(db, credential, ((first.passage_ref, first.revision + 1),), authorize),
        prepare(db, credential, refs + refs, authorize),
        prepare(db, credential, refs + ((second.passage_ref, second.revision),), authorize),
        prepare(db, credential, refs, lambda probe: profile.check_source(credential, probe)),
    ):
        assert denied.status in {"rejected", "dependency_unavailable"} and denied.payload is None
    admit(credentials, owner, "replace_local_policy")
    local = replace_policy(client, owner, source, {"expected_epoch": 4, "basis_id": str(uuid4()), "rules": []})
    assert local.status_code == 200
    assert prepare(db, credential, refs, authorize).status == "rejected"
    assert connection.execute("""
        SELECT count(*) FROM thalion.delivery_record AS delivery
        JOIN thalion.request_record AS request USING (org_id, request_id) WHERE request.destination = 'synthetic-gateway'
    """).fetchone() == (0,)


def test_model_delivery_detects_source_revocation_between_eligibility_and_exact_payload_check(transport, evidence_transport, revocation_authority):
    client, _, (_, approver), *_ = transport
    db, profile, credential, first, second, rule = arrange(transport, evidence_transport, revocation_authority)
    connection, tenant, _, source_ref, _ = db
    independent, source, _ = revocation_authority
    _, first_scope, _ = model_probe(evidence_transport)
    second_scope = replace(first_scope, object_id=second.passage_ref, revision=second.revision)
    second_rule = rule | {"passage_id": str(second.passage_ref)}
    assert client.post(model_policy_path(source_ref), headers=command_headers(approver), json={
        "expected_epoch": 3, "basis_id": str(uuid4()), "rules": [rule, second_rule],
    }).status_code == 200
    private_json(profile.root / GRANTS, [grant_for(credential, scope) for scope in (first_scope, second_scope)])
    checks = []

    def authorize(probe):
        checks.append(probe)
        if len(checks) == 2:
            source_revocations.revoke(independent, source.authority_ref, tenant.space_ref, credential.employee_ref,
                                      second.passage_ref, "evidence", basis_ref=uuid4())
        return profile.check_model_source(credential, probe)

    result = prepare(db, credential, ((first.passage_ref, first.revision), (second.passage_ref, second.revision)), authorize)
    assert len(checks) == 2
    assert result.status == "rejected" and result.payload is None
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)
    assert prepare(db, credential, ((first.passage_ref, first.revision),), authorize).status == "succeeded"


def test_model_delivery_rejects_changed_local_policy_and_reports_authority_failure(transport, evidence_transport, revocation_authority):
    client, _, (_, approver), *_ = transport
    db, profile, credential, first, _, _ = arrange(transport, evidence_transport, revocation_authority)
    connection, _, _, source, _ = db
    checks = []

    def change_policy(probe):
        checks.append(probe)
        if len(checks) == 2:
            assert client.post(model_policy_path(source), headers=command_headers(approver), json={
                "expected_epoch": 3, "basis_id": str(uuid4()), "rules": [],
            }).status_code == 200
        return profile.check_model_source(credential, probe)

    refs = ((first.passage_ref, first.revision),)
    result = prepare(db, credential, refs, change_policy)
    assert len(checks) == 2 and result.status == "input_changed" and result.payload is None

    def unavailable(probe):
        raise AuthorizationUnavailable("Synthetic source authority outage.")

    failed = prepare(db, credential, refs, unavailable)
    assert failed.status == "dependency_unavailable" and failed.payload is None
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_model_delivery_uses_only_approved_pdf_and_docx_excerpts(transport, evidence_transport, revocation_authority):
    client, _, (_, approver), *_ = transport
    db, profile, credential, _, _, rule = arrange(transport, evidence_transport, revocation_authority)
    _, tenant, _, source, _ = db
    _, target, hidden_page = publish_pdf(db)
    _, _, (paragraph, hidden_paragraph) = publish_docx(db)
    assert set_rules(db, binding(tenant.actor_id, passage_ref=target), binding(tenant.actor_id, passage_ref=paragraph.passage_ref),
                     expected=3) == 4
    _, scope, _ = model_probe(evidence_transport)
    permitted = (replace(scope, object_id=target, revision=1), replace(scope, object_id=paragraph.passage_ref, revision=paragraph.revision))
    assert client.post(model_policy_path(source), headers=command_headers(approver), json={
        "expected_epoch": 4, "basis_id": str(uuid4()), "rules": [rule | {"passage_id": str(item.object_id)} for item in permitted],
    }).status_code == 200
    private_json(profile.root / "source-grants.json", {
        str(credential.employee_ref): [str(target), str(paragraph.passage_ref), str(hidden_page), str(hidden_paragraph.passage_ref)],
    })
    private_json(profile.root / GRANTS, [grant_for(credential, item) for item in permitted])
    refs = tuple((item.object_id, item.revision) for item in permitted)
    result = prepare(db, credential, refs, lambda probe: profile.check_model_source(credential, probe))
    assert result.status == "succeeded"
    assert json.loads(result.payload) == {"excerpts": [PAGE_TEXT.decode(), EXCERPT]}


@pytest.fixture
def dispatch_case(transport, evidence_transport, revocation_authority):
    from enterprise_kb.modules.access import model_dispatch

    db, profile, credential, first, _, _ = arrange(transport, evidence_transport, revocation_authority)
    connection, tenant, *_ = db
    audited = ingress(db, tenant.actor_id, BEFORE, operation="send_model_evidence.model_answer",
                      purpose="model_answer", destination="synthetic-gateway", space_id=tenant.space_id)
    context = replace(audited, operation="send_model_evidence")
    refs = ((first.passage_ref, first.revision),)
    spec = JobSpec(tenant.org_id, tenant.space_id, tenant.space_ref, "synthetic_model_excerpts",
                   model_dispatch.synthetic_model_job_digest(context, refs, region=credential.region,
                                                            traveler_class=credential.traveler_class), 1)
    external.enqueue_external_job(connection, spec, external.CallBudget("CNY", 0, 1), request_id=context.request_id)
    lease = claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR)
    return db, profile, credential, context, lease, refs


def dispatch_excerpts(case, authority=None, *, context=None, references=None):
    from enterprise_kb.modules.access import model_dispatch

    db, profile, credential, audited, lease, refs = case
    connection, _, _, _, store = db
    return model_dispatch.dispatch_synthetic_model_excerpts(
        connection, context or audited, lease, refs if references is None else references, store,
        region=credential.region, traveler_class=credential.traveler_class,
        check_authority=authority or (lambda probe: profile.check_model_source(credential, probe)),
    )


def test_model_dispatch_receives_exact_bytes_only_once_after_intent_commits(dispatch_case, monkeypatch):
    from enterprise_kb.modules.access import model_dispatch

    db, _, _, context, lease, _ = dispatch_case
    connection, tenant, url, *_ = db
    received = []
    receiver = model_dispatch._receive_synthetic_payload

    def observe(payload):
        with open_database(url) as reader:
            assert reader.execute("""
                SELECT call.state, call.input_digest, delivery.payload_digest
                FROM thalion.external_call AS call
                JOIN thalion.request_job AS link USING (org_id, job_id)
                JOIN thalion.delivery_record AS delivery USING (org_id, request_id)
                WHERE call.job_id = %s AND link.request_id = %s
            """, (lease.job_id, context.request_id)).fetchone() == ("sent", sha256(payload).digest(), sha256(payload).digest())
        received.append(payload)
        return receiver(payload)

    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", observe)
    result = dispatch_excerpts(dispatch_case)
    assert result.status == "succeeded"
    assert list(map(json.loads, received)) == [{"excerpts": ["上海住宿限额。\n"]}]
    assert result.input_digest == sha256(received[0]).digest()
    assert dispatch_excerpts(dispatch_case).status == "rejected"
    assert len(received) == 1
    assert external.external_call_usage(connection, tenant.org_id, lease.job_id) == external.CallUsage("CNY", 0, 0, 1, 0, 0)
    assert connection.execute("""
        SELECT state, artifact_ref FROM thalion.external_call WHERE call_id = %s
    """, (result.call_id,)).fetchone() == ("confirmed_success", None)


def test_model_dispatch_cannot_reuse_a_prepared_receipt_or_bind_a_different_request(dispatch_case, monkeypatch):
    from enterprise_kb.modules.access import model_dispatch

    db, profile, credential, context, _, refs = dispatch_case
    connection, tenant, *_ = db
    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", lambda *args: pytest.fail("unexpected dispatch"))
    unrelated = ingress(db, tenant.actor_id, BEFORE, operation="send_model_evidence.model_answer",
                        purpose="model_answer", destination="synthetic-gateway", space_id=tenant.space_id)
    assert dispatch_excerpts(dispatch_case, context=replace(unrelated, operation=context.operation)).status == "rejected"
    assert dispatch_excerpts(dispatch_case, references=((refs[0][0], refs[0][1] + 1),)).status == "rejected"
    assert prepare(db, credential, refs, lambda probe: profile.check_model_source(credential, probe), context=context).status == "succeeded"
    assert dispatch_excerpts(dispatch_case).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.external_call").fetchone() == (0,)


def test_model_dispatch_concurrent_workers_cannot_send_the_same_attempt_twice(dispatch_case, monkeypatch):
    from enterprise_kb.modules.access import model_dispatch

    db, profile, credential, _, _, _ = dispatch_case
    connection, tenant, url, source, store = db
    barrier = Barrier(2, timeout=5)
    receiver = model_dispatch._receive_synthetic_payload
    received = []

    def observe(payload):
        received.append(payload)
        return receiver(payload)

    def send():
        checks = []

        def authorize(probe):
            checks.append(probe)
            if len(checks) == 2:
                barrier.wait()
            return profile.check_model_source(credential, probe)

        with open_database(url) as worker:
            return dispatch_excerpts(((worker, tenant, url, source, store), *dispatch_case[1:]), authorize).status

    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", observe)
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(send) for _ in range(2)]
        assert sorted(future.result() for future in futures) == ["rejected", "succeeded"]
    assert len(received) == 1
    assert connection.execute("SELECT count(*) FROM thalion.external_call_receipt").fetchone() == (1,)


def test_model_dispatch_leaves_no_confirmed_receipt_when_receiver_digest_differs(dispatch_case, monkeypatch):
    from enterprise_kb.modules.access import model_dispatch

    db, _, _, _, _, _ = dispatch_case
    connection, *_ = db
    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", lambda payload: sha256(payload + b" ").digest())
    assert dispatch_excerpts(dispatch_case).status == "outcome_unknown"
    assert dispatch_excerpts(dispatch_case).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.external_call_receipt").fetchone() == (0,)


def test_model_dispatch_does_not_send_on_a_lease_lost_during_exact_check(dispatch_case, monkeypatch):
    from enterprise_kb.modules.access import model_dispatch

    db, profile, credential, _, lease, _ = dispatch_case
    connection, tenant, url, *_ = db
    checks = []
    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", lambda *args: pytest.fail("unexpected dispatch"))

    def authorize(probe):
        checks.append(probe)
        if len(checks) == 2:
            with open_database(url) as worker:
                expire(worker, lease)
                assert claim_job(worker, tenant.org_id, lease.spec.stage, tenant.other_worker_id, LEASE_FOR).generation == 2
        return profile.check_model_source(credential, probe)

    assert dispatch_excerpts(dispatch_case, authorize).status == "lease_lost"
    assert len(checks) == 2
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.external_call").fetchone() == (0,)


@pytest.mark.parametrize("change", ["expired_proof", "expired_lease", "local_policy", "source_revoked", "source_unavailable", "intent_retired"])
def test_model_dispatch_rechecks_lease_policy_and_source_after_commit(dispatch_case, revocation_authority, monkeypatch, change):
    from enterprise_kb.modules.access import model_dispatch

    db, profile, credential, _, lease, refs = dispatch_case
    connection, tenant, url, *_ = db
    original = model_dispatch.prepare_synthetic_model_excerpts
    lease_after_commit = None

    def lease_times(tx):
        return tx.execute("""
            SELECT generation, outcome, lease_expires_at, clock_timestamp()
            FROM thalion.job_attempt WHERE org_id = %s AND attempt_id = %s
        """, (tenant.org_id, lease.attempt_id)).fetchone()

    def reject_dispatch(*args):
        if change == "expired_lease":
            pytest.fail(f"unexpected dispatch: after expiry update {lease_after_commit!r}; at receiver {lease_times(connection)!r}")
        pytest.fail("unexpected dispatch")

    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", reject_dispatch)

    def change_after_commit(*args, **kwargs):
        nonlocal lease_after_commit
        result = original(*args, **kwargs)
        if result.status != "succeeded":
            return result
        with open_database(url) as independent:
            if change == "expired_proof":
                class ExpiredClock:
                    @staticmethod
                    def now(tz):
                        return result.valid_until.astimezone(tz)

                monkeypatch.setattr(model_dispatch, "datetime", ExpiredClock)
            elif change == "expired_lease":
                expire(independent, lease)
            elif change == "local_policy":
                independent.execute("UPDATE thalion.space SET safety_epoch = safety_epoch + 1 WHERE space_id = %s", (tenant.space_id,))
            elif change == "source_revoked":
                authority_db, source, _ = revocation_authority
                source_revocations.revoke(authority_db, source.authority_ref, tenant.space_ref, credential.employee_ref,
                                          refs[0][0], "evidence", basis_ref=uuid4())
            elif change == "intent_retired":
                call_id, = independent.execute("SELECT call_id FROM thalion.external_call").fetchone()
                external.mark_call_unknown(independent, tenant.org_id, call_id)
        if change == "expired_lease":
            with open_database(url) as observer:
                lease_after_commit = lease_times(observer)
            generation, outcome, expires_at, observed_at = lease_after_commit
            assert (generation, outcome) == (lease.generation, "running")
            assert expires_at <= observed_at, f"Committed lease is still valid: {lease_after_commit!r}"
        return result

    def authorize(probe):
        if change == "source_unavailable" and connection.execute("SELECT count(*) FROM thalion.external_call").fetchone() == (1,):
            raise AuthorizationUnavailable("Synthetic authority unavailable after dispatch intent.")
        return profile.check_model_source(credential, probe)

    monkeypatch.setattr(model_dispatch, "prepare_synthetic_model_excerpts", change_after_commit)
    assert dispatch_excerpts(dispatch_case, authorize).status == "outcome_unknown"
    assert dispatch_excerpts(dispatch_case).status == "rejected"
    assert connection.execute("SELECT state FROM thalion.external_call").fetchall() == [("outcome_unknown",)]
    assert connection.execute("SELECT count(*) FROM thalion.external_call_receipt").fetchone() == (0,)
