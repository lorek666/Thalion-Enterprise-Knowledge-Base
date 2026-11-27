from dataclasses import replace
from hashlib import sha256
import json
from uuid import uuid4

import pytest

from enterprise_kb.modules.access import model_dispatch
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.runtime import external
from enterprise_kb.runtime.jobs import JobSpec, claim_job

from test_docx_review import docx_table_review, locate
from test_docx_table_delivery import ready_docx_table
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, private_json, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_model_egress_delivery import dispatch_excerpts, prepare
from test_model_egress_policy import model_policy_path, rule_for
from test_model_source_authority import GRANTS
from test_persisted_access import binding, ingress, set_rules
from test_runtime import LEASE_FOR, runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_travel_search import BEFORE, corpus


@pytest.fixture
def docx_egress(ready_docx_table, transport, docx_table_review, revocation_authority):
    _, db, _, row = ready_docx_table
    client, _, (owner, approver), credentials, *_ = transport
    connection, _, _, source, _ = db
    _, _, _, _, run = docx_table_review
    nonmember = next(ref for ref, in locate(connection, run) if ref not in row.values())
    refs = tuple((ref, 1) for ref in (*row.values(), nonmember))
    credential = credentials[owner]
    admit(credentials, approver, "replace_model_policy")
    assert client.post(model_policy_path(source), headers=command_headers(approver), json={
        "expected_epoch": 2, "basis_id": str(uuid4()),
        "rules": [rule_for(credential.employee_ref, ref) for ref, _ in refs],
    }).status_code == 200
    profile = revocation_authority[2]
    private_json(profile.root / "source-grants.json", {str(credential.employee_ref): [str(ref) for ref, _ in refs]})
    private_json(profile.root / GRANTS, [
        {"employee_ref": str(credential.employee_ref), "purpose": "model_answer", "passage_id": str(ref),
         "revision": revision, "fields": ["excerpt"]} for ref, revision in refs
    ])
    return db, profile, credential, refs[:-1], refs[-1]


def enqueue(docx_egress):
    db, profile, credential, refs, _ = docx_egress
    connection, tenant, *_ = db
    context = ingress(db, tenant.actor_id, BEFORE, operation="send_model_evidence.model_answer",
                      purpose="model_answer", destination="synthetic-gateway", space_id=tenant.space_id)
    context = replace(context, operation="send_model_evidence")
    digest = model_dispatch.synthetic_model_job_digest(
        context, refs, region=credential.region, traveler_class=credential.traveler_class,
    )
    spec = JobSpec(tenant.org_id, tenant.space_id, tenant.space_ref, model_dispatch.MODEL_JOB_STAGE, digest, 1)
    external.enqueue_external_job(connection, spec, external.CallBudget("CNY", 0, 1), request_id=context.request_id)
    return db, profile, credential, context, claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR), refs


def test_docx_model_dispatch_receives_only_the_literal_role_values_and_seals_all_revisions(docx_egress, monkeypatch):
    case = enqueue(docx_egress)
    db, profile, credential, context, _, refs = case
    connection, *_ = db
    received, checks = [], []
    receiver = model_dispatch._receive_synthetic_payload

    def observe(payload):
        received.append(payload)
        return receiver(payload)

    def authorize(probe):
        checks.append(probe)
        return profile.check_model_source(credential, probe)

    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", observe)
    result = dispatch_excerpts(case, authorize)
    assert result.status == "succeeded"
    payload, = received
    assert json.loads(payload) == {"excerpts": [], "docx_units": [{
        "amount": "0600.50", "unit": "元/人·晚", "condition": "上海正式员工", "exception": "会议统一安排除外。\n须另行审批。",
    }]}
    assert len(checks) == 3
    assert all({(scope.object_id, scope.revision, scope.fields) for scope in probe.scopes} == {
        (ref, revision, frozenset({"excerpt"})) for ref, revision in refs
    } for probe in checks)
    assert checks[1].payload_sha256 == checks[2].payload_sha256 == sha256(payload).hexdigest()
    assert result.input_digest == sha256(payload).digest()
    assert connection.execute("""
        SELECT part.passage_ref, part.excerpt_revision
        FROM thalion.delivery_dependency AS part JOIN thalion.delivery_record USING (org_id, check_id)
        WHERE request_id = %s ORDER BY part.position
    """, (context.request_id,)).fetchall() == list(refs)


@pytest.mark.parametrize("missing", ["selection", "model_rule", "employee_rule", "model_grant", "employee_grant"])
def test_docx_model_egress_requires_all_exact_permissions_before_opening_the_original(docx_egress, transport, monkeypatch, missing):
    db, profile, credential, refs, nonmember = docx_egress
    connection, tenant, _, source, store = db
    client, _, (_, approver), *_ = transport
    selected = [refs]
    if missing == "selection":
        selected = [refs[:-1], refs[:-1] + (nonmember,), refs + (nonmember,), refs[:-1] + ((refs[-1][0], 2),)]
    elif missing == "model_rule":
        assert client.post(model_policy_path(source), headers=command_headers(approver), json={
            "expected_epoch": 3, "basis_id": str(uuid4()),
            "rules": [rule_for(credential.employee_ref, ref) for ref, _ in refs[:-1]],
        }).status_code == 200
    elif missing == "employee_rule":
        set_rules(db, binding(tenant.actor_id), *(binding(tenant.actor_id, passage_ref=ref) for ref, _ in refs[:-1]), expected=3)
    elif missing == "model_grant":
        grants = json.loads((profile.root / GRANTS).read_bytes())
        private_json(profile.root / GRANTS, [item for item in grants if item["passage_id"] != str(refs[-1][0])])
    else:
        private_json(profile.root / "source-grants.json", {str(credential.employee_ref): [str(ref) for ref, _ in refs[:-1]]})
    monkeypatch.setattr(store, "read", lambda *args: pytest.fail("A partly authorized DOCX row must not open its original."))
    for references in selected:
        result = prepare(db, credential, references, lambda probe: profile.check_model_source(credential, probe))
        assert (result.status, result.payload) == ("rejected", None)
    assert connection.execute("""
        SELECT 1 FROM thalion.delivery_record JOIN thalion.request_record USING (org_id, request_id)
        WHERE destination = 'synthetic-gateway'
    """).fetchone() is None


@pytest.mark.parametrize(("revoke_on", "status"), [(2, "rejected"), (3, "outcome_unknown")])
def test_docx_model_dispatch_rechecks_each_cell_before_sealing_and_before_receipt(
    docx_egress, revocation_authority, monkeypatch, revoke_on, status,
):
    case = enqueue(docx_egress)
    db, profile, credential, context, _, refs = case
    connection, tenant, *_ = db
    authority, source, _ = revocation_authority
    checks = []

    def authorize(probe):
        checks.append(probe)
        if len(checks) == revoke_on:
            source_revocations.revoke(authority, source.authority_ref, tenant.space_ref, credential.employee_ref,
                                      refs[-1][0], "evidence", basis_ref=uuid4())
        return profile.check_model_source(credential, probe)

    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", lambda *args: pytest.fail("Revoked DOCX row dispatched."))
    result = dispatch_excerpts(case, authorize)
    assert (result.status, result.input_digest) == (status, None)
    assert len(checks) == revoke_on
    assert {(scope.object_id, scope.revision) for scope in checks[-1].scopes} == set(refs)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record WHERE request_id = %s",
                              (context.request_id,)).fetchone() == (revoke_on - 2,)
