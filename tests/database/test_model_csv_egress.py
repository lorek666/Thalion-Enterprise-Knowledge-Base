from dataclasses import replace
from hashlib import sha256
import json
from uuid import uuid4

import pytest

from enterprise_kb.modules.access import model_dispatch
from enterprise_kb.modules.sources import registry, source_revocations
from enterprise_kb.runtime import external
from enterprise_kb.runtime.jobs import JobSpec, claim_job

from test_csv_alternatives import ALTERNATES, first_rule, publish_table
from test_csv_delivery import permit
from test_csv_linked_exceptions import linked_layout
from test_evidence_transport import evidence_transport, private_json, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_model_egress_delivery import dispatch_excerpts, prepare
from test_model_egress_policy import evidence_db, model_policy_path, rule_for
from test_model_source_authority import GRANTS, grant_for, model_probe
from test_persisted_access import ingress, set_rules
from test_runtime import LEASE_FOR, runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_sources import request_for
from test_travel_search import BEFORE, corpus


@pytest.fixture
def csv_egress(transport, evidence_transport, revocation_authority):
    client, db, (owner, approver), credentials, *_ = transport
    connection, tenant, _, _, store = db
    credential, scope, _ = model_probe(evidence_transport)
    contract = request_for(connection, tenant, tenant.actor_id, "csv-model-contract", "register_source_contract")
    source = registry.register_synthetic_source(connection, contract, tenant.space_id, registry.SyntheticSource(
        "model-csv", "model-csv-files", tenant.worker_id, processor_id=tenant.other_worker_id,
        quality_reviewer_id=tenant.actor_id, approver_id=tenant.other_actor_id,
        csv_amount_layout=replace(linked_layout(), alternate_columns=ALTERNATES),
        model_policy_approver_id=tenant.other_actor_id,
    ))
    amounts = (*db[:3], source, store)
    _, cells = publish_table(amounts)
    primary = first_rule(cells)
    alternative = first_rule(cells, unit_column=7, note_column=8)
    second = tuple(cells[position] for position in ((3, 1), (3, 2), (3, 3), (3, 5), (4, 8), (4, 6)))
    inline = tuple(cells[5, column] for column in range(1, 5))
    allowed = tuple(dict.fromkeys(primary + alternative + second + inline + (cells[2, 9],)))
    assert set_rules(amounts, *(permit(tenant.actor_id, cell) for cell in allowed)) == 2
    admit(credentials, approver, "replace_model_policy")
    response = client.post(model_policy_path(source), headers=command_headers(approver), json={
        "expected_epoch": 2, "basis_id": str(uuid4()),
        "rules": [rule_for(credentials[owner].employee_ref, cell.passage_ref) for cell in allowed],
    })
    assert response.status_code == 200
    profile = revocation_authority[2]
    private_json(profile.root / "source-grants.json", {str(credential.employee_ref): [str(cell.passage_ref) for cell in allowed]})
    private_json(profile.root / GRANTS, [
        grant_for(credential, replace(scope, object_id=cell.passage_ref, revision=cell.revision)) for cell in allowed
    ])
    return amounts, profile, credential, alternative, second, inline, cells


def references(cells):
    return tuple((cell.passage_ref, cell.revision) for cell in cells)


def test_csv_model_dispatch_sends_exact_complete_groups_with_shared_exception_and_selected_alternatives(csv_egress, monkeypatch):
    db, profile, credential, alternative, second, inline, cells = csv_egress
    connection, tenant, *_ = db
    refs = references(tuple(dict.fromkeys(alternative + second + inline)))
    audited = ingress(db, tenant.actor_id, BEFORE, operation="send_model_evidence.model_answer",
                      purpose="model_answer", destination="synthetic-gateway", space_id=tenant.space_id)
    context = replace(audited, operation="send_model_evidence")
    digest = model_dispatch.synthetic_model_job_digest(context, refs, region=credential.region, traveler_class=credential.traveler_class)
    spec = JobSpec(tenant.org_id, tenant.space_id, tenant.space_ref, model_dispatch.MODEL_JOB_STAGE, digest, 1)
    external.enqueue_external_job(connection, spec, external.CallBudget("CNY", 0, 1), request_id=context.request_id)
    lease = claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR)
    received = []
    receiver = model_dispatch._receive_synthetic_payload

    def observe(payload):
        received.append(payload)
        return receiver(payload)

    monkeypatch.setattr(model_dispatch, "_receive_synthetic_payload", observe)
    sent = dispatch_excerpts((db, profile, credential, context, lease, refs))
    assert sent.status == "succeeded"
    assert len(received) == 1 and sent.input_digest == sha256(received[0]).digest()
    common = {"unit": "元/晚", "exception": "会议统一安排除外", "exception_ref": "meeting", "exception_key": "meeting"}
    assert json.loads(received[0]) == {"excerpts": [], "csv_units": [
        common | {"amount": "600", "condition": "普通员工"},
        common | {"amount": "750", "condition": "驻点员工"},
        {"amount": "300", "unit": "元/晚", "condition": "实习员工", "exception": "无"},
    ]}
    assert connection.execute("""
        SELECT part.passage_ref, part.excerpt_revision
        FROM thalion.delivery_dependency AS part JOIN thalion.delivery_record USING (org_id, check_id)
        WHERE request_id = %s ORDER BY part.position
    """, (context.request_id,)).fetchall() == list(refs)
    assert cells[2, 2].passage_ref not in {ref for ref, _ in refs}
    assert cells[4, 4].passage_ref not in {ref for ref, _ in refs}


def test_csv_model_egress_rejects_partial_ambiguous_and_unsupported_groups_before_read(csv_egress, monkeypatch):
    db, profile, credential, alternative, _, _, cells = csv_egress
    connection, tenant, _, _, store = db
    monkeypatch.setattr(type(store), "read", lambda *args: pytest.fail("A partial CSV group cannot open its original."))
    authorize = lambda probe: profile.check_model_source(credential, probe)
    for selected in (alternative[:-1], alternative + (cells[2, 2],), alternative + (cells[2, 9],)):
        result = prepare(db, credential, references(selected), authorize)
        assert (result.status, result.payload) == ("rejected", None)
    grants_path = profile.root / GRANTS
    grants = json.loads(grants_path.read_bytes())
    private_json(grants_path, [
        grant for grant in grants if grant["passage_id"] != str(alternative[1].passage_ref)
    ])
    denied = prepare(db, credential, references(alternative), authorize)
    assert (denied.status, denied.payload) == ("rejected", None)
    private_json(grants_path, grants)
    assert set_rules(db, permit(tenant.actor_id),
                     *(permit(tenant.actor_id, cell) for cell in alternative if cell != alternative[1]), expected=3) == 4
    denied = prepare(db, credential, references(alternative), authorize)
    assert (denied.status, denied.payload) == ("rejected", None)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_csv_model_egress_does_not_replace_a_revoked_alternative_at_final_check(csv_egress, revocation_authority):
    db, profile, credential, alternative, second, _, _ = csv_egress
    connection, tenant, *_ = db
    authority, source, _ = revocation_authority
    checks = []

    def revoke_shared_note(probe):
        checks.append(probe)
        if len(checks) == 2:
            source_revocations.revoke(authority, source.authority_ref, tenant.space_ref, credential.employee_ref,
                                      alternative[-2].passage_ref, "evidence", basis_ref=uuid4())
        return profile.check_model_source(credential, probe)

    refs = references(tuple(dict.fromkeys(alternative + second)))
    result = prepare(db, credential, refs, revoke_shared_note)
    assert (result.status, result.payload) == ("rejected", None)
    assert len(checks) == 2 and {(scope.object_id, scope.revision) for scope in checks[-1].scopes} == set(refs)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)
