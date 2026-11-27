from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from enterprise_kb.database import upgrade
from enterprise_kb.modules.sources import registry

from test_access_policy_transport import policy_path, replace_policy
from test_evidence import create_evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_identity import migrate_to_revision
from test_persisted_access import binding, set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_sources import request_for
from test_travel_search import corpus


@pytest.fixture
def evidence_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    return create_evidence_db(connection, tenant, database_url, tmp_path, model_policy_approver_id=tenant.other_actor_id)


def model_policy_path(source):
    return f"/internal/sources/{source}/model-egress-policy"


def test_reader_credentials_cannot_read_or_register_model_egress_policy(transport):
    client, db, (owner, _), _, *_ = transport
    path = model_policy_path(db[3])
    assert client.get(path, headers=bearer(owner)).status_code == 403
    assert client.post(path, headers=command_headers(owner), json={}).status_code == 403


def rule_for(user, passage):
    now = datetime.now(UTC)
    return {
        "subject_id": str(user), "passage_id": str(passage), "operation": "send_model_evidence",
        "effect": "allow", "purpose": "model_answer", "destination": "synthetic-gateway", "fields": ["excerpt"],
        "valid_from": now.isoformat(), "valid_until": (now + timedelta(hours=1)).isoformat(),
    }


def test_only_independent_approver_can_replace_model_rules_and_local_policy_stays_separate(transport):
    client, db, (owner, approver), credentials, _, first, restricted = transport
    connection, tenant, _, source, _ = db
    path = model_policy_path(source)
    local_path = policy_path(source)
    admit(credentials, owner, "read_local_policy", "replace_local_policy", "read_model_policy", "replace_model_policy")
    admit(credentials, approver, "read_model_policy", "replace_model_policy")
    assert client.get(path, headers=bearer(owner)).status_code == 403
    local = client.get(local_path, headers=bearer(owner)).json()
    snapshot = client.get(path, headers=bearer(approver)).json()
    assert snapshot["rules"] == [] and snapshot["policy_revision"] == local["policy_revision"]
    rule = rule_for(credentials[approver].employee_ref, restricted.passage_ref)
    command = {"expected_epoch": snapshot["safety_epoch"], "basis_id": str(uuid4()), "rules": [rule]}
    key = str(uuid4())
    assert client.post(path, headers=command_headers(owner), json=command).status_code == 403
    assert replace_policy(client, owner, source, command).status_code == 400
    granted = client.post(path, headers=command_headers(approver, key), json=command)
    assert granted.status_code == 200 and granted.headers["Cache-Control"] == "no-store"
    revision = granted.json()["policy_revision"]
    assert client.get(path, headers=bearer(approver)).json()["rules"] == [rule]
    assert client.get(local_path, headers=bearer(owner)).json()["rules"] == local["rules"]
    assert client.get(f"/v1/passages/{restricted.passage_ref}", headers=bearer(approver)).status_code == 404
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(approver)).status_code == 200
    assert client.post("/v1/search", headers=bearer(approver), json={
        "query": "上海住宿", "destination": "synthetic-gateway",
    }).status_code == 400
    tools = rpc(client, approver, "tools/list").json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == {"search", "read_passage"}
    updated = replace_policy(client, owner, source, {"expected_epoch": revision, "basis_id": str(uuid4()), "rules": []})
    assert updated.status_code == 200
    assert client.get(path, headers=bearer(approver)).json()["rules"] == [rule]
    revoked = {"expected_epoch": revision + 1, "basis_id": str(uuid4()), "rules": []}
    assert client.post(path, headers=command_headers(approver), json=revoked).status_code == 200
    assert client.post(path, headers=command_headers(approver, key), json=command).json()["policy_revision"] == revision
    assert client.get(path, headers=bearer(approver)).json()["rules"] == []
    assert client.post(path, headers=command_headers(approver), json=command).status_code == 409
    assert connection.execute("""
        SELECT operation, destination, scope_space_id, outcome FROM thalion.request_record WHERE request_id = %s
    """, (granted.json()["request_id"],)).fetchone() == (
        "replace_model_policy", "internal_access", tenant.space_id, "succeeded",
    )
    assert connection.execute("SELECT count(*) FROM thalion.external_call WHERE org_id = %s", (tenant.org_id,)).fetchone() == (0,)


def test_model_rules_require_a_scoped_passage_zoned_expiry_and_the_synthetic_destination(transport):
    client, db, (_, approver), credentials, _, first, _ = transport
    _, _, _, source, _ = db
    path = model_policy_path(source)
    admit(credentials, approver, "read_model_policy", "replace_model_policy")
    current = client.get(path, headers=bearer(approver)).json()
    rule = rule_for(credentials[approver].employee_ref, first.passage_ref)
    command = {"expected_epoch": current["safety_epoch"], "basis_id": str(uuid4()), "rules": [rule]}
    for invalid in (
        rule | {"destination": "employee"}, rule | {"destination": "other-gateway"},
        rule | {"purpose": "employee_evidence"}, rule | {"fields": ["original_page"]},
        rule | {"valid_until": "2026-11-23T00:00:00"},
        {name: value for name, value in rule.items() if name != "valid_until"},
        {name: value for name, value in rule.items() if name != "passage_id"},
    ):
        assert client.post(path, headers=command_headers(approver), json=command | {"rules": [invalid]}).status_code == 400
    outside = command | {"rules": [rule | {"passage_id": str(uuid4())}]}
    assert client.post(path, headers=command_headers(approver), json=outside).status_code == 403
    assert client.get(path, headers=bearer(approver)).json()["policy_revision"] == current["policy_revision"]


def test_model_contract_requires_a_designated_employee_independent_of_the_source_owner(transport):
    client, db, (owner, approver), credentials, *_ = transport
    connection, tenant, *_ = db
    context = request_for(connection, tenant, tenant.actor_id, "model-source", "register_source_contract")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_synthetic_source(connection, context, tenant.space_id, registry.SyntheticSource(
            "outbound-source", "outbound-namespace", tenant.worker_id, model_policy_approver_id=tenant.actor_id,
        ))
    source = registry.register_synthetic_source(connection, context, tenant.space_id, registry.SyntheticSource(
        "outbound-source", "outbound-namespace", tenant.worker_id, approver_id=tenant.other_actor_id,
    ))
    admit(credentials, approver, "read_model_policy", "replace_model_policy", "approve_effectivity")
    assert client.get(model_policy_path(source), headers=bearer(approver)).status_code == 403
    assert client.post(model_policy_path(source), headers=command_headers(approver), json={
        "expected_epoch": 1, "basis_id": str(uuid4()), "rules": [],
    }).status_code == 403


def test_model_policy_migration_leaves_existing_source_rules_and_approval_scope_unchanged(database_url, tmp_path):
    migrate_to_revision(database_url, "0075_document_responsibility")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Existing reader policy")
        db = create_evidence_db(connection, tenant, database_url, tmp_path)
        set_rules(db, binding(tenant.actor_id))
        legacy_rules = "SELECT to_jsonb(binding) - 'version_ref' FROM thalion.permission_binding AS binding"
        before = connection.execute(legacy_rules).fetchall()
        assert len(before) == 1
        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert connection.execute(legacy_rules).fetchall() == before
        assert connection.execute("SELECT model_policy_approver_id FROM thalion.source_contract_revision").fetchone() == (None,)
        assert connection.execute("SELECT safety_epoch, local_policy_revision FROM thalion.source").fetchone() == (2, 2)
