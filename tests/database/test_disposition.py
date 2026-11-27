from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.lifecycle import disposition
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from test_effectivity import BEGIN, SWITCH, approve
from test_evidence import claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_findings import CAPABILITY, conflict, report
from test_gaps import command_headers
from test_identity import space
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_travel_search import corpus, publish
from test_wiki_inputs import assemble
from test_wiki_publication import configure as authorize_wiki


PLAN = "/internal/lifecycle/disposition-preview"
POLICY = "/internal/lifecycle/retention-policy"


def configure(client, token, source, *, days=0, expected=0, action="archive", key=None, basis=None):
    return client.post(POLICY, headers=command_headers(token, key), json={
        "source_id": str(source), "expected_revision": expected, "keep_days": days,
        "action": action, "basis_id": str(basis or uuid4()),
    })


def plan(client, token, version, *, action="archive", reason="retention_expiry"):
    return client.post(PLAN, headers=bearer(token), json={
        "version_id": str(version), "action": action, "reason": reason,
    })


def versions(connection):
    return [row[0] for row in connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = 'document_version' ORDER BY object_id",
    ).fetchall()]


def test_disposition_preview_protects_both_conflict_sides_and_uncited_inputs(conflict):
    (client, db, (owner, _), credentials, _, *_), observations, _ = conflict
    connection, _, _, source, store = db
    admit(credentials, owner, CAPABILITY, "register_retention_policy", "plan_disposition")
    assert report(client, owner, observations).status_code == 200
    assert configure(client, owner, source).status_code == 200
    original_files = {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()}
    previous = {}
    for index, version in enumerate(versions(connection), 1):
        preview = plan(client, owner, version)
        assert preview.status_code == 200 and preview.headers["Cache-Control"] == "no-store"
        body = preview.json()
        assert body["decision"] == "protected" and not body["executable"]
        assert "conflict_evidence" in body["protections"]
        assert sum(item["kind"] == "wiki_revision" for item in body["copies"]) == index
        assert {item["state"] for item in body["copies"] if item["kind"] == "wiki_revision"} == {"protected"}
        assert "backup" in body["unverified_copy_kinds"] and "export" in body["unverified_copy_kinds"]
        assert all(observation["revision_id"] not in preview.text for observation in observations)
        previous[version] = body
    added = report(client, owner, observations, rule="statement_conflict")
    assert added.status_code == 200
    for version, first in previous.items():
        updated = plan(client, owner, version)
        assert updated.json()["protections"] == first["protections"] and updated.json()["copies"] == first["copies"]
        assert updated.json()["inventory_snapshot"] != first["inventory_snapshot"]
        assert added.json()["finding_id"] not in updated.text
    assert {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()} == original_files


def test_unprotected_local_copy_requires_policy_and_independent_review(transport):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "register_retention_policy", "plan_disposition")
    previous, _, _ = publish(db, "synthetic-unpublished", "未发布合成件", b"# Fixture\n\nIsolated historical copy.\n")
    assert plan(client, owner, previous.version_ref).json()["decision"] == "policy_missing"
    assert configure(client, owner, source, days=30).status_code == 200
    assert plan(client, owner, previous.version_ref).json()["decision"] == "retention_active"
    key, basis = str(uuid4()), uuid4()
    first = configure(client, owner, source, expected=1, key=key, basis=basis)
    assert first.status_code == 200 and first.json()["revision"] == 2
    assert configure(client, owner, source, expected=1, key=key, basis=basis).json()["policy_id"] == first.json()["policy_id"]
    assert configure(client, owner, source, expected=1).status_code == 409
    body = plan(client, owner, previous.version_ref).json()
    assert (body["decision"], body["executable"], body["approval_required"]) == ("review_required", False, True)
    assert {item["kind"] for item in body["copies"]} == {"original", "processing_manifest", "transcription"}
    assert plan(client, owner, previous.version_ref, action="destroy").json()["decision"] == "policy_disallows"
    assert connection.execute("SELECT revision FROM thalion.retention_policy_revision ORDER BY revision").fetchall() == [(1,), (2,)]


def test_local_inventory_binds_old_and_new_transcription_without_disclosing_copy_ids(transport):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, tenant, _, source, store = db
    admit(credentials, owner, "register_retention_policy", "plan_disposition")
    version, passage, first_run = publish(db, "copy-snapshot", "合成副本", b"# Local\n\nSynthetic copy.\n")
    assert configure(client, owner, source).status_code == 200

    first = plan(client, owner, version.version_ref).json()
    assert len(first["inventory_snapshot"]) == 64
    assert first["inventory_snapshot"] == plan(client, owner, version.version_ref).json()["inventory_snapshot"]
    assert first["inventory_snapshot"] != plan(client, owner, version.version_ref, action="destroy").json()["inventory_snapshot"]
    assert [item["kind"] for item in first["copies"]].count("transcription") == 1

    connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision WHERE configuration_revision = 1
    """)
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 2))
    second_run = processing.process_markdown_job(connection, claim(db), store)
    pending = plan(client, owner, version.version_ref).json()
    assert pending["inventory_snapshot"] != first["inventory_snapshot"]
    assert [item["kind"] for item in pending["copies"]].count("transcription") == 2
    review(db, second_run)
    approved = plan(client, owner, version.version_ref)
    assert approved.status_code == 200 and approved.json()["copies"] == pending["copies"]
    assert approved.json()["inventory_snapshot"] != pending["inventory_snapshot"]
    for internal in (passage.passage_ref, first_run.run_ref, second_run.run_ref):
        assert str(internal) not in approved.text
    assert approved.json()["executable"] is False
    epoch, = connection.execute("SELECT safety_epoch FROM thalion.source").fetchone()
    set_rules(db, binding(tenant.actor_id), expected=epoch)
    tightened = plan(client, owner, version.version_ref).json()
    assert tightened["copies"] == approved.json()["copies"]
    assert tightened["inventory_snapshot"] != approved.json()["inventory_snapshot"]


def test_plan_cannot_be_used_to_probe_other_spaces_or_bypass_current_effectivity(transport):
    client, db, (owner, employee), credentials, _, *_ = transport
    connection, tenant, _, source, _ = db
    version = versions(connection)[0]
    assert plan(client, owner, version).status_code == 403
    for token in (owner, employee):
        admit(credentials, token, "register_retention_policy", "plan_disposition")
    assert plan(client, employee, version).status_code == 403
    assert configure(client, employee, source).status_code == 403
    assert configure(client, owner, source).status_code == 200
    body = plan(client, owner, version).json()
    assert body["decision"] == "protected" and "current_effectivity" in body["protections"]
    assert plan(client, owner, version, reason="withdrawal").json()["decision"] == "reason_not_satisfied"
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[owner] = replace(credentials[owner], space_ref=other_space)
    assert plan(client, owner, version).status_code == 403
    assert configure(client, owner, source).status_code == 403


def test_sealed_base_without_a_wiki_revision_is_protected(transport):
    client, db, (owner, _), credentials, _, first, _ = transport
    connection, tenant, _, source, _ = db
    admit(credentials, owner, "register_retention_policy", "plan_disposition")
    version, cited, _ = publish(db, "base-input", "仅用于封存", b"# Fixture\n\nPrivate base fragment.\n")
    approve(connection, tenant, version, BEGIN, end=SWITCH)
    authorize_wiki(db, 2)
    base = assemble(db, (cited,))
    assert base.status == "succeeded"
    child = assemble(db, (first,), (base.manifest_ref,))
    assert child.status == "succeeded"
    assert configure(client, owner, source).status_code == 200
    preview = plan(client, owner, version.version_ref).json()
    assert (preview["decision"], preview["executable"]) == ("protected", False)
    assert set(preview["protections"]) == {"wiki_base_input", "wiki_full_input"}
    assert [item["state"] for item in preview["copies"] if item["kind"] == "wiki_input_manifest"] == [
        "protected", "protected",
    ]


def test_retention_writes_rollback_with_outbox_and_compete_on_revision(transport):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "register_retention_policy")
    connection.execute(
        "ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_retention_policy_event "
        "CHECK (event_type <> 'lifecycle.retention_policy.registered') NOT VALID"
    )
    stable_key = str(uuid4())
    assert configure(client, owner, source, key=stable_key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.retention_policy_revision").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_retention_policy_event")
    with ThreadPoolExecutor(max_workers=2) as workers:
        pending = [workers.submit(configure, client, owner, source, key=key) for key in (stable_key, str(uuid4()))]
        assert sorted(attempt.result(timeout=10).status_code for attempt in pending) == [200, 409]
    assert connection.execute("SELECT revision FROM thalion.retention_policy_revision").fetchall() == [(1,)]


def test_inventory_overflow_fails_without_a_partial_preview(transport, monkeypatch):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, *_ = db
    admit(credentials, owner, "plan_disposition")
    monkeypatch.setattr(disposition, "MAX_LOCAL_COPIES", 1)
    response = plan(client, owner, versions(connection)[0])
    assert response.status_code == 503
    assert set(response.json()) == {"request_id", "error"}
    outcome, = connection.execute(
        "SELECT outcome FROM thalion.request_record WHERE request_id = %s", (response.json()["request_id"],),
    ).fetchone()
    assert outcome == "dependency_unavailable"


def test_protection_fact_overflow_returns_no_inventory_snapshot(transport, monkeypatch):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, *_ = db
    admit(credentials, owner, "plan_disposition")
    monkeypatch.setattr(disposition, "MAX_LOCAL_FACTS", 0)
    response = plan(client, owner, versions(connection)[0])
    assert response.status_code == 503
    assert set(response.json()) == {"request_id", "error"}
