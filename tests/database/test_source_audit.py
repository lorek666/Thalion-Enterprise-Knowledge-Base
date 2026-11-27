from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.operations import source_audit
from enterprise_kb.modules.sources import registry
from enterprise_kb.transport import api

import test_backup_expiry as backup_expiry
import test_backup_inventory as backup
import test_original_export as archive
from test_backup_inventory import backup_inventory
from test_deletion_tombstone import approved, register, submitted
from test_disposition_cases import candidate, submit
from test_disposition_verification import original
from test_employee_original_download import download_path, downloads, grant_original
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_ingest_transport import MARKDOWN, file, upload
from test_original_export import archive_fixture
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_sources import request_for
from test_travel_search import BEFORE, BEGIN, SEARCH_FIELDS, approve as approve_rule, corpus, publish


READ = "read_source_audit"


def audit(client, token, source, *, query=""):
    return client.get(f"/internal/sources/{source}/audit{query}", headers=bearer(token))


def assert_operations(client, owner, source, expected):
    response = audit(client, owner, source)
    assert response.status_code == 200, response.text
    records = {row["request_id"]: row["operation"] for row in response.json()["requests"]}
    assert {request_id: records.get(request_id) for request_id in expected} == expected


def test_source_audit_correlates_http_ingest_and_collector_attempts(transport):
    client, db, (owner, _), credentials, *_ = transport
    source = db[3]
    admit(credentials, owner, READ, "upload_source_batch")
    document = file("audit.md", "Private batch title", "A", "audit-ingest", MARKDOWN)
    first = upload(client, owner, source, [document], "audit-attempt")
    replay = upload(client, owner, source, [document], "audit-attempt")
    conflict = upload(client, owner, source, [document | {"title": "Changed"}], "audit-attempt")
    assert first.status_code == replay.status_code == 200
    assert conflict.status_code == 409
    operations = {}
    for attempt in (first.json(), replay.json()):
        operations[attempt["request_id"]] = "upload_source_batch"
        operations[attempt["ingestion_request_id"]] = "register_version"
    assert_operations(client, owner, source, operations)
    missing = audit(client, owner, source, query=f"?request_id={conflict.json()['request_id']}")
    assert missing.json()["requests"] == []


def test_source_audit_correlates_backup_lifecycle(backup_inventory):
    ((client, db, (owner, reviewer), credentials, *_), _, (version, *_)), root = backup_inventory
    source = db[3]
    admit(credentials, owner, READ)
    admit(credentials, reviewer, backup.REGISTER, backup_expiry.SCHEDULE, backup_expiry.OBSERVE)
    backup_id = uuid4()
    stored = backup.store_copy(root, backup_id, original(db, version).read_bytes())
    enrolled = backup.register(client, reviewer, version, backup_id)
    assert enrolled.status_code == 200, enrolled.text
    due = backup_expiry.withdraw_for_due_backup(db, version)
    planned = backup_expiry.schedule(client, reviewer, backup_id, due)
    assert planned.status_code == 200, planned.text
    stored.unlink()
    observed = backup_expiry.observe(client, reviewer, backup_id)
    assert observed.status_code == 200, observed.text
    assert_operations(client, owner, source, {
        enrolled.json()["request_id"]: backup.REGISTER,
        planned.json()["request_id"]: backup_expiry.SCHEDULE,
        observed.json()["request_id"]: backup_expiry.OBSERVE,
    })


def test_source_audit_correlates_archive_lifecycle(archive_fixture, evidence_transport):
    client, db, owner, reviewer, _, _, version = archive_fixture
    admit(evidence_transport[3], owner, READ)
    opened = archive.request(client, owner, version)
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    approved = archive.approve(client, reviewer, export_id)
    assert approved.status_code == 200, approved.text
    sealed = archive.command(client, owner, f"/{export_id}/seal")
    assert sealed.status_code == 200, sealed.text
    assert_operations(client, owner, db[3], {
        opened.json()["request_id"]: archive.REQUEST,
        approved.json()["request_id"]: archive.APPROVE,
        sealed.json()["request_id"]: archive.EXPORT,
    })


def test_source_audit_correlates_only_matched_disposition_replays(candidate):
    (client, db, (owner, _), credentials, *_), preview, _ = candidate
    admit(credentials, owner, READ)
    first = submit(client, owner, preview, key="audit-disposition")
    replay = submit(client, owner, preview, key="audit-disposition")
    conflict = submit(client, owner, preview, key="audit-disposition", reason="withdrawal")
    assert first.status_code == replay.status_code == 200 and conflict.status_code == 409
    assert first.json()["case_id"] == replay.json()["case_id"]
    assert_operations(client, owner, db[3], {
        response.json()["request_id"]: "submit_disposition_case" for response in (first, replay)
    })
    missing = audit(client, owner, db[3], query=f"?request_id={conflict.json()['request_id']}")
    assert missing.json()["requests"] == []


def test_source_audit_correlates_delivery_and_disposition_without_exposing_evidence(candidate):
    (client, db, (owner, reviewer), credentials, live, *_), _, (version, *_), = candidate
    connection, tenant, _, source, _ = db
    assert audit(client, owner, source).status_code == 403
    assert audit(client, "invalid", source).status_code == 401
    search = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海住宿", "business_date": BEFORE.isoformat(),
    }).json()
    assert len(search["passages"]) == 2
    case = submitted(client, owner, credentials, source, version, expected=1)
    approval = approved(client, reviewer, credentials, case)
    admit(credentials, reviewer, "register_deletion_tombstone", READ)
    tombstone = register(client, reviewer, case, approval).json()
    assert tombstone["state"] == "restore_blocked"
    admit(credentials, owner, READ)
    live.clear()
    denied = client.get(f"/v1/passages/{search['passages'][0]['passage_id']}", headers=bearer(owner))
    assert denied.status_code == 404
    assert audit(client, reviewer, source).status_code == 403

    response = audit(client, owner, source)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {"request_id", "source_id", "requests", "next_cursor"}
    assert body["source_id"] == str(source)
    records = {row["request_id"]: row for row in body["requests"]}
    assert len(records) == len(body["requests"])
    assert {records[request_id]["operation"] for request_id in (
        search["request_id"], case["request_id"], tombstone["request_id"],
    )} == {"search", "submit_disposition_case", "register_deletion_tombstone"}
    assert "approve_disposition_case" in {row["operation"] for row in records.values()}
    assert denied.json()["request_id"] not in records
    assert all(set(row) == {
        "request_id", "actor_id", "operation", "destination", "outcome",
        "started_at", "completed_at", "elapsed_ms",
    } for row in records.values())
    assert all(row["outcome"] == "succeeded" for row in records.values())
    assert "上海" not in response.text and "Synthetic plan" not in response.text
    assert case["inventory_snapshot"] not in response.text and owner not in response.text
    assert str(version.version_ref) not in response.text

    exact = audit(client, owner, source, query=f"?request_id={search['request_id']}")
    assert exact.json()["requests"] == [records[search["request_id"]]]
    later = audit(client, owner, source, query=f"?request_id={exact.json()['request_id']}")
    assert [row["operation"] for row in later.json()["requests"]] == [READ]
    assert connection.execute("""
        SELECT principal_id, scope_space_id, operation, destination, outcome
        FROM thalion.request_record WHERE request_id = %s
    """, (exact.json()["request_id"],)).fetchone() == (
        tenant.actor_id, tenant.space_id, READ, "internal_audit", "succeeded",
    )
    listed = rpc(client, owner, "tools/list").json()["result"]["tools"]
    assert {tool["name"] for tool in listed} == {"search", "read_passage"}


def test_source_audit_projects_mixed_source_delivery_without_other_source_dependencies(transport):
    client, db, (owner, _), credentials, _, first, _ = transport
    connection, tenant, url, source, store = db
    second_source = registry.register_synthetic_source(
        connection, request_for(connection, tenant, tenant.actor_id, "audit-mixed-source", "register_source_contract"),
        tenant.space_id, registry.SyntheticSource(
            "audit-mixed", "audit-mixed", tenant.worker_id, approver_id=tenant.other_actor_id,
            processor_id=tenant.other_worker_id, quality_reviewer_id=tenant.actor_id,
        ),
    )
    second_db = connection, tenant, url, second_source, store
    version, passage, _ = publish(second_db, "audit-travel", "Private second source", "上海住宿补充说明。\n".encode())
    approve_rule(connection, tenant, version, BEGIN)
    set_rules(second_db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    admit(credentials, owner, READ)
    response = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海住宿", "business_date": BEFORE.isoformat(), "top_k": 5,
    })
    assert response.status_code == 200, response.text
    delivery = response.json()
    assert {str(first.passage_ref), str(passage.passage_ref)} <= {row["passage_id"] for row in delivery["passages"]}
    query = f"?request_id={delivery['request_id']}"
    primary = audit(client, owner, source, query=query)
    second = audit(client, owner, second_source, query=query)
    assert primary.status_code == second.status_code == 200
    assert primary.json()["requests"] == second.json()["requests"]
    row, = primary.json()["requests"]
    assert row["operation"] == "search" and row["request_id"] == delivery["request_id"]
    assert str(second_source) not in primary.text and str(passage.passage_ref) not in primary.text
    assert "Private second source" not in primary.text and "上海住宿" not in primary.text


def test_source_audit_cursor_and_exact_request_do_not_cross_source_or_current_ownership(transport, monkeypatch):
    client, db, (owner, other), credentials, _, first, _ = transport
    connection, tenant, _, source, _ = db
    other_source = registry.register_synthetic_source(
        connection, request_for(connection, tenant, tenant.actor_id, "audit-second-source", "register_source_contract"),
        tenant.space_id, registry.SyntheticSource("audit-second", "audit-other", tenant.worker_id),
    )
    admit(credentials, owner, READ)
    admit(credentials, other, READ)
    connection.execute("""
        ALTER TABLE thalion.request_record ALTER COLUMN started_at SET DEFAULT TIMESTAMPTZ '2020-01-01 00:00:00+00'
    """)
    seen = []
    for _ in range(21):
        response = client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(other))
        assert response.status_code == 200
        seen.append(response.json()["request_id"])
    connection.execute("""
        ALTER TABLE thalion.request_record ALTER COLUMN started_at SET DEFAULT clock_timestamp()
    """)
    seen.sort()
    connection.execute("""
        INSERT INTO thalion.request_record (
            org_id, scope_space_id, request_id, principal_id, client_id, operation, destination,
            business_date, configuration_revision
        )
        SELECT %s, %s, gen_random_uuid(), %s, 'synthetic-audit-volume', 'search', 'employee', %s, 1
        FROM generate_series(1, 20000)
    """, (tenant.org_id, tenant.space_id, tenant.actor_id, BEFORE))
    connection.execute("""
        UPDATE thalion.request_record SET outcome = 'no_evidence', elapsed_ms = 1, completed_at = clock_timestamp()
        WHERE client_id = 'synthetic-audit-volume'
    """)
    connection.execute("ANALYZE thalion.request_record")
    list_requests = source_audit.list_source_requests
    plans = []

    def inspect_first_page(session, *args):
        execute = session.execute

        def explain(statement, params=None):
            if "WITH linked_requests" in statement:
                plan, = execute("EXPLAIN (ANALYZE, FORMAT JSON) " + statement, params).fetchone()
                plans.append(plan[0]["Plan"])
            return execute(statement, params)

        with monkeypatch.context() as patch:
            patch.setattr(session, "execute", explain)
            return list_requests(session, *args)

    with monkeypatch.context() as patch:
        patch.setattr(source_audit, "list_source_requests", inspect_first_page)
        page = audit(client, owner, source)

    def plan_nodes(node):
        yield node
        for child in node.get("Plans", ()):
            yield from plan_nodes(child)

    request_scans = [
        node for node in plan_nodes(plans[0]) if node.get("Relation Name") == "request_record" and node["Actual Loops"]
    ]
    assert request_scans and all(node["Node Type"] in {"Index Scan", "Index Only Scan"} for node in request_scans)
    assert page.status_code == 200
    result = page.json()
    assert [row["request_id"] for row in result["requests"]] == seen[:0:-1]
    cursor = result["next_cursor"]
    assert cursor == seen[1]
    assert audit(client, owner, source, query=f"?after={cursor}&request_id={seen[0]}").status_code == 400
    assert audit(client, owner, other_source, query=f"?after={cursor}").status_code == 400
    unknown = audit(client, owner, other_source, query=f"?request_id={uuid4()}")
    foreign = audit(client, owner, other_source, query=f"?request_id={seen[0]}")
    assert unknown.status_code == foreign.status_code == 200
    assert unknown.json()["requests"] == foreign.json()["requests"] == []
    older = audit(client, owner, source, query=f"?after={cursor}").json()
    assert [row["request_id"] for row in older["requests"]] == [seen[0]]
    assert older["next_cursor"] is None
    assert audit(client, other, source).status_code == audit(client, owner, uuid4()).status_code == 403
    connection.execute("""
        UPDATE thalion.source SET owner_principal_id = %s
        WHERE (org_id, space_id, source_key) = (%s, %s, 'audit-second')
    """, (tenant.other_actor_id, tenant.org_id, tenant.space_id))
    assert audit(client, owner, other_source).status_code == 403
    connection.execute("UPDATE thalion.space SET owner_principal_id = %s", (tenant.other_actor_id,))
    assert audit(client, owner, source, query=f"?after={cursor}").status_code == 403


def test_source_audit_reads_original_delivery_metadata_without_opening_the_file(downloads, monkeypatch):
    client, connection, _, service, owner, _, version, _, db, _ = downloads
    grant_original(db, version)
    assert client.get(download_path(version), headers=bearer(owner)).status_code == 200
    request_id, = connection.execute("SELECT request_id FROM thalion.original_download_receipt").fetchone()
    credential = service.verify_token(owner)
    credentials = {owner: replace(credential, operations=credential.operations | {READ})}
    monkeypatch.setattr(service, "verify_token", credentials.get)

    def refuse_original(_asset):
        raise AssertionError("Audit metadata must not open an original.")

    monkeypatch.setattr(service.store, "read", refuse_original)
    result = audit(client, owner, db[3], query=f"?request_id={request_id}")
    assert result.status_code == 200
    record, = result.json()["requests"]
    assert (record["request_id"], record["operation"], record["outcome"]) == (str(request_id), "download_original", "succeeded")


def test_source_audit_discards_results_if_credentials_change_before_release(transport, monkeypatch):
    client, db, (owner, _), credentials, _, first, _ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, READ)
    read = client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).json()
    list_source_requests = source_audit.list_source_requests

    def revoke_before_release(*args):
        result = list_source_requests(*args)
        assert len(result["requests"]) == 1
        del credentials[owner]
        return result

    monkeypatch.setattr(source_audit, "list_source_requests", revoke_before_release)
    response = audit(client, owner, source, query=f"?request_id={read['request_id']}")
    assert response.status_code == 401 and "requests" not in response.json()
    assert connection.execute("SELECT count(*) FROM thalion.source_audit_access").fetchone() == (0,)
    assert connection.execute(
        "SELECT outcome FROM thalion.request_record WHERE request_id = %s", (response.json()["request_id"],),
    ).fetchone() == ("rejected",)


@pytest.mark.parametrize(
    ("change", "status"), [("credential", 401), ("space_owner", 403), ("source_owner", 403)],
)
def test_source_audit_rechecks_authority_at_http_dispatch(transport, monkeypatch, change, status):
    client, db, (owner, _), credentials, _, first, _ = transport
    connection, tenant, _, source, _ = db
    admit(credentials, owner, READ)
    read = client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).json()
    changed = False

    def change_at_dispatch():
        nonlocal changed
        if not changed:
            changed = True
            if change == "credential":
                del credentials[owner]
            elif change == "space_owner":
                connection.execute("""
                    UPDATE thalion.space SET owner_principal_id = %s WHERE (org_id, space_id) = (%s, %s)
                """, (tenant.other_actor_id, tenant.org_id, tenant.space_id))
            else:
                connection.execute("""
                    UPDATE thalion.source SET owner_principal_id = %s WHERE (org_id, space_id) = (%s, %s)
                """, (tenant.other_actor_id, tenant.org_id, tenant.space_id))
        return datetime.now(UTC)

    monkeypatch.setattr(api, "release_time", change_at_dispatch)
    result = audit(client, owner, source, query=f"?request_id={read['request_id']}")
    assert changed and result.status_code == status
    assert set(result.json()) == {"request_id", "error"}
    assert read["request_id"] not in result.text
    assert connection.execute("SELECT count(*) FROM thalion.source_audit_access").fetchone() == (0,)
    assert connection.execute(
        "SELECT outcome FROM thalion.request_record WHERE request_id = %s", (result.json()["request_id"],),
    ).fetchone() == ("rejected",)


def test_source_audit_rechecks_credential_after_durable_admission(transport, monkeypatch):
    client, db, (owner, _), credentials, _, first, _ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, READ)
    read = client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).json()
    record_access = source_audit.record_access

    def revoke_during_recording(*args):
        record_access(*args)
        del credentials[owner]

    monkeypatch.setattr(source_audit, "record_access", revoke_during_recording)
    response = audit(client, owner, source, query=f"?request_id={read['request_id']}")
    assert response.status_code == 401
    assert set(response.json()) == {"request_id", "error"}
    assert read["request_id"] not in response.text
    assert connection.execute(
        "SELECT request_id FROM thalion.source_audit_access",
    ).fetchone() == (UUID(response.json()["request_id"]),)
