from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import (
    effectivity, permission_checkpoints, reconciliation, registry, source_restrictions, source_revocations, sync,
)
from enterprise_kb.runtime.jobs import claim_job, enqueue_job, retry_job
from enterprise_kb.transport import api

from test_deletion_tombstone import REGISTER as REGISTER_TOMBSTONE, approved, register as register_tombstone, submitted
from test_effectivity import record
from test_employee_portal import browser, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_identity import space
from test_ingest_transport import file as ingest_file, upload
from test_runtime import LEASE_FOR, register_tenant, runtime_db, spec_for
from test_source_reconciliation import manifest, reconcile
from test_source_restrictions import rotate_collector
from test_source_revocations import independent_authority, revocation_authority
from test_source_sync import sync_request
from test_sources import CONTENT, OTHER_CONTENT, candidate, request_for, source_for
from test_travel_search import corpus


OPERATION = "read_source_sync_status"


def status_path(source_ref):
    return f"/internal/sources/{source_ref}/sync-status"


def _register_source(connection, tenant, *, owner_id, key, namespace):
    context = request_for(connection, tenant, tenant.actor_id, f"create-{key}", "register_source_contract")
    source_ref = registry.register_synthetic_source(
        connection, context, tenant.space_id,
        registry.SyntheticSource(key, namespace, tenant.worker_id),
    )
    if owner_id != tenant.actor_id:
        with connection.transaction():
            connection.execute("""
                UPDATE thalion.source SET owner_principal_id = %s
                WHERE (org_id, space_id, source_id) = (
                    SELECT org_id, space_id, object_id FROM thalion.object_identity
                    WHERE (org_id, space_id, object_type, public_id) = (%s, %s, 'source', %s)
                )
            """, (owner_id, tenant.org_id, tenant.space_id, source_ref))
    return source_ref


def _seed_source_activity(client, db, credentials, owner, employee, revocation_authority):
    connection, tenant, _, source_ref, store = db
    authority, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)

    present = candidate(tenant, source_ref, object_key="secret-present-key", source_version_key="rev-1")
    omitted = candidate(tenant, source_ref, object_key="secret-omitted-key", source_version_key="rev-1")
    mismatched = candidate(tenant, source_ref, object_key="secret-mismatch-key", source_version_key="rev-1")
    empty_payload = b"   \n"
    quarantined_ver = candidate(
        tenant, source_ref, object_key="secret-quarantined-key", source_version_key="rev-1",
        digest=sha256(empty_payload).digest(),
    )
    page = sync.SourcePage(None, uuid4(), (
        sync.PageOriginal(present, CONTENT),
        sync.PageOriginal(omitted, CONTENT),
        sync.PageOriginal(mismatched, CONTENT),
        sync.PageOriginal(quarantined_ver, empty_payload),
    ))
    page_receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
    present_ref, omitted_ref, mismatched_ref, quarantined_ref = page_receipt.version_refs

    processor_id, = connection.execute("""
        SELECT contract.processor_id
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id) =
             (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
    """, (tenant.org_id, tenant.space_id, source_ref)).fetchone()
    assert processor_id is not None

    while True:
        lease = claim_job(connection, tenant.org_id, "parse", processor_id, LEASE_FOR)
        if lease is None:
            break
        if lease.spec.target_ref in (present_ref, quarantined_ref):
            processing.process_markdown_job(connection, lease, store)
        elif lease.spec.target_ref == omitted_ref:
            retry_job(connection, lease, delay=timedelta(hours=1))
        else:
            retry_job(connection, lease, delay=timedelta(minutes=30))

    enqueue_job(connection, replace(spec_for(tenant, "private-sync-stage"), target_ref=source_ref))

    entries = (
        reconciliation.InventoryEntry(present.object_key, present.incarnation, present.source_version_key, present.digest),
        reconciliation.InventoryEntry(
            mismatched.object_key, mismatched.incarnation, mismatched.source_version_key, sha256(OTHER_CONTENT).digest(),
        ),
        reconciliation.InventoryEntry("secret-missing-key", "first", "rev-a", sha256(OTHER_CONTENT).digest()),
    )
    declared = manifest(reconciliation, entries, content_position=page.through)
    inv_receipt = reconcile(reconciliation, connection, tenant, source, declared, entries)

    withdrawn_event = uuid4()
    withdrawn_stop = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "sync-status-withdraw"),
        tenant.space_id, mismatched_ref, "withdrawn", withdrawn_event,
    )
    source_restrictions.acknowledge_removal(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, source_restrictions.Removal(
            withdrawn_event, mismatched.object_key, mismatched.incarnation,
            mismatched.source_version_key, "withdrawn", withdrawn_stop,
        ),
    )

    deleted_event = uuid4()
    omitted_original = SimpleNamespace(version_ref=omitted_ref)
    case = submitted(client, owner, credentials, source_ref, omitted_original)
    approval = approved(client, employee, credentials, case, basis=deleted_event)
    admit(credentials, employee, REGISTER_TOMBSTONE)
    tombstone = register_tombstone(client, employee, case, approval)
    assert tombstone.status_code == 200, tombstone.text
    source_restrictions.acknowledge_removal(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, source_restrictions.Removal(
            deleted_event, omitted.object_key, omitted.incarnation,
            omitted.source_version_key, "deleted", UUID(tombstone.json()["tombstone_id"]),
        ),
    )

    rev1 = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        present_ref, "evidence", basis_ref=uuid4(),
    )
    source_restrictions.acknowledge_revocation(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, rev1.decision_ref, trusted,
    )
    cp1 = permission_checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=permission_checkpoints.COMMIT),
        source, uuid4(), None, trusted,
    )
    rev2 = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[owner].employee_ref,
        present_ref, "evidence", basis_ref=uuid4(),
    )
    source_restrictions.acknowledge_revocation(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, rev2.decision_ref, trusted,
    )

    return {
        "source": source,
        "page": page_receipt,
        "inventory": inv_receipt,
        "checkpoint": cp1,
        "rev1": rev1,
        "rev2": rev2,
        "trusted": trusted,
    }


def test_sync_status_requires_scoped_owner_grant_and_isolates_watermarks_and_backlogs(transport, revocation_authority):
    client, db, (owner, employee), credentials, live, *_ = transport
    connection, tenant, _, source_ref, _ = db
    seeded = _seed_source_activity(client, db, credentials, owner, employee, revocation_authority)

    admit(credentials, owner, "upload_source_batch")
    bad_upload = upload(
        client, owner, source_ref,
        [ingest_file("secret-bad.exe", "Forbidden Binary", "A", "bad-obj", b"MZ\x00\x01")],
        "sync-status-rejected",
    )
    assert bad_upload.status_code == 200

    other_source_ref = _register_source(
        connection, tenant, owner_id=tenant.other_actor_id, key="colleague-source", namespace="colleague-ns",
    )
    enqueue_job(connection, replace(spec_for(tenant, "parse"), target_ref=other_source_ref))
    enqueue_job(connection, spec_for(tenant, "parse"))
    with connection.transaction():
        other_space_id, other_space_ref = space(connection, tenant.org_id, tenant.actor_id)
    other_space_tenant = replace(tenant, space_id=other_space_id, space_ref=other_space_ref)
    other_space_source = _register_source(
        connection, other_space_tenant, owner_id=tenant.actor_id, key="other-space-source", namespace="other-space-ns",
    )
    enqueue_job(connection, replace(spec_for(other_space_tenant, "parse"), target_ref=other_space_source))
    other_tenant = register_tenant(connection, "Other sync status tenant")
    other_tenant_source = source_for(connection, other_tenant)

    assert client.get(status_path(source_ref)).status_code == 401
    assert client.get(status_path(source_ref), headers=bearer(owner)).status_code == 403
    credentials[employee] = replace(credentials[employee], operations={OPERATION})
    assert client.get(status_path(source_ref), headers=bearer(employee)).status_code == 403
    credentials[owner] = replace(credentials[owner], operations={OPERATION})
    assert client.get(status_path("not-a-uuid"), headers=bearer(owner)).status_code == 400
    assert client.get(status_path(source_ref), params={"after": str(uuid4())}, headers=bearer(owner)).status_code == 400
    assert client.get(status_path(other_source_ref), headers=bearer(owner)).status_code == 403
    assert client.get(status_path(other_space_source), headers=bearer(owner)).status_code == 403
    assert client.get(status_path(other_tenant_source), headers=bearer(owner)).status_code == 403
    assert rpc(client, owner, "tools/list").json()["result"]["tools"] == []

    live.clear()
    response = client.get(status_path(source_ref), headers=bearer(owner))
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {
        "request_id", "observed_at", "source_id", "lifecycle", "contract_revision", "admission",
        "content_sync", "inventory_reconciliation", "permission_checkpoint", "restriction_receipts",
        "processing_and_review", "job_backlog_by_stage", "job_throughput_by_stage",
    }
    assert datetime.fromisoformat(body["observed_at"]).utcoffset() == timedelta(0)
    assert body["source_id"] == str(source_ref)
    assert body["lifecycle"] == "active"
    assert body["contract_revision"] == 1
    assert body["admission"] == "synthetic_only"

    assert body["content_sync"]["sequence"] == 1
    assert body["content_sync"]["through_cursor"] == str(seeded["page"].through)
    assert body["content_sync"]["item_count"] == 4
    assert datetime.fromisoformat(body["content_sync"]["committed_at"]).utcoffset() == timedelta(0)

    expected_diffs = {"version_not_registered": 0, "digest_mismatch": 0, "not_enumerated": 0}
    for diff in seeded["inventory"].differences:
        expected_diffs[diff.kind] += 1
    assert expected_diffs["version_not_registered"] == 1
    assert expected_diffs["digest_mismatch"] == 1
    assert expected_diffs["not_enumerated"] >= 2

    inv = body["inventory_reconciliation"]
    assert inv["sequence"] == 1
    assert inv["snapshot_ref"] == str(seeded["inventory"].snapshot_ref)
    assert inv["content_position"] == str(seeded["page"].through)
    assert inv["entry_count"] == 3
    assert inv["matched_count"] == 1
    assert inv["difference_counts"] == expected_diffs
    assert inv["review_required"] is True
    assert {detail["kind"] for detail in inv["difference_details"]} == {
        "version_not_registered", "digest_mismatch", "not_enumerated",
    }
    assert any(detail["kind"] == "not_enumerated" for detail in inv["difference_details"])
    assert all(set(detail) == {"object_ref", "kind", "has_source_version", "document_ref", "version_ref"}
               for detail in inv["difference_details"])
    assert any(detail["version_ref"] is not None for detail in inv["difference_details"])

    cp = body["permission_checkpoint"]
    assert cp["sequence"] == 1
    assert cp["checkpoint_ref"] == str(seeded["checkpoint"].checkpoint_ref)
    assert cp["contract_revision"] == 1
    assert cp["authority_ref"] == str(seeded["trusted"].authority_ref)
    assert cp["authority_stream_ref"] == str(seeded["checkpoint"].authority_stream_ref)
    assert cp["authority_generation"] == seeded["rev1"].generation
    assert cp["acknowledged_count"] == 1
    assert cp["last_acknowledged_generation"] == seeded["rev1"].generation

    receipts = body["restriction_receipts"]
    assert receipts["total"] == 4
    assert receipts["by_kind"] == {"withdrawn": 1, "deleted": 1, "permission_revoked": 2}
    assert receipts["latest_authority_generation"] == seeded["rev2"].generation
    assert datetime.fromisoformat(receipts["latest_committed_at"]).utcoffset() == timedelta(0)

    proc = body["processing_and_review"]
    assert proc["blocked_versions"] == 2
    assert proc["pending_quality_reviews"] == 1
    assert proc["pending_ocr_review_pages"] == 0
    assert proc["quarantined_versions"] == 1
    assert proc["rejected_ingest_items"] == 1
    assert proc["needs_confirmation_ingest_items"] == 0
    assert proc["registered_documents"] >= 4
    assert proc["registered_versions"] >= 4
    assert proc["current_contract_versions"] == proc["registered_versions"]

    by_stage = {row["stage"]: row for row in body["job_backlog_by_stage"]}
    assert set(by_stage) == {"parse", "other"}
    assert by_stage["parse"]["unfinished"] == 2
    assert by_stage["parse"]["states"] == {"retry_delayed": 2}
    assert by_stage["parse"]["next_retry_at"] is not None
    assert by_stage["other"]["unfinished"] == 1
    assert by_stage["other"]["states"] == {"ready": 1}

    for forbidden in (
        "secret-present-key", "secret-omitted-key", "secret-mismatch-key", "secret-missing-key",
        "secret-bad.exe", "Forbidden Binary", "private-sync-stage",
        str(other_source_ref), str(other_space_source), str(other_tenant_source), "上海住宿",
    ):
        assert forbidden not in response.text

    assert connection.execute("""
        SELECT ingress, operation, destination, outcome FROM thalion.request_record WHERE request_id = %s
    """, (body["request_id"],)).fetchone() == ("http", OPERATION, "internal_management", "succeeded")
    assert connection.execute("""
        SELECT 1 FROM thalion.delivery_record WHERE request_id = %s
    """, (body["request_id"],)).fetchone() is None


def test_sync_status_separates_contract_revisions_and_remains_readable_when_source_suspended(
    transport, revocation_authority,
):
    client, db, (owner, employee), credentials, _, *_ = transport
    connection, tenant, _, source_ref, _ = db
    seeded = _seed_source_activity(client, db, credentials, owner, employee, revocation_authority)
    admit(credentials, owner, OPERATION)

    rotate_collector(connection, tenant, seeded["source"])
    rotated = client.get(status_path(source_ref), headers=bearer(owner))
    assert rotated.status_code == 200
    body = rotated.json()
    assert body["contract_revision"] == 2
    assert body["content_sync"] is None
    assert body["inventory_reconciliation"] is None
    assert body["permission_checkpoint"]["checkpoint_ref"] == str(seeded["checkpoint"].checkpoint_ref)
    assert body["permission_checkpoint"]["contract_revision"] == 1
    assert body["restriction_receipts"]["total"] == 4
    assert body["processing_and_review"]["current_contract_versions"] == 0
    assert body["processing_and_review"]["registered_versions"] >= 4

    with connection.transaction():
        connection.execute("""
            UPDATE thalion.source SET lifecycle = 'suspended'
            WHERE (org_id, space_id, source_id) = (
                SELECT org_id, space_id, object_id FROM thalion.object_identity
                WHERE (org_id, space_id, object_type, public_id) = (%s, %s, 'source', %s)
            )
        """, (tenant.org_id, tenant.space_id, source_ref))
    suspended = client.get(status_path(source_ref), headers=bearer(owner))
    assert suspended.status_code == 200
    assert suspended.json()["lifecycle"] == "suspended"
    assert suspended.json()["permission_checkpoint"]["checkpoint_ref"] == str(seeded["checkpoint"].checkpoint_ref)

    fresh_source = _register_source(
        connection, tenant, owner_id=tenant.actor_id, key="fresh-empty-source", namespace="fresh-empty-ns",
    )
    empty = client.get(status_path(fresh_source), headers=bearer(owner))
    assert empty.status_code == 200
    empty_body = empty.json()
    assert empty_body["lifecycle"] == "active"
    assert empty_body["contract_revision"] == 1
    assert empty_body["content_sync"] is None
    assert empty_body["inventory_reconciliation"] is None
    assert empty_body["permission_checkpoint"] is None
    assert empty_body["restriction_receipts"] == {
        "total": 0,
        "by_kind": {"withdrawn": 0, "deleted": 0, "permission_revoked": 0},
        "latest_committed_at": None,
        "latest_authority_generation": None,
    }
    assert empty_body["processing_and_review"] == {
        "registered_documents": 0,
        "registered_versions": 0,
        "current_contract_versions": 0,
        "blocked_versions": 0,
        "pending_quality_reviews": 0,
        "pending_ocr_review_pages": 0,
        "quarantined_versions": 0,
        "rejected_ingest_items": 0,
        "needs_confirmation_ingest_items": 0,
    }
    assert empty_body["job_backlog_by_stage"] == []
    assert empty_body["job_throughput_by_stage"] == []


@pytest.mark.parametrize(("change", "status", "outcome"), [
    ("space_owner", 403, "rejected"),
    ("source_owner", 403, "rejected"),
    ("credential", 401, "rejected"),
    ("deadline", 503, "dependency_unavailable"),
])
def test_sync_status_checks_current_authority_before_dispatch(
    evidence_transport, transport, monkeypatch, change, status, outcome,
):
    service, db, (owner, _), credentials, *_ = evidence_transport
    client = transport[0]
    connection, tenant, _, source_ref, _ = db
    credentials[owner] = replace(credentials[owner], operations={OPERATION})
    execute = service.execute_internal

    def change_after_projection(*args, **kwargs):
        reply = execute(*args, **kwargs)
        assert reply.status_code == 200
        if change == "space_owner":
            connection.execute(
                "UPDATE thalion.space SET owner_principal_id = %s WHERE space_id = %s",
                (tenant.other_actor_id, tenant.space_id),
            )
        elif change == "source_owner":
            connection.execute("""
                UPDATE thalion.source SET owner_principal_id = %s
                WHERE (org_id, space_id, source_id) = (
                    SELECT org_id, space_id, object_id FROM thalion.object_identity
                    WHERE (org_id, space_id, object_type, public_id) = (%s, %s, 'source', %s)
                )
            """, (tenant.other_actor_id, tenant.org_id, tenant.space_id, source_ref))
        elif change == "credential":
            del credentials[owner]
        else:
            monkeypatch.setattr(api, "release_time", lambda: datetime.now(UTC) + timedelta(minutes=1))
        return reply

    monkeypatch.setattr(service, "execute_internal", change_after_projection)
    response = client.get(status_path(source_ref), headers=bearer(owner))
    assert response.status_code == status
    payload = response.json()
    for field in ("content_sync", "inventory_reconciliation", "permission_checkpoint", "job_backlog_by_stage"):
        assert field not in payload
    assert connection.execute(
        "SELECT outcome FROM thalion.request_record WHERE request_id = %s", (payload["request_id"],),
    ).fetchone() == (outcome,)


def test_sources_portal_displays_independent_watermarks_and_clears_session(portal, transport, revocation_authority):
    from playwright.sync_api import expect

    page, _, db, (owner, employee), credentials, *_ = portal
    client = transport[0]
    connection, tenant, _, source_ref, _ = db
    seeded = _seed_source_activity(client, db, credentials, owner, employee, revocation_authority)
    credentials[owner] = replace(credentials[owner], operations={OPERATION})

    page.set_viewport_size({"width": 390, "height": 820})
    response = page.goto("/manage/sources")
    assert response.status == 200 and response.headers["cache-control"] == "no-store"
    assert owner not in response.text() and str(seeded["page"].through) not in response.text()

    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="载入管理凭据").click()
    page.get_by_label("来源编号").fill(str(source_ref))
    page.get_by_role("button", name="查看同步状态").click()

    content_card = page.get_by_role("listitem").filter(has=page.get_by_role("heading", name="内容分页水位"))
    expect(content_card.get_by_text(str(seeded["page"].through), exact=True)).to_be_visible()
    inventory_card = page.get_by_role("listitem").filter(has=page.get_by_role("heading", name="完整盘点对账"))
    expect(inventory_card.get_by_text(str(seeded["inventory"].snapshot_ref), exact=True)).to_be_visible()
    expect(inventory_card.get_by_text(str(seeded["page"].through), exact=True)).to_be_visible()
    permission_card = page.get_by_role("listitem").filter(
        has=page.get_by_role("heading", name="独立权限确认点与显式收紧回执"),
    )
    expect(permission_card.get_by_text(str(seeded["checkpoint"].checkpoint_ref), exact=True)).to_be_visible()
    expect(page.get_by_text("存在尚未并入权限确认点的撤权回执", exact=True)).to_be_visible()
    expect(page.get_by_text("资料解析", exact=True)).to_be_visible()
    expect(page.get_by_text("延时重试", exact=True)).to_be_visible()
    expect(page.get_by_text("其他任务", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="资料入库")).to_have_attribute("href", "/manage/ingest")
    expect(page.get_by_role("link", name="任务积压")).to_have_attribute("href", "/manage/runtime")
    assert "/manage/sources" in client.get("/manage/ingest").text
    assert "/manage/sources" in client.get("/manage/runtime").text
    assert "private-sync-stage" not in page.content()
    assert "secret-present-key" not in page.content()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "sources-sync-status-mobile.png")

    page.set_viewport_size({"width": 1280, "height": 850})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "sources-sync-status-desktop.png")

    page.evaluate("""() => {
        const fetchReal = window.fetch;
        window.fetch = async (url, options) => {
            const response = await fetchReal(url, {...options, signal: undefined});
            await new Promise(resolve => {
                window.releaseSyncStatus = resolve;
                document.documentElement.dataset.syncStatusResponse = "held";
            });
            return response;
        };
    }""")
    page.get_by_role("button", name="刷新状态").click()
    expect(page.locator("html")).to_have_attribute("data-sync-status-response", "held")
    page.get_by_role("button", name="退出管理").click()
    page.evaluate("async () => { window.releaseSyncStatus(); await new Promise(requestAnimationFrame); }")
    expect(page.get_by_text(str(seeded["page"].through), exact=True)).to_have_count(0)
    expect(page.get_by_text("存在尚未并入权限确认点的撤权回执", exact=True)).to_have_count(0)
    expect(page.get_by_text("已退出，凭据与快照已清除。", exact=True)).to_be_visible()
    expect(page.get_by_label("管理测试凭据")).to_have_value("")
    assert page.evaluate("sessionStorage.length + localStorage.length") == 0
