from base64 import b64encode
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import pytest

from enterprise_kb.modules import glossary
from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.lifecycle import space_archive
from enterprise_kb.modules.operations import source_catalog
from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.modules.sources import departments, effectivity, registry
from enterprise_kb.ports.contracts import (
    ConnectorDeltaPage,
    ConnectorInventory,
    SecurityLogReceipt,
)
from enterprise_kb.runtime.jobs import claim_job
from enterprise_kb.transport import api, evidence

from test_employee_portal import browser, loopback_page
from test_evidence import create_evidence_db
from test_evidence_transport import bearer
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import LEASE_FOR, open_database, runtime_db
from test_sources import request_for
from test_travel_search import SEARCH_FIELDS


BUSINESS_DAY = date(2026, 11, 20)
ALL_MGMT_ROUTES = (
    "/manage/catalog",
    "/manage/ingest",
    "/manage/sources",
    "/manage/glossary",
    "/manage/effectivity",
    "/manage/responsibility",
    "/manage/readers",
    "/manage/governance",
    "/manage/model-egress",
    "/manage/wiki",
    "/manage/repairs",
    "/manage/feedback",
    "/manage/runtime",
    "/manage/lifecycle",
    "/manage/archives",
)


class _StubConnector:
    admission = "synthetic_local"

    def __init__(self, source_ref: UUID, initial_docs: list[dict], delta_docs: list[dict]):
        self.source_ref = source_ref
        self.initial_docs = list(initial_docs)
        self.delta_docs = list(delta_docs)
        self.synced = False

    def fetch_delta_page(self, source_ref: UUID, cursor: str | None) -> ConnectorDeltaPage:
        assert source_ref == self.source_ref
        if self.synced:
            return ConnectorDeltaPage(
                previous_cursor=cursor,
                through_cursor=cursor or "cursor-stage5-1",
                items=(),
                has_more=False,
            )
        self.synced = True
        return ConnectorDeltaPage(
            previous_cursor=cursor,
            through_cursor="cursor-stage5-1",
            items=tuple(self.delta_docs),
            has_more=False,
        )

    def fetch_full_inventory(self, source_ref: UUID) -> ConnectorInventory:
        assert source_ref == self.source_ref
        entries = []
        for item in [*self.initial_docs, *(self.delta_docs if self.synced else [])]:
            entries.append({
                "object_key": item["object_key"],
                "incarnation": item.get("incarnation", "v1"),
                "source_version_key": item["source_version_key"],
                "content_sha256": item["content_sha256"],
            })
        return ConnectorInventory(
            snapshot_ref="snap-stage5-1",
            observed_at=datetime.now(UTC),
            stable_object_keys=frozenset(item["object_key"] for item in entries),
            complete=True,
            entries=tuple(entries),
        )


class _RecordingAuditSink:
    admission = "synthetic_local"
    log_ref = uuid4()

    def __init__(self):
        self.records: list[dict] = []

    def append_restriction_receipt(self, space_ref: UUID, payload: dict) -> SecurityLogReceipt:
        self.records.append(payload)
        return SecurityLogReceipt(
            log_ref=self.log_ref,
            stream_ref=space_ref,
            generation=len(self.records),
            digest=sha256(str(payload).encode("utf-8")).digest(),
            recorded_at=datetime.now(UTC),
        )

    def verify_checkpoint(self, space_ref: UUID, expected_generation: int) -> bool:
        return len(self.records) >= expected_generation


def _publish_markdown(db, *, key: str, title: str, content: str):
    connection, tenant, _, source_ref, store = db
    raw = content.encode("utf-8")
    reg_ctx = request_for(connection, tenant, tenant.worker_id, str(uuid4()), "register_version")
    version = registry.register_synthetic_version(
        connection,
        reg_ctx,
        registry.SourceVersion(
            tenant.space_id,
            source_ref,
            1,
            key,
            "v1",
            "rev-1",
            title,
            "1.0",
            sha256(raw).digest(),
        ),
        raw,
        store,
    )
    lease = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert lease is not None
    run = processing.process_evidence_job(connection, lease, store)
    assert run.outcome == "pending_review"
    q_ctx = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "decide_evidence_quality")
    processing.decide_quality(connection, q_ctx, tenant.space_id, run.run_ref, run.manifest_digest, "approved", uuid4())
    eff_ctx = request_for(connection, tenant, tenant.other_actor_id, str(uuid4()), effectivity.APPROVE)
    effectivity.approve_synthetic_rule(
        connection,
        eff_ctx,
        tenant.space_id,
        version.version_ref,
        effectivity.Approval(BUSINESS_DAY - timedelta(days=10), None, "shanghai", "employee", uuid4()),
    )
    lexical.build_index(connection, store, tenant.space_ref, version.version_ref, run.run_ref)
    passages = processing.list_approved_passages(connection, tenant.org_id, tenant.space_id, version.version_ref)
    return version, passages[0], raw


@pytest.fixture
def stage5_env(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    db = create_evidence_db(connection, tenant, database_url, tmp_path)
    connection, tenant, database_url, source_ref, store = db

    doc_ver, doc_passage, doc_raw = _publish_markdown(
        db,
        key="travel-policy-stage5",
        title="2026 差旅住宿制度",
        content="# 2026 差旅住宿制度\n\n上海出差住宿标准每晚 680 元。\n",
    )
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))

    delta_bytes = "# 2026 差旅交通补充规定\n\n高铁优先选择二等座。\n".encode("utf-8")
    delta_digest = sha256(delta_bytes).hexdigest()
    connector = _StubConnector(
        source_ref=source_ref,
        initial_docs=[{
            "object_key": "travel-policy-stage5",
            "incarnation": "v1",
            "source_version_key": "rev-1",
            "content_sha256": sha256(doc_raw).hexdigest(),
        }],
        delta_docs=[{
            "action": "upsert",
            "object_key": "travel-rail-stage5",
            "incarnation": "v1",
            "source_version_key": "rev-sync-1",
            "display_name": "2026 差旅交通补充规定",
            "version_label": "1.0",
            "media_type": "text/markdown",
            "content_sha256": delta_digest,
            "content_base64": b64encode(delta_bytes).decode("ascii"),
        }],
    )
    audit_sink = _RecordingAuditSink()

    owner_token = "owner-stage5-token-0123456789abcdef"
    approver_token = "approver-stage5-token-0123456789abcd"
    restricted_token = "restricted-stage5-token-0123456789ab"
    expires = datetime.now(UTC) + timedelta(minutes=30)

    owner_ops = (
        source_catalog.OPERATIONS
        | glossary.OPERATIONS
        | departments.OPERATIONS
        | {space_archive.LIST, space_archive.REQUEST, space_archive.EXPORT, space_archive.VERIFY}
    )
    approver_ops = frozenset({
        space_archive.LIST,
        space_archive.APPROVE,
        space_archive.VERIFY,
    })
    restricted_ops = frozenset({"search", "read_passage"})

    refs = dict(
        connection.execute(
            """
            SELECT object_id, public_id FROM thalion.object_identity
            WHERE org_id = %s AND object_type = 'principal' AND object_id = ANY(%s)
            """,
            (tenant.org_id, [tenant.actor_id, tenant.other_actor_id]),
        ).fetchall()
    )
    creds = {
        owner_token: evidence.SyntheticCredential(
            refs[tenant.actor_id], tenant.space_ref, "stage5-owner", "shanghai", "employee", owner_ops, expires,
        ),
        approver_token: evidence.SyntheticCredential(
            refs[tenant.other_actor_id], tenant.space_ref, "stage5-approver", "shanghai", "employee", approver_ops, expires,
        ),
        restricted_token: evidence.SyntheticCredential(
            refs[tenant.other_actor_id], tenant.space_ref, "stage5-reader", "shanghai", "employee", restricted_ops, expires,
        ),
    }

    service = evidence.EvidenceService(
        lambda: open_database(database_url),
        creds.get,
        lambda cred, probe: authority_for({tenant.actor_id})(probe),
        store,
        check_archive_source=lambda cred, probe: authority_for({tenant.actor_id})(probe),
        security_audit_log=audit_sink,
        source_connector=connector,
    )
    app = api.create_app(service)
    client = TestClient(app, base_url="http://127.0.0.1")
    return {
        "connection": connection,
        "tenant": tenant,
        "database_url": database_url,
        "source_ref": source_ref,
        "store": store,
        "doc_ver": doc_ver,
        "doc_passage": doc_passage,
        "connector": connector,
        "audit_sink": audit_sink,
        "service": service,
        "app": app,
        "client": client,
        "owner_token": owner_token,
        "approver_token": approver_token,
        "restricted_token": restricted_token,
    }


def test_management_routes_unified_nav_and_sso(stage5_env):
    client = stage5_env["client"]
    for route in ALL_MGMT_ROUTES:
        resp = client.get(route)
        assert resp.status_code == 200, f"GET {route} failed: {resp.status_code}"
        html = resp.text
        assert "/manage/catalog" in html, f"{route} missing /manage/catalog nav link"
        assert "/manage/glossary" in html, f"{route} missing /manage/glossary nav link"
        assert "/manage/archives" in html, f"{route} missing /manage/archives nav link"
        assert "/manage/sso.js" in html, f"{route} missing sso.js script"
        assert 'maxlength="16384"' in html, f"{route} missing expanded password maxlength"

    for js_route in ("/manage/catalog.js", "/manage/glossary.js", "/manage/archives.js"):
        js_resp = client.get(js_route)
        assert js_resp.status_code == 200
        assert "javascript" in js_resp.headers["content-type"]


def test_stage5_apis_catalog_sync_and_space_archive_verify(stage5_env):
    client = stage5_env["client"]
    owner = stage5_env["owner_token"]
    approver = stage5_env["approver_token"]
    restricted = stage5_env["restricted_token"]
    source_ref = stage5_env["source_ref"]
    doc_ver = stage5_env["doc_ver"]

    # 1. Auth boundary for catalog & archive list
    assert client.get("/internal/sources/catalog").status_code == 401
    assert client.get("/internal/sources/catalog", headers=bearer(restricted)).status_code == 403
    assert client.get("/internal/lifecycle/space-archives", headers=bearer(restricted)).status_code == 403

    # 2. Catalog read
    cat = client.get("/internal/sources/catalog", headers=bearer(owner))
    assert cat.status_code == 200, cat.text
    cat_body = cat.json()
    assert cat_body["connector_configured"] is True
    assert cat_body["space"]["lifecycle"] == "active"
    assert len(cat_body["sources"]) == 1
    assert cat_body["sources"][0]["source_id"] == str(source_ref)
    assert len(cat_body["documents"]) == 1
    assert cat_body["documents"][0]["document_id"] == str(doc_ver.document_ref)

    # 3. Manual connector sync with reconciliation & audit sink emission
    sync_resp = client.post(
        f"/internal/sources/{source_ref}/connector-sync",
        headers=bearer(owner) | {"Idempotency-Key": "stage5-api-sync-1"},
        json={"reconcile": True, "max_pages": 5},
    )
    assert sync_resp.status_code == 200, sync_resp.text
    sync_body = sync_resp.json()
    assert sync_body["status"] == "succeeded"
    assert sync_body["pages_committed"] == 1
    assert len(sync_body["versions_registered"]) == 1
    assert sync_body["reconciliation_status"] == "reconciled"
    assert sync_body["reconciliation_matched"] == 2
    assert sync_body["reconciliation_differences"] == 0
    assert any(r.get("event_type") == "security.connector_sync_triggered" for r in stage5_env["audit_sink"].records)

    # Idempotency conflict with different body for same key
    conflict = client.post(
        f"/internal/sources/{source_ref}/connector-sync",
        headers=bearer(owner) | {"Idempotency-Key": "stage5-api-sync-1"},
        json={"reconcile": False, "max_pages": 5},
    )
    assert conflict.status_code == 409

    # Without connector configured -> 409 connector_not_configured
    saved_connector = stage5_env["service"].source_connector
    stage5_env["service"].source_connector = None
    try:
        no_conn = client.post(
            f"/internal/sources/{source_ref}/connector-sync",
            headers=bearer(owner) | {"Idempotency-Key": "stage5-api-sync-noconn"},
            json={},
        )
        assert no_conn.status_code == 409
        assert no_conn.json()["error"]["code"] == "connector_not_configured"
    finally:
        stage5_env["service"].source_connector = saved_connector

    # 4. Space archive full flow + list + offline verify
    req_resp = client.post(
        "/internal/lifecycle/space-archives",
        headers=bearer(owner) | {"Idempotency-Key": "stage5-arch-req-1"},
        json={"source_ids": [str(source_ref)], "version_ids": [str(doc_ver.version_ref)]},
    )
    assert req_resp.status_code == 200, req_resp.text
    export_id = req_resp.json()["export_id"]

    # Verify before sealing -> 409
    pre_verify = client.post(f"/internal/lifecycle/space-archives/{export_id}/verify", headers=bearer(owner))
    assert pre_verify.status_code == 409

    # Approver lists archives and approves
    approver_list = client.get("/internal/lifecycle/space-archives", headers=bearer(approver))
    assert approver_list.status_code == 200, approver_list.text
    assert approver_list.json()["caller_roles"]["is_source_approver"] is True
    assert approver_list.json()["archives"][0]["export_id"] == export_id
    assert approver_list.json()["archives"][0]["state"] == "requested"

    approve_resp = client.post(
        f"/internal/lifecycle/space-archives/{export_id}/approve",
        headers=bearer(approver) | {"Idempotency-Key": "stage5-arch-app-1"},
        json={"expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat()},
    )
    assert approve_resp.status_code == 200, approve_resp.text

    seal_resp = client.post(
        f"/internal/lifecycle/space-archives/{export_id}/seal",
        headers=bearer(owner) | {"Idempotency-Key": "stage5-arch-seal-1"},
        json={},
    )
    assert seal_resp.status_code == 200, seal_resp.text

    verify_resp = client.post(f"/internal/lifecycle/space-archives/{export_id}/verify", headers=bearer(owner))
    assert verify_resp.status_code == 200, verify_resp.text
    vbody = verify_resp.json()
    assert vbody["verified"] is True
    assert vbody["export_id"] == export_id
    assert vbody["format_version"] == space_archive.SPACE_ARCHIVE_FORMAT
    assert vbody["source_ids"] == [str(source_ref)]
    assert vbody["version_ids"] == [str(doc_ver.version_ref)]


def test_stage5_browser_e2e_catalog_glossary_archives_and_nav(browser, stage5_env):
    from playwright.sync_api import expect

    service = stage5_env["service"]
    owner = stage5_env["owner_token"]
    approver = stage5_env["approver_token"]
    source_ref = stage5_env["source_ref"]
    doc_ver = stage5_env["doc_ver"]

    # A. /manage/catalog E2E: login, trigger connector sync, set & clear explicit department, navigate via unified nav
    with loopback_page(browser, service, "/manage/catalog") as (page, base, response):
        assert response.status == 200
        page.fill("#catalog-token", owner)
        page.click("#catalog-access button[type=submit]")
        expect(page.locator("#catalog-workspace")).to_be_visible()
        expect(page.locator("#catalog-sources-list")).to_contain_text(str(source_ref))
        expect(page.locator("#catalog-docs-list")).to_contain_text("2026 差旅住宿制度")

        # Trigger connector sync with reconciliation checkbox enabled
        page.check("#catalog-reconcile")
        page.click(f'button[data-source-sync="{source_ref}"]')
        expect(page.locator("#catalog-docs-list")).to_contain_text("2026 差旅交通补充规定", timeout=15000)

        # Assign explicit department to document
        dept_form = page.locator(f'form[data-doc-dept-form="{doc_ver.document_ref}"]')
        dept_form.locator("input").nth(0).fill("finance")
        dept_form.locator("input").nth(1).fill("财务部")
        dept_form.locator("button[type=submit]").click()
        expect(page.locator("#catalog-docs-list")).to_contain_text("财务部 (finance)", timeout=10000)

        # Clear explicit department
        dept_form.get_by_role("button", name="清除归属").click()
        expect(page.locator("#catalog-status")).to_contain_text("已清除文档显式部门归属", timeout=10000)

        # Click unified top nav to navigate directly to /manage/glossary
        page.get_by_role("link", name="业务词典").click()
        expect(page).to_have_url(f"{base}/manage/glossary")

        # B. /manage/glossary E2E: create, edit, filter, deactivate, reactivate
        page.fill("#glossary-token", owner)
        page.click("#glossary-access button[type=submit]")
        expect(page.locator("#glossary-workspace")).to_be_visible()

        page.fill("#glossary-term", "住宿费")
        page.fill("#glossary-synonyms", "酒店报销, 房费")
        page.fill("#glossary-definition", "员工出差期间发生的合规酒店住宿费用。")
        page.click("#glossary-save-btn")
        expect(page.locator("#glossary-list")).to_contain_text("住宿费", timeout=10000)
        expect(page.locator("#glossary-list")).to_contain_text("酒店报销")

        # Edit existing term
        page.locator("#glossary-list").get_by_role("button", name="编辑").first.click()
        page.fill("#glossary-synonyms", "酒店报销, 房费, 差旅住宿")
        page.click("#glossary-save-btn")
        expect(page.locator("#glossary-list")).to_contain_text("差旅住宿", timeout=10000)

        # Deactivate & reactivate
        page.locator("#glossary-list").get_by_role("button", name="停用").first.click()
        expect(page.locator("#glossary-list")).to_contain_text("已停用", timeout=10000)
        page.locator("#glossary-list").get_by_role("button", name="重新启用").first.click()
        expect(page.locator("#glossary-list")).to_contain_text("启用中", timeout=10000)

        # Navigate to /manage/archives via unified nav
        page.get_by_role("link", name="归档导出").click()
        expect(page).to_have_url(f"{base}/manage/archives")

        # C. /manage/archives E2E: request (owner) -> approve (independent approver) -> seal (owner) -> offline verify
        page.fill("#archives-token", owner)
        page.click("#archives-access button[type=submit]")
        expect(page.locator("#archives-workspace")).to_be_visible()
        expect(page.locator("#archives-role-badge")).to_contain_text("空间负责人")

        page.click("#archives-request-btn")
        expect(page.locator("#archives-list")).to_contain_text("待独立审批", timeout=10000)

        # Log out and sign in as independent source approver
        page.click("#archives-logout")
        expect(page.locator("#archives-lock")).to_be_visible()
        page.fill("#archives-token", approver)
        page.click("#archives-access button[type=submit]")
        expect(page.locator("#archives-workspace")).to_be_visible()
        expect(page.locator("#archives-role-badge")).to_contain_text("来源独立审批人")

        page.locator("button[data-approve-export]").first.click()
        expect(page.locator("#archives-list")).to_contain_text("已批准待封存", timeout=10000)

        # Log out and sign in as space owner to seal and verify offline
        page.click("#archives-logout")
        page.fill("#archives-token", owner)
        page.click("#archives-access button[type=submit]")
        expect(page.locator("#archives-workspace")).to_be_visible()

        page.locator("button[data-seal-export]").first.click()
        expect(page.locator("#archives-list")).to_contain_text("已封存", timeout=15000)

        page.locator("button[data-verify-export]").first.click()
        expect(page.locator("#archives-list")).to_contain_text("离线完整性核验通过（verified = true）", timeout=15000)
