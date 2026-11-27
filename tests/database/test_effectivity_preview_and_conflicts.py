from datetime import date
from hashlib import sha256
from uuid import UUID, uuid4

from psycopg import errors
import pytest

from enterprise_kb.modules.sources import effectivity, originals, registry, responsibility
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.runtime.commands import IdempotencyConflict

from test_effectivity import record
from test_effectivity_transport import approve, load_approver, upload_policy
from test_employee_portal import browser, loopback_page
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_ingest_transport import MARKDOWN, file, upload
from test_runtime import runtime_db
from test_sources import register, request_for
from test_travel_search import BEFORE, SWITCH, corpus
from test_wiki_inputs import assemble
from test_wiki_invalidation import version_ref
from test_wiki_publication import authorize, configure
from test_wiki_search import reviewed


def _principal_ref(connection, principal_id: int) -> UUID:
    return connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
        (principal_id,),
    ).fetchone()[0]


def _publish_travel_wiki(db, first, second):
    configure(db, 2)
    manifest = assemble(db, (first, second))
    assert manifest.status == "succeeded"
    revision, approval = reviewed((db, manifest, first, second))
    publication = authorize(db, revision, approval)
    assert publication.status == "succeeded"
    return publication


def _register_second_version_for_existing_document(connection, tenant, source_id: int, document_id: int, store, key: str):
    doc_key, incarnation, source_ref = connection.execute(
        """
        SELECT d.source_object_key, d.incarnation, sid.public_id
        FROM thalion.document AS d
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (d.org_id, d.space_id, 'source', d.source_id)
        WHERE d.document_id = %s
        """,
        (document_id,),
    ).fetchone()
    payload = b"# Updated Travel Policy\n\nShanghai lodging allowance revised to 700 CNY.\n"
    return register(
        connection, tenant, source_ref, store,
        key=f"reg-{key}",
        object_key=doc_key,
        incarnation=incarnation,
        source_version_key=f"rev-{key}",
        display_name="Travel Policy v2",
        version_label="V2",
        digest=sha256(payload).digest(),
        payload=payload,
    )


def test_effectivity_preview_reports_switch_date_affected_wiki_overlaps_and_unready_notice(transport):
    client, db, (owner, reviewer), credentials, _, first, second = transport
    connection, tenant, _, _, store = db
    publication = _publish_travel_wiki(db, first, second)
    v1_ref = version_ref(connection, first)
    v1_row = connection.execute(
        """
        SELECT v.source_id, v.document_id, re.decision_ref, doc_id.public_id
        FROM thalion.object_identity AS vid
        JOIN thalion.document_version AS v ON v.version_id = vid.object_id
        JOIN thalion.rule_effectivity AS re ON re.version_id = v.version_id
        JOIN thalion.object_identity AS doc_id
          ON (doc_id.org_id, doc_id.space_id, doc_id.object_type, doc_id.object_id)
           = (v.org_id, v.space_id, 'document', v.document_id)
        WHERE vid.public_id = %s AND vid.object_type = 'document_version'
        ORDER BY re.recorded_at ASC LIMIT 1
        """,
        (v1_ref,),
    ).fetchone()
    source_id, document_id, existing_decision_ref, doc_ref = v1_row
    v2 = _register_second_version_for_existing_document(connection, tenant, source_id, document_id, store, "preview")

    admit(credentials, owner, effectivity.PREVIEW)
    admit(credentials, reviewer, effectivity.PREVIEW)
    bindings_before = connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone()

    # Non-approver (owner/collector) is strictly forbidden
    denied = client.post(
        f"/internal/sources/versions/{v2.version_ref}/effectivity-preview",
        headers=bearer(owner),
        json={"valid_from": "2026-12-15"},
    )
    assert denied.status_code == 403

    # Approver previews future switch replacing v1 (v2 has not been parsed/approved yet)
    preview_resp = client.post(
        f"/internal/sources/versions/{v2.version_ref}/effectivity-preview",
        headers=bearer(reviewer),
        json={
            "valid_from": "2026-12-15",
            "replaces_id": str(existing_decision_ref),
        },
    )
    assert preview_resp.status_code == 200 and preview_resp.headers["Cache-Control"] == "no-store"
    body = preview_resp.json()
    assert body["version_id"] == str(v2.version_ref)
    assert body["document_id"] == str(doc_ref)
    assert body["switch_date"] == "2026-12-15"
    assert body["processing_readiness"] == "pending_processing"
    assert "可用依据不足" in body["insufficient_evidence_notice"]
    assert body["replacement_status"] == "valid_replacement"
    assert body["overlapping_decisions"] == []
    assert any(
        topic["publication_id"] == str(publication.ref)
        for topic in body["affected_wiki_topics"]
    )
    # Ensure zero original text leakage and zero permission grants
    assert "Shanghai lodging" not in preview_resp.text
    assert connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone() == bindings_before

    # Without replaces_id and with narrowed region, preview surfaces partial scope overlap with existing decision
    overlap_resp = client.post(
        f"/internal/sources/versions/{v2.version_ref}/effectivity-preview",
        headers=bearer(reviewer),
        json={"valid_from": "2026-10-15", "region": "shanghai"},
    )
    assert overlap_resp.status_code == 200
    overlaps = overlap_resp.json()["overlapping_decisions"]
    assert any(
        item["decision_id"] == str(existing_decision_ref)
        and item["overlap_kind"] == "partial_scope_overlap"
        for item in overlaps
    )


def test_stop_preview_and_withdrawal_record_reason_and_stop_affected_wiki(transport):
    client, db, (owner, reviewer), credentials, _, first, second = transport
    connection, tenant, *_ = db
    publication = _publish_travel_wiki(db, first, second)
    v1_ref = version_ref(connection, first)

    admit(credentials, reviewer, effectivity.PREVIEW_STOP)
    admit(credentials, reviewer, effectivity.STOP)
    admit(credentials, owner, effectivity.STOP)

    # Preview stop impact lists active decisions and affected published Wiki topics
    prev = client.post(
        f"/internal/sources/versions/{v1_ref}/stop-preview",
        headers=bearer(reviewer),
        json={"kind": "withdrawn"},
    )
    assert prev.status_code == 200
    prev_body = prev.json()
    assert prev_body["stops_passage_retrieval"] is True
    assert prev_body["already_stopped"] is False
    assert len(prev_body["active_decisions"]) >= 1
    assert any(
        item["publication_id"] == str(publication.ref)
        for item in prev_body["affected_wiki_topics"]
    )

    # Non-approver cannot withdraw
    basis = str(uuid4())
    assert client.post(
        f"/internal/sources/versions/{v1_ref}/stop",
        headers=command_headers(owner),
        json={"kind": "withdrawn", "basis_id": basis, "reason": "Unauthorized attempt"},
    ).status_code == 403

    # Approver withdraws with reason and idempotency key
    key = str(uuid4())
    payload = {"kind": "withdrawn", "basis_id": basis, "reason": "制度已正式废止并由总部通知撤回"}
    stop_resp = client.post(
        f"/internal/sources/versions/{v1_ref}/stop",
        headers=command_headers(reviewer, key),
        json=payload,
    )
    assert stop_resp.status_code == 200 and stop_resp.headers["Cache-Control"] == "no-store"
    stop_body = stop_resp.json()
    assert stop_body["kind"] == "withdrawn"
    assert any(
        item["publication_id"] == str(publication.ref) and item["reason"] == "withdrawn"
        for item in stop_body["affected_wiki_topics"]
    )

    # Exact idempotent replay returns same decision_id; modified reason with same key conflicts (409)
    replay = client.post(
        f"/internal/sources/versions/{v1_ref}/stop",
        headers=command_headers(reviewer, key),
        json=payload,
    )
    assert replay.status_code == 200 and replay.json()["decision_id"] == stop_body["decision_id"]
    conflict = client.post(
        f"/internal/sources/versions/{v1_ref}/stop",
        headers=command_headers(reviewer, key),
        json=payload | {"reason": "不同原因"},
    )
    assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "effectivity_conflict"

    # Reason persisted in DB and Wiki publication is no longer available
    assert connection.execute(
        "SELECT reason FROM thalion.rule_use_stop WHERE decision_ref = %s",
        (stop_body["decision_id"],),
    ).fetchone() == ("制度已正式废止并由总部通知撤回",)
    assert connection.execute(
        "SELECT 1 FROM thalion.available_wiki_publication WHERE publication_ref = %s",
        (publication.ref,),
    ).fetchone() is None


def test_effectivity_conflict_registration_and_policy_owner_resolution(transport):
    client, db, (owner, reviewer), credentials, *_ = transport
    connection, tenant, _, _, store = db
    uploaded = upload_policy(client, db, owner, credentials)
    version1 = uploaded["version_id"]
    doc_id = uploaded["document_id"]
    doc_pk, source_id = connection.execute(
        """
        SELECT d.document_id, d.source_id
        FROM thalion.object_identity AS id
        JOIN thalion.document AS d ON d.document_id = id.object_id
        WHERE id.public_id = %s AND id.object_type = 'document'
        """,
        (doc_id,),
    ).fetchone()
    v2 = _register_second_version_for_existing_document(connection, tenant, source_id, doc_pk, store, "conflict")

    for op in (
        effectivity.APPROVE, effectivity.RECORD_CONFLICT,
        effectivity.LIST_CONFLICTS, effectivity.RESOLVE_CONFLICT,
    ):
        admit(credentials, reviewer, op)
    admit(credentials, owner, effectivity.LIST_CONFLICTS)
    admit(credentials, owner, effectivity.RESOLVE_CONFLICT)
    admit(credentials, owner, responsibility.SET)

    # Approve v1 with broad scope starting 2026-10-01
    existing_resp = approve(
        client, reviewer, version1,
        {"valid_from": "2026-10-01", "valid_to": "2027-01-01", "basis_id": str(uuid4())},
    )
    assert existing_resp.status_code == 200
    existing_dec = existing_resp.json()["decision_id"]

    # Non-overlapping fake conflict must be rejected by DB trigger (409)
    fake = client.post(
        f"/internal/sources/versions/{v2.version_ref}/effectivity-conflicts",
        headers=command_headers(reviewer),
        json={
            "existing_decision_id": existing_dec,
            "valid_from": "2027-02-01",
            "region": "shanghai",
            "basis_id": str(uuid4()),
            "summary": "No real overlap",
        },
    )
    assert fake.status_code == 409 and fake.json()["error"]["code"] == "effectivity_conflict"

    # Register real partial-scope overlap conflict (existing is all regions, v2 targets shanghai in 2026-11..2027-02)
    conflict_key = str(uuid4())
    conflict_body = {
        "existing_decision_id": existing_dec,
        "valid_from": "2026-11-01",
        "valid_to": "2027-02-01",
        "region": "shanghai",
        "basis_id": str(uuid4()),
        "summary": "上海地区新标准与全员通用制度在 2026-11 至 2026-12 重叠且无明确替代关系",
    }
    rec = client.post(
        f"/internal/sources/versions/{v2.version_ref}/effectivity-conflicts",
        headers=command_headers(reviewer, conflict_key),
        json=conflict_body,
    )
    assert rec.status_code == 200
    conflict_id = rec.json()["conflict_id"]
    assert rec.json()["status"] == "open"

    # Before owner is designated as document responsible person, owner cannot list or resolve conflicts
    assert client.get(
        f"/internal/sources/documents/{doc_id}/effectivity-conflicts",
        headers=bearer(owner),
    ).status_code == 403
    assert client.post(
        f"/internal/sources/effectivity-conflicts/{conflict_id}/resolution",
        headers=command_headers(owner),
        json={"outcome": "narrow_scope", "basis_id": str(uuid4()), "conclusion": "Not responsible yet"},
    ).status_code == 403

    # Assign owner as the document's policy responsible person
    owner_ref = _principal_ref(connection, tenant.actor_id)
    assign = client.post(
        f"/internal/sources/documents/{doc_id}/responsibility",
        headers=command_headers(owner),
        json={"expected_generation": 0, "responsible_id": str(owner_ref), "basis_id": str(uuid4())},
    )
    assert assign.status_code == 200

    # Now the designated policy responsible person can list and resolve the overlap conflict
    listed = client.get(
        f"/internal/sources/documents/{doc_id}/effectivity-conflicts",
        headers=bearer(owner),
    )
    assert listed.status_code == 200
    items = listed.json()["conflicts"]
    assert len(items) == 1 and items[0]["conflict_id"] == conflict_id and items[0]["status"] == "open"

    res_key = str(uuid4())
    res_resp = client.post(
        f"/internal/sources/effectivity-conflicts/{conflict_id}/resolution",
        headers=command_headers(owner, res_key),
        json={
            "outcome": "narrow_scope",
            "basis_id": str(uuid4()),
            "linked_decision_id": existing_dec,
            "conclusion": "保持全员旧版至年底，新版上海标准延后自 2027-01-01 单独生效。",
        },
    )
    assert res_resp.status_code == 200
    res_id = res_resp.json()["resolution_id"]
    assert res_resp.json()["outcome"] == "narrow_scope"

    # Second resolution with a different idempotency key is rejected (409)
    dup = client.post(
        f"/internal/sources/effectivity-conflicts/{conflict_id}/resolution",
        headers=command_headers(owner),
        json={
            "outcome": "keep_existing",
            "basis_id": str(uuid4()),
            "conclusion": "Attempting overwrite",
        },
    )
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "effectivity_conflict"

    # Resolved record is visible in document conflict list and protected against mutation
    listed_after = client.get(
        f"/internal/sources/documents/{doc_id}/effectivity-conflicts",
        headers=bearer(reviewer),
    ).json()["conflicts"]
    assert listed_after[0]["status"] == "resolved"
    assert listed_after[0]["resolution"]["resolution_id"] == res_id
    assert listed_after[0]["resolution"]["linked_decision_id"] == existing_dec

    with pytest.raises(errors.DatabaseError):
        connection.execute(
            "UPDATE thalion.rule_effectivity_conflict_resolution SET outcome = 'keep_existing' WHERE resolution_ref = %s",
            (res_id,),
        )
    connection.rollback()


def test_management_effectivity_page_preview_stop_and_conflict_flow(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, reviewer), credentials, *_ = transport
    connection, tenant, _, _, store = db
    uploaded = upload_policy(client, db, owner, credentials)
    v1 = uploaded["version_id"]
    doc_id = uploaded["document_id"]
    doc_pk, source_id = connection.execute(
        """
        SELECT d.document_id, d.source_id
        FROM thalion.object_identity AS id
        JOIN thalion.document AS d ON d.document_id = id.object_id
        WHERE id.public_id = %s AND id.object_type = 'document'
        """,
        (doc_id,),
    ).fetchone()
    v2 = _register_second_version_for_existing_document(connection, tenant, source_id, doc_pk, store, "browser")

    for op in effectivity.OPERATIONS:
        admit(credentials, reviewer, op)

    existing_dec = approve(
        client, reviewer, v1,
        {"valid_from": "2026-10-01", "valid_to": "2027-01-01", "basis_id": str(uuid4())},
    ).json()["decision_id"]

    with loopback_page(browser, service, "/manage/effectivity") as (page, _, _):
        load_approver(page, reviewer)
        # 1. Preview future switch & overlap detection
        page.get_by_label("资料版本编号").fill(str(v2.version_ref))
        page.get_by_label("生效日期").fill("2026-11-15")
        page.get_by_label("地区").fill("shanghai")
        page.get_by_role("button", name="预览切换与影响").click()
        expect(page.get_by_text("已加载换版影响预览。", exact=True)).to_be_visible()
        expect(page.locator("#effectivity-preview-readiness")).to_contain_text("可用依据不足")
        expect(page.locator("#effectivity-preview-overlaps")).to_contain_text(existing_dec)

        # 2. Register overlap conflict, list it, and record resolution
        page.get_by_label("候选版本编号").fill(str(v2.version_ref))
        page.get_by_label("重叠现有决定编号").fill(existing_dec)
        page.get_by_label("争议起始日").fill("2026-11-15")
        page.get_by_label("争议适用地域（选填）").fill("shanghai")
        page.get_by_label("登记依据编号").fill(str(uuid4()))
        page.get_by_label("争议说明").fill("上海地区试点条款与全国通用条款区间重叠")
        page.get_by_role("button", name="登记重叠争议").click()
        expect(page.locator("#effectivity-conflict-status")).to_contain_text("已登记重叠争议：")

        page.get_by_role("button", name="加载争议清单").click()
        expect(page.locator("#effectivity-conflict-list")).to_contain_text("待制度负责人裁定")

        page.get_by_label("裁定依据编号").fill(str(uuid4()))
        page.get_by_label("裁定结论说明").fill("确认维持现有全国版本，上海试点另行择期发布。")
        page.get_by_role("button", name="提交争议裁定").click()
        expect(page.locator("#effectivity-resolve-status")).to_contain_text("已记录裁定结论：")

        page.get_by_role("button", name="加载争议清单").click()
        expect(page.locator("#effectivity-conflict-list")).to_contain_text("已裁定")

        # 3. Preview stop impact and withdraw v1 with reason
        page.get_by_label("待撤回/暂停版本编号").fill(v1)
        page.get_by_role("button", name="预览撤回影响").click()
        expect(page.locator("#effectivity-stop-status")).to_contain_text("已加载撤回影响预览")
        page.get_by_label("停用依据编号").fill(str(uuid4()))
        page.get_by_label("撤回/暂停原因").fill("试点制度撤回停止检索")
        page.get_by_role("button", name="执行撤回/暂停").click()
        expect(page.locator("#effectivity-stop-status")).to_contain_text("已执行 withdrawn")

        # 4. Mobile 390px layout has no horizontal overflow
        page.set_viewport_size({"width": 390, "height": 844})
        overflow = page.evaluate("() => document.documentElement.scrollWidth > window.innerWidth")
        assert overflow is False

        # 5. Changing credential wipes all panels and inputs cleanly
        page.get_by_role("button", name="更换凭据").click()
        expect(page.locator("#effectivity-preview")).to_be_hidden()
        expect(page.locator("#effectivity-conflict-list")).to_be_empty()
        assert page.get_by_label("争议说明").input_value() == ""
