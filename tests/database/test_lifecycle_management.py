from uuid import uuid4

from test_employee_portal import browser, loopback_page
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_runtime import runtime_db
from test_travel_search import corpus, publish


def _load_lifecycle_token(page, token: str):
    page.get_by_label("管理测试凭据").fill(token)
    page.get_by_role("button", name="载入管理凭据").click()
    assert page.get_by_label("管理测试凭据").input_value() == ""


def test_lifecycle_management_portal_serves_hardened_assets(transport):
    client, *_ = transport
    page = client.get("/manage/lifecycle")
    script = client.get("/manage/lifecycle.js")
    assert page.status_code == 200 and script.status_code == 200
    assert page.headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in page.headers["Content-Security-Policy"]
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]
    assert "form-action 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert "管理与审计权限不授予原文读权" in page.text
    assert "<script>" not in page.text


def test_lifecycle_management_page_runs_retention_hold_disposition_and_source_audit(
    browser, evidence_transport, transport,
):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, reviewer), credentials, _, *_ = transport
    connection, _, _, source, _ = db
    disposable, _, _ = publish(db, "lifecycle-destroy", "合成待销毁制度", b"# Secret Original\n\nSynthetic destroy body.\n")
    holdable, _, _ = publish(db, "lifecycle-hold", "合成保全制度", b"# Hold Original\n\nSynthetic hold body.\n")
    # Trigger an audited employee search so source audit has real metadata records
    search_resp = client.post("/v1/search", headers=bearer(owner), json={"query": "上海住宿"})
    assert search_resp.status_code == 200

    admit(
        credentials, owner,
        "register_retention_policy", "plan_disposition", "submit_disposition_case",
        "approve_disposition_case", "read_source_audit",
    )
    admit(
        credentials, reviewer,
        "approve_disposition_case", "reject_disposition_case",
        "verify_disposition_original", "register_deletion_tombstone", "decide_hold",
    )
    bindings_before = connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone()

    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_role("link", name="保留处置与审计").click()
        expect(page).to_have_url("/manage/lifecycle")
        expect(page.get_by_role("heading", name="管理与审计凭据")).to_be_visible()

        # 1. Owner registers retention policy, previews and submits destroy disposition, verifies self-approval refusal, and queries source audit
        _load_lifecycle_token(page, owner)
        page.get_by_label("策略来源编号").fill(str(source))
        page.get_by_label("预期策略代次").fill("0")
        page.get_by_label("保存天数").fill("0")
        page.get_by_label("到期处置方式").select_option("destroy")
        page.get_by_label("策略审批依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="登记保留策略").click()
        expect(page.locator("#lifecycle-retention-status")).to_contain_text("已登记保留策略：")

        page.get_by_label("处置目标版本编号").fill(str(disposable.version_ref))
        page.get_by_label("处置动作").select_option("destroy")
        page.get_by_label("处置原因").select_option("retention_expiry")
        page.get_by_role("button", name="预览处置清点").click()
        expect(page.locator("#lifecycle-plan-status")).to_contain_text("已生成处置清点预览。")
        expect(page.locator("#lifecycle-plan-summary")).to_contain_text("review_required")
        expect(page.locator("#lifecycle-plan-copies")).to_contain_text("本地副本：original")

        page.get_by_role("button", name="按当前快照提交处置申请").click()
        expect(page.locator("#lifecycle-plan-status")).to_contain_text("已提交处置申请：")
        case_id = page.get_by_label("处置案件编号").input_value()
        snapshot = page.get_by_label("清点快照摘要").input_value()
        assert len(case_id) == 36 and len(snapshot) == 64

        # Self-approval by submitter must be rejected (403)
        page.get_by_label("复核/审批依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="独立批准处置").click()
        expect(page.locator("#lifecycle-case-status")).to_contain_text("无权执行")

        # Per-source audit returns metadata without any original body text
        page.get_by_label("审计目标来源编号").fill(str(source))
        page.get_by_role("button", name="查询来源审计").click()
        expect(page.locator("#lifecycle-audit-status")).to_contain_text("已加载")
        expect(page.locator("#lifecycle-audit-list")).to_contain_text("操作：")
        assert "Synthetic destroy body" not in page.locator("#lifecycle-audit-list").inner_text()

        # Switch credential clears all inputs and lists
        page.get_by_role("button", name="更换凭据").click()
        expect(page.locator("#lifecycle-audit-list")).to_be_empty()
        assert page.get_by_label("处置案件编号").input_value() == ""
        assert page.get_by_label("清点快照摘要").input_value() == ""

        # 2. Independent reviewer approves, verifies original digest, registers deletion tombstone, and places a legal hold
        _load_lifecycle_token(page, reviewer)
        page.get_by_label("处置案件编号").fill(case_id)
        page.get_by_label("清点快照摘要").fill(snapshot)
        page.get_by_label("复核/审批依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="独立批准处置").click()
        expect(page.locator("#lifecycle-case-status")).to_contain_text("已独立批准处置：")
        approval_id = page.get_by_label("已批准决定编号（登记墓碑用）").input_value()
        assert len(approval_id) == 36

        page.get_by_role("button", name="核验原件摘要").click()
        expect(page.locator("#lifecycle-case-status")).to_contain_text("原件摘要核验完成：")

        page.get_by_role("button", name="登记删除墓碑").click()
        expect(page.locator("#lifecycle-case-status")).to_contain_text("已登记删除墓碑：")
        expect(page.locator("#lifecycle-case-status")).to_contain_text("restore_blocked")

        page.get_by_label("保全目标版本编号").fill(str(holdable.version_ref))
        page.get_by_label("保全动作").select_option("establish")
        page.get_by_label("预期保全代次").fill("0")
        page.get_by_label("保全依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="提交保全决定").click()
        expect(page.locator("#lifecycle-hold-status")).to_contain_text("状态：held")

        # 3. Mobile 390px viewport has no horizontal overflow
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("() => document.documentElement.scrollWidth > window.innerWidth") is False

        # 4. Pagehide/bfcache lock clears sensitive state
        page.evaluate("""() => {
            window.dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true}));
            window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}));
        }""")
        expect(page.get_by_role("heading", name="管理与审计凭据")).to_be_visible()
        assert page.get_by_label("处置案件编号").input_value() == ""
        assert page.get_by_label("管理测试凭据").input_value() == ""

    assert connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone() == bindings_before
