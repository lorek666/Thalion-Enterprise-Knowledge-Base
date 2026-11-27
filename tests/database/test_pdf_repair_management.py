from dataclasses import replace
from uuid import uuid4

from enterprise_kb.modules.evidence import processing

from test_employee_portal import browser, loopback_page, screenshot
from test_evidence import evidence_db, review
from test_evidence_transport import private_json
from test_pdf_correction import TRANSCRIPT, fixture_page
from test_pdf_correction_review import DECIDE, PREVIEW
from test_pdf_processing import PAGE_TEXT, text_page
from test_pdf_repair import repair_lease
from test_pdf_repair_approval import permit_review, stage_batch
from test_pdf_review import path, pdf_review
from test_runtime import runtime_db


def load_reviewer(page, token):
    page.get_by_label("管理测试凭据").fill(token)
    page.get_by_role("button", name="载入审核凭据").click()


def open_batch_review(page, token, run):
    load_reviewer(page, token)
    page.get_by_role("radio", name="PDF 整批审定").check()
    page.get_by_label("校订批次编号").fill(str(run.run_ref))


def lookup_batch_page(page, run, number):
    page.get_by_label("物理页码").fill(str(number))
    with page.expect_response(f"**{path(run, number)}/review") as response:
        page.get_by_role("button", name="核对批次原页").click()
    assert response.value.status == 200
    return response.value.json()["request_id"]


def test_management_pdf_correction_through_whole_batch_approval(browser, pdf_review):
    from playwright.sync_api import expect

    db, _, service, _, _, credentials = pdf_review
    connection, _, version, original, _, reviewer, author = fixture_page(pdf_review, text_page(PAGE_TEXT), b"")
    review(db, original, decision="quarantined")
    credentials[reviewer] = replace(
        credentials[reviewer], operations=credentials[reviewer].operations | {PREVIEW, DECIDE},
    )
    permit_review(pdf_review, reviewer)
    with loopback_page(browser, service, "/manage/repairs") as (page, _, _):
        load_reviewer(page, author)
        page.get_by_role("radio", name="提交 OCR 候选").check()
        page.get_by_label("校订批次编号").fill(str(original.run_ref))
        page.get_by_label("物理页码").fill("2")
        expect(page.get_by_role("button", name="提交候选", exact=True)).to_be_hidden()
        page.get_by_role("button", name="查看提交原页").click()
        expect(page.get_by_role("img", name="PDF 原页，第 2 页")).to_be_visible()
        page.get_by_label("候选转录").fill(TRANSCRIPT)
        page.get_by_label("提交依据编号").fill(str(uuid4()))
        with page.expect_response(f"**{path(original, 2)}/corrections") as proposal:
            page.get_by_role("button", name="提交候选", exact=True).click()
        assert proposal.value.status == 200
        correction = proposal.value.json()["correction_id"]
        expect(page.get_by_text(f"候选已提交：{correction}", exact=True)).to_be_visible()
        expect(page.get_by_label("候选转录")).to_have_value("")
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)

        page.get_by_role("button", name="更换凭据").click()
        load_reviewer(page, reviewer)
        page.get_by_role("radio", name="复核 OCR 候选").check()
        page.get_by_label("候选编号", exact=True).fill(correction)
        page.get_by_role("button", name="查看候选对照").click()
        expect(page.get_by_role("img", name="PDF 原页，第 2 页")).to_be_visible()
        expect(page.get_by_text("原转录失败：未识别到文字", exact=True)).to_be_visible()
        expect(page.get_by_text(TRANSCRIPT, exact=True)).to_be_visible()
        page.get_by_label("复核依据编号").fill(str(uuid4()))
        with page.expect_response(f"**/pdf-corrections/{correction}/decision") as decision:
            page.get_by_role("button", name="批准候选").click()
        assert decision.value.status == 200 and decision.value.json()["outcome"] == "approved"
        expect(page.get_by_text("候选已批准。", exact=True)).to_be_visible()
        expect(page.get_by_text(TRANSCRIPT, exact=True)).to_have_count(0)
        assert connection.execute(
            "SELECT outcome FROM thalion.quality_decision WHERE run_ref = %s", (original.run_ref,),
        ).fetchall() == [("quarantined",)]

        repaired = processing.repair_pdf_job(
            connection, repair_lease(db, version), db[-1], replaces=original.run_ref, basis_ref=uuid4(),
        )
        page.get_by_role("radio", name="PDF 整批审定").check()
        page.get_by_label("校订批次编号").fill(str(repaired.run_ref))
        second = lookup_batch_page(page, repaired, 2)
        expect(page.get_by_text(TRANSCRIPT, exact=True)).to_be_visible()
        expect(page.get_by_text("已核对 1 / 2 页", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="批准整批")).to_be_disabled()
        screenshot(page, "management-pdf-repair-desktop.png")
        page.set_viewport_size({"width": 390, "height": 820})
        assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
        screenshot(page, "management-pdf-repair-mobile.png")
        first = lookup_batch_page(page, repaired, 1)
        expect(page.get_by_text(TRANSCRIPT, exact=True)).to_have_count(0)
        expect(page.get_by_text(PAGE_TEXT.decode(), exact=True)).to_be_visible()
        expect(page.get_by_text("已核对 2 / 2 页", exact=True)).to_be_visible()
        page.get_by_label("整批审定依据编号").fill(str(uuid4()))
        with page.expect_response(f"**/repairs/{repaired.run_ref}/pdf-approval") as approval:
            page.get_by_role("button", name="批准整批").click()
        assert approval.value.status == 200
        assert approval.value.request.post_data_json["preview_request_ids"] == [first, second]
        expect(page.get_by_text("修订批次已批准。", exact=True)).to_be_visible()
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
    assert set(connection.execute(
        "SELECT run_ref, outcome FROM thalion.quality_decision",
    ).fetchall()) == {(original.run_ref, "quarantined"), (repaired.run_ref, "approved")}


def test_management_pdf_approval_discards_pages_when_source_revokes(browser, pdf_review):
    from playwright.sync_api import expect

    _, profile, service, *_ = pdf_review
    connection, _, _, repaired, _, reviewer, _ = stage_batch(pdf_review)
    permit_review(pdf_review, reviewer)
    with loopback_page(browser, service, "/manage/repairs") as (page, _, _):
        open_batch_review(page, reviewer, repaired)
        lookup_batch_page(page, repaired, 1)
        lookup_batch_page(page, repaired, 2)
        expect(page.get_by_text("已核对 2 / 2 页", exact=True)).to_be_visible()
        expect(page.get_by_text(TRANSCRIPT, exact=True)).to_be_visible()
        private_json(profile.root / "pdf-page-grants.json", {})
        page.get_by_label("整批审定依据编号").fill(str(uuid4()))
        with page.expect_response(f"**/repairs/{repaired.run_ref}/pdf-approval") as response:
            page.get_by_role("button", name="批准整批").click()
        assert response.value.status == 403
        expect(page.get_by_text("此操作未获授权。", exact=True)).to_be_visible()
        expect(page.get_by_text(TRANSCRIPT, exact=True)).to_have_count(0)
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
        expect(page.get_by_text("已核对 2 / 2 页", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="批准整批")).to_be_hidden()
    assert connection.execute(
        "SELECT count(*) FROM thalion.quality_decision WHERE run_ref = %s", (repaired.run_ref,),
    ).fetchone() == (0,)


def test_late_pdf_batch_page_cannot_restore_replaced_reviewer_state(browser, pdf_review):
    from playwright.sync_api import expect

    _, _, service, *_ = pdf_review
    _, _, _, repaired, _, reviewer, author = stage_batch(pdf_review)
    permit_review(pdf_review, reviewer)
    with loopback_page(browser, service, "/manage/repairs") as (page, _, _):
        open_batch_review(page, reviewer, repaired)
        lookup_batch_page(page, repaired, 1)
        expect(page.get_by_text("已核对 1 / 2 页", exact=True)).to_be_visible()
        page.evaluate("""() => {
            const fetchReal = window.fetch;
            window.fetch = async (url, options) => {
                if (!url.endsWith("/review") || window.releaseOldTestResponse) return fetchReal(url, options);
                const response = await fetchReal(url, {...options, signal: undefined});
                if (!response.ok) throw new Error("Expected an authorized PDF batch preview");
                await new Promise(resolve => {
                    window.releaseOldTestResponse = resolve;
                    document.body.dataset.oldResponseReady = "true";
                });
                return response;
            };
        }""")
        page.get_by_label("物理页码").fill("2")
        page.get_by_role("button", name="核对批次原页").click()
        expect(page.locator("body")).to_have_attribute("data-old-response-ready", "true")
        page.get_by_role("button", name="更换凭据").click()
        open_batch_review(page, author, repaired)
        page.get_by_role("button", name="核对批次原页").click()
        expect(page.get_by_text("此操作未获授权。", exact=True)).to_be_visible()
        page.evaluate("""async () => {
            window.releaseOldTestResponse();
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        }""")
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
        expect(page.get_by_text(TRANSCRIPT, exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="批准整批")).to_be_hidden()
