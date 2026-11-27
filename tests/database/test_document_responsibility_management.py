from uuid import uuid4

from test_document_responsibility import decide, path, upload_document
from test_employee_portal import browser, loopback_page
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_runtime import runtime_db
from test_travel_search import corpus


def load(page, token, document):
    page.get_by_label("管理测试凭据").fill(token)
    page.get_by_role("button", name="载入管理凭据").click()
    page.get_by_label("资料编号").fill(document)
    page.get_by_role("button", name="读取当前负责人").click()


def test_source_owner_can_assign_and_revoke_document_responsibility_in_management(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, other), credentials, *_ = transport
    admit(credentials, owner, "read_document_responsibility", "set_document_responsibility")
    document = upload_document(client, db[3], owner, credentials)["document_id"]
    subject = str(credentials[other].employee_ref)
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_role("link", name="资料负责人").click()
        expect(page).to_have_url("/manage/responsibility")
        load(page, owner, document)
        expect(page.get_by_text("尚未登记负责人。", exact=True)).to_be_visible()
        page.get_by_label("受任员工编号").fill(subject)
        page.get_by_label("登记依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="保存责任决定").click()
        expect(page.get_by_text("已登记责任决定（代次 1）。", exact=True)).to_be_visible()
        page.get_by_role("button", name="读取当前负责人").click()
        expect(page.get_by_text(subject, exact=True)).to_be_visible()
        page.get_by_label("办理事项").select_option("revoke")
        expect(page.get_by_label("受任员工编号")).to_be_hidden()
        page.get_by_label("登记依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="保存责任决定").click()
        expect(page.get_by_text("已登记责任决定（代次 2）。", exact=True)).to_be_visible()
    current = client.get(path(document), headers=bearer(owner)).json()
    assert (current["state"], current["responsible_id"], current["generation"]) == ("unassigned", None, 2)


def test_responsibility_management_never_restores_a_late_snapshot_after_credential_change(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, other), credentials, *_ = transport
    admit(credentials, owner, "read_document_responsibility", "set_document_responsibility")
    document = upload_document(client, db[3], owner, credentials)["document_id"]
    with loopback_page(browser, service, "/manage/responsibility") as (page, _, response):
        assert response.status == 200 and response.headers["cache-control"] == "no-store"
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                window.fetch = realFetch;
                const response = await realFetch(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestResponsibility = resolve;
                    document.body.dataset.testResponsibilityReady = 'true';
                });
                return response;
            };
        }""")
        load(page, owner, document)
        expect(page.locator("body")).to_have_attribute("data-test-responsibility-ready", "true")
        page.get_by_role("button", name="更换凭据").click()
        load(page, other, document)
        expect(page.get_by_text("当前凭据不能管理该资料的负责人。", exact=True)).to_be_visible()
        page.evaluate("async () => { window.releaseTestResponsibility(); await new Promise(requestAnimationFrame); }")
        expect(page.get_by_text("尚未登记负责人。", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="保存责任决定")).to_be_hidden()


def test_responsibility_management_requires_a_fresh_snapshot_after_a_concurrent_change(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, other), credentials, *_ = transport
    admit(credentials, owner, "read_document_responsibility", "set_document_responsibility")
    document = upload_document(client, db[3], owner, credentials)["document_id"]
    current_subject = str(credentials[other].employee_ref)
    replacement = str(credentials[owner].employee_ref)
    with loopback_page(browser, service, "/manage/responsibility") as (page, _, _):
        load(page, owner, document)
        expect(page.get_by_text("尚未登记负责人。", exact=True)).to_be_visible()
        assert decide(client, owner, document, {
            "expected_generation": 0, "responsible_id": current_subject, "basis_id": str(uuid4()),
        }).status_code == 200
        page.get_by_label("受任员工编号").fill(replacement)
        page.get_by_label("登记依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="保存责任决定").click()
        expect(page.get_by_text("负责人的决定已变化或提交冲突，请重新读取。", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="保存责任决定")).to_be_hidden()
        expect(page.get_by_text("尚未登记负责人。", exact=True)).to_have_count(0)
        page.get_by_role("button", name="读取当前负责人").click()
        expect(page.get_by_text(current_subject, exact=True)).to_be_visible()
        expect(page.get_by_label("受任员工编号")).to_have_value("")
        page.get_by_label("受任员工编号").fill(replacement)
        page.get_by_label("登记依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="保存责任决定").click()
        expect(page.get_by_text("已登记责任决定（代次 2）。", exact=True)).to_be_visible()
    current = client.get(path(document), headers=bearer(owner)).json()
    assert (current["state"], current["responsible_id"], current["generation"]) == ("assigned", replacement, 2)
