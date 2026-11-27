from datetime import date
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.sources.effectivity import select_rule

from test_employee_portal import browser, loopback_page
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_ingest_transport import MARKDOWN, file, upload
from test_runtime import runtime_db
from test_travel_search import corpus


def upload_policy(client, db, owner, credentials):
    admit(credentials, owner, "upload_source_batch")
    response = upload(client, owner, db[3], [file("travel.md", "New travel rule", "A", "new-rule", MARKDOWN)])
    assert response.status_code == 200
    return response.json()["files"][0]


def approve(client, token, version, data, key=None):
    return client.post(
        f"/internal/sources/versions/{version}/effectivity", headers=command_headers(token, key), json=data,
    )


def test_approver_records_effectivity_for_the_exact_uploaded_version_without_granting_read_access(transport):
    client, db, (owner, reviewer), credentials, *_ = transport
    connection, tenant, *_ = db
    uploaded = upload_policy(client, db, owner, credentials)
    version = uploaded["version_id"]
    date_start = date(2026, 12, 1)
    document = UUID(uploaded["document_id"])
    assert select_rule(connection, tenant.org_id, tenant.space_id, document, date_start,
                       region="shanghai", traveler_class="employee").status == "not_applicable"
    bindings = connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone()
    admit(credentials, reviewer, "approve_effectivity")
    data = {"valid_from": date_start.isoformat(), "valid_to": "2027-01-01", "region": "shanghai", "basis_id": str(uuid4())}
    key = str(uuid4())
    response = approve(client, reviewer, version, data, key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    receipt = response.json()
    assert set(receipt) == {"request_id", "decision_id"}
    assert approve(client, reviewer, version, data, key).json()["decision_id"] == receipt["decision_id"]
    conflict = approve(client, reviewer, version, data | {"valid_to": "2027-02-01"}, key)
    assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "effectivity_conflict"
    selection = select_rule(connection, tenant.org_id, tenant.space_id, document, date_start,
                            region="shanghai", traveler_class="employee")
    assert (selection.status, selection.version_ref, selection.decision_ref) == (
        "applicable", UUID(version), UUID(receipt["decision_id"]),
    )
    assert select_rule(connection, tenant.org_id, tenant.space_id, document, date_start,
                       region="beijing", traveler_class="employee").status == "not_applicable"
    assert connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone() == bindings
    assert connection.execute("""
        SELECT operation, destination, scope_space_id, principal_id, outcome FROM thalion.request_record
        WHERE request_id = %s
    """, (receipt["request_id"],)).fetchone() == (
        "approve_effectivity", "internal_sources", tenant.space_id, tenant.other_actor_id, "succeeded",
    )


def test_effectivity_requires_the_current_designated_approver_and_valid_arguments(transport):
    client, db, (owner, reviewer), credentials, *_ = transport
    connection, *_ = db
    version = upload_policy(client, db, owner, credentials)["version_id"]
    before = connection.execute("SELECT count(*) FROM thalion.rule_effectivity").fetchone()
    data = {"valid_from": "2026-12-01", "basis_id": str(uuid4())}
    admit(credentials, owner, "approve_effectivity")
    assert approve(client, owner, version, data).status_code == 403
    assert approve(client, reviewer, version, data).status_code == 403
    admit(credentials, reviewer, "approve_effectivity")
    assert approve(client, reviewer, uuid4(), data).status_code == 403
    assert approve(client, reviewer, version, data | {"valid_from": "20261201"}).status_code == 400
    assert approve(client, reviewer, version, data | {"valid_to": "2026-12-01"}).status_code == 400
    assert approve(client, reviewer, version, data | {"readers": [str(uuid4())]}).status_code == 400
    connection.execute("UPDATE thalion.source SET lifecycle = 'suspended'")
    assert approve(client, reviewer, version, data).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.rule_effectivity").fetchone() == before


def load_approver(page, token):
    page.get_by_label("管理测试凭据").fill(token)
    page.get_by_role("button", name="载入审批凭据").click()
    assert page.get_by_label("管理测试凭据").input_value() == ""


def fill_decision(page, version):
    page.get_by_label("资料版本编号").fill(version)
    page.get_by_label("生效日期").fill("2026-12-01")
    page.get_by_label("结束日期").fill("2027-01-01")
    page.get_by_label("审批依据编号").fill(str(uuid4()))
    page.get_by_label("地区").fill("shanghai")
    page.get_by_label("人员类别").fill("employee")


def test_management_effectivity_page_records_decision_without_granting_access(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, reviewer), credentials, *_ = transport
    connection, tenant, *_ = db
    uploaded = upload_policy(client, db, owner, credentials)
    version = uploaded["version_id"]
    admit(credentials, owner, "approve_effectivity")
    admit(credentials, reviewer, "approve_effectivity")
    bindings = connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone()
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        page.get_by_role("link", name="生效审批").click()
        expect(page).to_have_url("/manage/effectivity")
        expect(page.get_by_role("heading", name="审批人凭据")).to_be_visible()
        load_approver(page, owner)
        fill_decision(page, version)
        submit = page.get_by_role("button", name="登记生效决定")
        submit.click()
        expect(page.get_by_text("只有当前来源指定的审批人可以登记。", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="审批回执")).to_be_hidden()
        page.get_by_role("button", name="更换凭据").click()
        load_approver(page, reviewer)
        assert page.get_by_label("资料版本编号").input_value() == ""
        fill_decision(page, version)
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (...args) => {
                window.fetch = realFetch;
                await realFetch(...args);
                throw new TypeError('Synthetic lost response');
            };
        }""")
        with page.expect_request(f"**/versions/{version}/effectivity") as first:
            submit.click()
        expect(page.get_by_text("未收到审批结果，请保留表单原样重试。", exact=True)).to_be_visible()
        with page.expect_request(f"**/versions/{version}/effectivity") as retried:
            submit.click()
        assert retried.value.headers["idempotency-key"] == first.value.headers["idempotency-key"]
        decision = select_rule(connection, tenant.org_id, tenant.space_id, UUID(uploaded["document_id"]),
                               date(2026, 12, 1), region="shanghai", traveler_class="employee")
        assert decision.status == "applicable" and decision.version_ref == UUID(version)
        expect(page.get_by_text(str(decision.decision_ref), exact=True)).to_be_visible()
        page.get_by_label("结束日期").fill("2027-02-01")
        expect(page.get_by_role("heading", name="审批回执")).to_be_hidden()
        submit.click()
        expect(page.get_by_text("与现有决定冲突，请核对日期、范围和被替代决定。", exact=True)).to_be_visible()
    assert connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone() == bindings
    assert connection.execute("SELECT count(*) FROM thalion.rule_effectivity WHERE decision_ref = %s",
                              (decision.decision_ref,)).fetchone() == (1,)


@pytest.mark.parametrize("exit_action", ["change_credential", "pagehide"])
def test_late_effectivity_response_cannot_restore_receipt(browser, evidence_transport, transport, exit_action):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, reviewer), credentials, *_ = transport
    version = upload_policy(client, db, owner, credentials)["version_id"]
    admit(credentials, reviewer, "approve_effectivity")
    with loopback_page(browser, service, "/manage/effectivity") as (page, _, response):
        assert response.status == 200 and response.headers["cache-control"] == "no-store"
        assert "form-action 'none'" in response.headers["content-security-policy"]
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                const response = await realFetch(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestApproval = resolve;
                    document.body.dataset.testApprovalReady = 'true';
                });
                return response;
            };
        }""")
        load_approver(page, reviewer)
        fill_decision(page, version)
        page.get_by_role("button", name="登记生效决定").click()
        expect(page.locator("body")).to_have_attribute("data-test-approval-ready", "true")
        if exit_action == "change_credential":
            page.get_by_role("button", name="更换凭据").click()
            load_approver(page, owner)
        else:
            page.evaluate("""() => {
                window.dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true}));
                window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}));
            }""")
            expect(page.get_by_role("heading", name="审批人凭据")).to_be_visible()
        page.evaluate("async () => { window.releaseTestApproval(); await new Promise(requestAnimationFrame); }")
        expect(page.get_by_role("heading", name="审批回执")).to_be_hidden()
        expect(page.locator("#effectivity-decision")).to_be_empty()
        assert page.get_by_label("资料版本编号").input_value() == ""
        assert page.get_by_label("管理测试凭据").input_value() == ""
