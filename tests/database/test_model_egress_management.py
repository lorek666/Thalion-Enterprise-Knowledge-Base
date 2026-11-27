from uuid import uuid4

from test_access_policy_transport import load_policy_page, policy_path, replace_policy
from test_employee_portal import browser, loopback_page
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_model_egress_policy import evidence_db, model_policy_path, rule_for
from test_runtime import runtime_db
from test_travel_search import corpus


MANAGEMENT_PATH = "/manage/model-egress"


def test_approver_can_register_and_remove_model_rules_without_changing_local_rules(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, approver), credentials, _, first, restricted = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "read_local_policy")
    admit(credentials, approver, "read_model_policy", "replace_model_policy")
    local_before = client.get(policy_path(source), headers=bearer(owner)).json()["rules"]
    rule = rule_for(credentials[approver].employee_ref, restricted.passage_ref) | {"purpose": "model_review"}
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_role("link", name="外发规则").click()
        expect(page).to_have_url(MANAGEMENT_PATH)
        page.set_viewport_size({"width": 390, "height": 844})
        expect(page.get_by_text("synthetic-gateway", exact=True)).to_be_visible()
        load_policy_page(page, approver, source)
        expect(page.get_by_text("当前共享策略修订 2。", exact=True)).to_be_visible()
        page.get_by_role("button", name="新增外发规则").click()
        draft = page.get_by_role("group", name="外发规则 1")
        draft.get_by_label("主体编号").fill(rule["subject_id"])
        draft.get_by_label("片段编号").fill(rule["passage_id"])
        draft.get_by_label("外发用途").select_option(rule["purpose"])
        draft.get_by_label("摘录", exact=True).check()
        draft.get_by_label("有效起始").fill(rule["valid_from"])
        draft.get_by_label("有效截止").fill("2026-11-23T12:00:00")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.get_by_label("变更依据编号").fill(str(uuid4()))
        save = page.get_by_role("button", name="保存外发规则")
        confirmation = page.get_by_label("确认替换该来源的全部外发规则")
        expect(save).to_be_disabled()
        confirmation.check()
        save.click()
        expect(page.get_by_role("status")).to_contain_text("起止时间均须带时区")
        draft.get_by_label("有效截止").fill(rule["valid_until"])
        expect(save).to_be_disabled()
        confirmation.check()
        save.click()
        expect(page.get_by_text("已登记规则修订 3。", exact=True)).to_be_visible()
        assert client.get(model_policy_path(source), headers=bearer(approver)).json()["rules"] == [rule]
        assert client.get(f"/v1/passages/{restricted.passage_ref}", headers=bearer(approver)).status_code == 404
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(approver)).status_code == 200
        page.get_by_role("button", name="读取当前规则").click()
        expect(draft.get_by_label("外发用途")).to_have_value(rule["purpose"])
        draft.get_by_role("button", name="移除此规则").click()
        page.get_by_label("变更依据编号").fill(str(uuid4()))
        confirmation.check()
        save.click()
        expect(page.get_by_text("已登记规则修订 4。", exact=True)).to_be_visible()
    assert client.get(model_policy_path(source), headers=bearer(approver)).json()["rules"] == []
    assert client.get(policy_path(source), headers=bearer(owner)).json()["rules"] == local_before
    assert connection.execute("SELECT count(*) FROM thalion.external_call").fetchone() == (0,)


def test_egress_management_requires_reloading_after_a_concurrent_reader_change(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, approver), credentials, *_ = transport
    source = db[3]
    admit(credentials, owner, "read_local_policy", "replace_local_policy")
    admit(credentials, approver, "read_model_policy", "replace_model_policy")
    with loopback_page(browser, service, MANAGEMENT_PATH) as (page, _, response):
        assert response.status == 200 and response.headers["cache-control"] == "no-store"
        load_policy_page(page, approver, source)
        expect(page.get_by_text("当前共享策略修订 2。", exact=True)).to_be_visible()
        changed = replace_policy(client, owner, source, {"expected_epoch": 2, "basis_id": str(uuid4()), "rules": []})
        assert changed.status_code == 200
        page.get_by_label("变更依据编号").fill(str(uuid4()))
        page.get_by_label("确认替换该来源的全部外发规则").check()
        save = page.get_by_role("button", name="保存外发规则")
        save.click()
        expect(page.get_by_role("status")).to_contain_text("请读取当前规则后重新核对")
        expect(save).to_be_hidden()
        page.get_by_role("button", name="读取当前规则").click()
        expect(page.get_by_text("当前共享策略修订 3。", exact=True)).to_be_visible()
        expect(page.get_by_label("变更依据编号")).to_have_value("")
        expect(save).to_be_disabled()


def test_egress_management_discards_the_approvers_late_snapshot_after_switching_credentials(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, approver), credentials, *_ = evidence_transport
    admit(credentials, approver, "read_model_policy", "replace_model_policy")
    admit(credentials, owner, "read_local_policy", "read_model_policy", "replace_model_policy")
    with loopback_page(browser, service, MANAGEMENT_PATH) as (page, _, response):
        assert response.status == 200
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                window.fetch = realFetch;
                const response = await realFetch(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestEgress = resolve;
                    document.body.dataset.testEgressReady = 'true';
                });
                return response;
            };
        }""")
        load_policy_page(page, approver, db[3])
        expect(page.locator("body")).to_have_attribute("data-test-egress-ready", "true")
        page.get_by_role("button", name="更换凭据").click()
        load_policy_page(page, owner, db[3])
        expect(page.get_by_role("status")).to_contain_text("当前凭据不能管理该来源的规则")
        page.evaluate("async () => { window.releaseTestEgress(); await new Promise(requestAnimationFrame); }")
        expect(page.get_by_role("button", name="保存外发规则")).to_be_hidden()
        expect(page.get_by_text("当前共享策略修订 2。", exact=True)).to_have_count(0)


def test_egress_management_retries_a_committed_save_without_creating_another_revision(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (_, approver), credentials, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, approver, "read_model_policy", "replace_model_policy")
    with loopback_page(browser, service, MANAGEMENT_PATH) as (page, _, _):
        load_policy_page(page, approver, source)
        expect(page.get_by_text("当前共享策略修订 2。", exact=True)).to_be_visible()
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                window.fetch = realFetch;
                await realFetch(url, options);
                throw new TypeError('Synthetic lost response');
            };
        }""")
        page.get_by_label("变更依据编号").fill(str(uuid4()))
        page.get_by_label("确认替换该来源的全部外发规则").check()
        save = page.get_by_role("button", name="保存外发规则")
        save.click()
        expect(page.get_by_role("status")).to_contain_text("保存结果未知时请保留表单原样重试")
        assert client.get(model_policy_path(source), headers=bearer(approver)).json()["policy_revision"] == 3
        save.click()
        expect(page.get_by_text("已登记规则修订 3。", exact=True)).to_be_visible()
    assert connection.execute("SELECT count(*) FROM thalion.policy_revision").fetchone() == (2,)
