from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import socket
from threading import Thread
from time import monotonic, sleep
from uuid import uuid4

import pytest
import uvicorn

from enterprise_kb.transport.api import create_app

from test_evidence import evidence_db
from test_evidence_transport import add_search_source, evidence_transport, transport
from test_runtime import runtime_db
from test_travel_search import BEFORE, corpus


@pytest.fixture
def browser():
    if os.environ.get("THALION_BROWSER_E2E") != "1":
        pytest.skip("Set THALION_BROWSER_E2E=1 and install the browser group to run Chromium tests.")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as driver:
        options = {"headless": True}
        if channel := os.environ.get("THALION_BROWSER_CHANNEL"):
            options["channel"] = channel
        with driver.chromium.launch(**options) as application:
            yield application


@contextmanager
def loopback_page(browser, service, path="/"):
    app = create_app(service)
    server = uvicorn.Server(uvicorn.Config(app, lifespan="on", access_log=False, log_level="warning", proxy_headers=False))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bound:
        bound.bind(("127.0.0.1", 0))
        base = f"http://127.0.0.1:{bound.getsockname()[1]}"
        worker = Thread(target=server.run, kwargs={"sockets": [bound]}, daemon=True)
        worker.start()
        try:
            deadline = monotonic() + 10
            while not server.started and worker.is_alive() and monotonic() < deadline:
                sleep(0.02)
            assert server.started, "The synthetic loopback portal did not start."
            with browser.new_context(base_url=base, viewport={"width": 1280, "height": 860}) as context:
                page = context.new_page()
                response = page.goto(path)
                yield page, base, response
        finally:
            server.should_exit = True
            worker.join(timeout=10)
            assert not worker.is_alive(), "The synthetic loopback portal did not stop."


@pytest.fixture
def portal(browser, evidence_transport):
    service, *fixtures = evidence_transport
    with loopback_page(browser, service) as (page, base, _):
        yield page, base, *fixtures


def test_employee_shell_is_public_but_never_embeds_identity_or_protected_content(transport):
    client, _, tokens, *_ = transport
    page = client.get("/")
    assert page.status_code == 200 and page.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert "form-action 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert "核对制度原文" in page.text and "受限审批说明" not in page.text
    assert all(token not in page.text for token in tokens)
    assert not page.cookies
    for path in ("/employee/portal.js", "/employee/portal.css"):
        asset = client.get(path)
        assert asset.status_code == 200 and asset.headers["Cache-Control"] == "no-store"
    assert client.get("/employee/credentials.json").status_code == 404


def load_credential(page, token):
    page.get_by_label("本机测试凭据").fill(token)
    page.get_by_role("button", name="载入凭据").click()
    assert page.get_by_label("本机测试凭据").input_value() == ""


def find_travel(page):
    page.get_by_label("关键词或问题").fill("上海住宿")
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    page.get_by_role("button", name="查找依据").click()


def screenshot(page, name):
    if location := os.environ.get("THALION_BROWSER_SCREENSHOTS"):
        page.screenshot(path=Path(location) / name, full_page=True, animations="disabled")


def test_employee_search_reopens_exact_reference_and_discards_revoked_material(portal):
    from playwright.sync_api import expect

    page, _, db, (employee, _), _, live, first, _ = portal
    _, tenant, *_ = db
    screenshot(page, "employee-locked.png")
    load_credential(page, employee)
    find_travel(page)
    expect(page.get_by_role("heading", name="住宿标准", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="受限审批说明", exact=True)).to_be_visible()
    expect(page.get_by_text(f"业务日期 {BEFORE.isoformat()}")).to_be_visible()
    with page.expect_request(f"**/v1/passages/{first.passage_ref}") as requested:
        page.get_by_role("button", name="核对原文：住宿标准").click()
    assert requested.value.method == "GET"
    detail = page.get_by_role("region", name="原文核对")
    expect(detail.get_by_text("上海住宿限额。", exact=True)).to_be_visible()
    expect(detail.get_by_text("上海 / 第 1 段", exact=True)).to_be_visible()
    screenshot(page, "employee-reference.png")
    live.remove(tenant.actor_id)
    page.get_by_role("button", name="核对原文：住宿标准").click()
    expect(page.get_by_text("该引用不可用。请重新查找依据。", exact=True)).to_be_visible()
    assert "受限审批说明" not in page.locator("body").inner_text()
    assert "上海住宿限额。" not in page.locator("body").inner_text()


def test_late_old_employee_response_cannot_repopulate_new_session(portal):
    from playwright.sync_api import expect

    page, base, _, (employee, other), *_ = portal
    page.evaluate("""() => {
        const fetchReal = window.fetch;
        let delayNext = true;
        window.fetch = async (url, options) => {
            if (!delayNext || url !== '/v1/search') return fetchReal(url, options);
            delayNext = false;
            const response = await fetchReal(url, {...options, signal: undefined});
            await new Promise(resolve => {
                window.releaseOldTestResponse = resolve;
                document.body.dataset.oldResponseReady = "true";
            });
            return response;
        };
    }""")
    load_credential(page, employee)
    find_travel(page)
    expect(page.locator("body")).to_have_attribute("data-old-response-ready", "true")
    page.get_by_role("button", name="更换凭据").click()
    expect(page.get_by_role("heading", name="载入测试凭据")).to_be_visible()
    load_credential(page, other)
    find_travel(page)
    expect(page.get_by_role("heading", name="住宿标准", exact=True)).to_be_visible()
    page.evaluate("""async () => {
        window.releaseOldTestResponse();
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    }""")
    expect(page.get_by_role("heading", name="受限审批说明", exact=True)).to_have_count(0)
    expect(page.get_by_text("1 条可核对依据", exact=True)).to_be_visible()
    assert page.url == f"{base}/"
    assert page.evaluate("[localStorage.length, sessionStorage.length, document.cookie, history.state]") == [0, 0, "", None]
    page.get_by_role("button", name="退出").click()
    expect(page.get_by_role("heading", name="载入测试凭据")).to_be_visible()
    assert "上海住宿" not in page.locator("body").inner_text()
    assert page.get_by_label("关键词或问题").input_value() == ""


def test_employee_shared_reference_requires_recipient_authorization(portal):
    from playwright.sync_api import expect

    page, base, _, (employee, restricted), _, _, _, second = portal
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=base)
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, employee)
    find_travel(page)
    page.get_by_role("button", name="核对原文：受限审批说明").click()
    detail = page.get_by_role("region", name="原文核对")
    expect(detail.get_by_role("heading", name="受限审批说明")).to_be_visible()
    detail.get_by_role("button", name="复制引用链接").click()
    expect(detail.get_by_text("已复制引用链接。", exact=True)).to_be_visible()
    link = page.evaluate("navigator.clipboard.readText()")
    assert link == f"{base}/#ref={second.passage_ref}"
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, "employee-shared-reference.png")

    reads = []
    page.on("request", lambda request: reads.append(request) if "/v1/passages/" in request.url else None)
    page.goto(link)
    expect(page.get_by_text("载入凭据后核验共享引用。", exact=True)).to_be_visible()
    assert page.url == f"{base}/" and reads == []
    assert str(second.passage_ref) not in page.locator("body").inner_text()
    with page.expect_response(f"**/v1/passages/{second.passage_ref}") as rejected:
        load_credential(page, restricted)
    assert rejected.value.status == 404
    expect(detail.get_by_text("该引用不可用。请重新查找依据。", exact=True)).to_be_visible()
    expect(detail.get_by_role("button", name="复制引用链接")).to_have_count(0)
    assert "受限审批说明" not in page.locator("body").inner_text()

    page.get_by_role("button", name="更换凭据").click()
    load_credential(page, employee)
    expect(page.get_by_label("关键词或问题")).to_be_focused()
    assert len(reads) == 1


def test_shared_reference_is_consumed_once_before_page_restore(portal):
    from playwright.sync_api import expect

    page, base, _, (employee, _), _, _, first, _ = portal
    page.goto("/employee/not-a-resource")
    page.goto(f"{base}/#ref={first.passage_ref}")
    expect(page.get_by_text("载入凭据后核验共享引用。", exact=True)).to_be_visible()
    assert page.url == f"{base}/"
    load_credential(page, employee)
    expect(page.get_by_role("region", name="原文核对").get_by_role("heading", name="住宿标准")).to_be_visible()
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))")
    expect(page.get_by_role("heading", name="载入测试凭据")).to_be_visible()
    load_credential(page, employee)
    expect(page.get_by_label("关键词或问题")).to_be_focused()
    expect(page.get_by_role("heading", name="住宿标准")).to_have_count(0)
    assert page.evaluate("[localStorage.length, sessionStorage.length, document.cookie, history.state]") == [0, 0, "", None]


def test_page_restore_and_navigation_do_not_reanimate_old_evidence(portal):
    from playwright.sync_api import expect

    page, _, _, (employee, _), *_ = portal
    load_credential(page, employee)
    find_travel(page)
    expect(page.get_by_role("heading", name="受限审批说明", exact=True)).to_be_visible()
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))")
    expect(page.get_by_role("heading", name="载入测试凭据")).to_be_visible()
    assert "受限审批说明" not in page.locator("body").inner_text()
    load_credential(page, employee)
    find_travel(page)
    expect(page.get_by_role("heading", name="受限审批说明", exact=True)).to_be_visible()
    page.goto("/employee/not-a-resource")
    page.go_back()
    expect(page.get_by_role("heading", name="载入测试凭据")).to_be_visible()
    assert page.get_by_label("本机测试凭据").input_value() == ""
    assert "受限审批说明" not in page.locator("body").inner_text()


def test_mobile_layout_and_keyboard_search(portal):
    from playwright.sync_api import expect

    page, _, _, (employee, _), *_ = portal
    page.set_viewport_size({"width": 390, "height": 844})
    page.get_by_label("本机测试凭据").fill(employee)
    page.get_by_label("本机测试凭据").press("Enter")
    expect(page.get_by_label("关键词或问题")).to_be_focused()
    page.get_by_label("关键词或问题").fill("上海住宿")
    page.get_by_label("关键词或问题").press("Enter")
    expect(page.get_by_role("heading", name="住宿标准", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, "employee-mobile.png")


def test_employee_search_by_known_source_clears_on_identity_change(portal):
    from playwright.sync_api import expect

    page, _, db, (employee, other), *_ = portal
    _, _, _, source, _ = db
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, employee)
    source_input = page.get_by_label("来源编号")
    expect(source_input).to_be_visible(timeout=3000)
    source_input.fill(str(uuid4()))
    find_travel(page)
    expect(page.get_by_text("没有找到可用依据。", exact=False)).to_be_visible()
    expect(page.get_by_role("heading", name="受限审批说明", exact=True)).to_have_count(0)

    source_input.fill(str(source))
    with page.expect_request("**/v1/search") as sent:
        find_travel(page)
    assert sent.value.post_data_json["source_ids"] == [str(source)]
    expect(page.get_by_role("heading", name="受限审批说明", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, "employee-source-filter.png")

    page.get_by_role("button", name="更换凭据").click()
    load_credential(page, other)
    expect(source_input).to_have_value("")
    with page.expect_request("**/v1/search") as sent:
        find_travel(page)
    assert "source_ids" not in sent.value.post_data_json
    expect(page.get_by_role("heading", name="住宿标准", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="受限审批说明", exact=True)).to_have_count(0)


def test_employee_can_choose_an_authorized_source_and_switch_identity(portal):
    from playwright.sync_api import expect

    page, _, db, (employee, other), *_ = portal
    source, _ = add_search_source(db)
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, employee)
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    page.get_by_role("button", name="查看可筛选来源").click()
    choices = page.get_by_label("可筛选来源")
    expect(choices.get_by_role("option", name="另一来源", exact=False)).to_have_count(1)
    choices.select_option(str(source))
    expect(page.get_by_label("来源编号")).to_have_value(str(source))
    screenshot(page, "employee-source-options.png")
    find_travel(page)
    expect(page.get_by_role("heading", name="另一来源", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="住宿标准", exact=True)).to_have_count(0)
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    page.get_by_label("业务日期").fill("2025-01-01")
    expect(choices).to_be_hidden()
    expect(choices.get_by_role("option", name="另一来源", exact=False)).to_have_count(0)

    page.get_by_role("button", name="更换凭据").click()
    load_credential(page, other)
    expect(page.get_by_label("来源编号")).to_have_value("")
    expect(choices.get_by_role("option", name="另一来源", exact=False)).to_have_count(0)
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    page.get_by_role("button", name="查看可筛选来源").click()
    expect(choices.get_by_role("option", name="住宿标准", exact=False)).to_have_count(1)
    expect(choices.get_by_role("option", name="另一来源", exact=False)).to_have_count(0)


def test_employee_source_facets_use_full_matching_count_and_clear_on_switch(portal):
    from playwright.sync_api import expect

    page, _, _, (employee, restricted), *_ = portal
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, employee)
    page.get_by_label("原文条数").fill("1")
    find_travel(page)
    facets = page.get_by_role("region", name="匹配资料按来源")
    expect(facets.get_by_text("2 份", exact=True)).to_be_visible()
    expect(page.locator("#results li")).to_have_count(1)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    page.get_by_role("button", name="更换凭据").click()
    expect(facets).to_have_count(0)
    load_credential(page, restricted)
    find_travel(page)
    expect(facets.get_by_text("1 份", exact=True)).to_be_visible()
    expect(facets.get_by_text("2 份", exact=True)).to_have_count(0)
    expect(facets.get_by_text("受限审批说明")).to_have_count(0)


def test_search_suggestions_reopen_current_evidence_and_discard_old_identity_response(portal):
    from playwright.sync_api import expect

    page, _, _, (employee, restricted), *_ = portal
    page.set_viewport_size({"width": 390, "height": 844})
    page.evaluate("""() => {
        const fetchReal = window.fetch.bind(window);
        let delayNext = true;
        window.fetch = async (url, options) => {
            if (!delayNext || url !== '/employee/search-suggestions') return fetchReal(url, options);
            delayNext = false;
            const response = await fetchReal(url, {...options, signal: undefined});
            await new Promise(resolve => {
                window.releaseOldSuggestionResponse = resolve;
                document.body.dataset.oldSuggestionReady = "true";
            });
            return response;
        };
    }""")
    load_credential(page, employee)
    page.get_by_label("关键词或问题").fill("受限")
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    trigger = page.get_by_role("button", name="查找标题建议")
    trigger.click()
    expect(page.locator("body")).to_have_attribute("data-old-suggestion-ready", "true")
    page.get_by_role("button", name="更换凭据").click()
    load_credential(page, restricted)
    page.get_by_label("关键词或问题").fill("住宿")
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    trigger.click()
    suggestion = page.get_by_role("button", name="核对建议：住宿标准", exact=True)
    expect(suggestion).to_be_visible()
    page.evaluate("""async () => {
        window.releaseOldSuggestionResponse();
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    }""")
    expect(page.get_by_role("button", name="核对建议：受限审批说明")).to_have_count(0)
    with page.expect_request("**/v1/passages/*"):
        suggestion.click()
    expect(page.get_by_role("region", name="原文核对").get_by_text("上海住宿限额。", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.get_by_label("业务日期").fill("2025-01-01")
    expect(suggestion).to_have_count(0)


def test_employee_submits_exact_feedback_and_clears_it_on_identity_switch(portal):
    from playwright.sync_api import expect

    from enterprise_kb.modules.operations import feedback

    page, _, _, (employee, other), credentials, _, first, _ = portal
    credentials[employee] = replace(credentials[employee], operations=credentials[employee].operations | {
        feedback.RECORD, feedback.STATUS,
    })
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, employee)
    find_travel(page)
    page.get_by_role("button", name="核对原文：住宿标准").click()
    detail = page.get_by_role("region", name="原文核对")
    detail.get_by_role("button", name="反馈此引用").press("Enter")
    expect(page.get_by_label("补充说明（可选）")).to_be_focused()
    page.get_by_label("补充说明（可选）").fill("合成级别的备注")
    with page.expect_request("**/internal/feedback") as sent:
        page.get_by_role("button", name="提交反馈").click()
    request_body = sent.value.post_data_json
    assert request_body["passage_id"] == str(first.passage_ref)
    assert request_body["category"] == "incorrect_evidence" and sent.value.headers["idempotency-key"]
    expect(page.get_by_text("已提交，待核对。", exact=False)).to_be_visible()
    lookup = page.get_by_label("反馈编号")
    ref = lookup.input_value()
    assert len(ref) == 36
    page.get_by_role("button", name="查询进度").click()
    expect(page.get_by_text("待核对 · 第 1 代", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, "employee-feedback-mobile.png")
    page.get_by_role("button", name="更换凭据").click()
    expect(lookup).to_have_value("")
    assert ref not in page.locator("body").inner_text()
    assert page.get_by_label("补充说明（可选）").input_value() == ""
    load_credential(page, other)
    lookup.fill(ref)
    lookup.press("Enter")
    expect(page.get_by_text("当前凭据无法查看这条反馈。", exact=True)).to_be_visible()
