import json
from uuid import uuid4

from test_employee_portal import browser, portal
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport
from test_feedback_work import admit
from test_travel_search import corpus
from test_runtime import runtime_db


GAPS = "/internal/feedback/gaps"


def command_headers(token):
    return bearer(token) | {"Idempotency-Key": str(uuid4())}


def create_gap(page, base, token, query):
    search = page.request.post(
        f"{base}/v1/search",
        headers=bearer(token) | {"Content-Type": "application/json"},
        data=json.dumps({"query": query}),
    )
    assert search.ok
    request_id = search.json()["request_id"]
    recorded = page.request.post(
        f"{base}{GAPS}",
        headers=command_headers(token) | {"Content-Type": "application/json"},
        data=json.dumps({"origin_request_id": request_id}),
    )
    assert recorded.ok
    return recorded.json()["gap_id"]


def login_to_gap_view(page, token):
    page.goto("/manage/feedback?view=gaps")
    page.get_by_label("办理测试凭据").fill(token)
    page.locator("#work-login-button").click()


def test_gap_view_supports_deep_link_empty_state_and_real_reclassification(portal):
    from playwright.sync_api import expect

    page, base, _, (owner, _), credentials, *_ = portal
    admit(credentials, owner, "record_gap", "read_gap_queue", "reclassify_gap")
    gap_id = create_gap(page, base, owner, "合成缺口队列归类")

    login_to_gap_view(page, owner)
    expect(page.get_by_role("heading", name="管理搜索缺口队列", exact=True)).to_be_visible()
    expect(page.get_by_text(gap_id, exact=True)).to_be_visible()
    page.get_by_role("button", name="处理这条缺口").click()
    page.get_by_label("缺口归类").select_option("conditions_missing")
    page.get_by_role("button", name="保存缺口归类").click()
    expect(page.get_by_text("已保存缺口归类。", exact=True)).to_be_visible()
    expect(page.get_by_text("当前没有待处理的搜索缺口。", exact=True)).to_be_visible()
    assert page.url.endswith("/manage/feedback?view=gaps")


def test_gap_view_paginates_after_loading_real_queue(portal):
    from playwright.sync_api import expect

    page, base, _, (owner, _), credentials, *_ = portal
    admit(credentials, owner, "record_gap", "read_gap_queue", "reclassify_gap")
    for index in range(21):
        create_gap(page, base, owner, f"合成分页缺口队列-{index}")

    login_to_gap_view(page, owner)
    expect(page.get_by_role("listitem")).to_have_count(20)
    expect(page.get_by_role("button", name="下一页缺口")).to_be_visible()
    page.get_by_role("button", name="下一页缺口").click()
    expect(page.get_by_role("listitem")).to_have_count(1)
    expect(page.get_by_text("第 2 页 · 本页 1 条", exact=True)).to_be_visible()


def test_gap_view_surfaces_queue_errors(portal):
    from playwright.sync_api import expect

    page, _, _, (owner, _), credentials, *_ = portal
    admit(credentials, owner, "read_gap_queue")
    page.route("**/internal/feedback/gaps**", lambda route: route.fulfill(status=503, body=""))

    login_to_gap_view(page, owner)
    expect(page.get_by_text("暂时无法读取缺口队列，请刷新重试。", exact=True)).to_be_visible()
