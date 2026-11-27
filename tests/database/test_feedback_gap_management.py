from uuid import uuid4

import pytest

from test_employee_portal import browser, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport
from test_feedback_work import admit
from test_runtime import runtime_db
from test_travel_search import corpus


GAPS = "/internal/feedback/gaps"


def command_headers(token):
    return bearer(token) | {"Idempotency-Key": str(uuid4())}


def create_gap(page, base, token, query):
    search = page.request.post(
        f"{base}/v1/search",
        headers=bearer(token),
        data={"query": query},
    )
    assert search.ok
    request_id = search.json()["request_id"]
    recorded = page.request.post(
        f"{base}{GAPS}",
        headers=command_headers(token),
        data={"origin_request_id": request_id},
    )
    assert recorded.ok
    return recorded.json()["gap_id"]


def login_to_gap_view(page, token):
    page.goto("/manage/feedback?view=gaps")
    page.get_by_label("办理测试凭据").fill(token)
    page.get_by_role("button", name="查看缺口队列").click()


@pytest.mark.parametrize(("width", "classification"), [(1280, "conditions_missing"), (390, "permission_review")])
def test_gap_view_supports_deep_link_empty_state_and_real_reclassification(portal, width, classification):
    from playwright.sync_api import expect

    page, base, _, (owner, _), credentials, *_ = portal
    page.set_viewport_size({"width": width, "height": 900})
    admit(credentials, owner, "record_gap", "read_gap_queue", "reclassify_gap")
    gap_id = create_gap(page, base, owner, "合成缺口队列归类")

    login_to_gap_view(page, owner)
    expect(page.get_by_role("heading", name="管理搜索缺口队列", exact=True)).to_be_visible()
    expect(page.get_by_text(gap_id, exact=True)).to_be_visible()
    expect(page.get_by_text("合成缺口队列归类", exact=True)).to_have_count(0)
    page.get_by_role("button", name="处理这条缺口").click()
    page.get_by_label("缺口归类").select_option(classification)
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, f"gap-queue-review-{width}.png")
    with page.expect_request(f"**{GAPS}/{gap_id}/reclassify") as command:
        page.get_by_role("button", name="保存缺口归类").click()
    assert command.value.method == "POST"
    assert command.value.header_value("Idempotency-Key")
    assert command.value.post_data_json == {"expected_generation": 1, "classification": classification}
    expect(page.get_by_text("已保存缺口归类。", exact=True)).to_be_visible()
    expect(page.get_by_text("当前没有待处理的搜索缺口。", exact=True)).to_be_visible()
    assert page.url.endswith("/manage/feedback?view=gaps")


def test_gap_view_paginates_after_loading_real_queue(portal):
    from playwright.sync_api import expect

    page, base, _, (owner, _), credentials, *_ = portal
    admit(credentials, owner, "record_gap", "read_gap_queue", "reclassify_gap")
    gap_ids = sorted(create_gap(page, base, owner, f"合成分页缺口队列-{index}") for index in range(21))

    login_to_gap_view(page, owner)
    rows = page.locator("#gap-items h3")
    expect(rows).to_have_text(gap_ids[:20])
    expect(page.get_by_role("button", name="下一页缺口")).to_be_visible()
    page.get_by_role("button", name="下一页缺口").click()
    expect(rows).to_have_text(gap_ids[20:])
    expect(page.get_by_text("第 2 页 · 本页 1 条", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="下一页缺口")).to_be_hidden()
    page.get_by_role("button", name="上一页缺口").click()
    expect(rows).to_have_text(gap_ids[:20])


def test_gap_view_surfaces_queue_errors(portal):
    from playwright.sync_api import expect

    page, _, _, (owner, _), credentials, *_ = portal
    admit(credentials, owner, "read_gap_queue")
    pending = []
    page.route(f"**{GAPS}", lambda route: pending.append(route))

    login_to_gap_view(page, owner)
    expect(page.get_by_text("正在读取缺口队列…", exact=True)).to_be_visible()
    expect(page.locator("#gap-items")).to_have_attribute("aria-busy", "true")
    pending[0].fulfill(status=503, body="")
    expect(page.get_by_text("暂时无法读取缺口队列，请刷新重试。", exact=True)).to_be_visible()
    expect(page.locator("#gap-items")).to_have_attribute("aria-busy", "false")
    page.unroute(f"**{GAPS}")
    page.get_by_role("button", name="刷新缺口队列").click()
    expect(page.get_by_text("当前没有待处理的搜索缺口。", exact=True)).to_be_visible()


def test_gap_access_denial_preserves_feedback_session_and_history(portal):
    from playwright.sync_api import expect

    page, _, _, (_, employee), credentials, *_ = portal
    admit(credentials, employee, "read_feedback_queue", "read_gap_queue")
    page.goto("/manage/feedback")
    page.get_by_label("办理测试凭据").fill(employee)
    page.get_by_role("button", name="查看待办").click()
    expect(page.get_by_text("当前没有待办工单。", exact=True)).to_be_visible()

    page.get_by_role("link", name="搜索缺口队列").click()
    expect(page).to_have_url("/manage/feedback?view=gaps")
    expect(page.get_by_text("当前凭据未获准查看缺口队列。", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="处理这条缺口")).to_have_count(0)
    page.go_back()
    expect(page.get_by_text("当前没有待办工单。", exact=True)).to_be_visible()
    page.go_forward()
    expect(page.get_by_text("当前凭据未获准查看缺口队列。", exact=True)).to_be_visible()


def test_gap_review_reloads_after_conflict(portal):
    from playwright.sync_api import expect

    page, base, _, (owner, _), credentials, *_ = portal
    admit(credentials, owner, "record_gap", "read_gap_queue", "reclassify_gap")
    gap_id = create_gap(page, base, owner, "合成缺口归类冲突")
    login_to_gap_view(page, owner)
    page.get_by_role("button", name="处理这条缺口").click()

    path = f"{GAPS}/{gap_id}/reclassify"
    changed = page.request.post(f"{base}{path}", headers=command_headers(owner), data={
        "expected_generation": 1, "classification": "permission_review",
    })
    assert changed.ok
    page.get_by_label("缺口归类").select_option("conditions_missing")
    with page.expect_response(f"**{path}") as conflict:
        page.get_by_role("button", name="保存缺口归类").click()
    assert conflict.value.status == 409
    expect(page.get_by_text("缺口已变化，请重新核对后再保存。", exact=True)).to_be_visible()
    expect(page.get_by_text("当前没有待处理的搜索缺口。", exact=True)).to_be_visible()
    expect(page.get_by_label("缺口归类")).to_be_hidden()
