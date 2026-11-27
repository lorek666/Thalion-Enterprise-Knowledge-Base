from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from enterprise_kb.modules.sources import effectivity
from enterprise_kb.transport import api

from test_effectivity import record
from test_employee_portal import browser, load_credential, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_runtime import register_tenant, runtime_db
from test_travel_search import BEFORE, corpus
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble
from test_wiki_invalidation import version_ref
from test_wiki_publication import authorize, configure
from test_wiki_search import reviewed

STATUS_PATH = "/internal/wiki/status"
STATUS_OPERATION = "read_wiki_status"


def seed(db, first, second):
    connection, tenant, *_ = db
    configure(db, 2)
    sealed = assemble(db, (first, second))
    workspace = (db, sealed, first, second)
    revision, approval = reviewed(workspace)
    publication = authorize(db, revision, approval)
    assert publication.status == "succeeded"
    assert candidate(workspace).status == "succeeded"
    rejected = candidate(workspace)
    assert submit(db, rejected.ref, preview(db, rejected.ref), decision="rejected").status == "succeeded"
    for topic in ("drafts", "new-leads"):
        assert candidate(workspace, topic=topic).status == "succeeded"
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "stop-for-management"), tenant.space_id,
        version_ref(connection, second), "withdrawn", uuid4(),
    )
    return connection.execute("SELECT wiki_ref FROM thalion.wiki WHERE topic_key = 'travel'").fetchone()[0]


def test_management_requires_separate_grant_and_exposes_no_evidence(transport):
    client, db, (owner, employee), credentials, live, first, second = transport
    connection, *_ = db
    stopped = seed(db, first, second)
    assert client.get(STATUS_PATH).status_code == 401
    assert client.get(STATUS_PATH, headers=bearer(owner)).status_code == 403
    credentials[employee] = replace(credentials[employee], operations={STATUS_OPERATION})
    assert client.get(STATUS_PATH, headers=bearer(employee)).status_code == 403
    credentials[owner] = replace(credentials[owner], operations={STATUS_OPERATION})
    live.clear()
    response = client.get(STATUS_PATH, headers=bearer(owner))
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    data = response.json()
    assert set(data) == {"request_id", "topics", "next_cursor"}
    selected, = [topic for topic in data["topics"] if topic["wiki_id"] == str(stopped)]
    assert selected == {
        "wiki_id": str(stopped), "state": "needs_rebuild", "generation": 1, "reasons": ["withdrawn"],
        "review": {"awaiting_review": 1, "approved": 0, "rejected": 1, "stale": 0},
    }
    assert all(text not in response.text for text in ("本地差旅", "上海住宿", "travel", str(first.passage_ref), "markdown"))
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).status_code == 403
    assert rpc(client, owner, "tools/list").json()["result"]["tools"] == []
    assert connection.execute(
        "SELECT operation, destination, outcome FROM thalion.request_record WHERE request_id = %s", (data["request_id"],),
    ).fetchone() == (STATUS_OPERATION, "internal_management", "succeeded")
    assert connection.execute(
        "SELECT 1 FROM thalion.delivery_record WHERE request_id = %s", (data["request_id"],),
    ).fetchone() is None


def test_management_rechecks_ownership_and_credential_before_releasing(evidence_transport, monkeypatch):
    from enterprise_kb.modules.wiki import management

    service, db, (owner, _), credentials, _, first, second = evidence_transport
    connection, tenant, *_ = db
    seed(db, first, second)
    credentials[owner] = replace(credentials[owner], operations={STATUS_OPERATION})
    caller = service.identify(owner)
    connection.execute("UPDATE thalion.space SET owner_principal_id = %s WHERE space_id = %s",
                       (tenant.other_actor_id, tenant.space_id))
    assert service.execute_wiki_status(caller).status_code == 403
    connection.execute("UPDATE thalion.space SET owner_principal_id = %s WHERE space_id = %s",
                       (tenant.actor_id, tenant.space_id))
    read_status = management.list_topic_status

    def revoke_after_projection(*args, **kwargs):
        result = read_status(*args, **kwargs)
        del credentials[owner]
        return result

    monkeypatch.setattr(management, "list_topic_status", revoke_after_projection)
    denied = service.execute_wiki_status(caller)
    assert denied.status_code == 401 and b'"topics"' not in denied.body
    assert connection.execute(
        "SELECT outcome FROM thalion.request_record WHERE request_id = %s", (denied.request_id,),
    ).fetchone() == ("rejected",)


def test_management_page_cursor_is_bounded_and_cannot_select_another_scope(transport, monkeypatch):
    from enterprise_kb.modules.wiki import management

    client, db, (owner, _), credentials, _, first, second = transport
    seed(db, first, second)
    connection, *_ = db
    other_tenant = register_tenant(connection, "Other management organization")
    foreign_ref, = connection.execute(
        "INSERT INTO thalion.wiki (org_id, space_id, topic_key) VALUES (%s, %s, 'other-space') RETURNING wiki_ref",
        (other_tenant.org_id, other_tenant.space_id),
    ).fetchone()
    credentials[owner] = replace(credentials[owner], operations={STATUS_OPERATION})
    monkeypatch.setattr(management, "PAGE_SIZE", 2)
    headers = bearer(owner)
    initial = client.get(STATUS_PATH, headers=headers).json()
    tail = client.get(STATUS_PATH, params={"after": initial["next_cursor"]}, headers=headers).json()
    assert len(initial["topics"]) == 2 and len(tail["topics"]) == 1 and tail["next_cursor"] is None
    refs = [topic["wiki_id"] for topic in initial["topics"] + tail["topics"]]
    assert refs == sorted(set(refs))
    assert str(foreign_ref) not in refs
    assert client.get(STATUS_PATH, params={"space_id": str(uuid4())}, headers=headers).status_code == 400
    assert client.get(STATUS_PATH + "?after=invalid", headers=headers).status_code == 400
    assert client.get(STATUS_PATH + f"?after={refs[0]}&after={refs[1]}", headers=headers).status_code == 400


def test_management_distinguishes_recorded_approval_from_stale_generation(transport):
    client, db, (owner, _), credentials, _, first, second = transport
    configure(db, 2)
    workspace = (db, assemble(db, (first, second)), first, second)
    first_review = reviewed(workspace)
    reviewed(workspace)
    assert authorize(db, *first_review).status == "succeeded"
    reviewed(workspace)
    credentials[owner] = replace(credentials[owner], operations={STATUS_OPERATION})
    status = client.get(STATUS_PATH, headers=bearer(owner)).json()["topics"]
    assert len(status) == 1 and status[0]["state"] == "published"
    assert status[0]["review"] == {"awaiting_review": 0, "approved": 1, "rejected": 0, "stale": 1}


def test_transport_does_not_release_management_metadata_after_deadline(transport, monkeypatch):
    client, db, (owner, _), credentials, _, first, second = transport
    seed(db, first, second)
    credentials[owner] = replace(credentials[owner], operations={STATUS_OPERATION})
    monkeypatch.setattr(api, "release_time", lambda: datetime.now(UTC) + timedelta(minutes=1))
    response = client.get(STATUS_PATH, headers=bearer(owner))
    assert response.status_code == 503 and response.json()["error"]["code"] == "dependency_unavailable"
    assert "topics" not in response.json()


def test_management_shell_is_static_and_session_clears_metadata(portal):
    from playwright.sync_api import expect

    page, base, db, (owner, employee), credentials, _, first, second = portal
    stopped = seed(db, first, second)
    credentials[owner] = replace(credentials[owner], operations={STATUS_OPERATION})
    page.set_viewport_size({"width": 390, "height": 820})
    response = page.goto("/manage/wiki")
    assert response.status == 200 and response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    expect(page.get_by_role("heading", name="Wiki 发布台账")).to_be_visible()
    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="查看发布台账").click()
    expect(page.get_by_text(str(stopped), exact=True)).to_be_visible()
    expect(page.get_by_text("待重编", exact=True)).to_be_visible()
    expect(page.get_by_text("来源撤回", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-wiki.png")
    page.get_by_role("button", name="退出管理").click()
    expect(page.get_by_text(str(stopped), exact=True)).to_have_count(0)
    page.get_by_label("管理测试凭据").fill(employee)
    page.get_by_role("button", name="查看发布台账").click()
    expect(page.get_by_text("当前凭据没有此空间的管理权限。", exact=True)).to_be_visible()
    assert page.evaluate("[localStorage.length, sessionStorage.length, document.cookie]") == [0, 0, ""]
    assert page.url == f"{base}/manage/wiki"


def test_employee_can_opt_into_reviewed_claims_and_recheck_their_references(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, _), _, _, first, second = portal
    connection, tenant, *_ = db
    configure(db, 2)
    workspace = (db, assemble(db, (first, second)), first, second)
    assert authorize(db, *reviewed(workspace)).status == "succeeded"
    load_credential(page, owner)
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    page.get_by_label("关键词或问题").fill("限额")
    topic_toggle = page.get_by_role("checkbox", name="附带已审核 Wiki 陈述")
    expect(topic_toggle).not_to_be_checked()
    topic_toggle.check()
    page.get_by_role("button", name="查找依据").click()
    wiki = page.get_by_role("region", name="已审核 Wiki 陈述")
    expect(wiki.get_by_role("heading", name="本地差旅")).to_be_visible()
    expect(wiki.get_by_text("上海住宿限额以原文为准。", exact=True)).to_be_visible()
    with page.expect_request(f"**/v1/passages/{first.passage_ref}") as opened:
        wiki.get_by_role("button", name="核对依据 1").click()
    assert opened.value.method == "GET"
    expect(page.get_by_role("region", name="原文核对").get_by_text("上海住宿限额。", exact=True)).to_be_visible()
    screenshot(page, "employee-wiki.png")
    topic_toggle.uncheck()
    expect(wiki).to_have_count(0)
    expect(page.get_by_text("1 条可核对依据", exact=True)).to_be_visible()
    topic_toggle.check()
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "stop-for-employee"), tenant.space_id,
        version_ref(connection, second), "withdrawn", uuid4(),
    )
    page.get_by_role("button", name="查找依据").click()
    expect(page.get_by_text("1 条可核对依据", exact=True)).to_be_visible()
    expect(wiki).to_have_count(0)
    page.get_by_role("button", name="退出", exact=True).click()
    load_credential(page, owner)
    expect(topic_toggle).not_to_be_checked()
