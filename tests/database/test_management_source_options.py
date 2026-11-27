from dataclasses import replace

import pytest

from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_employee_portal import browser, loopback_page
from test_feedback_work import admit
from test_identity import space
from test_runtime import register_tenant, runtime_db
from test_source_sync_status import _register_source
from test_travel_search import corpus


PATH = "/internal/sources/options"


@pytest.mark.parametrize(("usage", "operation"), [
    ("readers", "read_local_policy"), ("sync", "read_source_sync_status"),
])
def test_source_picker_lists_only_sources_the_caller_can_manage(transport, usage, operation):
    client, db, (owner, other), credentials, *_ = transport
    connection, tenant, *_ = db
    restricted = _register_source(connection, tenant, owner_id=tenant.other_actor_id,
                                  key="choose-colleague", namespace="choose-colleague")
    first = _register_source(connection, tenant, owner_id=tenant.actor_id,
                             key="choose-a", namespace="choose-a")
    second = _register_source(connection, tenant, owner_id=tenant.actor_id,
                              key="choose-b", namespace="choose-b")
    with connection.transaction():
        space_id, space_ref = space(connection, tenant.org_id, tenant.actor_id)
    other_space = replace(tenant, space_id=space_id, space_ref=space_ref)
    for index, outside in enumerate((other_space, register_tenant(connection, "Second tenant"))):
        _register_source(connection, outside, owner_id=outside.actor_id,
                         key=f"choose-outside-{index}", namespace="choose-outside")

    params = {"usage": usage, "q": "CHOOSE-", "limit": "1"}
    assert client.get(PATH, params=params).status_code == 401
    assert client.get(PATH, params=params, headers=bearer(owner)).status_code == 403
    admit(credentials, owner, operation)
    admit(credentials, other, operation)
    response = client.get(PATH, params=params, headers=bearer(owner))
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["sources"] == [{"id": str(first), "name": "choose-a", "status": "active"}]
    cursor = response.json()["next_cursor"]
    assert cursor
    next_page = client.get(PATH, params=params | {"after": cursor}, headers=bearer(owner)).json()
    assert next_page["sources"] == [{"id": str(second), "name": "choose-b", "status": "active"}]
    assert next_page["next_cursor"] is None
    assert str(restricted) not in response.text
    assert client.get(PATH, params=params | {"q": "%"}, headers=bearer(owner)).json()["sources"] == []
    assert client.get(PATH, params=params | {"limit": "501"}, headers=bearer(owner)).status_code == 400
    assert client.get(PATH, params=params | {"space_id": str(space_ref)}, headers=bearer(owner)).status_code == 400
    other_result = client.get(PATH, params=params, headers=bearer(other))
    if usage == "sync":
        assert other_result.status_code == 403
    else:
        assert other_result.json()["sources"] == [{"id": str(restricted), "name": "choose-colleague", "status": "active"}]


def test_reader_subject_picker_limits_visibility_and_paginates(transport):
    client, db, (owner, employee), credentials, *_ = transport
    connection, tenant, _, source_ref, _ = db
    outside = register_tenant(connection, "Unrelated directory")
    connection.execute("""
        INSERT INTO thalion.principal_directory_profile
            (org_id, principal_id, display_name, employee_number, email, title, directory_state)
        VALUES (%s, %s, '林晓', 'employee-12', 'lin@example.invalid', '主管', 'active'),
               (%s, %s, '林雨', 'employee-13', 'rain@example.invalid', '专员', 'departed'),
               (%s, %s, '林外', 'private-18', 'other@example.invalid', '专员', 'active')
        """, (tenant.org_id, tenant.actor_id, tenant.org_id, tenant.other_actor_id, outside.org_id, outside.actor_id))
    path = f"/internal/sources/{source_ref}/reader-subjects"
    admit(credentials, owner, "read_local_policy")
    admit(credentials, employee, "read_local_policy", "read_admin_directory")
    assert client.get(path, headers=bearer(owner)).status_code == 403
    assert client.get(path, headers=bearer(employee)).status_code == 403
    admit(credentials, owner, "read_admin_directory")
    first = client.get(path, params={"q": "林", "limit": 1}, headers=bearer(owner)).json()
    second = client.get(path, params={"q": "林", "after": first["next_cursor"], "limit": 1}, headers=bearer(owner)).json()
    subjects = {item["name"]: item for item in first["subjects"] + second["subjects"]}
    assert subjects.keys() == {"林晓", "林雨"}
    assert subjects["林晓"]["id"] == str(credentials[owner].employee_ref)
    assert subjects["林雨"]["selectable"] is False
    by_email = client.get(path, params={"q": "lin@"}, headers=bearer(owner)).json()
    assert [subject["name"] for subject in by_email["subjects"]] == ["林晓"]
    assert client.get(path, params={"q": "%"}, headers=bearer(owner)).json()["subjects"] == []


@pytest.mark.parametrize(("path", "usage", "operation", "search_selector", "selected_selector"), [
    ("/manage/readers", "readers", "read_local_policy", "#readers-source", "#readers-source-id"),
    ("/manage/sources", "sync", "read_source_sync_status", "#sources-id", "#sources-id-value"),
])
def test_management_pages_search_and_select_an_owned_source(
    browser, evidence_transport, path, usage, operation, search_selector, selected_selector,
):
    from playwright.sync_api import expect

    service, db, (owner, _), credentials, *_ = evidence_transport
    connection, tenant, *_ = db
    source_ref = _register_source(connection, tenant, owner_id=tenant.actor_id,
                                  key="picker-alpha", namespace="picker-alpha")
    admit(credentials, owner, operation)
    with loopback_page(browser, service, path) as (page, _, response):
        assert response.status == 200
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入管理凭据").click()
        page.locator(search_selector).fill("picker-")
        option = page.get_by_role("option").filter(has_text="picker-alpha")
        expect(option).to_be_visible()
        option.click()
        expect(page.locator(selected_selector)).to_have_value(str(source_ref))
        if usage == "readers":
            expect(page.get_by_text("当前规则已载入。", exact=True)).to_be_visible()
        else:
            expect(page.get_by_role("heading", name="来源契约与状态", exact=True)).to_be_visible()
