from dataclasses import replace
from hashlib import sha256
from uuid import UUID

import pytest

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.access.policy import PASSAGE_FIELDS
from enterprise_kb.modules.evidence import processing
from enterprise_kb.transport.local import LocalProfile

from test_csv_processing import csv_cells, register_csv
from test_effectivity import BEGIN, approve
from test_employee_portal import browser, load_credential, portal, screenshot
from test_evidence import claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, private_json, rpc, transport
from test_feedback_work import EVIDENCE_CAPABILITY, QUEUE_CAPABILITY, QUEUE_PATH, admit, assign, submit
from test_persisted_access import binding, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import corpus


def publish_csv(db):
    connection, tenant, _, _, store = db
    version = register_csv(db, key="register-readable-csv", object_key="csv-policy-1")
    run = processing.process_evidence_job(connection, claim(db), store)
    review(db, run)
    approve(connection, tenant, version, BEGIN)
    return version, run, csv_cells(db, version)


def permit(principal, cell=None, *, effect="allow", fields=PASSAGE_FIELDS):
    return replace(binding(principal, passage_ref=cell.passage_ref if cell else None, effect=effect), fields=fields)


def read_cell(client, token, cell):
    return client.get(f"/v1/passages/{cell.passage_ref}", headers=bearer(token))


def assert_no_delivery(connection, reply, status):
    assert reply.status_code == status and "passage" not in reply.json()
    ref = UUID(reply.json()["request_id"])
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record WHERE request_id = %s", (ref,)).fetchone() == (0,)


def test_csv_http_mcp_and_receipt_contain_only_the_authorized_cell(transport):
    client, db, (owner, other), _, _, _, _ = transport
    connection, tenant, *_ = db
    version, _, (target, amount, exception, other_row, *_) = publish_csv(db)
    set_rules(db, permit(tenant.actor_id), permit(tenant.actor_id, target),
              permit(tenant.other_actor_id, amount), expected=2)

    http = read_cell(client, owner, target)
    assert http.status_code == 200 and http.headers["Cache-Control"] == "no-store"
    expected = http.json()["passage"]
    assert (expected["source_type"], expected["version_id"], expected["excerpt"], expected["location"]) == (
        "csv", str(version.version_ref), "0017", {"row_id": 2, "columns": [{"column": 1, "header": "编号"}]},
    )
    mcp = rpc(client, owner, "tools/call", name="read_passage", arguments={"id": str(target.passage_ref)})
    result = mcp.json()["result"]
    assert mcp.status_code == 200 and mcp.headers["Cache-Control"] == "no-store"
    assert not result["isError"] and result["structuredContent"]["passage"] == expected
    assert result["structuredContent"] != http.json()
    for reply in (http, mcp):
        assert all(secret not in reply.text for secret in ("不得补报", "限额", str(amount.passage_ref), str(exception.passage_ref)))
    for forbidden in (amount, exception, other_row):
        assert_no_delivery(connection, read_cell(client, owner, forbidden), 404)
    other_reply = read_cell(client, other, amount)
    assert other_reply.json()["passage"]["excerpt"] == "600"
    assert_no_delivery(connection, read_cell(client, other, target), 404)

    receipt = connection.execute("""
        SELECT dependency.passage_ref, dependency.excerpt_revision, delivery.payload_digest, delivery.dependency_count
        FROM thalion.delivery_record AS delivery
        JOIN thalion.delivery_dependency AS dependency USING (check_id)
        JOIN thalion.delivery_citation AS citation USING (check_id, position)
        WHERE delivery.request_id = %s
    """, (UUID(http.json()["request_id"]),)).fetchall()
    assert receipt == [(target.passage_ref, target.revision, sha256(http.content).digest(), 1)]


def test_csv_current_source_grant_and_all_fields_are_required(transport, evidence_transport, tmp_path_factory):
    client, db, (owner, _), credentials, _, _, _ = transport
    service = evidence_transport[0]
    connection, tenant, *_ = db
    version, _, (_, target, private, *_) = publish_csv(db)
    set_rules(db, permit(tenant.actor_id, target), permit(tenant.actor_id, private), expected=2)
    root = tmp_path_factory.mktemp("csv-profile")
    root.chmod(0o700)
    private_json(root / "credentials.json", [])
    grants = root / "source-grants.json"
    employee = str(credentials[owner].employee_ref)
    private_json(grants, {employee: [str(version.version_ref), str(target.passage_ref)]})
    profile = LocalProfile(root)
    service.check_source = profile.check_source
    assert read_cell(client, owner, target).json()["passage"]["excerpt"] == "600"
    assert_no_delivery(connection, read_cell(client, owner, private), 404)

    def incomplete(credential, probe):
        (scope,) = probe.scopes
        assert (scope.object_id, scope.revision) == (target.passage_ref, target.revision)
        decision = profile.check_source(credential, probe)
        return replace(decision, permitted_fields={scope: scope.fields - {"location"}})

    service.check_source = incomplete
    assert_no_delivery(connection, read_cell(client, owner, target), 404)
    service.check_source = profile.check_source
    private_json(grants, {employee: [str(version.version_ref)]})
    assert_no_delivery(connection, read_cell(client, owner, target), 404)

    def outage(*_):
        raise AuthorizationUnavailable("The synthetic authority is unavailable.")

    service.check_source = outage
    assert_no_delivery(connection, read_cell(client, owner, target), 503)


@pytest.mark.parametrize("change", ["policy", "quality"])
def test_csv_final_check_drops_payload_after_concurrent_restriction(transport, evidence_transport, change):
    client, db, (owner, _), _, _, _, _ = transport
    service = evidence_transport[0]
    connection, tenant, database_url, source, store = db
    _, run, (_, target, *_) = publish_csv(db)
    set_rules(db, permit(tenant.actor_id, target), expected=2)
    check = service.check_source

    def restrict(credential, probe):
        decision = check(credential, probe)
        with open_database(database_url) as concurrent:
            change_db = (concurrent, tenant, database_url, source, store)
            if change == "policy":
                set_rules(change_db, permit(tenant.actor_id, target), permit(tenant.actor_id, effect="deny"), expected=3)
            else:
                review(change_db, run, decision="quarantined")
        return decision

    service.check_source = restrict
    assert_no_delivery(connection, read_cell(client, owner, target), 503 if change == "policy" else 404)
    service.check_source = check
    assert_no_delivery(connection, read_cell(client, owner, target), 404)


def test_csv_cell_uses_approved_revision_digest_not_just_original_hash(transport, monkeypatch):
    from enterprise_kb.modules.access import travel

    client, db, (owner, _), _, _, _, _ = transport
    connection, tenant, *_ = db
    _, _, (_, target, *_) = publish_csv(db)
    set_rules(db, permit(tenant.actor_id, target), expected=2)
    resolve = processing.list_approved_csv_cells

    def corrupt_locator(*args, **kwargs):
        return tuple(replace(cell, digest=bytes(32)) for cell in resolve(*args, **kwargs))

    monkeypatch.setattr(travel, "list_approved_csv_cells", corrupt_locator, raising=False)
    assert_no_delivery(connection, read_cell(client, owner, target), 503)


def test_assigned_csv_feedback_still_requires_the_assignees_exact_cell(transport):
    client, db, (owner, assignee), credentials, _, _, _ = transport
    connection, tenant, *_ = db
    _, _, (_, target, neighbor, *_) = publish_csv(db)
    set_rules(db, permit(tenant.actor_id, target), permit(tenant.other_actor_id, neighbor), expected=2)
    origin = read_cell(client, owner, target).json()["request_id"]
    ref = submit(connection, tenant, UUID(origin), target)
    assign(connection, tenant, ref)
    admit(credentials, assignee, EVIDENCE_CAPABILITY)
    route = f"{QUEUE_PATH}/{ref}/evidence"
    assert_no_delivery(connection, client.get(route, headers=bearer(assignee)), 404)
    set_rules(db, permit(tenant.other_actor_id, target), expected=3)
    reply = client.get(route, headers=bearer(assignee))
    assert reply.status_code == 200 and reply.json()["passage"]["excerpt"] == "600"
    assert "不得补报" not in reply.text


@pytest.mark.parametrize("width", [390, 1280])
def test_employee_csv_location_and_value_clear_on_identity_switch(portal, width):
    from playwright.sync_api import expect

    page, _, db, (owner, other), _, _, _, _ = portal
    _, tenant, *_ = db
    _, _, (target, neighbor, *_) = publish_csv(db)
    set_rules(db, permit(tenant.actor_id, target), permit(tenant.other_actor_id, neighbor), expected=2)
    page.set_viewport_size({"width": width, "height": 844})
    load_credential(page, owner)
    page.get_by_text("按引用编号打开", exact=True).click()
    field = page.get_by_label("引用编号", exact=True)
    field.fill(str(target.passage_ref))
    page.get_by_role("button", name="打开引用").click()
    detail = page.get_by_role("region", name="原文核对")
    expect(detail.get_by_text("0017", exact=True)).to_be_visible()
    expect(detail.get_by_text("第 2 行 / 第 1 列（编号）", exact=True)).to_be_visible()
    assert "不得补报" not in detail.inner_text() and "限额" not in detail.inner_text()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, f"employee-csv-{width}.png")
    page.get_by_role("button", name="更换凭据").click()
    assert "0017" not in page.locator("body").inner_text()
    load_credential(page, other)
    expect(field).to_be_hidden()
    page.get_by_text("按引用编号打开", exact=True).click()
    expect(field).to_have_value("")
    field.fill(str(target.passage_ref))
    page.get_by_role("button", name="打开引用").click()
    expect(page.get_by_text("该引用不可用。请重新查找依据。", exact=True)).to_be_visible()


def test_csv_feedback_page_displays_only_the_assignees_cell_and_clears_it_on_exit(portal):
    from playwright.sync_api import expect

    page, base, db, (owner, assignee), credentials, *_ = portal
    connection, tenant, *_ = db
    _, _, (target, neighbor, *_) = publish_csv(db)
    set_rules(db, permit(tenant.actor_id, target), permit(tenant.other_actor_id, neighbor), expected=2)
    original = page.request.get(f"{base}/v1/passages/{target.passage_ref}", headers=bearer(owner))
    assert original.ok
    ref = submit(connection, tenant, UUID(original.json()["request_id"]), target)
    assign(connection, tenant, ref)
    admit(credentials, assignee, QUEUE_CAPABILITY, EVIDENCE_CAPABILITY)
    page.goto("/manage/feedback")
    page.get_by_label("办理测试凭据").fill(assignee)
    page.get_by_role("button", name="查看待办").click()
    expect(page.get_by_text(str(ref), exact=True)).to_be_visible()
    page.get_by_role("button", name="打开工单").click()
    read = page.get_by_role("button", name="以本人权限核对原文")
    read.click()
    expect(page.get_by_text("无法查看这条原文，请确认工单分派和本人读权。", exact=True)).to_be_visible()
    evidence = page.locator("#work-evidence")
    expect(evidence).to_be_empty()

    set_rules(db, permit(tenant.other_actor_id, target), expected=3)
    read.click()
    expect(evidence.get_by_text("0017", exact=True)).to_be_visible()
    expect(evidence.get_by_text("第 2 行 / 第 1 列（编号）", exact=True)).to_be_visible()
    assert "限额" not in evidence.inner_text() and "不得补报" not in evidence.inner_text()
    screenshot(page, "feedback-csv.png")
    page.get_by_role("button", name="退出办理").click()
    expect(evidence).to_be_empty()
