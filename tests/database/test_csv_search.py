from dataclasses import replace
from hashlib import sha256
import json
from uuid import UUID

import pytest

from enterprise_kb.modules.evidence import csv_evidence
from enterprise_kb.transport import evidence

from test_csv_delivery import permit
from test_csv_processing import csv_cells
from test_csv_units import amount_db, enroll, process, units
from test_employee_portal import browser, load_credential, portal, screenshot
from test_effectivity import BEFORE, BEGIN, approve
from test_evidence import evidence_db, review
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_persisted_access import authority_for, ingress, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import corpus, publish, search


def published_amount(db):
    connection, tenant, *_ = db
    version, candidate = process(db)
    review(db, candidate)
    approve(connection, tenant, version, BEGIN)
    group = units(db, version)[0]
    return candidate, {member.role: member.cell for member in group.members}


def test_csv_http_and_mcp_return_a_complete_citable_unit_with_a_single_receipt(transport, monkeypatch):
    client, db, (owner, _), *_ = transport
    connection, tenant, _, _, store = db
    source = enroll(connection, tenant, csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外"))
    amounts = (*db[:3], source, store)
    _, cells = published_amount(amounts)
    set_rules(amounts, *(permit(tenant.actor_id, cell) for cell in cells.values()))
    args = {"query": "600", "business_date": BEFORE.isoformat(), "top_k": 4, "include_wiki": True}
    request_refs = iter((
        UUID("75000000-0000-4000-8000-000000000001"),
        UUID("00170000-0000-4000-8000-000000000002"),
    ))
    with monkeypatch.context() as patch:
        patch.setattr(evidence, "uuid4", lambda: next(request_refs))
        http = client.post("/v1/search", json=args, headers=bearer(owner))
        mcp = rpc(client, owner, "tools/call", name="search", arguments=args)
    assert http.status_code == mcp.status_code == 200
    assert http.headers["Cache-Control"] == mcp.headers["Cache-Control"] == "no-store"
    result = mcp.json()["result"]
    assert not result["isError"]
    body = http.json()
    structured = result["structuredContent"]
    assert structured | {"request_id": body["request_id"]} == body
    assert json.loads(result["content"][0]["text"]) == structured
    assert body["status"] == "hits" and body["wiki"] == []
    assert {part["passage_id"] for part in body["passages"]} == {str(cell.passage_ref) for cell in cells.values()}
    assert [part["excerpt"] for part in body["passages"]] == ["600", "元/人·晚", "普通员工", "会议统一安排除外"]
    assert all(part["source_type"] == "csv" and part["location"]["row_id"] == 2 for part in body["passages"])
    for current, encoded in ((body, http.content), (structured, result["content"][0]["text"].encode())):
        public_ids = {"passage_id", "version_id"}
        assert str(UUID(current["request_id"])) == current["request_id"]
        assert all(str(UUID(part[field])) == part[field] for part in current["passages"] for field in public_ids)
        business_fields = {key: value for key, value in current.items() if key != "request_id"}
        business_fields["passages"] = [
            {key: value for key, value in part.items() if key not in public_ids} for part in current["passages"]
        ]
        assert all(secret not in json.dumps(business_fields, ensure_ascii=False)
                   for secret in ("不属于证据组", "0017", "750"))
        matched = connection.execute("""
            SELECT dependency.passage_ref, dependency.excerpt_revision, delivery.payload_digest, delivery.dependency_count
            FROM thalion.delivery_record AS delivery
            JOIN thalion.delivery_dependency AS dependency USING (check_id)
            JOIN thalion.delivery_citation AS citation USING (check_id, position)
            WHERE delivery.request_id = %s
        """, (UUID(current["request_id"]),)).fetchall()
        assert set(matched) == {
            (cell.passage_ref, cell.revision, sha256(encoded).digest(), 4) for cell in cells.values()
        }
    cell = client.get(f"/v1/passages/{cells['unit'].passage_ref}", headers=bearer(owner))
    assert cell.json()["passage"]["excerpt"] == "元/人·晚"
    small = client.post("/v1/search", json=args | {"top_k": 3}, headers=bearer(owner)).json()
    assert (small["status"], small["passages"]) == ("no_evidence", [])


def test_markdown_wildcard_in_the_same_source_cannot_grant_the_missing_csv_unit(amount_db):
    connection, tenant, *_ = amount_db
    _, cells = published_amount(amount_db)
    version, passage, _ = publish(amount_db, "approval", "审批", "# 上海\n\n600 以上须经书面审批。\n".encode())
    approve(connection, tenant, version, BEGIN)
    set_rules(amount_db, permit(tenant.actor_id),
              *(permit(tenant.actor_id, cell) for role, cell in cells.items() if role != "unit"))
    denied = json.loads(search(amount_db, "600", top_k=5).payload)
    assert [result["passage_id"] for result in denied["passages"]] == [str(passage.passage_ref)]
    set_rules(amount_db, permit(tenant.actor_id),
              *(permit(tenant.actor_id, cell) for cell in cells.values()), expected=2)
    allowed = json.loads(search(amount_db, "600", top_k=5).payload)
    assert len(allowed["passages"]) == 5
    bounded = json.loads(search(amount_db, "600", top_k=3).payload)
    assert [result["passage_id"] for result in bounded["passages"]] == [str(passage.passage_ref)]


def test_source_facets_require_a_complete_authorized_csv_hit_even_above_top_k(transport):
    client, db, (employee, _), *_ = transport
    connection, tenant, _, _, store = db
    source = enroll(connection, tenant, csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外"))
    amounts = (*db[:3], source, store)
    _, cells = published_amount(amounts)
    set_rules(amounts, *(permit(tenant.actor_id, cell) for role, cell in cells.items() if role != "unit"))
    args = {"query": "600", "business_date": BEFORE.isoformat(), "top_k": 1, "include_source_facets": True}

    denied = client.post("/v1/search", json=args, headers=bearer(employee))
    assert denied.status_code == 200
    assert denied.json()["status"] == "no_evidence" and denied.json()["source_facets"] == []

    set_rules(amounts, *(permit(tenant.actor_id, cell) for cell in cells.values()), expected=2)
    found = client.post("/v1/search", json=args, headers=bearer(employee))
    assert found.status_code == 200
    body = found.json()
    assert body["status"] == "hits" and body["passages"] == []
    assert [(entry["source_id"], entry["document_count"]) for entry in body["source_facets"]] == [(str(source), 1)]
    assert connection.execute(
        "SELECT dependency_count FROM thalion.delivery_record WHERE request_id = %s", (body["request_id"],),
    ).fetchone() == (4,)


def test_search_suggestions_require_all_roles_of_an_authorized_csv_group(transport):
    client, db, (employee, _), *_ = transport
    connection, tenant, _, _, store = db
    source = enroll(connection, tenant, csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外"))
    amounts = (*db[:3], source, store)
    _, cells = published_amount(amounts)
    set_rules(amounts, *(permit(tenant.actor_id, cell) for role, cell in cells.items() if role != "unit"))
    args = {"prefix": "ＳＹＮ", "source_id": str(source), "business_date": BEFORE.isoformat()}
    path = "/employee/search-suggestions"
    assert client.post(path, json=args, headers=bearer(employee)).json()["suggestions"] == []
    set_rules(amounts, *(permit(tenant.actor_id, cell) for cell in cells.values()), expected=2)
    found = client.post(path, json=args, headers=bearer(employee)).json()
    assert found["suggestions"] == [
        {"title": "Synthetic travel rules", "passage_id": str(cells["amount"].passage_ref)},
    ]
    assert connection.execute(
        "SELECT dependency_count FROM thalion.delivery_record WHERE request_id = %s", (found["request_id"],),
    ).fetchone() == (4,)


def test_employee_source_options_require_an_authorized_complete_csv_group(transport):
    client, db, (owner, _), *_ = transport
    connection, tenant, _, _, store = db
    source = enroll(connection, tenant, csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外"))
    amounts = (*db[:3], source, store)
    _, cells = published_amount(amounts)
    url = f"/employee/source-options?business_date={BEFORE}"
    set_rules(amounts, *(permit(tenant.actor_id, cell) for role, cell in cells.items() if role != "unit"))
    partial = client.get(url, headers=bearer(owner))
    assert partial.status_code == 200
    assert {option["source_id"] for option in partial.json()["options"]} == {str(db[3])}

    set_rules(amounts, *(permit(tenant.actor_id, cell) for cell in cells.values()), expected=2)
    full = client.get(url, headers=bearer(owner))
    assert full.status_code == 200
    assert {option["source_id"] for option in full.json()["options"]} == {str(db[3]), str(source)}
    assert {ref for ref, in connection.execute(
        """
        SELECT dependency.passage_ref FROM thalion.delivery_record AS delivery
        JOIN thalion.delivery_dependency AS dependency USING (check_id)
        WHERE delivery.request_id = %s AND dependency.source_id = (
            SELECT object_id FROM thalion.object_identity WHERE public_id = %s
        )
        """, (full.json()["request_id"], source),
    )} == {cell.passage_ref for cell in cells.values()}


def test_csv_search_never_opens_an_original_when_one_member_lacks_source_fields(amount_db, monkeypatch):
    _, tenant, _, _, store = amount_db
    _, cells = published_amount(amount_db)
    set_rules(amount_db, *(permit(tenant.actor_id, cell) for cell in cells.values()))
    denied = cells["exception"]

    def check(probe):
        full = authority_for({tenant.actor_id})(probe)
        return replace(full, permitted_fields={
            scope: fields - {"location"} if scope.object_id == denied.passage_ref else fields
            for scope, fields in full.permitted_fields.items()
        })

    def unexpected_read(*_):
        pytest.fail("A partly authorized CSV original must not be opened for search.")

    monkeypatch.setattr(type(store), "read", unexpected_read)
    assert search(amount_db, "600", authority=check).status == "no_evidence"


def test_search_ignores_incomplete_rows_and_nonmember_cells_even_with_explicit_read_rights(amount_db):
    connection, tenant, *_ = amount_db
    version, candidate = process(amount_db)
    review(amount_db, candidate)
    approve(connection, tenant, version, BEGIN)
    set_rules(amount_db, *(permit(tenant.actor_id, cell) for cell in csv_cells(amount_db, version)))
    assert search(amount_db, "750").status == "no_evidence"
    assert search(amount_db, "不属于证据组").status == "no_evidence"
    rendered = json.loads(search(amount_db, "实习员工", top_k=4).payload)
    assert [part["excerpt"] for part in rendered["passages"]] == ["0", "元/人·晚", "实习员工", "无"]


@pytest.mark.parametrize("change", ["source", "quality"])
def test_csv_final_check_discards_the_whole_group_if_a_member_or_run_is_restricted(amount_db, change):
    connection, tenant, database_url, source, store = amount_db
    candidate, cells = published_amount(amount_db)
    set_rules(amount_db, *(permit(tenant.actor_id, cell) for cell in cells.values()))
    context = ingress(amount_db, tenant.actor_id, BEFORE, operation="search")
    checks = []

    def check(probe):
        full = authority_for({tenant.actor_id})(probe)
        checks.append(probe)
        current = {(scope.object_id, scope.revision) for scope in probe.scopes}
        selected = {(cell.passage_ref, cell.revision) for cell in cells.values()}
        if len(checks) == 1:
            assert len(current) == 8 and selected < current
        if len(checks) == 2:
            assert current == selected
            if change == "quality":
                with open_database(database_url) as concurrent:
                    review((concurrent, tenant, database_url, source, store), candidate, decision="quarantined")
            else:
                return replace(full, permitted_fields={
                    scope: fields if scope.object_id != cells["unit"].passage_ref else frozenset()
                    for scope, fields in full.permitted_fields.items()
                })
        return full

    decision = search(amount_db, "600", context=context, authority=check)
    assert len(checks) == 2 and decision.payload is None
    assert decision.status == ("input_changed" if change == "quality" else "rejected")
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record WHERE request_id = %s",
                              (context.request_id,)).fetchone() == (0,)


def test_employee_search_displays_and_reopens_cells_then_clears_the_entire_group(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, _), *_ = portal
    connection, tenant, _, _, store = db
    source = enroll(connection, tenant, csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外"))
    amounts = (*db[:3], source, store)
    _, cells = published_amount(amounts)
    set_rules(amounts, *(permit(tenant.actor_id, cell) for cell in cells.values()))
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, owner)
    page.get_by_label("关键词或问题").fill("600")
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    search_button = page.get_by_role("button", name="查找依据")
    search_button.click()
    result = page.get_by_role("region", name="检索结果")
    values = ("600", "元/人·晚", "普通员工", "会议统一安排除外")
    for value in values:
        expect(result.get_by_text(value, exact=True)).to_be_visible()
    unit = result.get_by_role("listitem").filter(has_text="元/人·晚")
    unit.get_by_role("button", name="核对原文：Synthetic travel rules").click()
    original = page.get_by_role("region", name="原文核对")
    expect(original.get_by_text("第 2 行 / 第 3 列（单位）", exact=True)).to_be_visible()
    expect(original.get_by_text("元/人·晚", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, "employee-csv-search.png")
    set_rules(amounts, *(permit(tenant.actor_id, cell) for role, cell in cells.items() if role != "unit"), expected=2)
    search_button.click()
    expect(result.get_by_text("没有找到可用依据。可换个关键词或检查业务日期。", exact=True)).to_be_visible()
    for value in values:
        expect(result.get_by_text(value, exact=True)).to_be_hidden()
    expect(original.get_by_text("元/人·晚", exact=True)).to_be_hidden()
