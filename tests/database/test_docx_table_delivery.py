from dataclasses import replace
from hashlib import sha256
from uuid import UUID

import pytest

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.operations import feedback

from test_docx_review import decide, docx_table_review, grant, locate, open_preview
from test_employee_portal import browser, load_credential, loopback_page
from test_evidence import evidence_db, review
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback import open_feedback
from test_feedback_work import EVIDENCE_CAPABILITY, QUEUE_PATH, admit, assign
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import BEFORE, SEARCH_FIELDS, corpus


ARGS = {"query": "0600.50", "business_date": BEFORE.isoformat(), "top_k": 4, "include_wiki": True}
ROW_TEXT = "适用人群：上海正式员工\n上限：0600.50\n单位：元/人·晚\n例外：会议统一安排除外。\n须另行审批。"


@pytest.fixture
def ready_docx_table(transport, docx_table_review):
    client, *_ = transport
    service, db, (owner, _), version, run = docx_table_review
    connection, tenant, *_ = db
    refs = [ref for ref, in locate(connection, run)]
    set_rules(db, *(grant(tenant, ref) for ref in refs), *(
        replace(binding(tenant.actor_id, passage_ref=ref), fields=SEARCH_FIELDS) for ref in refs
    ))
    preview = open_preview(client, owner, run, tables=True)
    assert preview.status_code == 200
    assert decide(client, owner, run, preview.json()["preview_id"]).status_code == 200
    unit, = processing.list_approved_docx_units(connection, tenant.org_id, tenant.space_id, version.version_ref)
    return service, db, version, {member.role: member.cell.passage_ref for member in unit.members}


def test_http_and_mcp_deliver_a_complete_row_and_reopen_it_with_exact_dependencies(transport, ready_docx_table):
    client, _, (owner, _), *_ = transport
    _, db, _, refs = ready_docx_table
    connection, *_ = db
    http = client.post("/v1/search", headers=bearer(owner), json=ARGS)
    mcp = rpc(client, owner, "tools/call", name="search", arguments=ARGS).json()["result"]
    assert http.status_code == 200 and not mcp["isError"]
    body = http.json()
    assert mcp["structuredContent"] | {"request_id": body["request_id"]} == body
    assert body["status"] == "hits" and body["wiki"] == []
    assert [(part["passage_id"], part["excerpt"], part["location"]["columns"][0]) for part in body["passages"]] == [
        (str(refs["amount"]), "0600.50", {"column": 2, "header": "上限"}),
        (str(refs["unit"]), "元/人·晚", {"column": 3, "header": "单位"}),
        (str(refs["condition"]), "上海正式员工", {"column": 1, "header": "适用人群"}),
        (str(refs["exception"]), "会议统一安排除外。\n须另行审批。", {"column": 4, "header": "例外"}),
    ]
    assert all(part["source_type"] == "docx" and part["location"] | {"columns": []} == {
        "heading_path": ["差旅", "住宿"], "table": 1, "row_id": 2, "columns": [],
    } for part in body["passages"])
    assert client.post("/v1/search", headers=bearer(owner), json=ARGS | {"top_k": 3}).json()["status"] == "no_evidence"
    assert client.post("/v1/search", headers=bearer(owner), json=ARGS | {"query": "800"}).json()["status"] == "no_evidence"

    opened = client.get(f"/v1/passages/{refs['amount']}", headers=bearer(owner))
    reopened = rpc(client, owner, "tools/call", name="read_passage", arguments={"id": str(refs["amount"])}).json()["result"]
    assert opened.status_code == 200 and not reopened["isError"]
    passage = opened.json()["passage"]
    assert reopened["structuredContent"]["passage"] == passage
    assert (passage["passage_id"], passage["excerpt"]) == (str(refs["amount"]), ROW_TEXT)
    assert [(column["column"], column["header"]) for column in passage["location"]["columns"]] == [
        (1, "适用人群"), (2, "上限"), (3, "单位"), (4, "例外"),
    ]
    for response, visible in ((http, set(refs.values())), (opened, {refs["amount"]})):
        assert response.headers["cache-control"] == "no-store"
        dependencies = connection.execute("""
            SELECT dep.passage_ref, dep.excerpt_revision, delivery.payload_digest, citation.position IS NOT NULL
            FROM thalion.delivery_record AS delivery JOIN thalion.delivery_dependency AS dep USING (check_id)
            LEFT JOIN thalion.delivery_citation AS citation USING (check_id, position)
            WHERE delivery.request_id = %s
        """, (UUID(response.json()["request_id"]),)).fetchall()
        assert set(dependencies) == {
            (ref, 1, sha256(response.content).digest(), ref in visible) for ref in refs.values()
        }


@pytest.mark.parametrize("missing", ["local", "authority"])
def test_one_denied_cell_prevents_search_and_reference_from_opening_the_original(
    transport, ready_docx_table, monkeypatch, missing,
):
    client, _, (owner, other), *_ = transport
    service, db, version, refs = ready_docx_table
    _, tenant, _, _, store = db
    token = other if missing == "local" else owner
    if missing == "local":
        set_rules(db, replace(binding(tenant.other_actor_id), fields=SEARCH_FIELDS), *(
            replace(binding(tenant.other_actor_id, passage_ref=ref), fields=SEARCH_FIELDS)
            for key, ref in refs.items() if key != "unit"
        ), expected=2)
    else:
        live = authority_for({tenant.actor_id})

        def deny_unit(credential, probe):
            proof = live(probe)
            return replace(proof, permitted_fields={
                scope: fields - {"location"} if scope.object_id == refs["unit"] else fields
                for scope, fields in proof.permitted_fields.items()
            })

        service.check_source = deny_unit
    read = store.read

    def refuse_read(asset):
        if asset.digest == version.digest:
            pytest.fail("Must not read a DOCX original for a partly authorized row.")
        return read(asset)

    monkeypatch.setattr(store, "read", refuse_read)
    search = client.post("/v1/search", headers=bearer(token), json=ARGS)
    assert search.status_code == 200 and search.json()["passages"] == []
    assert client.get(f"/v1/passages/{refs['amount']}", headers=bearer(token)).status_code == 404


@pytest.mark.parametrize(("operation", "error"), [("search", 403), ("read", 404), ("outage", 503)])
def test_final_source_check_can_discard_the_entire_docx_row(transport, ready_docx_table, operation, error):
    client, _, (owner, _), *_ = transport
    service, db, _, refs = ready_docx_table
    connection, tenant, *_ = db
    live = authority_for({tenant.actor_id})
    probes = []

    def check(credential, probe):
        probes.append({(scope.object_id, scope.revision) for scope in probe.scopes})
        if len(probes) == 2 and operation == "outage":
            raise AuthorizationUnavailable("Synthetic authority outage.")
        proof = live(probe)
        if len(probes) == 2:
            return replace(proof, permitted_fields={
                scope: frozenset() if scope.object_id == refs["exception"] else fields
                for scope, fields in proof.permitted_fields.items()
            })
        return proof

    service.check_source = check
    response = (client.post("/v1/search", headers=bearer(owner), json=ARGS) if operation == "search"
                else client.get(f"/v1/passages/{refs['amount']}", headers=bearer(owner)))
    assert response.status_code == error and "0600.50" not in response.text
    required = {(ref, 1) for ref in refs.values()}
    assert len(probes) == 2 and probes[0] >= required and probes[1] == required
    assert connection.execute("SELECT 1 FROM thalion.delivery_record WHERE request_id = %s",
                              (UUID(response.json()["request_id"]),)).fetchone() is None


def test_quarantine_during_final_check_discards_the_current_row(transport, ready_docx_table, docx_table_review):
    client, _, (owner, _), *_ = transport
    service, db, _, refs = ready_docx_table
    connection, tenant, database_url, source, store = db
    _, _, _, _, run = docx_table_review
    live = authority_for({tenant.actor_id})
    probes = []

    def check(credential, probe):
        probes.append(probe)
        if len(probes) == 2:
            with open_database(database_url) as concurrent:
                review((concurrent, tenant, database_url, source, store), run, decision="quarantined")
        return live(probe)

    service.check_source = check
    response = client.post("/v1/search", headers=bearer(owner), json=ARGS)
    assert response.status_code == 503 and "0600.50" not in response.text
    assert len(probes) == 2 and {scope.object_id for scope in probes[-1].scopes} == set(refs.values())
    assert connection.execute("SELECT 1 FROM thalion.delivery_record WHERE request_id = %s",
                              (UUID(response.json()["request_id"]),)).fetchone() is None
    assert client.post("/v1/search", headers=bearer(owner), json=ARGS).json()["status"] == "no_evidence"
    assert client.get(f"/v1/passages/{refs['amount']}", headers=bearer(owner)).status_code == 404


def test_assigned_feedback_requires_current_authorization_for_the_whole_row(transport, ready_docx_table):
    client, _, (owner, handler), credentials, *_ = transport
    _, db, _, refs = ready_docx_table
    connection, tenant, *_ = db
    display = client.get(f"/v1/passages/{refs['amount']}", headers=bearer(owner))
    origin = UUID(display.json()["request_id"])
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    report = feedback.record_feedback(connection, call, feedback.FeedbackSpec(origin, "incorrect_evidence", refs["amount"]))
    assign(connection, tenant, report)
    admit(credentials, handler, EVIDENCE_CAPABILITY)
    path = f"{QUEUE_PATH}/{report}/evidence"
    set_rules(db, replace(binding(tenant.other_actor_id, passage_ref=refs["amount"]), fields=SEARCH_FIELDS), expected=2)
    assert client.get(path, headers=bearer(handler)).status_code == 404
    set_rules(db, *(replace(binding(tenant.other_actor_id, passage_ref=ref), fields=SEARCH_FIELDS)
                    for ref in refs.values()), expected=3)
    checked = client.get(path, headers=bearer(handler))
    assert checked.status_code == 200 and checked.json()["passage"]["excerpt"] == ROW_TEXT
    evidence_ref = UUID(checked.json()["request_id"])
    transition = open_feedback(connection, tenant, tenant.other_actor_id, feedback.TRANSITION)
    feedback.transition_feedback(connection, transition, report, 2, "explain", basis_id=evidence_ref,
                                 conclusion_code="source_text_confirmed")
    assert connection.execute("SELECT state FROM thalion.current_feedback").fetchone() == ("explained",)


def test_employee_page_shows_the_full_row_and_clears_it_when_one_cell_is_revoked(browser, transport, ready_docx_table):
    from playwright.sync_api import expect

    _, _, (owner, _), *_ = transport
    service, db, _, refs = ready_docx_table
    _, tenant, *_ = db
    with loopback_page(browser, service, "/") as (page, _, _):
        page.set_viewport_size({"width": 390, "height": 844})
        load_credential(page, owner)
        page.get_by_label("关键词或问题").fill(ARGS["query"])
        page.get_by_label("业务日期").fill(BEFORE.isoformat())
        page.get_by_role("button", name="查找依据").click()
        results = page.get_by_role("region", name="检索结果")
        amount = results.get_by_role("listitem").filter(has_text="0600.50")
        expect(amount.get_by_text("差旅 / 住宿 / 第 1 表 / 第 2 行 / 第 2 列（上限）", exact=True)).to_be_visible()
        open_original = amount.get_by_role("button", name="核对原文：Synthetic travel rules")
        open_original.click()
        original = page.get_by_role("region", name="原文核对")
        expect(original.get_by_text("差旅 / 住宿 / 第 1 表 / 第 2 行 · 4 个单元格", exact=True)).to_be_visible()
        expect(original.locator(".excerpt")).to_have_text(ROW_TEXT)
        assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
        set_rules(db, *(replace(binding(tenant.actor_id, passage_ref=ref), fields=SEARCH_FIELDS)
                        for key, ref in refs.items() if key != "exception"), expected=2)
        open_original.click()
        expect(original.get_by_text("该引用不可用。请重新查找依据。", exact=True)).to_be_visible()
        expect(original.locator(".excerpt")).to_have_count(0)
        expect(amount).to_have_count(0)
