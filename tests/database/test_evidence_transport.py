import json
import os
import re
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_bytes, token_urlsafe
from time import monotonic, sleep
from uuid import uuid4
from zoneinfo import ZoneInfo

import httpx2
import pytest
from fastapi.testclient import TestClient

from enterprise_kb.modules.access import travel
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.sources import registry
from enterprise_kb.transport import api, evidence, local

from test_effectivity import BEGIN, approve
from test_evidence import evidence_db
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import open_database, runtime_db
from test_sources import request_for
from test_travel_search import BEFORE, SEARCH_FIELDS, corpus, publish


VERSION = "2026-07-28"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def rpc(client, token, method, *, name=None, arguments=None, extra_headers=None):
    headers = {
        **bearer(token), "Accept": "application/json, text/event-stream",
        "Mcp-Protocol-Version": VERSION, "Mcp-Method": method,
    }
    params = {"_meta": {
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }}
    if name is not None:
        headers["Mcp-Name"] = name
        params.update(name=name, arguments=arguments)
    return client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 13, "method": method, "params": params},
        headers=headers | (extra_headers or {}),
    )


@pytest.fixture
def evidence_transport(corpus):
    db, _, first, second, *_ = corpus
    connection, tenant, database_url, _, store = db
    set_rules(
        db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        replace(binding(tenant.other_actor_id, passage_ref=first.passage_ref), fields=SEARCH_FIELDS),
    )
    tokens = [token_urlsafe(32) for _ in range(2)]
    credentials = {}
    for index, principal_id in enumerate((tenant.actor_id, tenant.other_actor_id)):
        employee_ref = connection.execute(
            "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
            (principal_id,),
        ).fetchone()[0]
        credentials[tokens[index]] = evidence.SyntheticCredential(
            employee_ref, tenant.space_ref, "synthetic-ui", "shanghai", "employee",
            frozenset({"search", "read_passage"}), datetime.now(UTC) + timedelta(minutes=5),
        )
    live = {tenant.actor_id, tenant.other_actor_id}
    service = evidence.EvidenceService(
        lambda: open_database(database_url), credentials.get,
        lambda credential, probe: authority_for(live)(probe), store,
    )
    return service, db, tokens, credentials, live, first, second


@pytest.fixture
def transport(evidence_transport):
    service, *fixtures = evidence_transport
    with TestClient(api.create_app(service), base_url="http://127.0.0.1") as client:
        yield client, *fixtures


def test_http_and_mcp_share_exact_business_response_and_audit(transport):
    client, db, (employee, _), _, _, first, _ = transport
    connection, *_ = db
    args = {"query": "上海住宿", "business_date": BEFORE.isoformat(), "top_k": 2, "include_wiki": False}
    http = client.post("/v1/search", json=args, headers=bearer(employee) | {"X-Thalion-Ingress": "mcp"})
    mcp = rpc(client, employee, "tools/call", name="search", arguments=args, extra_headers={"X-Thalion-Ingress": "http"})
    assert http.status_code == mcp.status_code == 200
    assert http.headers["Cache-Control"] == mcp.headers["Cache-Control"] == "no-store"
    result = mcp.json()["result"]
    assert result["resultType"] == "complete" and not result["isError"]
    structured = result["structuredContent"]
    tool_text = result["content"][0]["text"]
    assert json.loads(tool_text) == structured
    expected = http.json()
    assert structured | {"request_id": expected["request_id"]} == expected
    assert len(expected["passages"]) == 2 and structured["request_id"] != expected["request_id"]
    request_audit = connection.execute(
        """
        SELECT request_id::text, outcome, payload_digest, ingress, destination FROM thalion.request_record
        JOIN thalion.delivery_record USING (org_id, request_id)
        """,
    ).fetchall()
    assert set(request_audit) == {
        (expected["request_id"], "succeeded", sha256(http.content).digest(), "http", "employee"),
        (structured["request_id"], "succeeded", sha256(tool_text.encode()).digest(), "mcp", "employee"),
    }
    by_http = client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(employee)).json()
    by_mcp = rpc(client, employee, "tools/call", name="read_passage", arguments={"id": str(first.passage_ref)}).json()
    assert by_http["passage"] == by_mcp["result"]["structuredContent"]["passage"]


def test_second_employee_cannot_read_unauthorized_citation_and_revocation_is_current(transport):
    client, _, (employee, other), _, live, first, second = transport
    args = {"query": "上海住宿", "business_date": BEFORE.isoformat()}
    restricted = client.post("/v1/search", json=args, headers=bearer(other)).json()
    assert [item["passage_id"] for item in restricted["passages"]] == [str(first.passage_ref)]
    unknown = client.get(f"/v1/passages/{uuid4()}", headers=bearer(other))
    denied = client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(other))
    assert denied.status_code == unknown.status_code == 404
    assert denied.json()["error"] == unknown.json()["error"]
    live.clear()
    empty = rpc(client, employee, "tools/call", name="search", arguments=args).json()["result"]
    assert not empty["isError"] and empty["structuredContent"]["status"] == "no_evidence"
    read = rpc(client, employee, "tools/call", name="read_passage", arguments={"id": str(first.passage_ref)})
    assert read.json()["result"]["structuredContent"]["error"]["code"] == "citation_unavailable"


def test_identity_is_required_before_mcp_dispatch_and_cannot_be_in_request_body(transport):
    client, _, (employee, _), credentials, _, first, _ = transport
    denied = rpc(client, "invalid", "tools/list")
    assert denied.status_code == 401 and denied.headers["WWW-Authenticate"].startswith("Bearer")
    listed = rpc(client, employee, "tools/list").json()["result"]["tools"]
    assert {tool["name"] for tool in listed} == {"search", "read_passage"}
    assert all(tool["annotations"]["readOnlyHint"] for tool in listed)
    spoof = {"query": "上海住宿", "principal_id": 999, "destination": "model"}
    invalid = client.post("/v1/search", json=spoof, headers=bearer(employee))
    assert invalid.status_code == 400
    assert invalid.json() == {
        "request_id": invalid.json()["request_id"],
        "error": {"code": "invalid_arguments", "message": "请求参数无效。"},
    }
    invalid = rpc(client, employee, "tools/call", name="search", arguments=spoof).json()["result"]
    assert invalid["isError"] and invalid["structuredContent"]["error"]["code"] == "invalid_arguments"
    credentials[employee] = replace(credentials[employee], operations=frozenset({"search"}))
    denied_http = client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(employee))
    denied_mcp = rpc(client, employee, "tools/call", name="read_passage", arguments={"id": str(first.passage_ref)})
    assert denied_http.status_code == denied_mcp.status_code == 403
    credentials[employee] = replace(credentials[employee], expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert client.post("/v1/search", json={"query": "上海住宿"}, headers=bearer(employee)).status_code == 401


def test_mcp_header_body_mismatch_is_protocol_error_and_not_tool_error(transport):
    client, _, (employee, _), *_ = transport
    mismatch = rpc(client, employee, "tools/call", name="search", arguments={"query": "住宿"},
                   extra_headers={"Mcp-Name": "read_passage"})
    assert mismatch.status_code == 400 and "error" in mismatch.json() and "result" not in mismatch.json()
    wrong_origin = rpc(client, employee, "tools/list", extra_headers={"Origin": "https://another.invalid"})
    assert wrong_origin.status_code == 403 and "result" not in wrong_origin.json()


def test_disabling_synthetic_employee_invalidates_both_routes(transport):
    client, db, (employee, _), *_ = transport
    connection, tenant, *_ = db
    connection.execute("UPDATE thalion.principal SET disabled = true WHERE principal_id = %s", (tenant.actor_id,))
    assert client.post("/v1/search", json={"query": "上海住宿"}, headers=bearer(employee)).status_code == 401
    assert rpc(client, employee, "tools/list").status_code == 401


def test_authority_failure_is_not_no_evidence_or_undelivered_content(transport, monkeypatch):
    client, _, (employee, _), *_ = transport

    def unavailable(*args):
        raise AuthorizationUnavailable("confidential diagnostics")

    monkeypatch.setattr(evidence.EvidenceService, "authority_for", unavailable)
    args = {"query": "上海住宿", "business_date": BEFORE.isoformat()}
    http = client.post("/v1/search", json=args, headers=bearer(employee))
    mcp = rpc(client, employee, "tools/call", name="search", arguments=args)
    assert http.status_code == 503 and mcp.status_code == 200
    assert "confidential" not in http.text + mcp.text
    assert http.json()["error"]["code"] == "dependency_unavailable"
    assert mcp.json()["result"]["isError"]
    assert mcp.json()["result"]["structuredContent"]["error"] == http.json()["error"]


def test_expired_seal_is_discarded_at_both_response_boundaries(transport, monkeypatch):
    client, _, (employee, _), *_ = transport
    monkeypatch.setattr(api, "release_time", lambda: datetime.now(UTC) + timedelta(minutes=1))
    args = {"query": "上海住宿", "business_date": BEFORE.isoformat()}
    http = client.post("/v1/search", json=args, headers=bearer(employee))
    mcp = rpc(client, employee, "tools/call", name="search", arguments=args)
    assert http.status_code == 503 and "passages" not in http.json()
    assert mcp.status_code == 200 and mcp.json()["result"]["isError"]
    assert mcp.json()["result"]["structuredContent"]["error"]["code"] == "dependency_unavailable"


def test_no_protected_body_is_sent_if_release_expires_after_headers(transport, monkeypatch):
    client, _, (employee, _), *_ = transport
    checks = iter((datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=1)))
    monkeypatch.setattr(api, "release_time", lambda: next(checks))
    reply = client.post("/v1/search", json={"query": "上海住宿"}, headers=bearer(employee))
    assert reply.content == b""


def test_search_filters_spaces_and_uses_business_timezone_without_a_user_date(transport):
    client, db, (employee, _), _, _, first, _ = transport
    _, tenant, *_ = db
    default = client.post("/v1/search", json={"query": "上海住宿"}, headers=bearer(employee))
    assert default.json()["business_date"] == datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
    no_access = client.post("/v1/search", json={"query": "上海住宿", "space_ids": [str(uuid4())]}, headers=bearer(employee))
    assert no_access.status_code == 200 and no_access.json()["status"] == "no_evidence"
    in_scope = client.post(
        "/v1/search", json={"query": "上海住宿", "space_ids": [str(tenant.space_ref)]}, headers=bearer(employee),
    )
    assert str(first.passage_ref) in {part["passage_id"] for part in in_scope.json()["passages"]}


def add_search_source(db):
    connection, tenant, database_url, _, store = db
    registration = request_for(
        connection, tenant, tenant.actor_id, "register-second-source", "register_source_contract",
    )
    selected = registry.register_synthetic_source(
        connection, registration, tenant.space_id,
        registry.SyntheticSource(
            "policy-library", "policy-library", tenant.worker_id, approver_id=tenant.other_actor_id,
            processor_id=tenant.other_worker_id, quality_reviewer_id=tenant.actor_id,
        ),
    )
    selected_db = connection, tenant, database_url, selected, store
    version, passage, _ = publish(selected_db, "allowance", "另一来源", "上海住宿限额。\n".encode())
    approve(connection, tenant, version, BEGIN)
    set_rules(selected_db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    return selected, passage


def test_employee_source_options_only_use_current_readable_evidence(transport):
    client, db, (employee, restricted), credentials, live, _, _ = transport
    connection, tenant, _, source, _ = db
    second_source, _ = add_search_source(db)
    url = f"/employee/source-options?business_date={BEFORE}"

    assert client.get(url).status_code == 401
    response = client.get(url, headers=bearer(employee))
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert {option["source_id"] for option in response.json()["options"]} == {str(source), str(second_source)}
    assert all(set(option) == {"source_id", "example_title"} for option in response.json()["options"])
    assert "policy-library" not in response.text
    restricted_response = client.get(url, headers=bearer(restricted))
    assert restricted_response.status_code == 200
    assert restricted_response.json()["options"] == [{"source_id": str(source), "example_title": "住宿标准"}]
    assert connection.execute(
        """
        SELECT request.operation, delivery.payload_digest, count(citation.position)
        FROM thalion.request_record AS request JOIN thalion.delivery_record AS delivery USING (request_id, org_id)
        LEFT JOIN thalion.delivery_citation AS citation USING (check_id)
        WHERE request.request_id = %s GROUP BY request.operation, delivery.payload_digest
        """, (restricted_response.json()["request_id"],),
    ).fetchone() == ("list_employee_sources", sha256(restricted_response.content).digest(), 0)
    early = client.get("/employee/source-options?business_date=2025-01-01", headers=bearer(employee))
    assert early.status_code == 200 and early.json()["options"] == []
    assert client.get(f"{url}&space_ids={uuid4()}", headers=bearer(employee)).status_code == 400
    assert client.get(f"{url}&business_date={BEFORE}", headers=bearer(employee)).status_code == 400

    live.remove(tenant.actor_id)
    revoked = client.get(url, headers=bearer(employee))
    assert revoked.status_code == 200 and revoked.json()["options"] == []
    credentials[employee] = replace(credentials[employee], operations=frozenset({"read_passage"}))
    assert client.get(url, headers=bearer(employee)).status_code == 403


def test_employee_source_options_fail_closed_at_final_authorization(transport, evidence_transport, monkeypatch):
    client, db, (employee, _), _, live, *_ = transport
    service, *_ = evidence_transport
    _, tenant, *_ = db
    checked = 0
    live_authority = authority_for(live)

    def revoke_after_discovery(credential, probe):
        nonlocal checked
        checked += 1
        if checked == 2:
            live.remove(tenant.actor_id)
        return live_authority(probe)

    monkeypatch.setattr(service, "check_source", revoke_after_discovery)
    result = client.get(f"/employee/source-options?business_date={BEFORE}", headers=bearer(employee))
    assert result.status_code == 503 and checked == 2
    assert result.json()["error"]["code"] == "dependency_unavailable"
    assert "options" not in result.json()


def test_employee_suggestions_use_readable_titles_and_do_not_seed_search_feedback(transport):
    client, db, (employee, restricted), credentials, live, first, second = transport
    connection, tenant, _, source, _ = db
    url = "/employee/search-suggestions"
    arguments = {"prefix": "受限", "business_date": BEFORE.isoformat()}
    assert client.post(url, json=arguments).status_code == 401
    assert client.post(f"{url}?prefix=住宿", json=arguments, headers=bearer(employee)).status_code == 400
    assert client.post(url, json=arguments | {"prefix": " "}, headers=bearer(employee)).status_code == 400
    found = client.post(url, json=arguments, headers=bearer(employee))
    assert found.status_code == 200 and found.headers["Cache-Control"] == "no-store"
    assert found.json()["suggestions"] == [{"title": "受限审批说明", "passage_id": str(second.passage_ref)}]
    assert connection.execute(
        """
        SELECT operation, payload_digest, dependency_count FROM thalion.delivery_record
        JOIN thalion.request_record USING (org_id, request_id) WHERE request_id = %s
        """, (found.json()["request_id"],),
    ).fetchone() == ("list_employee_title_suggestions", sha256(found.content).digest(), 1)
    for table in ("delivery_citation", "search_scope_observation", "feedback_search_match"):
        assert connection.execute(f"SELECT count(*) FROM thalion.{table}").fetchone() == (0,)

    hidden = client.post(url, json=arguments, headers=bearer(restricted)).json()
    absent = client.post(url, json=arguments | {"prefix": "未登记"}, headers=bearer(restricted)).json()
    assert hidden | {"request_id": absent["request_id"]} == absent
    assert hidden["suggestions"] == []
    scope = arguments | {"prefix": " 住宿 ", "source_id": str(source)}
    matching = client.post(url, json=scope, headers=bearer(restricted)).json()
    assert matching["suggestions"] == [{"title": "住宿标准", "passage_id": str(first.passage_ref)}]
    for change in ({"source_id": str(uuid4())}, {"business_date": "2025-01-01"}):
        assert client.post(url, json=scope | change, headers=bearer(restricted)).json()["suggestions"] == []
    live.remove(tenant.actor_id)
    assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(employee)).status_code == 404
    credentials[employee] = replace(credentials[employee], operations=frozenset({"read_passage"}))
    assert client.post(url, json=arguments, headers=bearer(employee)).status_code == 403


def test_employee_suggestions_fail_closed_if_authority_changes_before_response(
    transport, evidence_transport, monkeypatch,
):
    client, db, (employee, _), _, live, *_ = transport
    service, *_ = evidence_transport
    connection, tenant, *_ = db
    probes = []

    def revoke_at_final_check(credential, probe):
        probes.append(probe)
        if len(probes) == 2:
            live.remove(tenant.actor_id)
        return authority_for(live)(probe)

    monkeypatch.setattr(service, "check_source", revoke_at_final_check)
    response = client.post("/employee/search-suggestions", json={
        "prefix": "住宿", "business_date": BEFORE.isoformat(),
    }, headers=bearer(employee))
    assert response.status_code == 503 and len(probes) == 2
    assert "住宿标准" not in response.text and "suggestions" not in response.json()
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_source_filter_narrows_before_delivery_on_http_and_mcp(transport):
    client, db, (employee, restricted), _, live, first, second = transport
    _, tenant, _, source, _ = db
    selected, passage = add_search_source(db)
    arguments = {"query": "上海住宿", "business_date": BEFORE.isoformat()}

    def search(token, source_refs=None, *, via_mcp=False):
        params = arguments if source_refs is None else arguments | {"source_ids": source_refs}
        if via_mcp:
            result = rpc(client, token, "tools/call", name="search", arguments=params).json()["result"]
            assert not result["isError"]
            return result["structuredContent"]
        reply = client.post("/v1/search", json=params, headers=bearer(token))
        assert reply.status_code == 200
        return reply.json()

    assert {item["passage_id"] for item in search(employee)["passages"]} == {
        str(first.passage_ref), str(second.passage_ref), str(passage.passage_ref),
    }
    exact = search(employee, [str(selected)])
    assert [item["passage_id"] for item in exact["passages"]] == [str(passage.passage_ref)]
    assert search(employee, [str(selected)], via_mcp=True)["passages"] == exact["passages"]
    assert {
        item["passage_id"] for item in search(employee, [str(source)])["passages"]
    } == {str(first.passage_ref), str(second.passage_ref)}

    denied = search(restricted, [str(selected)])
    unknown = search(restricted, [str(uuid4())])
    assert denied | {"request_id": unknown["request_id"]} == unknown
    assert unknown["status"] == "no_evidence" and unknown["passages"] == unknown["wiki"] == []
    assert search(employee, [])["status"] == "no_evidence"
    live.remove(tenant.actor_id)
    assert search(employee, [str(selected)], via_mcp=True)["status"] == "no_evidence"


def test_source_filter_does_not_seed_a_space_wide_missing_evidence_baseline(transport, evidence_transport, monkeypatch):
    client, db, (employee, _), *_ = transport
    service, *_ = evidence_transport
    connection, *_ = db
    monkeypatch.setattr(service, "retest_key", token_bytes(32))
    result = client.post(
        "/v1/search", json={"query": "上海住宿", "source_ids": [str(uuid4())]}, headers=bearer(employee),
    )
    assert result.status_code == 200 and result.json()["status"] == "no_evidence"
    assert connection.execute(
        "SELECT visibility_limited, empty_fingerprint FROM thalion.search_scope_observation WHERE request_id = %s",
        (result.json()["request_id"],),
    ).fetchone() == (True, None)
    invalid = client.post(
        "/v1/search", json={"query": "上海住宿", "source_ids": [1]}, headers=bearer(employee),
    )
    assert invalid.status_code == 400


def test_search_source_facets_count_visible_matched_documents_before_top_k(transport):
    client, db, (employee, restricted), *_ = transport
    connection, tenant, _, source, _ = db
    other_source, _ = add_search_source(db)
    content = "\n\n".join(f"上海住宿补充 {number}。" for number in range(22))
    matching, *_ = publish(db, "multi-section", "住宿补充", content.encode())
    unrelated, *_ = publish(db, "rail-fares", "其他文件", "铁路票价。\n".encode())
    for version in (matching, unrelated):
        approve(connection, tenant, version, BEGIN)
    arguments = {
        "query": "上海住宿", "business_date": BEFORE.isoformat(), "top_k": 1, "include_source_facets": True,
    }

    def facets(body):
        return {entry["source_id"]: entry["document_count"] for entry in body["source_facets"]}

    response = client.post("/v1/search", json=arguments, headers=bearer(employee))
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert len(body["passages"]) == 1
    assert facets(body) == {str(source): 3, str(other_source): 1}
    assert connection.execute(
        """
        SELECT source_facets, dependency_count, payload_digest, (SELECT count(*) FROM thalion.delivery_citation AS displayed
        WHERE displayed.check_id = delivery.check_id)
        FROM thalion.delivery_record AS delivery WHERE request_id = %s
        """, (body["request_id"],),
    ).fetchone() == (True, 25, sha256(response.content).digest(), 1)
    via_mcp = rpc(client, employee, "tools/call", name="search", arguments=arguments).json()["result"]
    assert not via_mcp["isError"]
    assert via_mcp["structuredContent"] | {"request_id": body["request_id"]} == body

    restricted_view = client.post("/v1/search", json=arguments, headers=bearer(restricted)).json()
    assert facets(restricted_view) == {str(source): 1}
    assert "受限审批说明" not in json.dumps(restricted_view, ensure_ascii=False)
    filtered = client.post(
        "/v1/search", json=arguments | {"source_ids": [str(other_source)]}, headers=bearer(employee),
    ).json()
    assert facets(filtered) == {str(other_source): 1}
    denied = client.post(
        "/v1/search", json=arguments | {"source_ids": [str(other_source)]}, headers=bearer(restricted),
    ).json()
    unknown = client.post(
        "/v1/search", json=arguments | {"source_ids": [str(uuid4())]}, headers=bearer(restricted),
    ).json()
    assert denied | {"request_id": unknown["request_id"]} == unknown
    assert denied["status"] == "no_evidence" and denied["source_facets"] == []
    invalid = client.post("/v1/search", json=arguments | {"include_source_facets": 1}, headers=bearer(employee))
    assert invalid.status_code == 400


def test_source_facets_recheck_matches_that_will_not_be_displayed(transport, evidence_transport, monkeypatch):
    client, db, (employee, _), _, live, _, second = transport
    service, *_ = evidence_transport
    connection, *_ = db
    checks = []

    def revoke_one_after_ranking(credential, probe):
        checks.append(probe)
        authority = authority_for(live)(probe)
        if len(checks) == 2:
            return replace(authority, permitted_fields={
                scope: fields if scope.object_id != second.passage_ref else frozenset()
                for scope, fields in authority.permitted_fields.items()
            })
        return authority

    monkeypatch.setattr(service, "check_source", revoke_one_after_ranking)
    result = client.post("/v1/search", headers=bearer(employee), json={
        "query": "上海住宿 限额", "business_date": BEFORE.isoformat(), "top_k": 1, "include_source_facets": True,
    })
    assert result.status_code == 503 and len(checks) == 2
    assert second.passage_ref in {scope.object_id for scope in checks[-1].scopes}
    assert "source_facets" not in result.json()
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


@pytest.mark.parametrize("limit", ["MAX_SEARCH_DOCUMENTS", "MAX_SEARCH_PASSAGES"])
def test_source_filter_cannot_probe_hidden_source_with_candidate_limit(transport, monkeypatch, limit):
    client, db, (_, restricted), *_ = transport
    _, tenant, _, source, _ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS), expected=2)
    monkeypatch.setattr(travel, limit, 1)
    for source_ref in (source, uuid4()):
        result = client.post(
            "/v1/search", json={"query": "上海住宿", "source_ids": [str(source_ref)]}, headers=bearer(restricted),
        )
        assert result.status_code == 503 and result.json()["error"]["code"] == "dependency_unavailable"


def test_source_filter_preserves_authority_outage_for_known_and_unknown_ids(evidence_transport, transport, monkeypatch):
    service, *_ = evidence_transport
    client, db, (employee, _), *_ = transport

    def unavailable(*_):
        raise AuthorizationUnavailable()

    monkeypatch.setattr(service, "check_source", unavailable)
    for source_ref in (db[3], uuid4()):
        result = client.post(
            "/v1/search", json={"query": "上海住宿", "source_ids": [str(source_ref)]}, headers=bearer(employee),
        )
        assert result.status_code == 503 and result.json()["error"]["code"] == "dependency_unavailable"


def test_untrusted_hosts_and_oversized_search_bodies_cannot_dispatch(transport):
    client, _, (employee, _), *_ = transport
    invalid_host = client.post(
        "/v1/search", json={"query": "上海住宿"}, headers=bearer(employee) | {"Host": "public.invalid"},
    )
    assert invalid_host.status_code == 403
    oversized = client.post(
        "/v1/search", json={"query": "A" * (64 * 1024)}, headers=bearer(employee),
    )
    assert oversized.status_code == 413


def private_json(path, data):
    pending = path.with_suffix(".pending")
    descriptor = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(data, stream)
    os.replace(pending, path)


def test_retest_key_is_optional_but_configured_key_must_be_private(tmp_path):
    tmp_path.chmod(0o700)
    private_json(tmp_path / "credentials.json", [])
    private_json(tmp_path / "source-grants.json", {})
    assert local.LocalProfile(tmp_path).retest_key is None
    key_file = tmp_path / "feedback-retest-key.json"
    private_json(key_file, "bad-key")
    with pytest.raises(ValueError, match="Invalid private feedback retest key"):
        local.LocalProfile(tmp_path)
    key = token_bytes(32)
    private_json(key_file, key.hex())
    assert local.LocalProfile(tmp_path).retest_key == local.LocalProfile(tmp_path).retest_key == key
    key_file.chmod(0o644)
    with pytest.raises(AuthorizationUnavailable):
        local.LocalProfile(tmp_path)


def test_installed_loopback_service_reads_current_private_source_permissions(corpus):
    db, _, first, _, *_ = corpus
    connection, tenant, database_url, source, store = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    employee_ref = connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
        (tenant.actor_id,),
    ).fetchone()[0]
    token = token_urlsafe(32)
    profile = store.root
    private_json(profile / "credentials.json", [{
        "token_sha256": sha256(token.encode()).hexdigest(),
        "employee_ref": str(employee_ref), "space_ref": str(tenant.space_ref), "client_id": "synthetic-ui",
        "region": "shanghai", "traveler_class": "employee", "operations": ["search", "read_passage"],
        "expires_at": (datetime.now(UTC) + timedelta(minutes=3)).isoformat(),
    }])
    grant_file = profile / "source-grants.json"
    private_json(grant_file, {str(employee_ref): [str(first.passage_ref)]})
    private_json(profile / "feedback-retest-key.json", token_bytes(32).hex())
    output_path = profile / "loopback.log"
    with output_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [sys.executable, "-I", "-m", "enterprise_kb.transport.local", "--profile", str(profile),
             "--originals", str(store.root), "--port", "0"],
            stdout=output, stderr=subprocess.STDOUT, env=os.environ | {"THALION_DATABASE_URL": database_url},
        )
        try:
            timeout = monotonic() + 15
            while monotonic() < timeout and process.poll() is None:
                match = re.search(r"Uvicorn running on http://127\.0\.0\.1:([0-9]+)", output_path.read_text())
                if match:
                    break
                sleep(0.05)
            else:
                pytest.fail("The installed synthetic loopback server did not start.")
            with httpx2.Client(base_url=f"http://127.0.0.1:{match[1]}", trust_env=False) as client:
                hits = client.post("/v1/search", json={"query": "上海住宿"}, headers=bearer(token))
                assert hits.status_code == 200
                assert [part["passage_id"] for part in hits.json()["passages"]] == [str(first.passage_ref)]
                assert connection.execute(
                    "SELECT octet_length(fingerprint) FROM thalion.feedback_search_match WHERE request_id = %s",
                    (hits.json()["request_id"],),
                ).fetchone() == (32,)
                options_url = f"/employee/source-options?business_date={BEFORE}"
                options = client.get(options_url, headers=bearer(token))
                assert options.status_code == 200
                assert options.json()["options"] == [{"source_id": str(source), "example_title": "住宿标准"}]
                suggestions_path = "/employee/search-suggestions"
                suggestion_request = {"prefix": "住宿", "source_id": str(source), "business_date": BEFORE.isoformat()}
                suggestions = client.post(suggestions_path, json=suggestion_request, headers=bearer(token))
                assert suggestions.status_code == 200
                assert suggestions.json()["suggestions"] == [
                    {"title": "住宿标准", "passage_id": str(first.passage_ref)},
                ]
                private_json(grant_file, {str(employee_ref): []})
                revoked = client.get(options_url, headers=bearer(token))
                assert revoked.status_code == 200 and revoked.json()["options"] == []
                withdrawn = client.post(suggestions_path, json=suggestion_request, headers=bearer(token))
                assert withdrawn.status_code == 200 and withdrawn.json()["suggestions"] == []
                unavailable = rpc(client, token, "tools/call", name="read_passage", arguments={"id": str(first.passage_ref)})
                assert unavailable.status_code == 200 and unavailable.json()["result"]["isError"]
                assert unavailable.json()["result"]["structuredContent"]["error"]["code"] == "citation_unavailable"
                grant_file.chmod(0o644)
                assert client.post("/v1/search", json={"query": "上海住宿"}, headers=bearer(token)).status_code == 503
                assert client.post(suggestions_path, json=suggestion_request, headers=bearer(token)).status_code == 503
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
