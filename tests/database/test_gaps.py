from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from secrets import token_bytes, token_urlsafe
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from psycopg.errors import CheckViolation, ObjectNotInPrerequisiteState

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.operations import feedback
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request

from test_effectivity import approve, record
from test_employee_portal import browser, load_credential, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback import open_feedback, present
from test_feedback_work import admit
from test_identity import migrate_to_revision, principal, space
from test_persisted_access import binding, set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_travel_search import BEFORE, BEGIN, SEARCH_FIELDS, corpus, publish


GAPS = "/internal/feedback/gaps"


def command_headers(token, key=None):
    return bearer(token) | {"Idempotency-Key": key or str(uuid4())}


def record_gap(client, token, origin, key=None):
    return client.post(GAPS, headers=command_headers(token, key), json={"origin_request_id": str(origin)})


def test_gap_capture_preserves_hidden_limits_and_dependency_failures(evidence_transport, transport, monkeypatch):
    service, *_ = evidence_transport
    client, db, (owner, _), credentials, live, *_ = transport
    connection, tenant, *_ = db
    query = {"query": "合成无匹配查询"}
    no_hit = client.post("/v1/search", headers=bearer(owner), json=query).json()
    assert no_hit["status"] == "no_evidence"
    assert record_gap(client, owner, no_hit["request_id"]).status_code == 403
    admit(credentials, owner, "record_gap", "read_gap_queue")
    live.remove(tenant.actor_id)
    restricted = rpc(client, owner, "tools/call", name="search", arguments=query).json()["result"]["structuredContent"]
    live.add(tenant.actor_id)
    assert restricted | {"request_id": no_hit["request_id"]} == no_hit

    def unavailable(*_):
        raise AuthorizationUnavailable("合成私有故障详情")

    with monkeypatch.context() as temporary:
        temporary.setattr(service, "check_source", unavailable)
        failed = client.post("/v1/search", headers=bearer(owner), json=query)
        assert failed.status_code == 503
    excluded = client.post("/v1/search", headers=bearer(owner), json=query | {"space_ids": [str(uuid4())]}).json()
    assert excluded["status"] == "no_evidence"
    assert record_gap(client, owner, excluded["request_id"]).status_code == 403
    gap_ids = []
    for origin in (no_hit, restricted, failed.json()):
        reply = record_gap(client, owner, origin["request_id"])
        assert reply.status_code == 200
        assert set(reply.json()) == {"request_id", "gap_id"}
        gap_ids.append(reply.json()["gap_id"])
    queue = client.get(GAPS, headers=bearer(owner))
    assert queue.status_code == 200 and queue.headers["Cache-Control"] == "no-store"
    assert queue.json()["items"] == [{"gap_id": gap_ids[0], "classification": "no_visible_match", "generation": 1}]
    facts = connection.execute("SELECT gap_ref, observation FROM thalion.gap_event").fetchall()
    assert dict(facts) == dict(zip(map(UUID, gap_ids), ("no_visible_match", "visibility_limited", "dependency_unavailable")))
    assert all(secret not in queue.text for secret in (query["query"], "合成私有故障详情", *(item["request_id"] for item in (no_hit, restricted))))


def test_scoped_empty_search_matches_later_delivery_without_inventing_a_receipt(evidence_transport, transport, monkeypatch):
    service, *_ = evidence_transport
    client, db, (owner, _), credentials, live, *_ = transport
    connection, tenant, *_ = db
    key = token_bytes(32)
    monkeypatch.setattr(service, "retest_key", key)
    admit(credentials, owner, "record_gap", "read_gap_queue")
    arguments = {"query": "合成出租车凭证", "business_date": BEFORE.isoformat()}

    def search(params=arguments):
        return client.post("/v1/search", headers=bearer(owner), json=params).json()

    empty = search()
    assert empty["status"] == "no_evidence"
    assert record_gap(client, owner, empty["request_id"]).status_code == 200
    live.remove(tenant.actor_id)
    restricted = search()
    live.add(tenant.actor_id)
    assert restricted | {"request_id": empty["request_id"]} == empty
    excluded = search(arguments | {"space_ids": [str(uuid4())]})
    assert excluded["status"] == "no_evidence"
    with monkeypatch.context() as temporary:
        temporary.setattr(service, "retest_key", None)
        no_key = search()
    assert no_key["status"] == "no_evidence"
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.feedback_search_match").fetchone() == (0,)

    version, part, _ = publish(db, "gap-taxi", "凭证", "# 凭证\n\n合成出租车凭证。\n".encode())
    approve(connection, tenant, version, BEGIN)
    result = rpc(client, owner, "tools/call", name="search", arguments=arguments).json()["result"]["structuredContent"]
    assert [item["passage_id"] for item in result["passages"]] == [str(part.passage_ref)]
    fingerprint, = connection.execute(
        "SELECT fingerprint FROM thalion.feedback_search_match WHERE request_id = %s", (result["request_id"],),
    ).fetchone()
    scope_facts = connection.execute(
        """
        SELECT request_id::text, to_jsonb(scope)->>'empty_fingerprint', to_jsonb(scope)::text
        FROM thalion.search_scope_observation AS scope
        """,
    ).fetchall()
    assert {request_id: value for request_id, value, _ in scope_facts} == {
        empty["request_id"]: "\\x" + fingerprint.hex(),
        restricted["request_id"]: None,
        no_key["request_id"]: None,
        result["request_id"]: None,
    }
    assert all(arguments["query"] not in fact and key.hex() not in fact for _, _, fact in scope_facts)
    assert fingerprint.hex() not in (str(empty) + str(result) + client.get(GAPS, headers=bearer(owner)).text)


def test_empty_fingerprint_migration_keeps_legacy_scope_facts_and_rejects_ineligible_requests(database_url):
    migrate_to_revision(database_url, "0047_feedback_correction")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "legacy-gap-fact")

        def start(operation, outcome=None):
            ref = uuid4()
            start_request(connection, RequestStart(
                tenant.org_id, ref, tenant.actor_id, None, "synthetic-ui", operation, "employee", BEFORE, 1,
                space_id=tenant.space_id,
            ))
            if outcome is not None:
                assert finish_request(connection, tenant.org_id, ref, outcome, 0)
            return ref

        origin = start("search", "no_evidence")
        connection.execute(
            "INSERT INTO thalion.search_scope_observation VALUES (%s, %s, %s, false)",
            (tenant.org_id, tenant.space_id, origin),
        )
        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert connection.execute("SELECT request_id, empty_fingerprint FROM thalion.search_scope_observation").fetchall() == [
            (origin, None),
        ]
        with pytest.raises(ObjectNotInPrerequisiteState):
            connection.execute("UPDATE thalion.search_scope_observation SET empty_fingerprint = %s", (bytes(32),))
        for ref, limited in (
            (start("search"), False),
            (start("search", "dependency_unavailable"), False),
            (start("read_passage", "no_evidence"), False),
            (start("search", "no_evidence"), True),
        ):
            with pytest.raises(CheckViolation):
                connection.execute(
                    "INSERT INTO thalion.search_scope_observation VALUES (%s, %s, %s, %s, %s)",
                    (tenant.org_id, tenant.space_id, ref, limited, bytes(32)),
                )


@pytest.fixture
def supplement_work(evidence_transport, transport, monkeypatch):
    service, *_ = evidence_transport
    monkeypatch.setattr(service, "retest_key", token_bytes(32))
    client, db, (owner, reporter), credentials, live, old, _ = transport
    connection, tenant, *_ = db
    with connection.transaction():
        expert_id, expert_ref = principal(connection, tenant.org_id, "gap-supplement-expert")
    expert = token_urlsafe(32)
    credentials[expert] = replace(credentials[reporter], employee_ref=expert_ref)
    live.add(expert_id)
    set_rules(db, *(replace(binding(employee), fields=SEARCH_FIELDS) for employee in (
        tenant.actor_id, tenant.other_actor_id, expert_id,
    )), expected=2)
    admit(credentials, owner, "read_gap_queue", "reclassify_gap", feedback.TRANSITION, feedback.QUEUE)
    admit(credentials, reporter, "record_gap", feedback.RECORD, feedback.STATUS, feedback.NOTICES)
    admit(credentials, expert, feedback.TRANSITION, feedback.QUEUE)

    def search(query="合成候补凭证", *, token=reporter, day=BEFORE):
        result = client.post("/v1/search", headers=bearer(token), json={"query": query, "business_date": day.isoformat()})
        assert result.status_code == 200
        return result.json()

    def submit(origin):
        result = client.post("/internal/feedback", headers=command_headers(reporter), json={
            "origin_request_id": origin["request_id"], "category": "missing_evidence",
        })
        assert result.status_code == 200
        return result.json()["feedback_id"]

    def transition(ref, token, generation, action, *, key=None, **arguments):
        return client.post(f"/internal/feedback/{ref}/transitions", headers=command_headers(token, key), json={
            "expected_generation": generation, "action": action, **arguments,
        })

    def assign(ref):
        assert transition(ref, owner, 1, "assign", assignee_ref=str(expert_ref)).status_code == 200

    def add_source(object_key, text):
        version, part, _ = publish(db, object_key, "新增凭证", f"# 凭证\n\n{text}。\n".encode())
        approve(connection, tenant, version, BEGIN)
        return version, part

    return client, db, owner, reporter, expert, old, search, submit, transition, assign, add_source


@pytest.mark.parametrize("kind", ["empty", "partial", "standalone"])
def test_gap_closes_only_on_the_reporters_same_search_delivering_the_exact_supplement(supplement_work, kind):
    client, _, owner, reporter, expert, old, search, submit, transition, assign, add_source = supplement_work
    query = "上海住宿限额 合成候补凭证" if kind == "partial" else "合成候补凭证"
    origin = search(query)
    assert bool(origin["passages"]) is (kind == "partial")
    if kind == "standalone":
        gap = record_gap(client, reporter, origin["request_id"])
        assert gap.status_code == 200
    ref = submit(origin)
    assign(ref)
    _, part = add_source("provided", "合成候补凭证")
    early = search(query)
    self_read = str(present(client, expert, part))
    assert transition(ref, expert, 2, "mark_corrected").status_code == 409
    for wrong in (present(client, owner, part), present(client, expert, old)):
        assert transition(ref, expert, 2, "mark_corrected", correction_request_id=str(wrong)).status_code == 409
    marked = transition(ref, expert, 2, "mark_corrected", correction_request_id=self_read)
    assert marked.status_code == 200 and marked.json()["state"] == "awaiting_retest"
    assert len(client.get(GAPS, headers=bearer(owner)).json()["items"]) == 1
    _, unrelated = add_source("unrelated", "合成无关材料")
    wrong_hit = search(query + " 与无关材料")
    assert str(part.passage_ref) in {item["passage_id"] for item in wrong_hit["passages"]}
    assert any(item["passage_id"] == str(unrelated.passage_ref) for item in search("合成无关材料")["passages"])
    for wrong in (
        early, wrong_hit, search(query, token=owner), search(query, day=BEGIN), search("合成无关材料"),
    ):
        assert transition(ref, owner, 3, "verify_correction", retest_request_id=wrong["request_id"]).status_code == 409
    same = search(query)
    assert str(part.passage_ref) in {item["passage_id"] for item in same["passages"]}
    closed = transition(ref, owner, 3, "verify_correction", retest_request_id=same["request_id"])
    assert closed.status_code == 200 and closed.json()["state"] == "closed"
    assert client.get(GAPS, headers=bearer(owner)).json()["items"] == []
    progress = client.get(f"/internal/feedback/{ref}", headers=bearer(reporter)).json()
    assert (progress["state"], progress["conclusion_code"]) == ("closed", "correction_verified")
    notices = client.get("/internal/feedback/notices", headers=bearer(reporter)).json()["items"]
    assert [(item["feedback_id"], item["state"]) for item in notices] == [(ref, "closed"), (ref, "awaiting_retest")]


def test_standalone_gap_links_one_competing_report_and_rolls_back_with_outbox(supplement_work):
    client, db, _, reporter, _, _, search, submit, *_ = supplement_work
    connection, *_ = db
    origin = search()
    gap = record_gap(client, reporter, origin["request_id"])
    assert gap.status_code == 200
    gap_ref = UUID(gap.json()["gap_id"])
    connection.execute(
        "ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_gap_link_event "
        "CHECK (event_type <> 'operations.gap.feedback_linked') NOT VALID"
    )
    failure = client.post("/internal/feedback", headers=command_headers(reporter), json={
        "origin_request_id": origin["request_id"], "category": "missing_evidence",
    })
    assert failure.status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.feedback").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_gap_link_event")
    ready = Barrier(2, timeout=5)

    def submit_report():
        ready.wait()
        return UUID(submit(origin))

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(submit_report), pool.submit(submit_report)
        submitted = {first.result(), second.result()}
    assert len(submitted) == 2
    assert connection.execute("SELECT gap_ref, feedback_id FROM thalion.gap_event").fetchall() == [(gap_ref, None)]
    reports = connection.execute(
        "SELECT current.feedback_ref FROM thalion.current_feedback AS current JOIN thalion.feedback_gap_origin USING (feedback_id)"
    ).fetchall()
    assert len(reports) == 1 and reports[0][0] in submitted
    assert connection.execute(
        "SELECT count(*) FROM thalion.outbox_event WHERE event_type = 'operations.gap.feedback_linked'"
    ).fetchone() == (1,)


@pytest.mark.parametrize("width", [390, 1280])
def test_gap_supplement_and_retest_can_be_completed_in_the_portals(portal, supplement_work, width):
    from playwright.sync_api import expect

    page, _, _, _, credentials, *_ = portal
    _, _, owner, reporter, expert, _, _, _, _, _, add_source = supplement_work
    page.set_viewport_size({"width": width, "height": 860})

    def search():
        page.get_by_label("关键词或问题").fill("合成候补凭证")
        page.get_by_label("业务日期").fill(BEFORE.isoformat())
        page.get_by_role("button", name="查找依据").click()
        expect(page.locator("#result-request code")).to_be_visible(timeout=3000)
        return page.locator("#result-request code").inner_text()

    def open_work(token):
        page.get_by_label("办理测试凭据").fill(token)
        page.get_by_role("button", name="查看待办").click()
        page.get_by_role("button", name="打开工单").click()

    load_credential(page, reporter)
    origin = search()
    page.get_by_role("button", name="反馈缺少依据").click()
    page.get_by_role("button", name="提交反馈").click()
    expect(page.get_by_text("已提交，待核对。", exact=False)).to_be_visible()
    page.goto("/manage/feedback")
    open_work(owner)
    page.get_by_label("受任员工编号").fill(str(credentials[expert].employee_ref))
    page.get_by_role("button", name="保存分派").click()
    expect(page.get_by_text("已保存分派。", exact=True)).to_be_visible()

    _, part = add_source("browser-supplement", "合成候补凭证")
    page.goto("/")
    load_credential(page, expert)
    page.get_by_text("按引用编号打开", exact=True).click()
    page.get_by_label("引用编号", exact=True).fill(str(part.passage_ref))
    page.get_by_role("button", name="打开引用").click()
    request = page.locator("#reference-content code").last
    expect(request).to_be_visible()
    supplement = request.inner_text()
    assert UUID(supplement) != part.passage_ref
    page.get_by_role("button", name="更换凭据").click()
    assert supplement not in page.locator("body").inner_text()
    page.goto("/manage/feedback")
    open_work(expert)
    field = page.get_by_label("补源取证请求编号")
    field.fill(supplement)
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, f"gap-supplement-{width}.png")
    page.get_by_role("button", name="登记补源").click()
    expect(page.get_by_text("已登记修正，等待提交人复测。", exact=True)).to_be_visible()
    expect(field).to_have_value("")
    page.get_by_role("button", name="打开工单").click()
    field.fill(supplement)
    page.get_by_role("button", name="退出办理").click()
    expect(field).to_have_value("")
    assert page.evaluate("[localStorage.length, sessionStorage.length, document.cookie]") == [0, 0, ""]

    page.goto("/")
    load_credential(page, reporter)
    retest = search()
    assert UUID(retest) != UUID(origin)
    page.get_by_role("button", name="更换凭据").click()
    assert retest not in page.locator("body").text_content()
    page.goto("/manage/feedback")
    open_work(owner)
    page.get_by_label("复测请求编号").fill(retest)
    page.get_by_role("button", name="确认复测通过").click()
    expect(page.get_by_text("已复核并关闭工单。", exact=True)).to_be_visible()
    expect(page.get_by_text("当前没有待办工单。", exact=True)).to_be_visible()


def test_supplement_withdrawal_blocks_closure_and_failed_event_rolls_back(supplement_work):
    client, db, owner, _, expert, _, search, submit, transition, assign, add_source = supplement_work
    connection, tenant, *_ = db
    ref = submit(search())
    assign(ref)
    version, part = add_source("withdrawable", "合成候补凭证")
    read = str(present(client, expert, part))
    connection.execute(
        "ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_supplement_event "
        "CHECK (event_type <> 'operations.feedback.transitioned') NOT VALID"
    )
    assert transition(ref, expert, 2, "mark_corrected", correction_request_id=read).status_code == 503
    assert connection.execute("SELECT state FROM thalion.current_feedback").fetchone() == ("pending",)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_supplement_event")
    assert transition(ref, expert, 2, "mark_corrected", correction_request_id=read).status_code == 200
    retest = search()
    assert retest["status"] == "hits"
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", str(uuid4())), tenant.space_id,
        version.version_ref, "withdrawn", uuid4(),
    )
    assert transition(ref, owner, 3, "verify_correction", retest_request_id=retest["request_id"]).status_code == 409
    assert len(client.get(GAPS, headers=bearer(owner)).json()["items"]) == 1


def test_gap_reclassification_and_closure_are_mutually_exclusive(supplement_work):
    client, db, owner, _, expert, _, search, submit, transition, assign, add_source = supplement_work
    connection, *_ = db
    ref = submit(search())
    assign(ref)
    _, part = add_source("competing", "合成候补凭证")
    read = str(present(client, expert, part))
    assert transition(ref, expert, 2, "mark_corrected", correction_request_id=read).status_code == 200
    gap = client.get(GAPS, headers=bearer(owner)).json()["items"][0]
    retest = search()
    ready = Barrier(2, timeout=5)

    def reclassify():
        ready.wait()
        return client.post(f"{GAPS}/{gap['gap_id']}/reclassify", headers=command_headers(owner), json={
            "expected_generation": gap["generation"], "classification": "conditions_missing",
        }).status_code

    def close():
        ready.wait()
        return transition(ref, owner, 3, "verify_correction", retest_request_id=retest["request_id"]).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        reviewed, verified = pool.submit(reclassify), pool.submit(close)
        assert sorted([reviewed.result(), verified.result()]) == [200, 409]
    if reviewed.result() == 200:
        assert connection.execute("SELECT state FROM thalion.current_feedback").fetchone() == ("awaiting_retest",)
    else:
        assert connection.execute("SELECT state FROM thalion.current_feedback").fetchone() == ("closed",)
    assert client.get(GAPS, headers=bearer(owner)).json()["items"] == []


def test_gap_report_links_partial_search_once_with_no_employee_text(transport):
    client, db, (owner, employee), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    admit(credentials, owner, "record_gap", "read_gap_queue")
    admit(credentials, employee, "record_gap")
    origin = client.post("/v1/search", headers=bearer(owner), json={"query": "上海住宿限额"}).json()
    assert origin["status"] == "hits"
    assert record_gap(client, employee, origin["request_id"]).status_code == 403
    assert record_gap(client, owner, origin["request_id"]).status_code == 403
    assert record_gap(client, owner, present(client, owner, first)).status_code == 403
    report = feedback.FeedbackSpec(UUID(origin["request_id"]), "missing_evidence", note="合成反馈内部备注")
    for _ in range(2):
        call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
        feedback.record_feedback(connection, call, report)
    queue = client.get(GAPS, headers=bearer(owner))
    assert queue.status_code == 200
    assert len(queue.json()["items"]) == 1 and queue.json()["items"][0]["classification"] == "reported_missing"
    assert "合成反馈内部备注" not in queue.text and origin["request_id"] not in queue.text
    event, = connection.execute("SELECT to_jsonb(gap)::text FROM thalion.gap_event AS gap").fetchall()
    assert "合成反馈内部备注" not in event[0] and "上海住宿限额" not in event[0]


def test_gap_report_with_authorized_hits_but_incomplete_scope_stays_out_of_queue(transport):
    client, db, (owner, employee), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    admit(credentials, employee, "record_feedback")
    admit(credentials, owner, "read_gap_queue")
    origin = client.post("/v1/search", headers=bearer(employee), json={"query": "上海住宿"}).json()
    assert [item["passage_id"] for item in origin["passages"]] == [str(first.passage_ref)]
    report = client.post("/internal/feedback", headers=command_headers(employee), json={
        "origin_request_id": origin["request_id"], "category": "missing_evidence",
    })
    assert report.status_code == 200
    assert client.get(GAPS, headers=bearer(owner)).json()["items"] == []
    assert connection.execute(
        "SELECT observation FROM thalion.gap_event WHERE org_id = %s", (tenant.org_id,),
    ).fetchall() == [("visibility_limited",)]


def test_legacy_scoped_search_without_scope_fact_is_not_a_candidate(transport):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, tenant, *_ = db
    admit(credentials, owner, "record_gap", "read_gap_queue")
    origin = uuid4()
    business_date, revision = connection.execute(
        "SELECT current_date, config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,),
    ).fetchone()
    start_request(connection, RequestStart(
        tenant.org_id, origin, tenant.actor_id, None, "synthetic-ui", "search", "employee", business_date, revision,
        space_id=tenant.space_id,
    ))
    assert finish_request(connection, tenant.org_id, origin, "no_evidence", 0)
    assert record_gap(client, owner, origin).status_code == 200
    assert client.get(GAPS, headers=bearer(owner)).json()["items"] == []
    assert connection.execute("SELECT observation FROM thalion.gap_event").fetchall() == [("scope_unverified",)]


def test_owner_review_withdraws_candidate_and_preserves_original_fact(transport):
    client, db, (owner, employee), credentials, _, *_ = transport
    connection, tenant, *_ = db
    for token in (owner, employee):
        admit(credentials, token, "record_gap", "read_gap_queue", "reclassify_gap")
    origin = client.post("/v1/search", headers=bearer(owner), json={"query": "合成无权威结论"}).json()["request_id"]
    stable_key = str(uuid4())
    first = record_gap(client, owner, origin, stable_key)
    assert first.status_code == 200
    ref = first.json()["gap_id"]
    assert record_gap(client, owner, origin).json()["gap_id"] == ref
    assert record_gap(client, owner, origin, stable_key).json()["gap_id"] == ref
    assert client.get(GAPS, headers=bearer(employee)).status_code == 403
    path = f"{GAPS}/{ref}/reclassify"
    body = {"expected_generation": 1, "classification": "permission_review"}
    assert client.post(path, headers=command_headers(employee), json=body).status_code == 403
    assert client.post(path, headers=command_headers(owner), json=body | {"classification": "no_source"}).status_code == 400
    assert client.post(path, headers=command_headers(owner), json=body | {"expected_generation": 2}).status_code == 409
    headers = command_headers(owner)
    changed = client.post(path, headers=headers, json=body)
    assert changed.status_code == 200
    assert changed.json()["generation"] == 2 and changed.json()["classification"] == "permission_review"
    assert client.post(path, headers=headers, json=body).status_code == 200
    assert client.post(path, headers=command_headers(owner), json=body).status_code == 409
    assert client.get(GAPS, headers=bearer(owner)).json()["items"] == []
    assert connection.execute("SELECT observation FROM thalion.gap_event").fetchall() == [("no_visible_match",)]
    assert connection.execute(
        "SELECT actor_id, generation, classification FROM thalion.gap_review",
    ).fetchall() == [(tenant.actor_id, 2, "permission_review")]


def test_owner_cannot_rebind_gap_to_another_space(transport):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, tenant, *_ = db
    admit(credentials, owner, "record_gap", "read_gap_queue", "reclassify_gap")
    origin = client.post("/v1/search", headers=bearer(owner), json={"query": "合成无结果"}).json()["request_id"]
    ref = record_gap(client, owner, origin).json()["gap_id"]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[owner] = replace(credentials[owner], space_ref=other_space)
    assert record_gap(client, owner, origin).status_code == 403
    assert client.get(GAPS, headers=bearer(owner)).json()["items"] == []
    assert client.post(f"{GAPS}/{ref}/reclassify", headers=command_headers(owner), json={
        "expected_generation": 1, "classification": "conditions_missing",
    }).status_code == 403
    assert connection.execute("SELECT generation FROM thalion.current_gap").fetchall() == [(1,)]


@pytest.mark.parametrize("query", ["合成无结果", "上海住宿"])
def test_failed_scope_seal_cannot_release_search_or_commit_receipt(transport, query):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, *_ = db
    admit(credentials, owner, "record_gap", "read_gap_queue")
    connection.execute(
        "ALTER TABLE thalion.search_scope_observation ADD CONSTRAINT test_scope_seal CHECK (false) NOT VALID"
    )
    failed = client.post("/v1/search", headers=bearer(owner), json={"query": query})
    assert failed.status_code == 503
    origin = failed.json()["request_id"]
    assert connection.execute(
        "SELECT outcome FROM thalion.request_record WHERE request_id = %s", (origin,),
    ).fetchone() == ("dependency_unavailable",)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)
    assert record_gap(client, owner, origin).status_code == 200
    assert client.get(GAPS, headers=bearer(owner)).json()["items"] == []


def test_gap_record_and_review_rollback_with_outbox(transport):
    client, db, (owner, _), credentials, _, *_ = transport
    connection, tenant, *_ = db
    admit(credentials, owner, "record_gap", "reclassify_gap", "read_gap_queue")
    origin = client.post("/v1/search", headers=bearer(owner), json={"query": "合成缺口"}).json()["request_id"]
    connection.execute(
        "ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_gap_event "
        "CHECK (event_type NOT IN ('operations.gap.recorded', 'operations.gap.reclassified')) NOT VALID"
    )
    assert record_gap(client, owner, origin).status_code == 503
    with pytest.raises(CheckViolation):
        call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
        feedback.record_feedback(connection, call, feedback.FeedbackSpec(UUID(origin), "missing_evidence"))
    assert connection.execute("SELECT count(*) FROM thalion.gap_event").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.feedback").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_gap_event")
    ref = record_gap(client, owner, origin).json()["gap_id"]
    connection.execute(
        "ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_gap_review "
        "CHECK (event_type <> 'operations.gap.reclassified') NOT VALID"
    )
    arguments = {"expected_generation": 1, "classification": "conditions_missing"}
    path = f"{GAPS}/{ref}/reclassify"
    assert client.post(path, json=arguments, headers=command_headers(owner)).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.gap_review").fetchone() == (0,)
    assert [item["gap_id"] for item in client.get(GAPS, headers=bearer(owner)).json()["items"]] == [ref]
