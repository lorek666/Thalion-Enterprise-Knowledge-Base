from dataclasses import replace
from uuid import UUID, uuid4

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.operations import feedback

from test_employee_portal import browser, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback import open_feedback, present
from test_persisted_access import binding, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import SEARCH_FIELDS, corpus
from test_wiki_inputs import assemble
from test_wiki_publication import authorize, configure
from test_wiki_search import reviewed


QUEUE_PATH = "/internal/feedback"
QUEUE_CAPABILITY = "read_feedback_queue"
EVIDENCE_CAPABILITY = "read_feedback_evidence"
QUARANTINE_CAPABILITY = "quarantine_feedback_evidence"


def admit(credentials, token, *operations):
    credential = credentials[token]
    credentials[token] = replace(credential, operations=credential.operations | set(operations))


def submit(connection, tenant, origin, passage, note=None):
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    spec = feedback.FeedbackSpec(origin, "incorrect_evidence", passage.passage_ref, note)
    return feedback.record_feedback(connection, call, spec)


def assign(connection, tenant, ref, expected=1, assignee=None):
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.TRANSITION)
    return feedback.transition_feedback(
        connection, call, ref, expected, "assign", assignee_id=assignee or tenant.other_actor_id,
    )


def test_owner_queue_pages_over_one_space_and_assignee_sees_only_current_work(transport):
    client, db, (owner, employee), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    origin = present(client, owner, first)
    reports = sorted(submit(connection, tenant, origin, first, "合成保密反馈") for _ in range(21))
    assign(connection, tenant, reports[0])
    assert client.get(QUEUE_PATH).status_code == 401
    assert client.get(QUEUE_PATH, headers=bearer(owner)).status_code == 403
    for token in (owner, employee):
        admit(credentials, token, QUEUE_CAPABILITY)
    first_page = client.get(QUEUE_PATH, headers=bearer(owner))
    assert first_page.status_code == 200 and first_page.headers["Cache-Control"] == "no-store"
    payload = first_page.json()
    assert payload["role"] == "owner"
    assert [item["feedback_id"] for item in payload["items"]] == list(map(str, reports[:20]))
    assert payload["items"][0] == {
        "feedback_id": str(reports[0]), "state": "pending", "generation": 2,
        "category": "incorrect_evidence", "assigned": True, "has_citation": True,
    }
    next_page = client.get(QUEUE_PATH, headers=bearer(owner), params={"after": payload["next_cursor"]}).json()
    assert [item["feedback_id"] for item in next_page["items"]] == [str(reports[-1])]
    assert next_page["next_cursor"] is None
    assigned = client.get(QUEUE_PATH, headers=bearer(employee)).json()
    assert (assigned["role"], assigned["next_cursor"], assigned["items"]) == ("assignee", None, [payload["items"][0]])
    assert all(secret not in first_page.text for secret in (str(origin), str(first.passage_ref), "合成保密反馈"))
    assert client.get(QUEUE_PATH, headers=bearer(owner), params={"space_id": str(uuid4())}).status_code == 400
    discovered = rpc(client, owner, "tools/list").json()["result"]["tools"]
    assert {tool["name"] for tool in discovered} == {"search", "read_passage"}


def test_feedback_evidence_needs_both_current_assignment_and_current_passage_access(transport):
    client, db, (owner, employee), credentials, live, _, second = transport
    connection, tenant, *_ = db
    origin = present(client, owner, second)
    ref = submit(connection, tenant, origin, second, "说明不可返回给处理人")
    route = f"{QUEUE_PATH}/{ref}/evidence"
    assert client.get(route, headers=bearer(employee)).status_code == 403
    admit(credentials, employee, EVIDENCE_CAPABILITY)
    assert client.get(route, headers=bearer(employee)).status_code == 404
    assign(connection, tenant, ref)
    assert client.get(route, headers=bearer(employee)).status_code == 404
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
              replace(binding(tenant.other_actor_id, passage_ref=second.passage_ref), fields=SEARCH_FIELDS), expected=2)
    reply = client.get(route, headers=bearer(employee))
    assert reply.status_code == 200 and reply.headers["Cache-Control"] == "no-store"
    read = reply.json()
    assert set(read) == {"request_id", "passage"}
    assert read["passage"]["passage_id"] == str(second.passage_ref)
    assert read["passage"]["excerpt_revision"] == second.revision
    assert "说明不可返回" not in reply.text and str(origin) not in reply.text
    assert connection.execute(
        """
        SELECT work.generation, request.principal_id, request.operation, request.outcome
        FROM thalion.feedback_evidence_read AS work JOIN thalion.request_record AS request USING (org_id, request_id)
        WHERE work.request_id = %s
        """, (UUID(read["request_id"]),),
    ).fetchone() == (2, tenant.other_actor_id, "read_passage", "succeeded")
    live.remove(tenant.other_actor_id)
    revoked = client.get(route, headers=bearer(employee))
    assert revoked.status_code == 404 and "passage" not in revoked.json()
    unknown = client.get(f"{QUEUE_PATH}/{uuid4()}/evidence", headers=bearer(employee))
    assert revoked.json()["error"] == unknown.json()["error"]


def test_feedback_evidence_refuses_different_revision_and_authority_outage(evidence_transport, transport, monkeypatch):
    from enterprise_kb.modules.evidence import processing
    from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

    from test_evidence import claim, review

    service, *_ = evidence_transport
    client, db, (owner, employee), credentials, _, first, _ = transport
    connection, tenant, _, _, store = db
    origin = present(client, owner, first)
    ref = submit(connection, tenant, origin, first)
    assign(connection, tenant, ref)
    admit(credentials, employee, EVIDENCE_CAPABILITY)
    route = f"{QUEUE_PATH}/{ref}/evidence"
    with monkeypatch.context() as temporary:
        def unavailable(*_):
            raise AuthorizationUnavailable("合成依赖故障详情")

        temporary.setattr(service, "check_source", unavailable)
        failed = client.get(route, headers=bearer(employee))
        assert failed.status_code == 503 and "合成依赖故障详情" not in failed.text
    target, digest = connection.execute(
        """
        SELECT job.target_ref, job.input_digest FROM thalion.job AS job
        JOIN thalion.passage_excerpt AS excerpt ON excerpt.run_ref = job.result_ref
        JOIN thalion.object_identity AS location ON location.object_id = excerpt.passage_id
        WHERE location.object_type = 'passage' AND location.public_id = %s
        """, (first.passage_ref,),
    ).fetchone()
    connection.execute(
        """
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
        """,
    )
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, target, "parse", digest, 2))
    run = processing.process_markdown_job(connection, claim(db), store)
    review(db, run)
    assert client.get(route, headers=bearer(employee)).status_code == 404
    current = client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(employee))
    assert current.status_code == 200 and current.json()["passage"]["excerpt_revision"] == 2


def test_reassignment_at_final_feedback_evidence_check_drops_reply_and_receipt(evidence_transport, transport, monkeypatch):
    service, *_ = evidence_transport
    client, db, (owner, employee), credentials, _, first, _ = transport
    connection, tenant, database_url, *_ = db
    origin = present(client, owner, first)
    ref = submit(connection, tenant, origin, first)
    assign(connection, tenant, ref)
    admit(credentials, employee, EVIDENCE_CAPABILITY, QUEUE_CAPABILITY)
    with connection.transaction():
        successor = connection.execute(
            """
            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
            VALUES (%s, 'employee', 'https://synthetic.invalid', %s) RETURNING principal_id
            """, (tenant.org_id, str(uuid4())),
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO thalion.object_identity (object_type, object_id, org_id) VALUES ('principal', %s, %s)",
            (successor, tenant.org_id),
        )
    existing = service.check_source

    def transfer(credential, probe):
        with open_database(database_url) as concurrent:
            assign(concurrent, tenant, ref, 2, successor)
        return existing(credential, probe)

    monkeypatch.setattr(service, "check_source", transfer)
    reply = client.get(f"{QUEUE_PATH}/{ref}/evidence", headers=bearer(employee))
    assert reply.status_code == 404 and "passage" not in reply.json()
    request_id = UUID(reply.json()["request_id"])
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record WHERE request_id = %s", (request_id,)).fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.feedback_evidence_read WHERE request_id = %s", (request_id,)).fetchone() == (0,)
    assert client.get(QUEUE_PATH, headers=bearer(employee)).json()["items"] == []


def test_feedback_management_assigns_then_assignee_checks_and_explains(portal):
    from playwright.sync_api import expect

    page, base, db, (owner, employee), credentials, _, first, _ = portal
    connection, tenant, *_ = db
    initial = page.request.get(f"{base}/v1/passages/{first.passage_ref}", headers=bearer(owner))
    assert initial.ok
    ref = submit(connection, tenant, UUID(initial.json()["request_id"]), first, "不可随队列显示的说明")
    for token in (owner, employee):
        admit(credentials, token, QUEUE_CAPABILITY, EVIDENCE_CAPABILITY, feedback.TRANSITION)
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto("/manage/feedback")

    def enter(token):
        page.get_by_label("办理测试凭据").fill(token)
        page.get_by_label("办理测试凭据").press("Enter")
        expect(page.get_by_text(str(ref), exact=True)).to_be_visible()
        assert "不可随队列显示" not in page.locator("body").inner_text()

    enter(owner)
    page.get_by_role("button", name="打开工单").click()
    page.get_by_label("受任员工编号").fill(str(credentials[employee].employee_ref))
    page.get_by_role("button", name="保存分派").click()
    expect(page.get_by_text("已保存分派。", exact=True)).to_be_visible()
    page.get_by_role("button", name="退出办理").click()
    expect(page.get_by_label("办理测试凭据")).to_have_value("")
    enter(employee)
    page.get_by_role("button", name="打开工单").click()
    explain = page.get_by_role("button", name="记录已有依据")
    expect(explain).to_be_disabled()
    page.get_by_role("button", name="以本人权限核对原文").click()
    expect(page.get_by_text("上海住宿限额。", exact=True)).to_be_visible()
    expect(explain).to_be_disabled()
    page.get_by_label("发给提交人的处理结论").select_option("source_text_confirmed")
    expect(explain).to_be_enabled()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, "feedback-work-mobile.png")
    explain.click()
    expect(page.get_by_text("已记录解释决定。", exact=True)).to_be_visible()
    expect(page.get_by_text("当前没有待办工单。", exact=True)).to_be_visible()
    assert "上海住宿限额。" not in page.locator("body").inner_text()
    page.get_by_role("button", name="退出办理").click()
    assert str(ref) not in page.locator("body").inner_text()
    assert page.evaluate("[localStorage.length, sessionStorage.length, document.cookie]") == [0, 0, ""]


def test_confirmed_feedback_quarantines_the_exact_batch_and_stops_dependent_wiki(transport):
    client, db, (owner, employee), credentials, _, first, second = transport
    connection, tenant, *_ = db
    configure(db, 2)
    origin = present(client, owner, second)
    sealed = assemble(db, (first, second))
    published = authorize(db, *reviewed((db, sealed, first, second)))
    assert published.status == "succeeded"
    ref = submit(connection, tenant, origin, second)
    route = f"{QUEUE_PATH}/{ref}/quarantine"
    evidence_route = f"{QUEUE_PATH}/{ref}/evidence"
    owner_headers = bearer(owner) | {"Idempotency-Key": str(uuid4())}
    parameters = {"expected_generation": 1, "basis_request_id": str(origin)}
    assert client.post(route, headers=owner_headers, json=parameters).status_code == 403
    admit(credentials, owner, EVIDENCE_CAPABILITY, QUARANTINE_CAPABILITY)
    admit(credentials, employee, QUARANTINE_CAPABILITY)
    assert client.post(route, headers=bearer(employee) | {"Idempotency-Key": str(uuid4())}, json=parameters).status_code == 403
    assert client.post(route, headers=owner_headers, json=parameters).status_code == 409
    basis_response = client.get(evidence_route, headers=bearer(owner))
    assert basis_response.status_code == 200
    basis = basis_response.json()["request_id"]
    params = {"expected_generation": 1, "basis_request_id": basis}
    assert client.post(route, headers=owner_headers, json=params | {"expected_generation": 2}).status_code == 409
    connection.execute("ALTER TABLE thalion.wiki_availability_event ADD CONSTRAINT test_failed_stop CHECK (false)")
    assert client.post(route, headers=owner_headers, json=params).status_code == 503
    assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner)).status_code == 200
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision WHERE outcome = 'quarantined'").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.wiki_availability_event DROP CONSTRAINT test_failed_stop")
    action = client.post(route, headers=owner_headers, json=params)
    assert action.status_code == 200
    assert set(action.json()) == {"request_id", "decision_id"}
    decision_id = UUID(action.json()["decision_id"])
    assert connection.execute(
        "SELECT basis_ref, outcome FROM thalion.quality_decision WHERE decision_ref = %s", (decision_id,),
    ).fetchone() == (UUID(basis), "quarantined")
    assert connection.execute(
        "SELECT cause_ref, reason FROM thalion.wiki_availability_event WHERE publication_ref = %s", (published.ref,),
    ).fetchall() == [(decision_id, "quarantined")]
    replay = client.post(route, headers=owner_headers, json=params)
    assert replay.status_code == 200 and replay.json()["decision_id"] == str(decision_id)
    assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner)).status_code == 404
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).status_code == 200
    assert connection.execute("SELECT state, generation FROM thalion.current_feedback").fetchall() == [("pending", 1)]


def test_queue_and_evidence_do_not_follow_employee_to_other_space(transport):
    client, db, (owner, _), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    original = present(client, owner, first)
    ref = submit(connection, tenant, original, first)
    with connection.transaction():
        other_space = connection.execute(
            """
            INSERT INTO thalion.space (org_id, name, classification, owner_principal_id)
            VALUES (%s, 'Another local space', 'internal', %s) RETURNING space_id
            """, (tenant.org_id, tenant.actor_id),
        ).fetchone()[0]
        other_ref = connection.execute(
            """
            INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id)
            VALUES (%s, %s, 'space', %s) RETURNING public_id
            """, (tenant.org_id, other_space, other_space),
        ).fetchone()[0]
    admit(credentials, owner, QUEUE_CAPABILITY, EVIDENCE_CAPABILITY)
    credentials[owner] = replace(credentials[owner], space_ref=other_ref)
    assert client.get(QUEUE_PATH, headers=bearer(owner)).json()["items"] == []
    assert client.get(f"{QUEUE_PATH}/{ref}/evidence", headers=bearer(owner)).status_code == 404


def test_owner_and_work_receipt_do_not_replace_source_quality_role(transport):
    client, db, (owner, employee), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    original = present(client, owner, first)
    ref = submit(connection, tenant, original, first)
    connection.execute(
        "UPDATE thalion.space SET owner_principal_id = %s WHERE space_id = %s", (tenant.other_actor_id, tenant.space_id),
    )
    admit(credentials, employee, EVIDENCE_CAPABILITY, QUARANTINE_CAPABILITY)
    evidence_reply = client.get(f"{QUEUE_PATH}/{ref}/evidence", headers=bearer(employee))
    assert evidence_reply.status_code == 200
    denied = client.post(f"{QUEUE_PATH}/{ref}/quarantine", headers=bearer(employee) | {"Idempotency-Key": str(uuid4())}, json={
        "expected_generation": 1, "basis_request_id": evidence_reply.json()["request_id"],
    })
    assert denied.status_code == 403
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(employee)).status_code == 200


def test_feedback_management_warns_about_batch_isolation_and_clears_evidence(portal):
    from playwright.sync_api import expect

    page, base, db, (owner, _), credentials, _, first, _ = portal
    connection, tenant, *_ = db
    original = page.request.get(f"{base}/v1/passages/{first.passage_ref}", headers=bearer(owner))
    assert original.ok
    ref = submit(connection, tenant, UUID(original.json()["request_id"]), first)
    admit(credentials, owner, QUEUE_CAPABILITY, EVIDENCE_CAPABILITY, QUARANTINE_CAPABILITY)
    page.goto("/manage/feedback")
    page.get_by_label("办理测试凭据").fill(owner)
    page.get_by_role("button", name="查看待办").click()
    expect(page.get_by_text(str(ref), exact=True)).to_be_visible()
    page.get_by_role("button", name="打开工单").click()
    expect(page.get_by_role("button", name="隔离此转录批次")).to_be_hidden()
    page.get_by_role("button", name="以本人权限核对原文").click()
    expect(page.get_by_text("隔离针对整个转录批次，依赖该批次的 Wiki 会停用；不删除原件。", exact=True)).to_be_visible()
    page.get_by_role("button", name="隔离此转录批次").click()
    expect(page.get_by_text("已隔离转录批次。工单仍待处理。", exact=True)).to_be_visible()
    assert "上海住宿限额。" not in page.locator("body").inner_text()
    assert page.request.get(f"{base}/v1/passages/{first.passage_ref}", headers=bearer(owner)).status == 404
