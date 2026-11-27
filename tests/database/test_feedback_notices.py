from dataclasses import replace
from uuid import UUID, uuid4

from enterprise_kb.modules.operations import feedback

from test_employee_portal import browser, load_credential, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback import open_feedback, present
from test_feedback_work import QUEUE_PATH, admit, assign, submit
from test_runtime import runtime_db
from test_travel_search import corpus


NOTICES_PATH = f"{QUEUE_PATH}/notices"
NOTICE_CAPABILITY = "read_feedback_notices"


def mark_corrected(connection, tenant, ref):
    assign(connection, tenant, ref)
    call = open_feedback(connection, tenant, tenant.other_actor_id, feedback.TRANSITION)
    return feedback.transition_feedback(connection, call, ref, 2, "mark_corrected")


def test_explanation_persists_controlled_conclusion_without_exposing_source_or_notes(transport):
    client, db, (owner, handler), credentials, live, first, _ = transport
    connection, tenant, *_ = db
    origin = present(client, owner, first)
    ref = submit(connection, tenant, origin, first, "本机合成保密备注")
    assign(connection, tenant, ref)
    basis = present(client, handler, first)
    admit(credentials, handler, feedback.TRANSITION, feedback.STATUS)
    admit(credentials, owner, feedback.STATUS)
    path = f"{QUEUE_PATH}/{ref}"
    headers = bearer(handler) | {"Idempotency-Key": str(uuid4())}
    arguments = {"expected_generation": 2, "action": "explain", "basis_request_id": str(basis),
                 "conclusion_code": "applicability_confirmed"}
    assert client.post(f"{path}/transitions", headers=headers, json=arguments | {"note": "任意文本"}).status_code == 400
    assert client.post(f"{path}/transitions", headers=headers, json=arguments | {"conclusion_code": []}).status_code == 400
    assert client.post(f"{path}/transitions", headers=headers, json=arguments | {
        "action": "mark_corrected", "basis_request_id": str(basis),
    }).status_code == 400
    assert client.post(f"{path}/transitions", headers=headers, json=arguments).status_code == 200
    assert client.post(f"{path}/transitions", headers=headers, json=arguments).status_code == 200
    assert client.post(f"{path}/transitions", headers=headers, json=arguments | {
        "conclusion_code": "source_text_confirmed",
    }).status_code == 409
    assert client.get(path, headers=bearer(handler)).status_code == 403
    live.discard(tenant.actor_id)
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).status_code == 404
    reply = client.get(path, headers=bearer(owner))
    assert reply.status_code == 200 and reply.headers["Cache-Control"] == "no-store"
    assert reply.json() == {"request_id": reply.json()["request_id"], "feedback_id": str(ref), "state": "explained",
                            "generation": 3, "conclusion_code": "applicability_confirmed"}
    assert all(value not in reply.text for value in (str(origin), str(basis), str(first.passage_ref), "合成保密"))
    assert connection.execute(
        "SELECT count(*) FROM thalion.feedback_decision WHERE action = 'explain'",
    ).fetchone() == (1,)


def test_notices_only_page_own_committed_outcomes_and_reject_foreign_cursor(transport):
    client, db, (owner, handler), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    assert client.get(NOTICES_PATH).status_code == 401
    assert client.get(NOTICES_PATH, headers=bearer(owner)).status_code == 403
    for token in (owner, handler):
        admit(credentials, token, NOTICE_CAPABILITY)
    handler_call = open_feedback(connection, tenant, tenant.other_actor_id, feedback.RECORD)
    handler_report = feedback.record_feedback(connection, handler_call, feedback.FeedbackSpec(
        present(client, handler, first), "incorrect_evidence", first.passage_ref,
    ))
    mark_corrected(connection, tenant, handler_report)
    origin = present(client, owner, first)
    reports = [submit(connection, tenant, origin, first, "通知不得包含合成备注") for _ in range(21)]
    connection.execute("""
        ALTER TABLE thalion.feedback_decision ALTER COLUMN recorded_at SET DEFAULT TIMESTAMPTZ '2026-11-20 12:00:00+00'
    """)
    for ref in reports[:-1]:
        mark_corrected(connection, tenant, ref)
    connection.execute("""
        ALTER TABLE thalion.feedback_decision ALTER COLUMN recorded_at SET DEFAULT TIMESTAMPTZ '2026-11-20 11:59:59+00'
    """)
    mark_corrected(connection, tenant, reports[-1])
    pending = submit(connection, tenant, origin, first)
    assign(connection, tenant, pending)
    decisions = connection.execute("""
        SELECT decision.recorded_at, decision.decision_ref, identity.public_id
        FROM thalion.feedback_decision AS decision
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (decision.org_id, decision.space_id, 'feedback', decision.feedback_id)
        WHERE identity.public_id = ANY(%s) AND decision.action = 'mark_corrected'
    """, (reports,)).fetchall()
    assert {report for _, _, report in decisions} == set(reports)
    expected = [(str(notice), str(report)) for _, notice, report in sorted(decisions, reverse=True)]
    assert [item["feedback_id"] for item in client.get(NOTICES_PATH, headers=bearer(handler)).json()["items"]] == [
        str(handler_report),
    ]
    response = client.get(NOTICES_PATH, headers=bearer(owner))
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    page = response.json()
    assert set(page) == {"request_id", "items", "next_cursor"}
    assert [(item["notice_id"], item["feedback_id"]) for item in page["items"]] == expected[:20]
    assert all(set(item) == {"notice_id", "feedback_id", "state"} for item in page["items"])
    assert {item["state"] for item in page["items"]} == {"awaiting_retest"}
    assert all(secret not in response.text for secret in (str(origin), str(first.passage_ref), str(pending), "合成备注"))
    assert page["next_cursor"] == page["items"][-1]["notice_id"]
    params = {"after": page["next_cursor"]}
    last = client.get(NOTICES_PATH, params=params, headers=bearer(owner)).json()
    assert [(item["notice_id"], item["feedback_id"]) for item in last["items"]] == expected[20:]
    assert last["next_cursor"] is None
    assert client.get(NOTICES_PATH, params=params, headers=bearer(handler)).json()["items"] == []
    assert client.get(NOTICES_PATH, params={"space_id": str(tenant.space_ref)}, headers=bearer(owner)).status_code == 400
    with connection.transaction():
        space_id = connection.execute(
            """
            INSERT INTO thalion.space (org_id, name, classification, owner_principal_id)
            VALUES (%s, 'Another notice scope', 'internal', %s) RETURNING space_id
            """, (tenant.org_id, tenant.actor_id),
        ).fetchone()[0]
        space_ref = connection.execute(
            """
            INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id)
            VALUES (%s, %s, 'space', %s) RETURNING public_id
            """, (tenant.org_id, space_id, space_id),
        ).fetchone()[0]
    credentials[owner] = replace(credentials[owner], space_ref=space_ref)
    assert client.get(NOTICES_PATH, headers=bearer(owner)).json()["items"] == []


def test_notices_are_not_visible_if_the_decision_rolls_back_or_credential_is_revoked(evidence_transport, transport, monkeypatch):
    service, *_ = evidence_transport
    client, db, (owner, handler), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    admit(credentials, owner, NOTICE_CAPABILITY)
    admit(credentials, handler, feedback.TRANSITION)
    ref = submit(connection, tenant, present(client, owner, first), first)
    assign(connection, tenant, ref)
    arguments = {"expected_generation": 2, "action": "mark_corrected"}
    headers = bearer(handler) | {"Idempotency-Key": str(uuid4())}
    connection.execute(
        "ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_rollback_notice "
        "CHECK (event_type <> 'operations.feedback.transitioned') NOT VALID"
    )
    path = f"{QUEUE_PATH}/{ref}/transitions"
    assert client.post(path, headers=headers, json=arguments).status_code == 503
    assert client.get(NOTICES_PATH, headers=bearer(owner)).json()["items"] == []
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_rollback_notice")
    assert client.post(path, headers=headers, json=arguments).status_code == 200
    read = feedback.list_feedback_notices

    def read_then_revoke(*args):
        result = read(*args)
        credentials[owner] = replace(credentials[owner], operations=credentials[owner].operations - {NOTICE_CAPABILITY})
        return result

    with monkeypatch.context() as temporary:
        temporary.setattr(feedback, "list_feedback_notices", read_then_revoke)
        response = client.get(NOTICES_PATH, headers=bearer(owner))
    assert response.status_code == 401 and str(ref) not in response.text
    assert service.verify_token(owner) == credentials[owner]
    assert client.get(NOTICES_PATH, headers=bearer(owner)).status_code == 403


def test_reporter_reviews_notice_and_identity_switch_clears_result(portal):
    from playwright.sync_api import expect

    page, base, db, (owner, handler), credentials, _, first, _ = portal
    connection, tenant, *_ = db
    admit(credentials, owner, NOTICE_CAPABILITY, feedback.STATUS)
    origin = page.request.get(f"{base}/v1/passages/{first.passage_ref}", headers=bearer(owner)).json()
    ref = submit(connection, tenant, UUID(origin["request_id"]), first, "通知不显示的说明")
    mark_corrected(connection, tenant, ref)
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, owner)
    show = page.get_by_role("button", name="查看我的通知")
    expect(show).to_be_visible(timeout=1800)
    show.click()
    notice = page.get_by_role("region", name="反馈通知")
    expect(notice.get_by_text("已登记修正，等待你复测。", exact=True)).to_be_visible()
    notice.get_by_role("button", name="查看处理进度").click()
    expect(page.get_by_label("反馈编号")).to_have_value(str(ref))
    expect(page.get_by_text("处理结论：已登记修正，请按原条件重新取证。", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    assert "通知不显示的说明" not in page.locator("body").inner_text()
    screenshot(page, "feedback-notices-mobile.png")
    page.evaluate("""() => {
        const fetchReal = window.fetch;
        window.fetch = async (url, options) => {
            if (url !== "/internal/feedback/notices") return fetchReal(url, options);
            window.fetch = fetchReal;
            const response = await fetchReal(url, {...options, signal: undefined});
            await new Promise(resolve => {
                window.releaseOldTestNotice = resolve;
                document.body.dataset.oldNoticeReady = "true";
            });
            return response;
        };
    }""")
    show.click()
    expect(page.locator("body")).to_have_attribute("data-old-notice-ready", "true")
    page.get_by_role("button", name="更换凭据").click()
    load_credential(page, handler)
    page.evaluate("""async () => {
        window.releaseOldTestNotice();
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    }""")
    expect(page.get_by_label("反馈编号")).to_have_value("")
    expect(notice.get_by_text("已登记修正，等待你复测。", exact=True)).to_have_count(0)
    page.get_by_role("button", name="查看我的通知").click()
    expect(notice.get_by_text("当前凭据无法查看反馈通知。", exact=True)).to_be_visible()
