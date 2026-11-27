from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from enterprise_kb.runtime.commands import IdempotencyConflict

from test_evidence import evidence_db, review
from test_evidence_transport import bearer, evidence_transport, transport
from test_persisted_access import binding, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import BEFORE, SEARCH_FIELDS, corpus
from test_wiki_inputs import assemble, compile_rule
from test_wiki_publication import authorize
from test_wiki_search import reviewed


def open_feedback(connection, tenant, principal_id, operation, space_id=None, key=None):
    from enterprise_kb.modules.operations import feedback
    from enterprise_kb.runtime.audit import RequestStart, start_request

    scope = tenant.space_id if space_id is None else space_id
    request_id = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request_id, principal_id, None, "synthetic-ui", operation,
        "internal_feedback", BEFORE, 1, space_id=scope,
    ))
    return feedback.FeedbackCall(tenant.org_id, scope, principal_id, request_id, key or str(uuid4()), 1)


def present(client, token, passage):
    reply = client.get(f"/v1/passages/{passage.passage_ref}", headers=bearer(token))
    assert reply.status_code == 200
    return UUID(reply.json()["request_id"])


def test_feedback_only_attaches_to_own_exact_displayed_receipt(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, employee), _, _, first, second = transport
    connection, tenant, *_ = db
    original = present(client, owner, first)
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    spec = feedback.FeedbackSpec(original, "incorrect_evidence", first.passage_ref, "内部备注：单位有误")
    saved = feedback.record_feedback(connection, call, spec)
    repeated = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD, key=call.key)
    assert feedback.record_feedback(connection, repeated, spec) == saved
    with pytest.raises(IdempotencyConflict):
        feedback.record_feedback(connection, repeated, replace(spec, note="不同说明"))
    with pytest.raises(feedback.FeedbackNotAdmitted):
        feedback.record_feedback(connection, call, replace(spec, passage_ref=second.passage_ref))
    stranger = open_feedback(connection, tenant, tenant.other_actor_id, feedback.RECORD)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        feedback.record_feedback(connection, stranger, spec)
    assert present(client, employee, first) != original
    assert connection.execute(
        "SELECT state, generation, excerpt_revision FROM thalion.current_feedback",
    ).fetchall() == [("pending", 1, first.revision)]
    assert connection.execute(
        "SELECT count(*) FROM thalion.outbox_event WHERE object_ref = %s AND event_type = 'operations.feedback.recorded'",
        (saved,),
    ).fetchone() == (1,)
    assert "内部备注" not in repr(spec)


def test_search_receipt_distinguishes_visible_citations_from_hidden_wiki_inputs(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, _), *_fixtures, first, second = transport
    connection, tenant, *_ = db
    review_rule = replace(compile_rule(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review")
    publish_rule = replace(review_rule, operation="publish_wiki_revision", purpose="wiki_publication")
    set_rules(db, compile_rule(tenant.actor_id), review_rule, publish_rule,
              replace(binding(tenant.actor_id), fields=SEARCH_FIELDS), expected=2)
    sealed = assemble(db, (first, second))
    assert authorize(db, *reviewed((db, sealed, first, second))).status == "succeeded"
    response = client.post("/v1/search", headers=bearer(owner), json={
        "query": "限额", "business_date": BEFORE.isoformat(), "include_wiki": True, "top_k": 1,
    }).json()
    assert response["wiki"][0]["claims"][0]["passage_ids"] == [str(first.passage_ref)]
    original = UUID(response["request_id"])
    assert connection.execute(
        "SELECT dependency_count FROM thalion.delivery_record WHERE request_id = %s", (original,),
    ).fetchone() == (2,)
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        feedback.record_feedback(connection, call, feedback.FeedbackSpec(original, "incorrect_evidence", second.passage_ref))
    assert feedback.record_feedback(connection, call, feedback.FeedbackSpec(original, "incorrect_evidence", first.passage_ref))


def test_only_scoped_search_accepts_uncited_feedback(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, _), *_ = transport
    connection, tenant, *_ = db
    scoped = {"query": "不存在的知识主题", "space_ids": [str(tenant.space_ref)]}
    excluded = scoped | {"space_ids": [str(uuid4())]}
    replies = [client.post("/v1/search", json=arguments, headers=bearer(owner)).json() for arguments in (scoped, excluded)]
    assert all(reply["status"] == "no_evidence" for reply in replies)
    first, second = (UUID(reply["request_id"]) for reply in replies)
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        feedback.record_feedback(connection, call, feedback.FeedbackSpec(second, "missing_evidence"))
    assert feedback.record_feedback(connection, call, feedback.FeedbackSpec(first, "missing_evidence"))


def test_feedback_transitions_require_live_roles_generation_and_independent_retest(transport):
    from enterprise_kb.modules.evidence import processing
    from enterprise_kb.modules.operations import feedback
    from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

    from test_evidence import claim

    client, db, (owner, employee), _, _, first, second = transport
    connection, tenant, _, _, store = db
    original = present(client, employee, first)
    call = open_feedback(connection, tenant, tenant.other_actor_id, feedback.RECORD)
    ref = feedback.record_feedback(connection, call, feedback.FeedbackSpec(original, "incorrect_evidence", first.passage_ref))

    def change(actor, generation, action, **options):
        command = open_feedback(connection, tenant, actor, feedback.TRANSITION)
        return feedback.transition_feedback(connection, command, ref, generation, action, **options)

    with pytest.raises(feedback.FeedbackNotAdmitted):
        change(tenant.other_actor_id, 1, "assign", assignee_id=tenant.other_actor_id)
    change(tenant.actor_id, 1, "assign", assignee_id=tenant.other_actor_id)
    with pytest.raises(feedback.FeedbackConflict):
        change(tenant.actor_id, 1, "assign", assignee_id=tenant.other_actor_id)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        change(tenant.actor_id, 2, "mark_corrected")
    change(tenant.other_actor_id, 2, "mark_corrected")
    same = present(client, employee, first)
    unrelated = present(client, owner, second)
    for retest in (original, same, unrelated):
        with pytest.raises(feedback.FeedbackConflict):
            change(tenant.actor_id, 3, "verify_correction", retest_id=retest)

    allowance = connection.execute(
        """
        SELECT request.target_ref, request.input_digest FROM thalion.job AS request
        JOIN thalion.passage_excerpt AS excerpt ON excerpt.run_ref = request.result_ref
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
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, allowance[0], "parse", allowance[1], 2))
    run = processing.process_markdown_job(connection, claim(db), store)
    review(db, run)
    retest = present(client, employee, first)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        change(tenant.other_actor_id, 3, "verify_correction", retest_id=retest)
    change(tenant.actor_id, 3, "verify_correction", retest_id=retest)
    assert connection.execute("SELECT state, generation FROM thalion.current_feedback").fetchall() == [("closed", 4)]
    assert connection.execute(
        "SELECT actor_id, action, retest_request_id FROM thalion.feedback_decision ORDER BY generation",
    ).fetchall() == [(tenant.actor_id, "assign", None), (tenant.other_actor_id, "mark_corrected", None),
                     (tenant.actor_id, "verify_correction", retest)]
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.feedback_decision SET retest_request_id = NULL")


def test_internal_feedback_http_checks_permissions_and_returns_only_safe_progress(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, employee), credentials, live, first, _ = transport
    connection, tenant, *_ = db
    original = present(client, employee, first)
    params = {
        "origin_request_id": str(original), "category": "incorrect_evidence", "passage_id": str(first.passage_ref),
        "note": "合成敏感说明，不能出现在工单进度里",
    }
    submit_headers = bearer(employee) | {"Idempotency-Key": str(uuid4())}
    route = "/internal/feedback"
    assert client.post(route, headers=submit_headers, json=params).status_code == 403
    credentials[employee] = replace(credentials[employee], operations=credentials[employee].operations | {
        feedback.RECORD, feedback.STATUS, feedback.TRANSITION,
    })
    credentials[owner] = replace(credentials[owner], operations=credentials[owner].operations | {
        feedback.STATUS, feedback.TRANSITION,
    })
    recorded = client.post(route, headers=submit_headers, json=params)
    assert recorded.status_code == 200 and recorded.headers["Cache-Control"] == "no-store"
    body = recorded.json()
    assert set(body) == {"request_id", "feedback_id", "state", "generation"}
    ref = body["feedback_id"]
    assert client.post(route, headers=submit_headers, json=params).json()["feedback_id"] == ref
    assert client.post(route, headers=submit_headers, json=params | {"note": "同键不同输入"}).status_code == 409
    status_path = f"{route}/{ref}"
    assert client.get(status_path, headers=bearer(owner)).status_code == 403
    assert client.get(status_path).status_code == 401
    assign = {"action": "assign", "expected_generation": 1, "assignee_ref": str(credentials[employee].employee_ref)}
    owner_headers = bearer(owner) | {"Idempotency-Key": str(uuid4())}
    assert client.post(f"{status_path}/transitions", headers=submit_headers, json=assign).status_code == 403
    assigned = client.post(f"{status_path}/transitions", headers=owner_headers, json=assign)
    assert assigned.status_code == 200 and assigned.json()["generation"] == 2
    live.clear()
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(employee)).status_code == 404
    progress = client.get(status_path, headers=bearer(employee))
    assert progress.status_code == 200
    assert progress.json() == {"request_id": progress.json()["request_id"], "feedback_id": ref,
                               "state": "pending", "generation": 2}
    assert all(secret not in progress.text for secret in (params["note"], str(first.passage_ref), str(original)))
    assert connection.execute(
        "SELECT operation, outcome FROM thalion.request_record WHERE request_id = %s", (progress.json()["request_id"],),
    ).fetchone() == (feedback.STATUS, "succeeded")


def test_feedback_rolls_back_if_outbox_cannot_commit(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, _), *_fixtures, first, _ = transport
    connection, tenant, *_ = db
    original = present(client, owner, first)
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    connection.execute("ALTER TABLE thalion.outbox_event ADD CHECK (event_type <> 'operations.feedback.recorded')")
    with pytest.raises(errors.CheckViolation):
        feedback.record_feedback(connection, call, feedback.FeedbackSpec(original, "incorrect_evidence", first.passage_ref, "测试说明"))
    assert connection.execute("SELECT count(*) FROM thalion.feedback").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.feedback_note").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.request_command WHERE request_id = %s", (call.request_id,)).fetchone() == (0,)


def test_feedback_explanation_requires_assignees_own_reread(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, employee), _, _, first, _ = transport
    connection, tenant, *_ = db
    original = present(client, owner, first)
    early = present(client, employee, first)
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    ref = feedback.record_feedback(connection, call, feedback.FeedbackSpec(original, "incorrect_evidence", first.passage_ref))
    assign = open_feedback(connection, tenant, tenant.actor_id, feedback.TRANSITION)
    feedback.transition_feedback(connection, assign, ref, 1, "assign", assignee_id=tenant.other_actor_id)
    explain = open_feedback(connection, tenant, tenant.other_actor_id, feedback.TRANSITION)
    with pytest.raises(ValueError):
        feedback.transition_feedback(connection, explain, ref, 2, "explain")
    for basis in (early, present(client, owner, first)):
        with pytest.raises(feedback.FeedbackConflict):
            feedback.transition_feedback(connection, explain, ref, 2, "explain", basis_id=basis)
    basis = present(client, employee, first)
    try:
        recorded = feedback.transition_feedback(connection, explain, ref, 2, "explain", basis_id=basis)
    except feedback.FeedbackConflict:
        ordering = connection.execute("""
            SELECT request.started_at - report.decided_at, delivery.valid_until - request.completed_at
            FROM thalion.current_feedback AS report
            JOIN thalion.request_record AS request ON (request.org_id, request.request_id) = (report.org_id, %s)
            JOIN thalion.delivery_record AS delivery ON (delivery.org_id, delivery.request_id) = (request.org_id, request.request_id)
            WHERE report.feedback_ref = %s
            """, (basis, ref)).fetchone()
        pytest.fail(f"The exact reread was refused; request ordering and delivery window deltas: {ordering!r}")
    assert recorded.state == "explained"
    assert connection.execute(
        "SELECT basis_request_id FROM thalion.feedback_decision WHERE action = 'explain'",
    ).fetchone() == (basis,)


def test_same_employee_cannot_rebind_feedback_to_a_different_space(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, _), _, _, first, _ = transport
    connection, tenant, *_ = db
    original = present(client, owner, first)
    with connection.transaction():
        different = connection.execute(
            """
            INSERT INTO thalion.space (org_id, name, classification, owner_principal_id)
            VALUES (%s, 'Another space', 'internal', %s) RETURNING space_id
            """, (tenant.org_id, tenant.actor_id),
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id) VALUES (%s, %s, 'space', %s)",
            (tenant.org_id, different, different),
        )
    spec = feedback.FeedbackSpec(original, "incorrect_evidence", first.passage_ref)
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    ref = feedback.record_feedback(connection, call, spec)
    wrong = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD, space_id=different)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        feedback.record_feedback(connection, wrong, spec)
    status = open_feedback(connection, tenant, tenant.actor_id, feedback.STATUS, space_id=different)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        feedback.get_feedback_progress(connection, status, ref)
    change = open_feedback(connection, tenant, tenant.actor_id, feedback.TRANSITION, space_id=different)
    with pytest.raises(feedback.FeedbackNotAdmitted):
        feedback.transition_feedback(connection, change, ref, 1, "assign", assignee_id=tenant.other_actor_id)


def test_competing_feedback_assignments_cannot_both_append_next_generation(transport):
    from enterprise_kb.modules.operations import feedback

    client, db, (owner, _), *_fixtures, first, _ = transport
    connection, tenant, database_url, *_ = db
    origin = present(client, owner, first)
    call = open_feedback(connection, tenant, tenant.actor_id, feedback.RECORD)
    ref = feedback.record_feedback(connection, call, feedback.FeedbackSpec(origin, "incorrect_evidence", first.passage_ref))
    simultaneous = Barrier(2, timeout=5)

    def try_assignment():
        with open_database(database_url) as concurrent:
            request = open_feedback(concurrent, tenant, tenant.actor_id, feedback.TRANSITION)
            simultaneous.wait()
            try:
                return feedback.transition_feedback(concurrent, request, ref, 1, "assign", assignee_id=tenant.other_actor_id)
            except feedback.FeedbackConflict:
                return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        attempts = [workers.submit(try_assignment) for _ in range(2)]
        assert sum(attempt.result() is not None for attempt in attempts) == 1
    assert connection.execute("SELECT generation FROM thalion.feedback_decision").fetchall() == [(2,)]


def test_credential_change_before_feedback_commit_rolls_back_writes(evidence_transport, transport, monkeypatch):
    from enterprise_kb.modules.operations import feedback

    service, *_ = evidence_transport
    client, db, (owner, _), credentials, _, first, _ = transport
    connection, *_ = db
    origin = present(client, owner, first)
    credential = credentials[owner] = replace(credentials[owner], operations=credentials[owner].operations | {feedback.RECORD})
    checks = iter((credential, credential, None))
    monkeypatch.setattr(service, "verify_token", lambda _token: next(checks))
    reply = client.post("/internal/feedback", headers=bearer(owner) | {"Idempotency-Key": str(uuid4())}, json={
        "origin_request_id": str(origin), "passage_id": str(first.passage_ref), "category": "incorrect_evidence",
    })
    assert reply.status_code == 401
    request_id = UUID(reply.json()["request_id"])
    assert connection.execute("SELECT count(*) FROM thalion.feedback").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.request_command WHERE request_id = %s", (request_id,)).fetchone() == (0,)
    assert connection.execute("SELECT outcome FROM thalion.request_record WHERE request_id = %s", (request_id,)).fetchone() == ("rejected",)
