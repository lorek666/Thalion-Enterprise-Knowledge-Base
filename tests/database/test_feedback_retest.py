from dataclasses import replace
from datetime import timedelta
from secrets import token_bytes
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.operations import feedback
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from test_evidence import claim, evidence_db, review
from test_evidence_transport import add_search_source, bearer, evidence_transport, rpc, transport
from test_feedback import open_feedback, present
from test_runtime import runtime_db
from test_travel_search import BEFORE, corpus


@pytest.fixture
def retest_work(evidence_transport, transport, corpus, monkeypatch):
    service, *_ = evidence_transport
    monkeypatch.setattr(service, "retest_key", token_bytes(32))
    client, db, (owner, reporter), credentials, live, first, _ = transport
    connection, tenant, *_ = db
    arguments = {"query": "上海住宿限额", "business_date": BEFORE.isoformat(), "top_k": 5}

    def search(*, token=reporter, params=arguments, via_mcp=False):
        if via_mcp:
            reply = rpc(client, token, "tools/call", name="search", arguments=params).json()
            return reply["result"]["structuredContent"]
        return client.post("/v1/search", json=params, headers=bearer(token)).json()

    origin = search()
    assert [item["passage_id"] for item in origin["passages"]] == [str(first.passage_ref)]

    def submit(request_id, passage_ref=first.passage_ref):
        call = open_feedback(connection, tenant, tenant.other_actor_id, feedback.RECORD)
        return feedback.record_feedback(connection, call, feedback.FeedbackSpec(
            UUID(request_id), "incorrect_evidence" if passage_ref else "missing_evidence", passage_ref,
        ))

    def change(ref, generation, action, *, actor=tenant.actor_id, **options):
        call = open_feedback(connection, tenant, actor, feedback.TRANSITION)
        return feedback.transition_feedback(connection, call, ref, generation, action, **options)

    def correct(ref):
        change(ref, 1, "assign", assignee_id=tenant.other_actor_id)
        change(ref, 2, "mark_corrected", actor=tenant.other_actor_id)

    def verify(ref, request_id):
        request_id = UUID(request_id) if isinstance(request_id, str) else request_id
        return change(ref, 3, "verify_correction", retest_id=request_id)

    def reprocess():
        _, version, *_ = corpus
        connection.execute(
            """
            INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
            SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision
            WHERE configuration_revision = 1
            """,
        )
        enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 2))
        review(db, processing.process_markdown_job(connection, claim(db), db[-1]))

    return search, arguments, origin, submit, correct, verify, reprocess, service, transport


def test_search_correction_closes_only_with_same_question_and_new_visible_revision(retest_work, monkeypatch):
    search, args, origin, submit, correct, verify, reprocess, service, transport_fixture = retest_work
    client, db, (owner, reporter), credentials, live, first, _ = transport_fixture
    connection, tenant, *_ = db
    report = submit(origin["request_id"])
    reprocess()
    early = search()
    correct(report)

    wrong_question = search(params=args | {"query": "上海住宿限额 上海"})
    assert wrong_question["passages"] == early["passages"]
    wrong_date = search(params=args | {"business_date": (BEFORE - timedelta(days=1)).isoformat()})
    wrong_view = search(params=args | {"include_wiki": True})
    wrong_scope = search(params=args | {"space_ids": [str(tenant.space_ref), str(uuid4())]})
    wrong_sources = search(params=args | {"source_ids": [str(db[3])]})
    assert wrong_sources["passages"] == early["passages"]
    wrong_identity = search(token=owner)
    original_credential = credentials[reporter]
    credentials[reporter] = replace(original_credential, client_id="another-client")
    wrong_client = search()
    credentials[reporter] = original_credential
    live.remove(tenant.other_actor_id)
    denied = search()
    assert denied["status"] == "no_evidence"
    live.add(tenant.other_actor_id)

    def unavailable(*_):
        raise AuthorizationUnavailable("合成权威服务不可用")

    with monkeypatch.context() as temporary:
        temporary.setattr(service, "check_source", unavailable)
        failure = search()
        assert failure["error"]["code"] == "dependency_unavailable"
    with monkeypatch.context() as temporary:
        temporary.setattr(service, "retest_key", token_bytes(32))
        rotated = search()
    for unrelated in (
        origin, early, wrong_question, wrong_date, wrong_view, wrong_scope, wrong_sources, wrong_identity,
        wrong_client, denied, failure, rotated,
    ):
        with pytest.raises(feedback.FeedbackConflict):
            verify(report, unrelated["request_id"])
    for unrelated in (uuid4(), present(client, reporter, first)):
        with pytest.raises(feedback.FeedbackConflict):
            verify(report, unrelated)

    renewed_token = "R" * 48
    credentials[renewed_token] = original_credential
    result = search(token=renewed_token, via_mcp=True)
    assert [(item["passage_id"], item["excerpt_revision"]) for item in result["passages"]] == [(str(first.passage_ref), 2)]
    credentials[owner] = replace(credentials[owner], operations=credentials[owner].operations | {feedback.TRANSITION})
    closed = client.post(
        f"/internal/feedback/{report}/transitions",
        headers=bearer(owner) | {"Idempotency-Key": str(uuid4())},
        json={"action": "verify_correction", "expected_generation": 3, "retest_request_id": result["request_id"]},
    )
    assert closed.status_code == 200 and closed.json()["state"] == "closed"
    assert connection.execute(
        "SELECT retest_request_id FROM thalion.feedback_decision WHERE action = 'verify_correction'",
    ).fetchall() == [(UUID(result["request_id"]),)]
    credentials[reporter] = replace(original_credential, operations=original_credential.operations | {
        feedback.STATUS, feedback.NOTICES,
    })
    notices = client.get("/internal/feedback/notices", headers=bearer(reporter)).json()["items"]
    assert [(item["feedback_id"], item["state"]) for item in notices] == [
        (str(report), "closed"), (str(report), "awaiting_retest"),
    ]
    progress = client.get(f"/internal/feedback/{report}", headers=bearer(reporter)).json()
    assert (progress["state"], progress["conclusion_code"]) == ("closed", "correction_verified")


@pytest.mark.parametrize("with_facets", [False, True])
def test_search_correction_accepts_the_same_source_set_across_http_and_mcp(retest_work, with_facets):
    search, args, _, submit, correct, verify, reprocess, _, transport_fixture = retest_work
    _, db, _, _, _, first, _ = transport_fixture
    source = str(db[3])
    selected, _ = add_search_source(db)
    other_source = str(selected)
    origin = search(params=args | {"source_ids": [source, other_source]})
    report = submit(origin["request_id"])
    reprocess()
    correct(report)

    narrowed = search(params=args | {"source_ids": [source]})
    retest = search(params=args | {
        "source_ids": [other_source, source, source], "include_source_facets": with_facets,
    }, via_mcp=True)
    assert narrowed["passages"] == retest["passages"]
    assert [(part["passage_id"], part["excerpt_revision"]) for part in retest["passages"]] == [
        (str(first.passage_ref), 2),
    ]
    with pytest.raises(feedback.FeedbackConflict):
        verify(report, narrowed["request_id"])
    verify(report, retest["request_id"])
    connection, *_ = db
    assert connection.execute(
        "SELECT retest_request_id FROM thalion.feedback_decision WHERE action = 'verify_correction'",
    ).fetchall() == [(UUID(retest["request_id"]),)]


def test_search_correction_cannot_close_on_unchanged_or_unbound_evidence(retest_work):
    search, _, origin, submit, correct, verify, reprocess, service, _ = retest_work
    unchanged = submit(origin["request_id"])
    correct(unchanged)
    with pytest.raises(feedback.FeedbackConflict):
        verify(unchanged, search()["request_id"])
    gap = submit(origin["request_id"], None)
    with pytest.raises(feedback.FeedbackConflict):
        correct(gap)
    service.retest_key = None
    unbound = submit(search()["request_id"])
    correct(unbound)
    reprocess()
    service.retest_key = token_bytes(32)
    result = search()
    for ref in (gap, unbound):
        with pytest.raises(feedback.FeedbackConflict):
            verify(ref, result["request_id"])


def test_search_match_is_private_and_commits_with_its_delivery(retest_work):
    search, args, origin, _, _, _, _, service, transport_fixture = retest_work
    _, db, (owner, _), *_ = transport_fixture
    connection, *_ = db
    repeat = search(via_mcp=True)
    other = search(token=owner)
    no_hit = search(params=args | {"query": "合成未命中问题"})
    origin_id, repeat_id, other_id = (UUID(output["request_id"]) for output in (origin, repeat, other))
    records = connection.execute(
        """
        SELECT request_id, fingerprint, (to_jsonb(request)::text || to_jsonb(match)::text)
        FROM thalion.feedback_search_match AS match JOIN thalion.request_record AS request USING (org_id, request_id)
        """,
    ).fetchall()
    stored = {request_id: fingerprint for request_id, fingerprint, _ in records}
    assert set(stored) == {origin_id, repeat_id, other_id}
    assert stored[origin_id] == stored[repeat_id] != stored[other_id]
    assert all(args["query"] not in row and service.retest_key.hex() not in row for _, _, row in records)
    assert no_hit["status"] == "no_evidence" and "fingerprint" not in repeat
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.feedback_search_match SET fingerprint = fingerprint")
    connection.execute("ALTER TABLE thalion.feedback_search_match ADD CHECK (false) NOT VALID")
    failed = search()
    assert failed["error"]["code"] == "dependency_unavailable"
    assert connection.execute(
        """
        SELECT request.outcome, delivery.check_id FROM thalion.request_record AS request
        LEFT JOIN thalion.delivery_record AS delivery USING (org_id, request_id) WHERE request.request_id = %s
        """, (failed["request_id"],),
    ).fetchone() == ("dependency_unavailable", None)
