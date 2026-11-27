from dataclasses import replace
from secrets import token_bytes
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.operations import feedback
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from test_effectivity import BEGIN, approve
from test_evidence import approved, claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback import open_feedback, present
from test_feedback_work import admit
from test_gaps import command_headers
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_travel_search import SEARCH_FIELDS, corpus, publish


CONTENT = "# 合成差旅\n\n往期示例：住宿限额 200 元。\n\n现行规定：住宿限额 300 元。\n".encode()
QUERY = {"query": "住宿限额"}


@pytest.fixture
def correction_work(transport, evidence_transport, request, monkeypatch):
    client, db, (owner, reporter), credentials, _, unrelated, _ = transport
    connection, tenant, *_ = db
    version, old, original_run = publish(db, "correction", "合成纠错制度", CONTENT)
    approve(connection, tenant, version, BEGIN)
    search_origin = getattr(request, "param", False)
    set_rules(
        db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        replace(binding(tenant.other_actor_id, passage_ref=old.passage_ref if search_origin else None), fields=SEARCH_FIELDS),
        expected=2,
    )
    admit(credentials, owner, feedback.TRANSITION)
    admit(credentials, reporter, feedback.TRANSITION)
    if search_origin:
        service, *_ = evidence_transport
        monkeypatch.setattr(service, "retest_key", token_bytes(32))
        result = client.post("/v1/search", headers=bearer(reporter), json=QUERY).json()
        assert [part["passage_id"] for part in result["passages"]] == [str(old.passage_ref)]
        origin = UUID(result["request_id"])
    else:
        origin = present(client, reporter, old)
    call = open_feedback(connection, tenant, tenant.other_actor_id, feedback.RECORD)
    ref = feedback.record_feedback(connection, call, feedback.FeedbackSpec(origin, "incorrect_evidence", old.passage_ref))
    route = f"/internal/feedback/{ref}/transitions"
    assigned = client.post(route, headers=command_headers(owner), json={
        "action": "assign", "expected_generation": 1, "assignee_ref": str(credentials[reporter].employee_ref),
    })
    assert assigned.status_code == 200, assigned.text
    review(db, original_run, decision="quarantined")
    blocked = client.get(f"/v1/passages/{old.passage_ref}", headers=bearer(reporter))
    assert blocked.status_code == 404
    connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
        """)
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 2))
    run = processing.process_markdown_job(connection, claim(db), db[-1])
    review(db, run)
    unchanged, replacement = approved(db, version)
    assert unchanged.passage_ref == old.passage_ref and unchanged.digest == old.digest
    assert unchanged.revision == replacement.revision == 2 and replacement.digest != old.digest
    return client, db, owner, reporter, route, unchanged, replacement, unrelated, run


def mark(client, token, route, proof=None, key=None):
    params = {"action": "mark_corrected", "expected_generation": 2}
    if proof is not None:
        params["correction_request_id"] = str(proof)
    return client.post(route, headers=command_headers(token, key), json=params)


def verify(client, owner, route, proof):
    return client.post(route, headers=command_headers(owner), json={
        "action": "verify_correction", "expected_generation": 3, "retest_request_id": str(proof),
    })


def test_quarantined_report_requires_a_materially_different_reviewed_locator(correction_work):
    client, db, owner, reporter, route, unchanged, replacement, unrelated, _ = correction_work
    connection, *_ = db
    assert mark(client, reporter, route).status_code == 409
    for proof in (
        present(client, reporter, unchanged), present(client, reporter, unrelated), present(client, owner, replacement),
    ):
        assert mark(client, reporter, route, proof).status_code == 409
    proof = present(client, reporter, replacement)
    key = str(uuid4())
    recorded = mark(client, reporter, route, proof, key)
    if recorded.status_code != 200:
        trace = connection.execute("""
            SELECT request.started_at - report.decided_at, delivery.valid_until - request.completed_at,
                   exists (
                       SELECT 1 FROM thalion.feedback_correction_candidate AS candidate
                       WHERE candidate.feedback_id = report.feedback_id AND candidate.request_id = request.request_id
                   )
            FROM thalion.current_feedback AS report
            JOIN thalion.request_record AS request ON (request.org_id, request.request_id) = (report.org_id, %s)
            JOIN thalion.delivery_record AS delivery ON (delivery.org_id, delivery.request_id) = (request.org_id, request.request_id)
            """, (proof,)).fetchone()
        pytest.fail(f"Correction refused; request ordering, delivery window, candidate: {trace!r}")
    assert recorded.status_code == 200 and recorded.json()["state"] == "awaiting_retest", recorded.text
    assert mark(client, reporter, route, proof, key).status_code == 200
    assert str(replacement.passage_ref) not in recorded.text
    assert verify(client, owner, route, proof).status_code == 409
    assert verify(client, owner, route, present(client, reporter, unchanged)).status_code == 409
    result = client.get(f"/v1/passages/{replacement.passage_ref}", headers=bearer(reporter)).json()
    assert "现行规定：住宿限额 300 元" in result["passage"]["excerpt"]
    closed = verify(client, owner, route, UUID(result["request_id"]))
    assert closed.status_code == 200 and closed.json()["state"] == "closed", closed.text
    assert connection.execute("""
        SELECT part.passage_ref, part.excerpt_revision
        FROM thalion.feedback_decision AS decision
        JOIN thalion.delivery_dependency AS part
          ON (part.check_id, part.position) = (decision.correction_check_id, decision.correction_position)
        WHERE decision.action = 'mark_corrected'
        """).fetchall() == [(replacement.passage_ref, replacement.revision)]


def test_retest_cannot_close_when_the_exact_replacement_is_no_longer_current(correction_work):
    client, db, owner, reporter, route, _, replacement, _, run = correction_work
    proof = present(client, reporter, replacement)
    recorded = mark(client, reporter, route, proof)
    assert recorded.status_code == 200, recorded.text
    retest = present(client, reporter, replacement)
    review(db, run, decision="quarantined")
    assert verify(client, owner, route, retest).status_code == 409
    assert db[0].execute("SELECT state, generation FROM thalion.current_feedback").fetchall() == [
        ("awaiting_retest", 3),
    ]


def test_correction_uses_record_order_when_wall_clock_moves_backward(correction_work):
    client, db, owner, reporter, route, _, replacement, _, _ = correction_work
    connection, *_ = db
    connection.execute("""
        CREATE FUNCTION thalion.test_feedback_clock_step() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.operation = 'read_passage' THEN
                NEW.started_at := clock_timestamp() - interval '30 seconds';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER test_feedback_clock_step BEFORE INSERT ON thalion.request_record
        FOR EACH ROW EXECUTE FUNCTION thalion.test_feedback_clock_step();
        """)
    proof = present(client, reporter, replacement)

    def wall_clock_says_early(request_id):
        return connection.execute("""
            SELECT request.started_at < report.decided_at
            FROM thalion.current_feedback AS report
            JOIN thalion.request_record AS request ON (request.org_id, request.request_id) = (report.org_id, %s)
            """, (request_id,)).fetchone() == (True,)

    assert wall_clock_says_early(proof)
    corrected = mark(client, reporter, route, proof)
    assert corrected.status_code == 200, corrected.text
    assert verify(client, owner, route, proof).status_code == 409
    retest = present(client, reporter, replacement)
    assert wall_clock_says_early(retest)
    assert verify(client, owner, route, retest).status_code == 200


@pytest.mark.parametrize("correction_work", [True], indirect=True)
def test_search_retest_requires_the_same_question_without_the_incorrect_reference(correction_work):
    client, db, owner, reporter, route, unchanged, replacement, _, _ = correction_work
    _, tenant, *_ = db
    owner_rule = replace(binding(tenant.actor_id), fields=SEARCH_FIELDS)
    reporter_replacement = replace(binding(tenant.other_actor_id, passage_ref=replacement.passage_ref), fields=SEARCH_FIELDS)
    set_rules(
        db, owner_rule, reporter_replacement,
        replace(binding(tenant.other_actor_id, passage_ref=unchanged.passage_ref), fields=SEARCH_FIELDS),
        expected=3,
    )
    assert mark(client, reporter, route, present(client, reporter, replacement)).status_code == 200
    both = client.post("/v1/search", headers=bearer(reporter), json=QUERY).json()
    assert {part["passage_id"] for part in both["passages"]} == {
        str(unchanged.passage_ref), str(replacement.passage_ref),
    }
    assert verify(client, owner, route, both["request_id"]).status_code == 409
    set_rules(db, owner_rule, reporter_replacement, expected=4)
    wrong = client.post("/v1/search", headers=bearer(reporter), json={"query": "现行规定 住宿限额"}).json()
    assert [part["passage_id"] for part in wrong["passages"]] == [str(replacement.passage_ref)]
    assert verify(client, owner, route, wrong["request_id"]).status_code == 409
    same = client.post("/v1/search", headers=bearer(reporter), json=QUERY).json()
    assert [part["passage_id"] for part in same["passages"]] == [str(replacement.passage_ref)]
    assert verify(client, owner, route, same["request_id"]).status_code == 200
