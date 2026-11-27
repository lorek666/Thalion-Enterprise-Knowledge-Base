from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from secrets import token_urlsafe
from threading import Barrier
from uuid import uuid4

import pytest
from psycopg import errors

from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback import open_feedback, present
from test_feedback_work import EVIDENCE_CAPABILITY, QUEUE_CAPABILITY, admit, assign, submit
from test_gaps import command_headers
from test_identity import space
from test_runtime import runtime_db
from test_travel_search import corpus


PATH = "/internal/feedback/handoffs"
ISSUE = "authorize_feedback_handoff"
ACCEPT = "accept_feedback_handoff"
REVOKE = "revoke_feedback_handoff"


@pytest.fixture
def handoff_work(transport):
    client, db, (owner, incumbent), credentials, _, passage, _ = transport
    connection, tenant, *_ = db
    with connection.transaction():
        successor_id, = connection.execute(
            """
            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
            VALUES (%s, 'employee', 'https://synthetic.invalid', %s) RETURNING principal_id
            """, (tenant.org_id, str(uuid4())),
        ).fetchone()
        successor_ref, = connection.execute(
            """
            INSERT INTO thalion.object_identity (object_type, object_id, org_id)
            VALUES ('principal', %s, %s) RETURNING public_id
            """, (successor_id, tenant.org_id),
        ).fetchone()
    successor = token_urlsafe(32)
    credentials[successor] = replace(credentials[incumbent], employee_ref=successor_ref)
    admit(credentials, incumbent, QUEUE_CAPABILITY, EVIDENCE_CAPABILITY, "transition_feedback")
    admit(credentials, successor, QUEUE_CAPABILITY, EVIDENCE_CAPABILITY)
    origin = present(client, owner, passage)
    work = [submit(connection, tenant, origin, passage) for _ in range(2)]
    for ref in work:
        assign(connection, tenant, ref)
    now, = connection.execute("SELECT clock_timestamp()").fetchone()
    params = {
        "from_employee_ref": str(credentials[incumbent].employee_ref),
        "to_employee_ref": str(successor_ref),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "basis_id": str(uuid4()),
        "items": [{"feedback_id": str(ref), "expected_generation": 2} for ref in work],
    }
    return client, connection, tenant, owner, incumbent, successor, successor_id, work, params, credentials


def issue(client, owner, params, key=None):
    return client.post(PATH, headers=command_headers(owner, key), json=params)


def resolve(client, token, grant, action="accept", key=None):
    return client.post(f"{PATH}/{grant}/{action}", headers=command_headers(token, key), json={})


def pending(client, token):
    return client.get("/internal/feedback", headers=bearer(token)).json()["items"]


def admit_handoff(credentials, owner, incumbent, successor):
    admit(credentials, owner, ISSUE, REVOKE)
    admit(credentials, incumbent, ACCEPT)
    admit(credentials, successor, ACCEPT, REVOKE)


def test_handoff_moves_only_the_sealed_work_without_copying_read_access(handoff_work):
    client, connection, _, owner, incumbent, successor, successor_id, work, params, credentials = handoff_work
    route = f"/internal/feedback/{work[0]}"
    original_read = client.get(f"{route}/evidence", headers=bearer(incumbent))
    assert original_read.status_code == 200, original_read.text
    key = str(uuid4())
    assert issue(client, owner, params, key).status_code == 403
    admit_handoff(credentials, owner, incumbent, successor)
    authorized = issue(client, owner, params, key)
    assert authorized.status_code == 200, authorized.text
    grant = authorized.json()["handoff_id"]
    assert issue(client, owner, params | {"items": list(reversed(params["items"]))}, key).json()["handoff_id"] == grant
    assert issue(client, owner, params | {"basis_id": str(uuid4())}, key).status_code == 409
    assert pending(client, successor) == []
    assert resolve(client, incumbent, grant).status_code == 403
    accepted_key = str(uuid4())
    accepted = resolve(client, successor, grant, key=accepted_key)
    assert accepted.status_code == 200 and accepted.headers["Cache-Control"] == "no-store", accepted.text
    assert accepted.json()["state"] == "accepted" and accepted.json()["item_count"] == 2
    assert resolve(client, successor, grant, key=accepted_key).status_code == 200
    assert resolve(client, successor, grant).status_code == 409
    assert not pending(client, incumbent)
    assert {item["feedback_id"]: item["generation"] for item in pending(client, successor)} == {
        str(ref): 3 for ref in work
    }
    assert client.get(f"{route}/evidence", headers=bearer(incumbent)).status_code == 404
    assert client.get(f"{route}/evidence", headers=bearer(successor)).status_code == 404
    original_ref = original_read.json()["passage"]["passage_id"]
    assert client.get(f"/v1/passages/{original_ref}", headers=bearer(incumbent)).status_code == 200
    assert client.post(f"{route}/transitions", headers=command_headers(incumbent), json={
        "action": "explain", "expected_generation": 3, "basis_request_id": original_read.json()["request_id"],
    }).status_code == 403
    assert connection.execute(
        "SELECT DISTINCT actor_id, assignee_id FROM thalion.feedback_decision WHERE generation = 3",
    ).fetchall() == [(successor_id, successor_id)]


def test_handoff_expiry_revocation_and_stale_items_leave_the_whole_batch_unchanged(handoff_work):
    client, connection, tenant, owner, incumbent, successor, _, work, params, credentials = handoff_work
    now, = connection.execute("SELECT clock_timestamp()").fetchone()
    expired = params | {"expires_at": (now - timedelta(minutes=1)).isoformat()}
    assert issue(client, owner, expired).status_code == 403
    admit_handoff(credentials, owner, incumbent, successor)
    assert issue(client, owner, expired).status_code == 409
    short_window = now + timedelta(seconds=2)
    short_lived = issue(client, owner, params | {"expires_at": short_window.isoformat()})
    assert short_lived.status_code == 200, short_lived.text
    connection.execute("SELECT pg_sleep_until(%s + interval '100 milliseconds')", (short_window,))
    assert resolve(client, successor, short_lived.json()["handoff_id"]).status_code == 409
    authorized = issue(client, owner, params)
    assert authorized.status_code == 200, authorized.text
    grant = authorized.json()["handoff_id"]
    assert resolve(client, successor, grant, "revoke").status_code == 403
    assert resolve(client, owner, grant, "revoke").json()["state"] == "revoked"
    assert resolve(client, successor, grant).status_code == 409
    next_grant = issue(client, owner, params).json()["handoff_id"]
    assign(connection, tenant, work[1], expected=2)
    assert resolve(client, successor, next_grant).status_code == 409
    assert not pending(client, successor)
    assert {item["feedback_id"]: item["generation"] for item in pending(client, incumbent)} == {
        str(work[0]): 2, str(work[1]): 3,
    }


def test_handoff_scope_and_event_failure_roll_back_the_transfer(handoff_work):
    client, connection, tenant, owner, incumbent, successor, _, work, params, credentials = handoff_work
    admit_handoff(credentials, owner, incumbent, successor)
    assert issue(client, owner, params | {"items": params["items"][:1] * 2}).status_code == 400
    assert issue(client, owner, params | {"items": [{"feedback_id": str(uuid4()), "expected_generation": 2}]}).status_code == 409
    grant = issue(client, owner, params).json()["handoff_id"]
    with connection.transaction():
        _, other_space_ref = space(connection, tenant.org_id, tenant.actor_id)
    original = credentials[successor]
    credentials[successor] = replace(original, space_ref=other_space_ref)
    assert resolve(client, successor, grant).status_code == 403
    credentials[successor] = original
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_handoff_event
        CHECK (event_type <> 'operations.feedback.handoff_accepted') NOT VALID
        """)
    key = str(uuid4())
    assert resolve(client, successor, grant, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.feedback_handoff_resolution").fetchone() == (0,)
    assert not pending(client, successor)
    assert {item["feedback_id"] for item in pending(client, incumbent)} == set(map(str, work))
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_handoff_event")
    assert resolve(client, successor, grant, key=key).status_code == 200


def test_only_one_of_concurrent_acceptance_and_revocation_wins(handoff_work):
    client, connection, _, owner, incumbent, successor, _, work, params, credentials = handoff_work
    admit_handoff(credentials, owner, incumbent, successor)
    grant = issue(client, owner, params).json()["handoff_id"]
    ready = Barrier(2, timeout=5)

    def decide(token, action):
        ready.wait()
        return resolve(client, token, grant, action)

    with ThreadPoolExecutor(max_workers=2) as workers:
        accepting = workers.submit(decide, successor, "accept")
        revoking = workers.submit(decide, owner, "revoke")
        results = accepting.result(timeout=10), revoking.result(timeout=10)
    assert sorted(reply.status_code for reply in results) == [200, 409]
    accepted = results[0].status_code == 200
    assert connection.execute(
        "SELECT outcome FROM thalion.feedback_handoff_resolution WHERE handoff_ref = %s", (grant,),
    ).fetchone() == ("accepted" if accepted else "revoked",)
    current, former = (successor, incumbent) if accepted else (incumbent, successor)
    assert {item["feedback_id"] for item in pending(client, current)} == set(map(str, work))
    assert pending(client, former) == []


def test_database_rejects_an_accepted_handoff_with_no_assignment_decisions(handoff_work):
    client, connection, tenant, owner, incumbent, successor, successor_id, _, params, credentials = handoff_work
    admit_handoff(credentials, owner, incumbent, successor)
    grant = issue(client, owner, params).json()["handoff_id"]
    call = open_feedback(connection, tenant, successor_id, ACCEPT)
    with pytest.raises(errors.CheckViolation, match="coverage must equal the sealed item count"):
        connection.execute("""
            INSERT INTO thalion.feedback_handoff_resolution (org_id, space_id, handoff_ref, actor_id, request_id, outcome)
            VALUES (%s, %s, %s, %s, %s, 'accepted')
            """, (tenant.org_id, tenant.space_id, grant, successor_id, call.request_id))
    assert connection.execute("SELECT count(*) FROM thalion.feedback_handoff_resolution").fetchone() == (0,)
    assert resolve(client, successor, grant).status_code == 200
