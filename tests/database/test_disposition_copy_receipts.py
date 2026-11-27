from dataclasses import replace
from datetime import date
from uuid import uuid4

from psycopg import errors
import pytest

from enterprise_kb.runtime.audit import RequestStart, start_request

from test_backup_expiry import observe, registered_copy, schedule, withdraw_for_due_backup
from test_backup_inventory import backup_inventory, register as enroll, store_copy
from test_deletion_tombstone import REGISTER, approved, register, submitted
from test_disposition_cases import PATH, candidate
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_holds import CAPABILITY as HOLD, decide
from test_identity import space
from test_lexical_index import build
from test_runtime import runtime_db
from test_travel_search import corpus


OBSERVE = "record_disposition_copy_observations"
EVENT = "lifecycle.disposition_copies.observed"


def capture(client, token, case, tombstone, *, key=None, **overrides):
    return client.post(f"{PATH}/{case['case_id']}/copy-observations", headers=command_headers(token, key), json={
        "tombstone_id": str(tombstone), "inventory_snapshot": case["inventory_snapshot"], **overrides,
    })


def block(client, reviewer, credentials, case):
    approval = approved(client, reviewer, credentials, case)
    admit(credentials, reviewer, REGISTER, OBSERVE)
    response = register(client, reviewer, case, approval)
    assert response.status_code == 200, response.text
    return response.json()["tombstone_id"]


def presence(receipt):
    return {item["kind"]: item["presence"] for item in receipt["copies"]}


def test_receipt_separates_remaining_copies_from_local_restore_block(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), _, (version, _, run) = candidate
    connection, _, _, source, _ = db
    projection = build(db, version, run)
    case = submitted(client, owner, credentials, source, version, expected=1)
    expected = original(db, version).read_bytes()
    tombstone = block(client, reviewer, credentials, case)
    key = str(uuid4())
    response = capture(client, reviewer, case, tombstone, key=key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert body["tombstone_id"] == tombstone and body["inventory_snapshot"] == case["inventory_snapshot"]
    assert body["restore_blocked_locally"] is True and body["executable"] is False
    assert presence(body) == {
        "index": "present_in_database", "original": "present_verified",
        "processing_manifest": "present_in_database", "transcription": "present_in_database",
    }
    assert body["remaining_items"] == [item["item"] for item in body["copies"]]
    assert str(projection) not in response.text and expected.decode().strip() not in response.text
    assert "cache" in body["unverified_copy_kinds"]
    assert original(db, version).read_bytes() == expected
    assert capture(client, reviewer, case, tombstone, key=key).json()["receipt_id"] == body["receipt_id"]
    assert connection.execute("SELECT count(*) FROM thalion.disposition_copy_receipt").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM thalion.outbox_event WHERE event_type = %s", (EVENT,)).fetchone() == (1,)
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("TRUNCATE thalion.disposition_copy_receipt")


def test_only_due_expiry_with_fresh_absence_excludes_a_backup_from_remaining(
    registered_copy, candidate, evidence_transport,
):
    client, db, owner, reviewer, version, backup, file = registered_copy
    _, _, _, credentials, *_ = candidate[0]
    service, *_ = evidence_transport
    connection, _, _, source, _ = db
    payload = file.read_bytes()
    expiry = withdraw_for_due_backup(db, version)
    assert schedule(client, reviewer, backup, expiry).status_code == 200
    case = submitted(client, owner, credentials, source, version, expected=1)
    tombstone = block(client, reviewer, credentials, case)
    assert presence(capture(client, reviewer, case, tombstone).json())["backup"] == "present_verified"
    moved = file.with_suffix(".fixture")
    file.rename(moved)
    unverified = capture(client, reviewer, case, tombstone).json()
    assert presence(unverified)["backup"] == "missing_unverified"
    assert observe(client, reviewer, backup).status_code == 200
    absent = capture(client, reviewer, case, tombstone).json()
    backup_item = next(item["item"] for item in absent["copies"] if item["kind"] == "backup")
    assert presence(absent)["backup"] == "absence_verified" and backup_item not in absent["remaining_items"]
    configured = service.backup_store
    service.backup_store = None
    assert presence(capture(client, reviewer, case, tombstone).json())["backup"] == "unobserved"
    service.backup_store = configured
    moved.rename(file)
    assert presence(capture(client, reviewer, case, tombstone).json())["backup"] == "reappeared"
    extra = uuid4()
    extra_path = store_copy(file.parent, extra, payload)
    assert enroll(client, reviewer, version, extra).status_code == 200
    later = capture(client, reviewer, case, tombstone).json()
    assert later["additional_registered_count"] == 1 and str(extra) not in str(later)
    assert extra_path.read_bytes() == file.read_bytes() == payload
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_backup_expiry_observation").fetchone() == (1,)


def test_receipts_require_current_independent_scope_and_commit_with_the_event(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), _, (version, *_) = candidate
    connection, tenant, _, source, _ = db
    case = submitted(client, owner, credentials, source, version, expected=1)
    admit(credentials, reviewer, OBSERVE, HOLD)
    route = f"{PATH}/{case['case_id']}/copy-observations"
    assert client.post(route, json={}).status_code == 401
    assert client.post(route, headers=bearer(reviewer), json={}).status_code == 400
    assert capture(client, reviewer, case, uuid4()).status_code == 409
    tombstone = block(client, reviewer, credentials, case)
    admit(credentials, owner, OBSERVE)
    assert capture(client, owner, case, tombstone).status_code == 403
    scoped = credentials[reviewer]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[reviewer] = replace(scoped, space_ref=other_space)
    assert capture(client, reviewer, case, tombstone).status_code == 403
    credentials[reviewer] = scoped
    assert capture(client, reviewer, case, tombstone, inventory_snapshot="0" * 64).status_code == 409
    connection.execute(f"""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_copy_observation_event
        CHECK (event_type <> '{EVENT}') NOT VALID
        """)
    key = str(uuid4())
    assert capture(client, reviewer, case, tombstone, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.disposition_copy_receipt").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_copy_observation_event")
    assert capture(client, reviewer, case, tombstone, key=key).status_code == 200
    assert decide(client, reviewer, version.version_ref).status_code == 200
    assert capture(client, reviewer, case, tombstone, key=key).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.disposition_copy_receipt").fetchone() == (1,)


def test_database_refuses_to_replace_a_sealed_item_with_a_destruction_claim(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), _, (version, *_) = candidate
    connection, tenant, _, source, _ = db
    case = submitted(client, owner, credentials, source, version, expected=1)
    tombstone = block(client, reviewer, credentials, case)
    assert capture(client, reviewer, case, tombstone).status_code == 200
    revision, = connection.execute("SELECT config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,)).fetchone()
    request_id = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request_id, tenant.other_actor_id, None, "synthetic-ui", OBSERVE,
        "internal_lifecycle", date(2026, 11, 22), revision, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation, match="sealed inventory or the expiry evidence"):
        connection.execute("""
            INSERT INTO thalion.disposition_copy_receipt (
                org_id, space_id, case_ref, submitted_by, inventory_snapshot, tombstone_ref, observed_by,
                request_id, copies, additional_registered_count
            )
            SELECT org_id, space_id, case_ref, submitted_by, inventory_snapshot, tombstone_ref, observed_by,
                   %s, jsonb_set(copies, '{0,1}', '"destroyed"'::jsonb), additional_registered_count
            FROM thalion.disposition_copy_receipt
            """, (request_id,))
    assert connection.execute("SELECT count(*) FROM thalion.disposition_copy_receipt").fetchone() == (1,)
