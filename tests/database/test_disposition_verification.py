from dataclasses import replace
from hashlib import sha256
from uuid import uuid4

from psycopg import errors
import pytest

from test_disposition import configure
from test_disposition_cases import PATH, REJECT, candidate, reject, submit
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_holds import CAPABILITY as HOLD, decide
from test_identity import space
from test_runtime import runtime_db
from test_travel_search import corpus


VERIFY = "verify_disposition_original"


def verification_path(case_id):
    return f"{PATH}/{case_id}/original-verification"


def verify(client, token, case, *, key=None, **changes):
    return client.post(verification_path(case["case_id"]), headers=command_headers(token, key), json={
        "inventory_snapshot": case["inventory_snapshot"], **changes,
    })


def original(db, version):
    connection, _, _, _, store = db
    return store.root / connection.execute("""
        SELECT asset.storage_key FROM thalion.asset AS asset
        JOIN thalion.document_version AS version USING (org_id, space_id, source_id, document_id, asset_id)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (version.org_id, version.space_id, 'document_version', version.version_id)
        WHERE identity.public_id = %s
    """, (version.version_ref,)).fetchone()[0]


def test_original_verification_requires_an_idempotency_key(transport):
    client, _, (owner, _), *_ = transport
    response = client.post(verification_path(uuid4()), headers=bearer(owner), json={})
    assert response.status_code == 400 and response.headers["Cache-Control"] == "no-store"


def test_original_verification_checks_bytes_without_disclosing_them(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    connection, tenant, *_ = db
    case = submit(client, owner, preview).json()
    admit(credentials, owner, VERIFY)
    assert verify(client, owner, case).status_code == 403
    assert verify(client, reviewer, case).status_code == 403
    admit(credentials, reviewer, VERIFY)
    valid = credentials[reviewer]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[reviewer] = replace(valid, space_ref=other_space)
    assert verify(client, reviewer, case).status_code == 403
    credentials[reviewer] = valid

    file = original(db, version)
    payload = file.read_bytes()
    key = str(uuid4())
    response = verify(client, reviewer, case, key=key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    result = response.json()
    assert (result["state"], result["executable"], result["copy_kind"]) == ("verified", False, "original")
    assert set(result) == {
        "case_id", "verification_id", "inventory_snapshot", "observed_at", "copy_kind", "state", "executable", "request_id",
    }
    assert file.name not in response.text and sha256(payload).hexdigest() not in response.text
    assert verify(client, reviewer, case, key=key).json()["verification_id"] == result["verification_id"]
    credentials[reviewer] = replace(valid, operations=valid.operations - {VERIFY})
    assert verify(client, reviewer, case, key=key).status_code == 403
    assert connection.execute("""
        SELECT content_digest, byte_length, observed_by, inventory_snapshot FROM thalion.disposition_original_observation
    """).fetchall() == [(sha256(payload).digest(), len(payload), tenant.other_actor_id, bytes.fromhex(case["inventory_snapshot"]))]
    assert file.read_bytes() == payload
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.disposition_original_observation")


def test_missing_and_tampered_originals_do_not_create_evidence(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    connection, *_ = db
    admit(credentials, reviewer, VERIFY)
    case = submit(client, owner, preview).json()
    file = original(db, version)
    payload = file.read_bytes()
    backup = file.with_name("isolated-test-original")
    file.rename(backup)
    key = str(uuid4())
    assert verify(client, reviewer, case, key=key).status_code == 503
    file.write_bytes(b"!" + payload[1:])
    assert verify(client, reviewer, case, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.disposition_original_observation").fetchone() == (0,)
    backup.replace(file)
    assert verify(client, reviewer, case, key=key).status_code == 200


def test_original_verification_stops_on_stale_or_rejected_case(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, _ = candidate
    connection, _, _, source, _ = db
    admit(credentials, reviewer, VERIFY, REJECT)
    first = submit(client, owner, preview).json()
    assert reject(client, reviewer, first).status_code == 200
    assert verify(client, reviewer, first).status_code == 409
    second = submit(client, owner, preview).json()
    assert configure(client, owner, source, expected=1).status_code == 200
    assert verify(client, reviewer, second).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.disposition_original_observation").fetchone() == (0,)


def test_new_hold_during_file_read_prevents_original_verification(candidate, monkeypatch):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    connection, _, _, _, store = db
    admit(credentials, reviewer, VERIFY, HOLD)
    case = submit(client, owner, preview).json()
    read = store.read
    observed = []

    def read_while_holding(asset):
        payload = read(asset)
        observed.append(decide(client, reviewer, version.version_ref).status_code)
        return payload

    monkeypatch.setattr(store, "read", read_while_holding)
    assert verify(client, reviewer, case).status_code == 409
    assert observed == [200]
    assert connection.execute("SELECT count(*) FROM thalion.disposition_original_observation").fetchone() == (0,)


def test_original_verification_rolls_back_if_event_is_not_durable(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    connection, *_ = db
    admit(credentials, reviewer, VERIFY)
    case = submit(client, owner, preview).json()
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_copy_event
        CHECK (event_type <> 'lifecycle.disposition_original.verified') NOT VALID
    """)
    key = str(uuid4())
    assert verify(client, reviewer, case, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.disposition_original_observation").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_copy_event")
    assert verify(client, reviewer, case, key=key).status_code == 200
    assert connection.execute("""
        SELECT object_ref FROM thalion.outbox_event WHERE event_type = 'lifecycle.disposition_original.verified'
    """).fetchall() == [(version.version_ref,)]
