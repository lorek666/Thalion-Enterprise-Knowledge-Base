from dataclasses import replace
from shutil import copytree
from uuid import UUID, uuid4

from psycopg import OperationalError, errors
import pytest

from enterprise_kb.database import local_connection_factory
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.sources import originals, restriction_log

from test_archive_rebuild import empty_rehearsal, rebuild_bundle
from test_archive_rule_checkpoint import (
    assert_empty, checked_bundle, confirm_unrelated_stop, rebuild, restore_source_authority, rule_log,
)
from test_disposition import configure, plan
from test_disposition_cases import PATH, approve, candidate, reject, submit
from test_disposition_verification import original
from test_effectivity import BEGIN, SWITCH, approve as approve_rule
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_holds import CAPABILITY as HOLD, decide
from test_identity import space
from test_original_export import archive_fixture
from test_persisted_access import authority_for, read
from test_rule_replay import rehearsal_clone
from test_runtime import runtime_db
from test_transcript_export import transcript
from test_travel_search import corpus


REGISTER = "register_deletion_tombstone"
KIND = "deletion_blocked"
EVENT = "lifecycle.deletion_tombstone.registered"


def register(client, token, case, approval_id, *, key=None, **changes):
    return client.post(f"{PATH}/{case['case_id']}/deletion-tombstone", headers=command_headers(token, key), json={
        "approval_id": str(approval_id), "inventory_snapshot": case["inventory_snapshot"], **changes,
    })


def submitted(client, owner, credentials, source, version, *, expected=0):
    admit(credentials, owner, "register_retention_policy", "plan_disposition", "submit_disposition_case")
    assert configure(client, owner, source, action="destroy", expected=expected).status_code == 200
    preview = plan(client, owner, version.version_ref, action="destroy").json()
    assert preview["decision"] == "review_required"
    response = submit(client, owner, preview)
    assert response.status_code == 200, response.text
    return response.json()


def approved(client, reviewer, credentials, case, **kwargs):
    admit(credentials, reviewer, "approve_disposition_case")
    response = approve(client, reviewer, case, **kwargs)
    assert response.status_code == 200, response.text
    return response.json()["decision_id"]


def test_tombstone_is_scoped_and_requires_a_current_destroy_approval(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    connection, tenant, _, source, _ = db
    admit(credentials, reviewer, "reject_disposition_case")
    archive_case, rejected_case = (submit(client, owner, preview).json() for _ in range(2))
    archive_approval = approved(client, reviewer, credentials, archive_case)
    rejected = reject(client, reviewer, rejected_case)
    assert rejected.status_code == 200
    admit(credentials, owner, REGISTER)
    assert register(client, owner, archive_case, archive_approval).status_code == 403
    assert register(client, reviewer, archive_case, archive_approval).status_code == 403
    admit(credentials, reviewer, REGISTER, HOLD)
    assert register(client, reviewer, archive_case, archive_approval).status_code == 409
    assert register(client, reviewer, rejected_case, rejected.json()["decision_id"]).status_code == 409
    case = submitted(client, owner, credentials, source, version, expected=1)
    path = f"{PATH}/{case['case_id']}/deletion-tombstone"
    assert client.post(path, json={}).status_code == 401
    assert client.post(path, headers=bearer(reviewer), json={}).status_code == 400
    assert register(client, reviewer, case, uuid4()).status_code == 409
    approval_id = approved(client, reviewer, credentials, case)
    credential = credentials[reviewer]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[reviewer] = replace(credential, space_ref=other_space)
    assert register(client, reviewer, case, approval_id).status_code == 403
    credentials[reviewer] = credential
    assert register(client, reviewer, case, approval_id, inventory_snapshot="z").status_code == 400
    assert register(client, reviewer, case, uuid4()).status_code == 409
    assert decide(client, reviewer, version.version_ref).status_code == 200
    assert register(client, reviewer, case, approval_id).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.rule_use_stop WHERE kind = %s", (KIND,)).fetchone() == (0,)


def test_tombstone_refuses_an_expired_approval(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), _, (version, *_) = candidate
    connection, _, _, source, _ = db
    admit(credentials, reviewer, REGISTER)
    case = submitted(client, owner, credentials, source, version, expected=1)
    expiry = connection.execute("SELECT clock_timestamp() + interval '3 seconds'").fetchone()[0]
    approval_id = approved(client, reviewer, credentials, case, expiry=expiry)
    connection.execute("SELECT pg_sleep(GREATEST(0, extract(epoch FROM (%s::timestamptz - clock_timestamp()))))", (expiry,))
    stored_expiry, checked_at = connection.execute("""
        SELECT expires_at, clock_timestamp() FROM thalion.disposition_decision WHERE decision_ref = %s
    """, (approval_id,)).fetchone()
    assert stored_expiry == expiry
    assert checked_at >= stored_expiry, f"Sleep ended before stored expiry: {checked_at=} {stored_expiry=}"
    response = register(client, reviewer, case, approval_id)
    if response.status_code != 409:
        after, = connection.execute("SELECT clock_timestamp()").fetchone()
        pytest.fail(f"Expected 409, got {response.status_code}: {checked_at=} {stored_expiry=} {after=}")
    assert connection.execute("SELECT count(*) FROM thalion.rule_use_stop WHERE kind = %s", (KIND,)).fetchone() == (0,)


def test_tombstone_and_event_rollback_together_and_old_archive_cannot_rebuild(checked_bundle, transcript, candidate):
    (client, db, owner, reviewer, *_), version, *_ = transcript
    connection, tenant, _, source, _ = db
    _, _, _, credentials, *_ = candidate[0]
    _, _, _, payload, _, _, log = checked_bundle
    confirm_unrelated_stop(db, log)
    case = submitted(client, owner, credentials, source, version, expected=1)
    approval_id = approved(client, reviewer, credentials, case)
    admit(credentials, reviewer, REGISTER)
    expected_bytes = original(db, version).read_bytes()
    key = str(uuid4())
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_deletion_event
        CHECK (event_type <> 'lifecycle.deletion_tombstone.registered') NOT VALID
    """)
    assert register(client, reviewer, case, approval_id, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.rule_use_stop WHERE kind = %s", (KIND,)).fetchone() == (0,)
    assert restriction_log.verify_replay_input(connection, log, tenant.org_id).status == "verified"
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_deletion_event")
    response = register(client, reviewer, case, approval_id, key=key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    receipt = response.json()
    assert receipt["state"] == "restore_blocked" and receipt["executable"] is False
    tombstone = UUID(receipt["tombstone_id"])
    assert register(client, reviewer, case, approval_id, key=key).json()["tombstone_id"] == str(tombstone)
    assert register(client, reviewer, case, approval_id).status_code == 409
    assert register(client, reviewer, case, uuid4(), key=key).status_code == 409
    assert plan(client, owner, version.version_ref, action="destroy").json()["decision"] == "restore_blocked"
    assert connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone() == (payload,)
    assert original(db, version).read_bytes() == expected_bytes
    assert connection.execute("SELECT object_ref FROM thalion.outbox_event WHERE event_type = %s", (EVENT,)).fetchall() == [
        (version.version_ref,),
    ]
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.rule_use_stop WHERE decision_ref = %s", (tombstone,))
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="could not be verified"):
        rebuild(checked_bundle, connection)
    assert_empty(checked_bundle)
    assert restriction_log.deliver_pending(connection, log, tenant.org_id).confirmed == (tombstone,)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="blocks an archived version"):
        rebuild(checked_bundle, connection)
    assert_empty(checked_bundle)


def test_old_snapshot_replays_tombstone_without_importing_approval_or_reopening_service(
    candidate, rule_log, postgres_server, tmp_path_factory,
):
    (client, db, (owner, reviewer), credentials, _, retained, _), _, (version, passage, _) = candidate
    connection, tenant, source_url, source, store = db
    approve_rule(connection, tenant, version, BEGIN, end=SWITCH)
    scratch = tmp_path_factory.mktemp("pre-deletion-snapshot")
    staged_store = originals.SyntheticOriginalStore(copytree(store.root, scratch / "originals"))
    authority = authority_for({tenant.actor_id})
    with rehearsal_clone(connection, source_url, postgres_server) as (primary, staged, staged_url):
        staged_db = (staged, tenant, staged_url, source, staged_store)
        assert read(staged_db, passage, tenant.actor_id, authority).payload is not None
        case = submitted(client, owner, credentials, source, version, expected=1)
        approval_id = approved(client, reviewer, credentials, case)
        admit(credentials, reviewer, REGISTER)
        registered = register(client, reviewer, case, approval_id)
        assert registered.status_code == 200, registered.text
        tombstone = UUID(registered.json()["tombstone_id"])
        assert read((primary, tenant, source_url, source, store), passage, tenant.actor_id, authority).payload is None
        assert restriction_log.rehearse_replay(primary, rule_log, staged, tenant.org_id).status == "closed"
        assert restriction_log.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (tombstone,)
        replayed = restriction_log.rehearse_replay(primary, rule_log, staged, tenant.org_id)
        assert (replayed.status, replayed.applied) == ("replayed", (tombstone,))
        assert restriction_log.rehearse_replay(primary, rule_log, staged, tenant.org_id).applied == ()
        assert staged.execute("SELECT count(*) FROM thalion.disposition_decision").fetchone() == (0,)
        assert read(staged_db, passage, tenant.actor_id, authority).payload is None
        assert read(staged_db, retained, tenant.actor_id, authority).payload is not None
        assert original(staged_db, version).read_bytes() == original(
            (primary, tenant, source_url, source, store), version,
        ).read_bytes()
        with pytest.raises(OperationalError, match="rehearsal"):
            local_connection_factory(staged_url)()
