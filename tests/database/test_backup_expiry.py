from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.lifecycle import backup_expiry
from enterprise_kb.modules.lifecycle.backup_inventory import SyntheticBackupStore
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.runtime.audit import RequestStart, start_request

from test_backup_inventory import PATH, REGISTER, backup_inventory, register, store_copy
from test_disposition import plan
from test_disposition_cases import candidate
from test_disposition_verification import original
from test_effectivity import record
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_holds import CAPABILITY as HOLD, decide
from test_runtime import runtime_db
from test_travel_search import corpus


SCHEDULE = "schedule_synthetic_backup_expiry"
OBSERVE = "observe_synthetic_backup_expiry"


@pytest.fixture
def registered_copy(backup_inventory):
    ((client, db, (owner, reviewer), credentials, _, *_), _, (version, *_)), root = backup_inventory
    admit(credentials, owner, SCHEDULE, OBSERVE)
    admit(credentials, reviewer, REGISTER, SCHEDULE, OBSERVE, HOLD)
    backup = uuid4()
    file = store_copy(root, backup, original(db, version).read_bytes())
    assert register(client, reviewer, version, backup).status_code == 200
    return client, db, owner, reviewer, version, backup, file


def withdraw(db, version, *, kind="withdrawn"):
    connection, tenant, *_ = db
    context = record(connection, tenant, "stop_rule_use", str(uuid4()))
    return effectivity.stop_synthetic_rule(connection, context, tenant.space_id, version.version_ref, kind, uuid4())


def withdraw_for_due_backup(db, version):
    connection, tenant, *_ = db
    context = record(connection, tenant, "stop_rule_use", str(uuid4()))
    with connection.transaction():
        connection.execute("""
            ALTER TABLE thalion.rule_use_stop ALTER COLUMN recorded_at
            SET DEFAULT (clock_timestamp() - interval '5 minutes')
        """)
        withdrawal = effectivity.stop_synthetic_rule(
            connection, context, tenant.space_id, version.version_ref, "withdrawn", uuid4(),
        )
        connection.execute("""
            ALTER TABLE thalion.rule_use_stop ALTER COLUMN recorded_at SET DEFAULT clock_timestamp()
        """)
        return connection.execute("""
            SELECT recorded_at + interval '1 minute' FROM thalion.rule_use_stop WHERE decision_ref = %s
        """, (withdrawal,)).fetchone()[0]


def command(client, token, backup, suffix, *, key=None, **body):
    return client.post(f"{PATH}/{backup}/{suffix}", headers=command_headers(token, key), json=body)


def schedule(client, token, backup, expires=None, *, key=None):
    return command(client, token, backup, "expiry-plan", key=key,
                   expected_expiry_at=(expires or datetime.now(UTC)).isoformat())


def database_time(db):
    return db[0].execute("SELECT clock_timestamp()").fetchone()[0]


def observe(client, token, backup, *, key=None):
    return command(client, token, backup, "expiry-observation", key=key)


def inventory(client, owner, version):
    view = plan(client, owner, version.version_ref, reason="withdrawal")
    assert view.status_code == 200, view.text
    body = view.json()
    return body, next(item for item in body["copies"] if item["kind"] == "backup")


def test_expiry_commands_require_credentials_and_idempotency_key(registered_copy):
    client, _, _, reviewer, _, backup, _ = registered_copy
    for suffix in ("expiry-plan", "expiry-observation"):
        url = f"{PATH}/{backup}/{suffix}"
        assert client.post(url, json={}).status_code == 401
        missing_key = client.post(url, headers={"Authorization": f"Bearer {reviewer}"}, json={})
        assert missing_key.status_code == 400 and missing_key.headers["Cache-Control"] == "no-store"


def test_withdrawal_bound_schedule_and_absence_never_mark_destruction(registered_copy):
    client, db, owner, reviewer, version, backup, file = registered_copy
    connection, *_ = db
    assert schedule(client, owner, backup).status_code == 403
    assert schedule(client, reviewer, backup).status_code == 409
    expiry = withdraw_for_due_backup(db, version)
    before, _ = inventory(client, owner, version)
    key = str(uuid4())
    planned = schedule(client, reviewer, backup, expiry, key=key)
    assert planned.status_code == 200, planned.text
    assert planned.json()["restore_prohibited"] is True
    assert planned.json()["state"] == "pending_expiry_verification"
    assert schedule(client, reviewer, backup, expiry, key=key).json()["schedule_id"] == planned.json()["schedule_id"]
    assert schedule(client, reviewer, backup, expiry, key=str(uuid4())).status_code == 409
    pending, known = inventory(client, owner, version)
    assert before["inventory_snapshot"] != pending["inventory_snapshot"]
    assert known["state"] == "backup_expiry_verification_due" and known["restore_prohibited"] is True
    assert str(backup) not in str(pending) and "backup" in pending["unverified_copy_kinds"]
    assert observe(client, reviewer, backup).status_code == 409
    assert file.is_file()
    file.unlink()
    observation_key = str(uuid4())
    observed = observe(client, reviewer, backup, key=observation_key)
    assert observed.status_code == 200, observed.text
    body = observed.json()
    assert body["state"] == "absence_observed" and body["restore_prohibited"] is True and body["executable"] is False
    assert observe(client, reviewer, backup, key=observation_key).json()["observation_id"] == body["observation_id"]
    assert observe(client, reviewer, backup).status_code == 409
    after, known = inventory(client, owner, version)
    assert after["inventory_snapshot"] != pending["inventory_snapshot"]
    assert known["state"] == "backup_absence_observed" and "backup" in after["unverified_copy_kinds"]
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_backup_copy").fetchone() == (1,)


def test_due_time_and_exact_backup_store_are_required(
    registered_copy, evidence_transport, tmp_path_factory, monkeypatch,
):
    client, db, owner, reviewer, version, backup, file = registered_copy
    service, *_ = evidence_transport
    expiry = withdraw_for_due_backup(db, version)
    assert observe(client, reviewer, backup).status_code == 409
    assert schedule(client, reviewer, uuid4()).status_code == 403
    not_due = uuid4()
    early_file = store_copy(file.parent, not_due, original(db, version).read_bytes())
    assert register(client, reviewer, version, not_due).status_code == 200
    assert schedule(client, reviewer, not_due, database_time(db) + timedelta(hours=1)).status_code == 200
    early_file.unlink()
    assert observe(client, reviewer, not_due).status_code == 409
    new_directory = tmp_path_factory.mktemp("different-backup-store")
    new_directory.chmod(0o700)
    previous = service.backup_store
    service.backup_store = SyntheticBackupStore(new_directory, service.store)
    alternate_file = store_copy(new_directory, backup, file.read_bytes())
    assert schedule(client, reviewer, backup, expiry).status_code == 503
    alternate_file.unlink()
    service.backup_store = previous
    rolled_back_time = database_time(db) - timedelta(milliseconds=100)
    assert schedule(client, reviewer, backup, expiry).status_code == 200
    service.backup_store = SyntheticBackupStore(new_directory, service.store)
    lock_target = backup_expiry._lock_target

    def read_clock_after_rollback(connection, call, operation, backup):
        scope, target, (withdrawal, withdrew_at, _) = lock_target(connection, call, operation, backup)
        return scope, target, (withdrawal, withdrew_at, rolled_back_time)

    with monkeypatch.context() as clock:
        clock.setattr(backup_expiry, "_lock_target", read_clock_after_rollback)
        assert observe(client, reviewer, backup).status_code == 503
    service.backup_store = previous
    target = original(db, version)
    file.unlink()
    file.symlink_to(target)
    assert observe(client, reviewer, backup).status_code == 409
    assert file.is_symlink()
    assert any(item["state"] == "backup_expiry_verification_due" for item in inventory(client, owner, version)[0]["copies"])


def test_new_hold_prevents_accepting_later_absence(registered_copy):
    client, db, owner, reviewer, version, backup, file = registered_copy
    expiry = withdraw_for_due_backup(db, version)
    assert schedule(client, reviewer, backup, expiry).status_code == 200
    assert decide(client, reviewer, version.version_ref).status_code == 200
    file.unlink()
    assert observe(client, reviewer, backup).status_code == 409
    _, known = inventory(client, owner, version)
    assert known["state"] == "protected" and known["restore_prohibited"] is True


def test_withdrawal_alone_prohibits_restore_even_without_an_expiry_plan(registered_copy):
    client, db, owner, reviewer, version, backup, _ = registered_copy
    withdraw(db, version, kind="suspended")
    assert "restore_prohibited" not in inventory(client, owner, version)[1]
    assert schedule(client, reviewer, backup, database_time(db)).status_code == 409
    withdraw(db, version)
    _, known = inventory(client, owner, version)
    assert known["state"] == "registered_backup" and known["restore_prohibited"] is True


def test_observation_and_event_are_atomic_and_history_is_immutable(registered_copy):
    client, db, owner, reviewer, version, backup, file = registered_copy
    connection, *_ = db
    expiry = withdraw_for_due_backup(db, version)
    assert schedule(client, reviewer, backup, expiry).status_code == 200
    file.unlink()
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_expiry_event
        CHECK (event_type <> 'lifecycle.synthetic_backup.absence_observed') NOT VALID
    """)
    before, _ = inventory(client, owner, version)
    key = str(uuid4())
    assert observe(client, reviewer, backup, key=key).status_code == 503
    assert inventory(client, owner, version)[0]["inventory_snapshot"] == before["inventory_snapshot"]
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_backup_expiry_observation").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_expiry_event")
    assert observe(client, reviewer, backup, key=key).status_code == 200
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.synthetic_backup_expiry_plan SET expected_expiry_at = now()")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.synthetic_backup_expiry_observation")


def test_database_will_not_accept_an_early_observation_with_a_current_request(registered_copy):
    client, db, _, reviewer, version, backup, _ = registered_copy
    connection, tenant, *_ = db
    withdraw(db, version)
    now = database_time(db)
    planned = schedule(client, reviewer, backup, now + timedelta(hours=1))
    assert planned.status_code == 200, planned.text
    config, = connection.execute("SELECT config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,)).fetchone()
    request = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request, tenant.other_actor_id, None, "synthetic-ui", OBSERVE, "internal_lifecycle",
        now.date(), config, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation, match="not yet due"):
        connection.execute("""
            INSERT INTO thalion.synthetic_backup_expiry_observation (
                org_id, space_id, backup_ref, schedule_ref, observed_at, recorded_by, request_id
            ) VALUES (%s, %s, %s, %s, clock_timestamp() + interval '2 hours', %s, %s)
            """, (tenant.org_id, tenant.space_id, backup, planned.json()["schedule_id"], tenant.other_actor_id, request))
