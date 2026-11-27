from dataclasses import replace
from datetime import date
from hashlib import sha256
from uuid import uuid4

from psycopg import errors
import pytest

from enterprise_kb.runtime.audit import RequestStart, start_request

from test_disposition import plan
from test_disposition_cases import REJECT, candidate, reject, submit
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_holds import CAPABILITY as HOLD, decide
from test_identity import space
from test_runtime import runtime_db
from test_travel_search import corpus


PATH = "/internal/lifecycle/backup-copies"
REGISTER = "register_synthetic_backup_copy"


def register(client, token, version, backup, *, key=None):
    return client.post(PATH, headers=command_headers(token, key), json={
        "version_id": str(version.version_ref), "backup_id": str(backup),
    })


def test_backup_registration_has_a_protected_command_boundary(transport):
    client, _, (owner, _), *_ = transport
    assert client.post(PATH, json={}).status_code == 401
    response = client.post(PATH, headers=bearer(owner), json={})
    assert response.status_code == 400 and response.headers["Cache-Control"] == "no-store"


@pytest.fixture
def backup_inventory(candidate, evidence_transport, tmp_path_factory):
    from enterprise_kb.modules.lifecycle.backup_inventory import SyntheticBackupStore

    service, *_ = evidence_transport
    root = tmp_path_factory.mktemp("separate-backups")
    root.chmod(0o700)
    service.backup_store = SyntheticBackupStore(root, service.store)
    return candidate, root


def store_copy(root, backup, payload):
    file = root / sha256(backup.bytes).hexdigest()
    file.write_bytes(payload)
    file.chmod(0o400)
    return file


def test_verified_backup_enrollment_changes_only_the_exact_version_inventory(backup_inventory):
    ((client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_)), root = backup_inventory
    connection, tenant, *_ = db
    admit(credentials, owner, REGISTER)
    admit(credentials, reviewer, REGISTER, REJECT)
    case = submit(client, owner, preview).json()
    backup = uuid4()
    payload = original(db, version).read_bytes()
    file = store_copy(root, backup, payload)
    assert register(client, owner, version, backup).status_code == 403
    scoped = credentials[reviewer]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[reviewer] = replace(scoped, space_ref=other_space)
    assert register(client, reviewer, version, backup).status_code == 403
    credentials[reviewer] = scoped
    other, = connection.execute("""
        SELECT public_id FROM thalion.object_identity WHERE object_type = 'document_version' AND public_id <> %s LIMIT 1
    """, (version.version_ref,)).fetchone()
    unrelated_before = plan(client, owner, other).json()["inventory_snapshot"]

    key = str(uuid4())
    enrolled = register(client, reviewer, version, backup, key=key)
    assert enrolled.status_code == 200 and enrolled.headers["Cache-Control"] == "no-store"
    assert enrolled.json() == {"backup_id": str(backup), "state": "registered", "executable": False,
                               "request_id": enrolled.json()["request_id"]}
    assert file.name not in enrolled.text and sha256(payload).hexdigest() not in enrolled.text
    assert register(client, reviewer, version, backup, key=key).status_code == 200
    assert register(client, reviewer, version, uuid4(), key=key).status_code == 409
    assert register(client, reviewer, version, backup).status_code == 409
    credentials[reviewer] = replace(scoped, operations=scoped.operations - {REGISTER})
    assert register(client, reviewer, version, backup, key=key).status_code == 403
    credentials[reviewer] = scoped
    updated = plan(client, owner, version.version_ref)
    assert updated.json()["inventory_snapshot"] != preview["inventory_snapshot"]
    assert [(copy["kind"], copy["state"]) for copy in updated.json()["copies"] if copy["kind"] == "backup"] == [
        ("backup", "registered_backup"),
    ]
    assert str(backup) not in updated.text and "backup" in updated.json()["unverified_copy_kinds"]
    assert plan(client, owner, other).json()["inventory_snapshot"] == unrelated_before
    assert reject(client, reviewer, case).status_code == 409
    assert file.read_bytes() == payload
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.synthetic_backup_copy")


def test_unavailable_wrong_or_aliased_backup_is_not_registered(backup_inventory):
    ((client, db, (_, reviewer), credentials, _, *_), _, (version, *_)), root = backup_inventory
    connection, *_ = db
    admit(credentials, reviewer, REGISTER)
    backup = uuid4()
    key = str(uuid4())
    assert register(client, reviewer, version, backup, key=key).status_code == 503
    source = original(db, version)
    payload = source.read_bytes()
    file = store_copy(root, backup, b"!" + payload[1:])
    assert register(client, reviewer, version, backup, key=key).status_code == 503
    file.unlink()
    file.hardlink_to(source)
    assert register(client, reviewer, version, backup, key=key).status_code == 503
    file.unlink()
    file.symlink_to(source)
    assert register(client, reviewer, version, backup, key=key).status_code == 503
    file.unlink()
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_backup_copy").fetchone() == (0,)
    store_copy(root, backup, payload)
    assert register(client, reviewer, version, backup, key=key).status_code == 200


def test_recording_existing_backup_does_not_override_a_hold(backup_inventory):
    ((client, db, (owner, reviewer), credentials, _, *_), _, (version, *_)), root = backup_inventory
    admit(credentials, reviewer, REGISTER, HOLD)
    assert decide(client, reviewer, version.version_ref).status_code == 200
    backup = uuid4()
    store_copy(root, backup, original(db, version).read_bytes())
    assert register(client, reviewer, version, backup).status_code == 200
    current = plan(client, owner, version.version_ref).json()
    assert current["decision"] == "protected" and current["executable"] is False
    assert [item["state"] for item in current["copies"] if item["kind"] == "backup"] == ["protected"]


def test_backup_store_not_configured_fails_closed(candidate):
    (client, _, (_, reviewer), credentials, _, *_), _, (version, *_) = candidate
    admit(credentials, reviewer, REGISTER)
    assert register(client, reviewer, version, uuid4()).status_code == 503


def test_backup_registry_checks_the_open_request_and_exact_asset(backup_inventory):
    ((client, db, (_, reviewer), credentials, _, *_), _, (version, *_)), root = backup_inventory
    connection, tenant, *_ = db
    admit(credentials, reviewer, REGISTER)
    backup = uuid4()
    store_copy(root, backup, original(db, version).read_bytes())
    registered = register(client, reviewer, version, backup).json()
    configuration, = connection.execute("SELECT config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,)).fetchone()
    clone = """
        INSERT INTO thalion.synthetic_backup_copy (
            org_id, space_id, version_id, backup_ref, asset_id, content_digest, byte_length, recorded_by, request_id
        )
        SELECT org_id, space_id, version_id, gen_random_uuid(), asset_id, content_digest, byte_length + 1, recorded_by, %s
        FROM thalion.synthetic_backup_copy WHERE backup_ref = %s
    """
    with pytest.raises(errors.CheckViolation, match="matching request and exact asset"):
        connection.execute(clone, (registered["request_id"], backup))
    request = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request, tenant.other_actor_id, None, "synthetic-ui", REGISTER, "internal_lifecycle",
        date(2026, 11, 21), configuration, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation, match="matching request and exact asset"):
        connection.execute(clone, (request, backup))
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_backup_copy").fetchone() == (1,)


def test_backup_registration_rolls_back_if_event_fails(backup_inventory):
    ((client, db, (_, reviewer), credentials, _, *_), _, (version, *_)), root = backup_inventory
    connection, *_ = db
    admit(credentials, reviewer, REGISTER)
    backup = uuid4()
    store_copy(root, backup, original(db, version).read_bytes())
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_backup_event
        CHECK (event_type <> 'lifecycle.synthetic_backup.registered') NOT VALID
    """)
    key = str(uuid4())
    assert register(client, reviewer, version, backup, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_backup_copy").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_backup_event")
    assert register(client, reviewer, version, backup, key=key).status_code == 200
    assert connection.execute("""
        SELECT object_ref FROM thalion.outbox_event WHERE event_type = 'lifecycle.synthetic_backup.registered'
    """).fetchall() == [(version.version_ref,)]
