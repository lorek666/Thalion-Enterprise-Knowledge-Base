from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

from psycopg import errors
import pytest

from enterprise_kb.database import upgrade
from enterprise_kb.modules.lifecycle import disposition
from enterprise_kb.modules.operations.context import OperationsCall
from enterprise_kb.runtime.audit import RequestStart, start_request

from test_disposition import configure, plan, versions
from test_evidence import create_evidence_db, evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_holds import CAPABILITY as HOLD, decide
from test_identity import migrate_to_revision, space
from test_runtime import open_database, register_tenant, runtime_db
from test_travel_search import corpus, publish


PATH = "/internal/lifecycle/disposition-cases"
SUBMIT = "submit_disposition_case"
REJECT = "reject_disposition_case"
APPROVE = "approve_disposition_case"


def submit(client, token, preview, *, key=None, **changes):
    return client.post(PATH, headers=command_headers(token, key), json={
        name: preview[name] for name in ("version_id", "action", "reason", "inventory_snapshot")
    } | changes)


def reject(client, token, case, *, key=None, basis=None, **changes):
    return client.post(f"{PATH}/{case['case_id']}/rejection", headers=command_headers(token, key), json={
        "inventory_snapshot": case["inventory_snapshot"], "basis_id": str(basis or uuid4()), **changes,
    })


def approve(client, token, case, *, key=None, basis=None, expiry=None, **changes):
    return client.post(f"{PATH}/{case['case_id']}/approval", headers=command_headers(token, key), json={
        "inventory_snapshot": case["inventory_snapshot"], "basis_id": str(basis or uuid4()),
        "expires_at": (expiry or datetime.now(UTC) + timedelta(minutes=5)).isoformat(), **changes,
    })


def test_disposition_commands_require_identity_and_an_idempotency_key(transport):
    client, _, (owner, _), *_ = transport
    for path in (PATH, f"{PATH}/{uuid4()}/rejection", f"{PATH}/{uuid4()}/approval"):
        assert client.post(path, json={}).status_code == 401
        invalid = client.post(path, headers=bearer(owner), json={})
        assert invalid.status_code == 400 and invalid.headers["Cache-Control"] == "no-store"


@pytest.fixture
def candidate(transport):
    client, db, (owner, _), credentials, _, *_ = transport
    _, _, _, source, _ = db
    admit(credentials, owner, "register_retention_policy", "plan_disposition", SUBMIT)
    version, passage, run = publish(db, "disposition-case", "合成处置申请", b"# Local\n\nSynthetic plan.\n")
    assert configure(client, owner, source).status_code == 200
    preview = plan(client, owner, version.version_ref).json()
    assert preview["decision"] == "review_required"
    return transport, preview, (version, passage, run)


def test_submission_seals_exact_inventory_without_changing_sources(candidate):
    (client, db, (owner, employee), credentials, _, *_), preview, (version, passage, run) = candidate
    connection, _, _, _, store = db
    before = {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()}
    admit(credentials, employee, SUBMIT)
    assert submit(client, employee, preview).status_code == 403
    stable_key = str(uuid4())
    response = submit(client, owner, preview, key=stable_key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    case = response.json()
    assert case["state"] == "submitted" and case["executable"] is False
    assert case["inventory_snapshot"] == preview["inventory_snapshot"]
    assert str(run.run_ref) not in response.text and str(passage.passage_ref) not in response.text
    assert submit(client, owner, preview, key=stable_key).json()["case_id"] == case["case_id"]
    assert submit(client, owner, preview, key=stable_key, action="destroy").status_code == 409
    sealed, digest = connection.execute("SELECT inventory_material, inventory_snapshot FROM thalion.disposition_case").fetchone()
    assert sha256(sealed).digest() == digest == bytes.fromhex(preview["inventory_snapshot"])
    assert str(run.run_ref).encode() in sealed and b'transcription' in sealed
    assert {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()} == before
    assert plan(client, owner, version.version_ref).json()["inventory_snapshot"] == preview["inventory_snapshot"]
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.disposition_case")


def test_submission_revalidates_the_preview_and_will_not_file_protected_material(candidate):
    (client, db, (owner, _), _, _, *_), preview, _ = candidate
    connection, _, _, source, _ = db
    wrong = "0" * 64 if preview["inventory_snapshot"] != "0" * 64 else "1" * 64
    assert submit(client, owner, preview, inventory_snapshot=wrong).status_code == 409
    protected_version = versions(connection)[0]
    protected = plan(client, owner, protected_version).json()
    assert protected["decision"] == "protected" and submit(client, owner, protected).status_code == 409
    assert configure(client, owner, source, expected=1, days=30).status_code == 200
    assert submit(client, owner, preview).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.disposition_case").fetchone() == (0,)


def test_database_refuses_a_mismatched_seal_or_request(candidate):
    (client, db, (owner, _), _, _, *_), preview, _ = candidate
    connection, tenant, *_ = db
    case = submit(client, owner, preview).json()
    configuration, = connection.execute(
        "SELECT config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,),
    ).fetchone()
    clone = """
        INSERT INTO thalion.disposition_case (
            org_id, space_id, source_id, contract_revision, version_id, policy_revision, action, reason,
            inventory_material, inventory_snapshot, submitted_by, request_id
        )
        SELECT org_id, space_id, source_id, contract_revision, version_id, policy_revision, action, reason,
               inventory_material || %s::bytea, inventory_snapshot, submitted_by, %s
        FROM thalion.disposition_case WHERE case_ref = %s
    """
    with pytest.raises(errors.CheckViolation, match="matching request"):
        connection.execute(clone, (b"", case["request_id"], case["case_id"]))
    request = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request, tenant.actor_id, None, "synthetic-ui", SUBMIT, "internal_lifecycle",
        date(2026, 11, 21), configuration, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation) as mismatch:
        connection.execute(clone, (b"changed", request, case["case_id"]))
    assert mismatch.value.diag.constraint_name == "disposition_case_inventory_digest"
    assert connection.execute("SELECT count(*) FROM thalion.disposition_case").fetchone() == (1,)


def test_independent_rejection_is_scoped_current_and_applied_once(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, _ = candidate
    connection, tenant, *_ = db
    case = submit(client, owner, preview).json()
    admit(credentials, owner, REJECT)
    assert reject(client, owner, case).status_code == 403
    assert reject(client, reviewer, case).status_code == 403
    admit(credentials, reviewer, REJECT)
    original = credentials[reviewer]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[reviewer] = replace(original, space_ref=other_space)
    assert reject(client, reviewer, case).status_code == 403
    credentials[reviewer] = original
    assert reject(client, reviewer, case, action="approve").status_code == 400
    assert reject(client, reviewer, case, inventory_snapshot="x").status_code == 400
    stable_key, basis = str(uuid4()), uuid4()
    response = reject(client, reviewer, case, key=stable_key, basis=basis)
    assert response.status_code == 200 and response.json()["state"] == "rejected"
    assert response.json()["executable"] is False
    assert reject(client, reviewer, case, key=stable_key, basis=basis).json()["decision_id"] == response.json()["decision_id"]
    credentials[reviewer] = replace(original, operations=original.operations - {REJECT})
    assert reject(client, reviewer, case, key=stable_key, basis=basis).status_code == 403
    credentials[reviewer] = original
    assert reject(client, reviewer, case, key=stable_key).status_code == 409
    assert reject(client, reviewer, case).status_code == 409
    assert connection.execute("SELECT decided_by FROM thalion.disposition_rejection").fetchall() == [(tenant.other_actor_id,)]
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.disposition_rejection SET basis_ref = gen_random_uuid()")


def test_rejection_fails_if_scope_changes_before_review(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, _ = candidate
    connection, _, _, source, _ = db
    case = submit(client, owner, preview).json()
    admit(credentials, reviewer, REJECT)
    assert configure(client, owner, source, expected=1).status_code == 200
    assert reject(client, reviewer, case).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.disposition_rejection").fetchone() == (0,)


def test_case_and_decision_write_atomically_with_outbox(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    connection, *_ = db
    admit(credentials, reviewer, REJECT)
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_case_event
        CHECK (event_type NOT IN ('lifecycle.disposition_case.submitted', 'lifecycle.disposition_case.rejected')) NOT VALID
    """)
    key = str(uuid4())
    assert submit(client, owner, preview, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.disposition_case").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_case_event")
    case = submit(client, owner, preview, key=key).json()
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_rejection_event
        CHECK (event_type <> 'lifecycle.disposition_case.rejected') NOT VALID
    """)
    assert reject(client, reviewer, case).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.disposition_rejection").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_rejection_event")
    with ThreadPoolExecutor(max_workers=2) as workers:
        pending = [workers.submit(reject, client, reviewer, case) for _ in range(2)]
        assert sorted(attempt.result(timeout=10).status_code for attempt in pending) == [200, 409]
    assert set(connection.execute("""
        SELECT event_type, object_ref FROM thalion.outbox_event
        WHERE event_type LIKE 'lifecycle.disposition_case.%'
    """).fetchall()) == {
        ("lifecycle.disposition_case.submitted", version.version_ref),
        ("lifecycle.disposition_case.rejected", version.version_ref),
    }


def test_approval_requires_current_independent_reviewer_and_expires_without_granting_execution(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, _ = candidate
    connection, tenant, _, _, store = db
    before = {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()}
    case = submit(client, owner, preview).json()
    admit(credentials, owner, APPROVE)
    assert approve(client, owner, case).status_code == 403
    admit(credentials, reviewer, REJECT)
    assert approve(client, reviewer, case).status_code == 403
    admit(credentials, reviewer, APPROVE)
    original = credentials[reviewer]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[reviewer] = replace(original, space_ref=other_space)
    assert approve(client, reviewer, case).status_code == 403
    credentials[reviewer] = original
    assert approve(client, reviewer, case, basis_id=None).status_code == 400
    assert approve(client, reviewer, case, expires_at="2026-11-22T12:00:00").status_code == 400
    assert approve(client, reviewer, case, expiry=datetime.now(UTC) + timedelta(hours=1)).status_code == 400
    assert approve(client, reviewer, case, expiry=datetime.now(UTC) - timedelta(minutes=1)).status_code == 409
    wrong = "0" * 64 if case["inventory_snapshot"] != "0" * 64 else "1" * 64
    assert approve(client, reviewer, case, inventory_snapshot=wrong).status_code == 409
    key, basis = str(uuid4()), uuid4()
    expiry, = connection.execute("SELECT clock_timestamp() + interval '3 seconds'").fetchone()
    response = approve(client, reviewer, case, key=key, basis=basis, expiry=expiry)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    decision = response.json()
    assert decision == {
        "request_id": decision["request_id"], "case_id": case["case_id"], "decision_id": decision["decision_id"],
        "inventory_snapshot": case["inventory_snapshot"], "state": "approved",
        "expires_at": expiry.astimezone(UTC).isoformat(), "executable": False,
    }
    assert approve(client, reviewer, case, key=key, basis=basis, expiry=expiry).json()["decision_id"] == decision["decision_id"]
    assert approve(client, reviewer, case, key=key, expiry=expiry).status_code == 409
    credentials[reviewer] = replace(original, operations=original.operations - {APPROVE})
    assert approve(client, reviewer, case, key=key, basis=basis, expiry=expiry).status_code == 403
    credentials[reviewer] = original
    connection.execute("SELECT pg_sleep(GREATEST(0, extract(epoch FROM (%s::timestamptz - clock_timestamp()))))", (expiry,))
    assert approve(client, reviewer, case, key=key, basis=basis, expiry=expiry).status_code == 409
    assert reject(client, reviewer, case).status_code == 409
    assert connection.execute("""
        SELECT outcome, inventory_snapshot, decided_by, basis_ref, expires_at
        FROM thalion.disposition_decision
    """).fetchall() == [("approved", bytes.fromhex(case["inventory_snapshot"]), tenant.other_actor_id, basis, expiry)]
    assert {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()} == before
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.disposition_decision SET expires_at = expires_at + interval '1 minute'")


def test_approval_refuses_stale_inventory_before_decision_and_on_replay(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    _, _, _, source, _ = db
    admit(credentials, reviewer, APPROVE, HOLD)
    stale = submit(client, owner, preview).json()
    assert configure(client, owner, source, expected=1).status_code == 200
    assert approve(client, reviewer, stale).status_code == 409
    updated = plan(client, owner, version.version_ref).json()
    case = submit(client, owner, updated).json()
    pending = submit(client, owner, updated).json()
    command = {"key": str(uuid4()), "basis": uuid4(), "expiry": datetime.now(UTC) + timedelta(minutes=5)}
    assert approve(client, reviewer, case, **command).status_code == 200
    assert decide(client, reviewer, version.version_ref).status_code == 200
    assert approve(client, reviewer, pending).status_code == 409
    assert approve(client, reviewer, case, **command).status_code == 409
    assert decide(client, reviewer, version.version_ref, action="release", generation=1).status_code == 200
    assert approve(client, reviewer, case, **command).status_code == 409


def test_approval_and_rejection_are_mutually_exclusive_and_approval_rolls_back_with_event(candidate):
    (client, db, (owner, reviewer), credentials, _, *_), preview, (version, *_) = candidate
    connection, *_ = db
    admit(credentials, reviewer, APPROVE, REJECT)
    case = submit(client, owner, preview).json()
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_approval_event
        CHECK (event_type <> 'lifecycle.disposition_case.approved') NOT VALID
    """)
    command = {"key": str(uuid4()), "basis": uuid4(), "expiry": datetime.now(UTC) + timedelta(minutes=5)}
    assert approve(client, reviewer, case, **command).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.disposition_decision").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_approval_event")
    with ThreadPoolExecutor(max_workers=2) as workers:
        approval = workers.submit(approve, client, reviewer, case, **command)
        rejection = workers.submit(reject, client, reviewer, case)
        assert sorted(attempt.result(timeout=10).status_code for attempt in (approval, rejection)) == [200, 409]
    winner = next(attempt.result().json() for attempt in (approval, rejection) if attempt.result().status_code == 200)
    assert connection.execute("SELECT outcome FROM thalion.disposition_decision").fetchall() == [(winner["state"],)]
    assert connection.execute("""
        SELECT event_type, object_ref FROM thalion.outbox_event
        WHERE event_type IN ('lifecycle.disposition_case.approved', 'lifecycle.disposition_case.rejected')
    """).fetchall() == [(f"lifecycle.disposition_case.{winner['state']}", version.version_ref)]


def test_upgrade_preserves_legacy_rejection_as_the_only_decision(database_url, tmp_path):
    migrate_to_revision(database_url, "0040_archive_source_checkpoint")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Legacy disposition")
        db = create_evidence_db(connection, tenant, database_url, tmp_path)
        _, _, _, source, _ = db
        version, *_ = publish(db, "legacy-disposition", "旧处置申请", b"# Local\n\nLegacy disposition.\n")
        revision, = connection.execute(
            "SELECT config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,),
        ).fetchone()

        def open_call(operation, actor):
            request = uuid4()
            start_request(connection, RequestStart(
                tenant.org_id, request, actor, None, "synthetic-ui", operation, "internal_lifecycle",
                date(2026, 11, 22), revision, space_id=tenant.space_id,
            ))
            return OperationsCall(tenant.org_id, tenant.space_id, actor, request, str(uuid4()), revision)

        disposition.register_retention_policy(
            connection, open_call(disposition.REGISTER, tenant.actor_id), source, 0, 0, "archive", uuid4(),
        )
        material = b"sealed inventory from the legacy disposition fixture"
        snapshot = sha256(material).digest()
        case_ref, = connection.execute("""
            INSERT INTO thalion.disposition_case (
                org_id, space_id, source_id, contract_revision, version_id, policy_revision, action, reason,
                inventory_material, inventory_snapshot, submitted_by, request_id
            )
            SELECT version.org_id, version.space_id, version.source_id, source.contract_revision, version.version_id,
                   1, 'archive', 'retention_expiry', %s, %s, %s, %s
            FROM thalion.document_version AS version
            JOIN thalion.source AS source USING (org_id, space_id, source_id)
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                 (version.org_id, version.space_id, 'document_version', version.version_id)
            WHERE identity.public_id = %s
            RETURNING case_ref
            """, (material, snapshot, tenant.actor_id, open_call(SUBMIT, tenant.actor_id).request_id, version.version_ref),
        ).fetchone()
        original = connection.execute("""
            INSERT INTO thalion.disposition_rejection (
                org_id, space_id, case_ref, inventory_snapshot, submitted_by, decided_by, request_id, basis_ref
            )
            SELECT org_id, space_id, case_ref, inventory_snapshot, submitted_by, %s, %s, %s
            FROM thalion.disposition_case WHERE case_ref = %s
            RETURNING decision_ref, recorded_at
            """, (tenant.other_actor_id, open_call(REJECT, tenant.other_actor_id).request_id, uuid4(), case_ref),
        ).fetchone()

        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert connection.execute("""
            SELECT inventory_material, inventory_snapshot FROM thalion.disposition_case WHERE case_ref = %s
            """, (case_ref,)).fetchone() == (material, snapshot)
        assert connection.execute("SELECT decision_ref, recorded_at FROM thalion.disposition_rejection").fetchall() == [original]
        approval_call = open_call(APPROVE, tenant.other_actor_id)
        with pytest.raises(disposition.DispositionConflict, match="inventory changed"):
            disposition.decide_disposition_case(
                connection, approval_call, case_ref, snapshot, uuid4(),
                datetime.now(UTC) + timedelta(minutes=5),
            )
        with pytest.raises(errors.UniqueViolation):
            connection.execute("""
                INSERT INTO thalion.disposition_decision (
                    org_id, space_id, case_ref, inventory_snapshot, submitted_by, decided_by, request_id, basis_ref,
                    outcome, expires_at
                )
                SELECT org_id, space_id, case_ref, inventory_snapshot, submitted_by, %s, %s, %s,
                       'approved', statement_timestamp() + interval '5 minutes'
                FROM thalion.disposition_case WHERE case_ref = %s
                """, (tenant.other_actor_id, approval_call.request_id, uuid4(), case_ref))
        assert connection.execute("SELECT outcome, expires_at FROM thalion.disposition_decision").fetchall() == [("rejected", None)]
