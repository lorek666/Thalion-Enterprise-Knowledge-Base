from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade

from test_evidence import create_evidence_db, evidence_db, register_markdown
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_identity import migrate_to_revision
from test_ingest_transport import MARKDOWN, file, upload
from test_runtime import open_database, register_tenant, runtime_db
from test_travel_search import corpus


def path(document):
    return f"/internal/sources/documents/{document}/responsibility"


def decide(client, token, document, arguments, key=None):
    return client.post(path(document), headers=command_headers(token, key), json=arguments)


def upload_document(client, source, owner, credentials):
    admit(credentials, owner, "upload_source_batch")
    result = upload(client, owner, source, [file("owner.md", "Synthetic owner", "A", "owner", MARKDOWN)])
    assert result.status_code == 200
    return result.json()["files"][0]


def test_document_responsibility_survives_new_versions_but_does_not_change_read_rights(transport):
    client, db, (owner, other), credentials, _, _, restricted = transport
    connection, tenant, _, source, _ = db
    doc = upload_document(client, source, owner, credentials)
    document = doc["document_id"]
    forbidden = client.get(path(document), headers=bearer(owner))
    assert forbidden.status_code == 403
    admit(credentials, owner, "read_document_responsibility", "set_document_responsibility")
    admit(credentials, other, "read_document_responsibility", "set_document_responsibility")
    current = client.get(path(document), headers=bearer(owner))
    assert current.status_code == 200 and current.headers["Cache-Control"] == "no-store"
    assert current.json() == {"request_id": current.json()["request_id"], "document_id": document, "generation": 0,
                              "responsible_id": None, "state": "unassigned", "expires_at": None}
    subject = str(credentials[other].employee_ref)
    command = {"expected_generation": 0, "responsible_id": subject, "basis_id": str(uuid4())}
    key = str(uuid4())
    policy_before = connection.execute("SELECT safety_epoch, local_policy_revision FROM thalion.source").fetchall()
    assert decide(client, other, document, command).status_code == 403
    assigned = decide(client, owner, document, command, key)
    assert assigned.status_code == 200 and assigned.headers["Cache-Control"] == "no-store"
    receipt = assigned.json()
    assert set(receipt) == {"request_id", "assignment_id", "generation"} and receipt["generation"] == 1
    assert decide(client, owner, document, command, key).json()["assignment_id"] == receipt["assignment_id"]
    assert decide(client, owner, document, command).status_code == 409
    assert client.get(path(document), headers=bearer(other)).status_code == 403
    assert client.get(f"/v1/passages/{restricted.passage_ref}", headers=bearer(other)).status_code == 404
    continued = upload(client, owner, source, [file("owner.md", "Synthetic owner", "B", "owner", MARKDOWN)])
    assert continued.status_code == 200 and continued.json()["files"][0]["document_id"] == document
    assert continued.json()["files"][0]["version_id"] != doc["version_id"]
    current = client.get(path(document), headers=bearer(owner)).json()
    assert (current["generation"], current["responsible_id"], current["state"]) == (1, subject, "assigned")
    revoked = decide(client, owner, document, command | {"expected_generation": 1, "responsible_id": None})
    assert revoked.status_code == 200 and revoked.json()["generation"] == 2
    assert decide(client, owner, document, command, key).json()["assignment_id"] == receipt["assignment_id"]
    current = client.get(path(document), headers=bearer(owner)).json()
    assert (current["generation"], current["responsible_id"], current["state"]) == (2, None, "unassigned")
    assert connection.execute("SELECT safety_epoch, local_policy_revision FROM thalion.source").fetchall() == policy_before
    assert connection.execute("""
        SELECT operation, destination, scope_space_id, outcome FROM thalion.request_record WHERE request_id = %s
    """, (receipt["request_id"],)).fetchone() == ("set_document_responsibility", "internal_sources", tenant.space_id, "succeeded")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.responsibility_assignment SET basis_ref = %s", (uuid4(),))
    with pytest.raises(errors.CheckViolation):
        connection.execute("""
            INSERT INTO thalion.responsibility_assignment (
                org_id, space_id, source_id, document_id, generation, responsible_id, approved_by, basis_ref, request_id
            ) SELECT org_id, space_id, source_id, document_id, 3, responsible_id, approved_by, basis_ref, request_id
              FROM thalion.responsibility_assignment WHERE assignment_ref = %s
        """, (receipt["assignment_id"],))


def test_responsibility_rejects_unscoped_subjects_and_reports_inactive_and_expired_assignments(transport):
    client, db, (owner, other), credentials, *_ = transport
    connection, tenant, _, source, _ = db
    admit(credentials, owner, "read_document_responsibility", "set_document_responsibility")
    document = upload_document(client, source, owner, credentials)["document_id"]
    other_tenant = register_tenant(connection, "Other organization")
    foreign_employee, = connection.execute("""
        SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s
    """, (other_tenant.actor_id,)).fetchone()
    subject = str(credentials[other].employee_ref)
    command = {"expected_generation": 0, "responsible_id": subject, "basis_id": str(uuid4())}
    assert decide(client, owner, uuid4(), command).status_code == 403
    assert decide(client, owner, document, command | {"responsible_id": str(foreign_employee)}).status_code == 403
    assert decide(client, owner, document, command | {"expires_at": "2026-11-23T00:00:00"}).status_code == 400
    assert decide(client, owner, document, command | {"expires_at": "2020-01-01T00:00:00Z"}).status_code == 400
    assert decide(client, owner, document, command | {"expected_generation": True}).status_code == 400
    assert decide(client, owner, document, command).status_code == 200
    connection.execute("UPDATE thalion.principal SET disabled = true WHERE principal_id = %s", (tenant.other_actor_id,))
    current = client.get(path(document), headers=bearer(owner)).json()
    assert (current["generation"], current["responsible_id"], current["state"]) == (1, None, "inactive")
    assert decide(client, owner, document, command | {"expected_generation": 1}).status_code == 403
    expires_at, = connection.execute("SELECT clock_timestamp() + interval '2 seconds'").fetchone()
    updated = decide(client, owner, document, command | {"expected_generation": 1,
        "responsible_id": str(credentials[owner].employee_ref), "expires_at": expires_at.isoformat()})
    assert updated.status_code == 200
    connection.execute("SELECT pg_sleep(greatest(0, extract(epoch FROM %s::timestamptz - clock_timestamp())))", (expires_at,))
    current = client.get(path(document), headers=bearer(owner)).json()
    assert (current["generation"], current["responsible_id"], current["state"]) == (2, None, "expired")
    connection.execute("UPDATE thalion.source SET lifecycle = 'suspended'")
    assert client.get(path(document), headers=bearer(owner)).status_code == 403


def test_migration_preserves_existing_exact_document_and_version_identity(database_url, tmp_path):
    migrate_to_revision(database_url, "0074_source_ingest")
    with open_database(database_url) as connection:
        fixture = create_evidence_db(connection, register_tenant(connection, "Existing source"), database_url, tmp_path)
        original = register_markdown(fixture)
        refs = [original.document_ref, original.version_ref]
        query = "SELECT public_id, object_id FROM thalion.object_identity WHERE public_id = ANY(%s) ORDER BY object_type"
        saved = connection.execute(query, (refs,)).fetchall()
        assert len(saved) == 2
        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert connection.execute(query, (refs,)).fetchall() == saved
        assert connection.execute("SELECT count(*) FROM thalion.responsibility_assignment").fetchone() == (0,)


def test_concurrent_responsibility_changes_cannot_both_replace_the_same_generation(transport):
    client, db, (owner, other), credentials, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "read_document_responsibility", "set_document_responsibility")
    document = upload_document(client, source, owner, credentials)["document_id"]
    start = Barrier(2, timeout=5)

    def assign(token):
        subject = str(credentials[token].employee_ref)
        body = {"expected_generation": 0, "responsible_id": subject, "basis_id": str(uuid4())}
        start.wait()
        return decide(client, owner, document, body).status_code, subject

    with ThreadPoolExecutor(max_workers=2) as workers:
        applied, rejected = sorted(workers.map(assign, (owner, other)))
    assert (applied[0], rejected[0]) == (200, 409)
    current = client.get(path(document), headers=bearer(owner)).json()
    assert (current["generation"], current["responsible_id"]) == (1, applied[1])
    assert connection.execute("SELECT count(*) FROM thalion.responsibility_assignment").fetchone() == (1,)
