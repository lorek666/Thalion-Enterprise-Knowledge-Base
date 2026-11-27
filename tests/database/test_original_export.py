from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
from uuid import uuid4
from zipfile import ZipFile

import pytest
from psycopg import errors

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.runtime.audit import RequestStart, start_request
from enterprise_kb.transport.local import LocalProfile

from test_disposition import plan
from test_disposition_cases import candidate
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, private_json, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_holds import CAPABILITY as HOLD, decide
from test_identity import space
from test_persisted_access import authority_for
from test_pdf_processing import PAGE_TEXT, pdf_document, register_pdf, text_page
from test_rule_restriction_log import stop
from test_runtime import runtime_db
from test_travel_search import corpus


PATH = "/internal/lifecycle/original-exports"
REQUEST = "request_original_export"
APPROVE = "approve_original_export"
EXPORT = "export_original_archive"


def command(client, token, path="", *, key=None, **body):
    return client.post(PATH + path, headers=command_headers(token, key), json=body)


def request(client, owner, version, **changes):
    return command(client, owner, **({"version_id": str(version.version_ref), "scope": "original_only"} | changes))


def approve(client, reviewer, export_id, **changes):
    expires = (datetime.now(UTC) + timedelta(minutes=2)).isoformat()
    return command(client, reviewer, f"/{export_id}/approval", **({"expires_at": expires} | changes))


@pytest.fixture
def archive_fixture(candidate, evidence_transport):
    (client, db, (owner, reviewer), credentials, _, *_), _, (version, *_) = candidate
    service, *_ = evidence_transport
    admit(credentials, owner, REQUEST, APPROVE, EXPORT)
    admit(credentials, reviewer, REQUEST, APPROVE, EXPORT, HOLD)
    allowed = {db[1].actor_id}
    service.check_archive_source = lambda credential, probe: authority_for(allowed)(probe)
    return client, db, owner, reviewer, service, allowed, version


@pytest.fixture
def pdf_archive_fixture(transport, evidence_transport, tmp_path_factory):
    client, db, (owner, reviewer), credentials, *_ = transport
    service, *_ = evidence_transport
    admit(credentials, owner, REQUEST, APPROVE, EXPORT)
    admit(credentials, reviewer, REQUEST, APPROVE, EXPORT, HOLD)
    version = register_pdf(db, pdf_document(text_page(PAGE_TEXT), text_page(b"Synthetic second page")))
    root = tmp_path_factory.mktemp("pdf-archive-profile")
    root.chmod(0o700)
    employee = str(credentials[owner].employee_ref)
    private_json(root / "credentials.json", [])
    private_json(root / "archive-grants.json", {employee: [str(version.version_ref)]})
    private_json(root / "source-grants.json", {employee: [str(version.version_ref)]})
    service.check_archive_source = LocalProfile(root).check_archive_source
    return client, db, owner, reviewer, root, employee, version


def test_pdf_original_export_requires_independent_approval_and_current_export_grant(pdf_archive_fixture):
    client, db, owner, reviewer, root, employee, version = pdf_archive_fixture
    connection, *_ = db
    assert request(client, reviewer, version).status_code == 403
    assert request(client, owner, version, scope="original_and_transcript").status_code == 409
    assert request(client, owner, version, scope="original_and_rebuild").status_code == 409
    for scope in ("original_and_wiki", "wiki_rebuild"):
        denied = request(client, owner, version, scope=scope, wiki_revision_id=str(uuid4()))
        assert denied.status_code == 409, denied.text
        assert denied.json()["error"]["code"] == "original_archive_conflict"
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_request").fetchone() == (0,)
    opened = request(client, owner, version)
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    uri = f"/{export_id}/seal"
    assert command(client, owner, uri).status_code == 409
    assert approve(client, owner, export_id).status_code == 403
    assert approve(client, reviewer, export_id).status_code == 200
    assert command(client, reviewer, uri).status_code == 403
    key = str(uuid4())
    private_json(root / "archive-grants.json", {})
    assert command(client, owner, uri, key=key).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(root / "archive-grants.json", {employee: [str(version.version_ref)]})
    response = command(client, owner, uri, key=key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert body["scope"] == "original_only" and body["restorable"] is False
    payload, digest = connection.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    assert sha256(payload).hexdigest() == digest.hex() == body["archive_sha256"]
    with ZipFile(BytesIO(payload)) as archive:
        assert archive.namelist() == ["manifest.json", "original.pdf"]
        expected = original(db, version).read_bytes()
        assert archive.read("original.pdf") == expected
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["version_id"] == str(version.version_ref)
        assert manifest["format_media_type"] == "application/pdf" and manifest["byte_length"] == len(expected)
        assert manifest["original_sha256"] == sha256(expected).hexdigest()
    assert PAGE_TEXT.decode() not in response.text
    assert command(client, owner, uri, key=key).json()["package_id"] == body["package_id"]
    private_json(root / "archive-grants.json", {})
    assert command(client, owner, uri, key=key).status_code == 403


@pytest.mark.parametrize("restriction", ["hold", "withdrawal"])
def test_pdf_original_export_refuses_changed_safety_scope(pdf_archive_fixture, restriction):
    client, db, owner, reviewer, _, _, version = pdf_archive_fixture
    connection, tenant, *_ = db
    opened = request(client, owner, version)
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    if restriction == "hold":
        assert decide(client, reviewer, version.version_ref).status_code == 200
    else:
        stop(connection, tenant, version.version_ref)
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert request(client, owner, version).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_database_rejects_pdf_wiki_archive_request_without_exact_publication(pdf_archive_fixture):
    _, db, _, _, _, _, version = pdf_archive_fixture
    connection, tenant, *_ = db
    revision, = connection.execute(
        "SELECT config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,),
    ).fetchone()
    request_id = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request_id, tenant.actor_id, None, "synthetic-ui", REQUEST, "internal_lifecycle",
        date(2026, 11, 22), revision, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation, match="Wiki archive requires the current exact publication"):
        connection.execute("""
            INSERT INTO thalion.synthetic_export_request (
                org_id, space_id, version_id, requester_id, snapshot, request_id, wiki_publication_ref
            )
            SELECT org_id, space_id, version_id, owner_id, snapshot, %s, %s
            FROM thalion.synthetic_original_export_target WHERE version_ref = %s
            """, (request_id, uuid4(), version.version_ref))
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_request").fetchone() == (0,)


def test_export_requests_are_authenticated_internal_commands(transport):
    client, *_ = transport
    assert client.post(PATH, json={}).status_code == 401


def test_archive_requires_independent_approval_and_writes_actual_scoped_archive(archive_fixture):
    client, db, owner, reviewer, _, allowed, version = archive_fixture
    connection, *_ = db
    before = plan(client, owner, version.version_ref).json()
    assert request(client, reviewer, version).status_code == 403
    assert request(client, owner, version, scope="original_and_wiki").status_code == 400
    requested = request(client, owner, version)
    assert requested.status_code == 200, requested.text
    export_id = requested.json()["export_id"]
    uri = f"/{export_id}/seal"
    assert command(client, owner, uri).status_code == 409
    assert approve(client, owner, export_id).status_code == 403
    assert approve(client, reviewer, export_id, expires_at="2020-01-01T00:00:00Z").status_code == 400
    assert approve(client, reviewer, export_id).status_code == 200
    assert command(client, reviewer, uri).status_code == 403
    key = str(uuid4())
    response = command(client, owner, uri, key=key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert body["state"] == "sealed" and body["restorable"] is False
    payload, digest = connection.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    assert sha256(payload).hexdigest() == digest.hex() == body["archive_sha256"]
    with ZipFile(BytesIO(payload)) as archive:
        assert set(archive.namelist()) == {"manifest.json", "original.md"}
        original_bytes = original(db, version).read_bytes()
        assert archive.read("original.md") == original_bytes
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["version_id"] == str(version.version_ref)
        assert manifest["original_sha256"] == sha256(original_bytes).hexdigest()
        assert manifest["scope"] == "original_only" and manifest["restorable"] is False
    assert "Synthetic plan" not in response.text
    assert command(client, owner, uri, key=key).json()["package_id"] == body["package_id"]
    assert command(client, owner, uri).status_code == 409
    allowed.clear()
    assert command(client, owner, uri, key=key).status_code == 403
    after = plan(client, owner, version.version_ref).json()
    assert after["inventory_snapshot"] != before["inventory_snapshot"]
    assert any(copy["kind"] == "export" for copy in after["copies"])
    assert "export" in after["unverified_copy_kinds"]


def test_employee_read_grants_or_authority_outage_cannot_authorize_export(archive_fixture, tmp_path_factory):
    client, db, owner, reviewer, service, _, version = archive_fixture
    connection, *_ = db
    root = tmp_path_factory.mktemp("archive-profile")
    root.chmod(0o700)
    employee = str(service.verify_token(owner).employee_ref)
    private_json(root / "credentials.json", [])
    private_json(root / "source-grants.json", {employee: [str(version.version_ref)]})
    profile = LocalProfile(root)
    service.check_archive_source = profile.check_archive_source
    export_id = request(client, owner, version).json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    key = str(uuid4())
    assert command(client, owner, uri, key=key).status_code == 403

    def unavailable(*_):
        raise AuthorizationUnavailable("Synthetic archive authority unavailable.")

    service.check_archive_source = unavailable
    assert command(client, owner, uri, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    service.check_archive_source = profile.check_archive_source
    private_json(root / "archive-grants.json", {employee: [str(uuid4())]})
    assert command(client, owner, uri, key=key).status_code == 403
    private_json(root / "archive-grants.json", {employee: [str(version.version_ref)]})
    assert command(client, owner, uri, key=key).status_code == 200
    private_json(root / "archive-grants.json", {})
    assert command(client, owner, uri, key=key).status_code == 403


def test_concurrent_sealing_and_cross_space_requests(archive_fixture, evidence_transport):
    client, db, owner, reviewer, _, _, version = archive_fixture
    _, _, _, credentials, *_ = evidence_transport
    connection, tenant, *_ = db
    export_id = request(client, owner, version).json()["export_id"]
    configured = credentials[reviewer]
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[reviewer] = replace(configured, space_ref=other_space)
    assert approve(client, reviewer, export_id).status_code == 403
    credentials[reviewer] = configured
    assert approve(client, reviewer, export_id).status_code == 200
    with ThreadPoolExecutor(max_workers=2) as workers:
        attempts = [workers.submit(command, client, owner, f"/{export_id}/seal") for _ in range(2)]
        assert sorted(attempt.result(timeout=12).status_code for attempt in attempts) == [200, 409]
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (1,)


def test_new_hold_during_authority_check_prevents_archive_sealing(archive_fixture):
    client, db, owner, reviewer, service, _, version = archive_fixture
    connection, *_ = db
    export_id = request(client, owner, version).json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    original_check = service.check_archive_source
    held = []

    def check(credential, probe):
        held.append(decide(client, reviewer, version.version_ref).status_code)
        return original_check(credential, probe)

    service.check_archive_source = check
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert held == [200]
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_archive_sealing_rolls_back_with_a_failed_event(archive_fixture):
    client, db, owner, reviewer, _, _, version = archive_fixture
    connection, *_ = db
    export_id = request(client, owner, version).json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_archive_event
        CHECK (event_type <> 'lifecycle.synthetic_export.sealed') NOT VALID
    """)
    key = str(uuid4())
    assert command(client, owner, uri, key=key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_archive_event")
    assert command(client, owner, uri, key=key).status_code == 200
