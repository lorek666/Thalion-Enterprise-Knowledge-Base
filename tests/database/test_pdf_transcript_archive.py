from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import pytest

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.lifecycle import archive_rehearsal

from test_disposition_verification import original
from test_evidence import evidence_db, review
from test_evidence_transport import private_json
from test_feedback_work import admit
from test_original_export import APPROVE, EXPORT, REQUEST, approve, command, request
from test_pdf_processing import PAGE_TEXT, text_page
from test_pdf_repair import repair_lease
from test_pdf_review import EmptyScan, pdf_review, stage_pdf
from test_rule_replay import rehearsal_clone
from test_runtime import runtime_db


SCOPE = "original_and_transcript"
EXCEPTION = b"Exception: no reimbursement"


def admit_archive(pdf_review, version):
    _, profile, service, client, (owner, reviewer), credentials = pdf_review
    admit(credentials, owner, REQUEST, EXPORT)
    admit(credentials, reviewer, APPROVE)
    who = str(credentials[owner].employee_ref)
    private_json(profile.root / "archive-grants.json", {who: [str(version.version_ref)]})
    service.check_archive_source = profile.check_archive_source
    return client, owner, reviewer, who


def page_grants(db, version):
    connection, tenant, *_ = db
    pages = processing.list_approved_pdf_pages(connection, tenant.org_id, tenant.space_id, version.version_ref)
    return {str(page.passage_ref): page.revision for page in pages}


def open_transcript(client, owner, reviewer, version):
    opened = request(client, owner, version, scope=SCOPE)
    assert opened.status_code == 200, opened.text
    export = opened.json()["export_id"]
    assert opened.json()["scope"] == SCOPE
    assert approve(client, reviewer, export).status_code == 200
    return f"/{export}/seal"


@pytest.fixture
def pdf_transcript(pdf_review):
    db, profile, service, *_ = pdf_review
    version, run = stage_pdf(db, text_page(PAGE_TEXT), b"", text_page(EXCEPTION))
    client, owner, reviewer, who = admit_archive(pdf_review, version)
    return db, profile, service, client, owner, reviewer, who, version, run


def test_pdf_archive_requires_exact_grants_and_preserves_all_physical_pages(pdf_transcript, postgres_server, tmp_path):
    db, profile, _, client, owner, reviewer, who, version, run = pdf_transcript
    connection, tenant, database_url, *_ = db
    review(db, run)
    uri = open_transcript(client, owner, reviewer, version)
    grants = page_grants(db, version)
    assert len(grants) == 2
    private_json(profile.root / "source-grants.json", {who: list(grants)})
    granted = profile.root / "transcript-archive-grants.json"
    key = uuid4().hex
    for denied in ({}, dict(list(grants.items())[:1]), {ref: revision + 1 for ref, revision in grants.items()}):
        private_json(granted, {who: denied})
        assert command(client, owner, uri, key=key).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)

    private_json(granted, {who: grants})
    sealed = command(client, owner, uri, key=key)
    assert sealed.status_code == 200, sealed.text
    assert sealed.json()["scope"] == SCOPE and sealed.json()["restorable"] is False
    assert PAGE_TEXT.decode() not in sealed.text and EXCEPTION.decode() not in sealed.text
    payload, = connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    expected_original = original(db, version).read_bytes()
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-pdf-transcript-archive.v1"
        assert manifest["format_media_type"] == "application/pdf"
        assert archive.read("original.pdf") == expected_original
        transcript = archive.read("transcription.json")
        info = json.loads(transcript)
        assert info["run_id"] == str(run.run_ref) and info["manifest_sha256"] == run.manifest_digest.hex()
        assert manifest["transcription_sha256"] == sha256(transcript).hexdigest()
        pages = info["pages"]
        assert [item["page"] for item in pages] == [1, 2, 3]
        assert pages[1] == {
            "page": 2, "method": "ocr", "reason": "empty", "ocr_profile_sha256": EmptyScan().fingerprint().hex(),
        }
        members = {"manifest.json", "original.pdf", "transcription.json"}
        for item, expected in zip(pages[::2], (PAGE_TEXT, EXCEPTION), strict=True):
            assert item["excerpt_revision"] == grants[item["passage_id"]]
            assert item["locator_revision"] == 1
            assert item["member"] == f"transcript/{item['passage_id']}.txt"
            assert item["sha256"] == sha256(expected).hexdigest()
            assert archive.read(item["member"]) == expected
            assert "byte_start" not in item
            members.add(item["member"])
        assert set(archive.namelist()) == members

    pin = archive_rehearsal.ArchivePin(
        tenant.org_id, tenant.space_id, UUID(sealed.json()["package_id"]), bytes.fromhex(sealed.json()["archive_sha256"]),
    )
    scratch = tmp_path / "pdf-transcript-stage"
    scratch.mkdir(mode=0o700)
    with rehearsal_clone(connection, database_url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as staged_archive:
            assert staged_archive.scope == SCOPE
            assert staged_archive.store.read(staged_archive.asset) == expected_original
    assert list(scratch.iterdir()) == []
    private_json(granted, {who: {}})
    assert command(client, owner, uri, key=key).status_code == 403


def test_pdf_transcript_reprocessing_invalidates_the_enrolled_run_and_exact_grants(pdf_transcript):
    db, profile, _, client, owner, reviewer, who, version, run = pdf_transcript
    connection, *_ = db
    assert request(client, owner, version, scope=SCOPE).status_code == 409
    review(db, run)
    grants = page_grants(db, version)
    old = open_transcript(client, owner, reviewer, version)
    replacement = processing.process_evidence_job(connection, repair_lease(db, version), db[-1], pdf_ocr=EmptyScan())
    assert request(client, owner, version, scope=SCOPE).status_code == 409
    review(db, replacement)
    assert command(client, owner, old).status_code == 409
    fresh = open_transcript(client, owner, reviewer, version)
    path = profile.root / "transcript-archive-grants.json"
    private_json(path, {who: grants})
    assert command(client, owner, fresh).status_code == 403
    new_grants = page_grants(db, version)
    assert new_grants == {ref: revision + 1 for ref, revision in grants.items()}
    private_json(path, {who: new_grants})
    assert command(client, owner, fresh).status_code == 200


def test_pdf_transcript_quarantine_during_authorization_prevents_sealing(pdf_transcript):
    db, profile, service, client, owner, reviewer, who, version, run = pdf_transcript
    review(db, run)
    uri = open_transcript(client, owner, reviewer, version)
    private_json(profile.root / "transcript-archive-grants.json", {who: page_grants(db, version)})
    quarantined = []

    def revoke(credential, check):
        decision = profile.check_archive_source(credential, check)
        quarantined.append(review(db, run, decision="quarantined"))
        return decision

    service.check_archive_source = revoke
    assert command(client, owner, uri).status_code == 409
    assert len(quarantined) == 1
    assert db[0].execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


@pytest.mark.parametrize("altered", ["failure_state", "transcript"])
def test_pdf_transcript_refuses_changed_sealed_page_rows(pdf_transcript, altered):
    db, profile, _, client, owner, reviewer, who, version, run = pdf_transcript
    connection, *_ = db
    review(db, run)
    uri = open_transcript(client, owner, reviewer, version)
    private_json(profile.root / "transcript-archive-grants.json", {who: page_grants(db, version)})
    with connection.transaction():
        connection.execute("ALTER TABLE thalion.pdf_page_observation DISABLE TRIGGER pdf_page_observation_immutable")
        if altered == "failure_state":
            connection.execute("""
                UPDATE thalion.pdf_page_observation SET reason = 'low_confidence' WHERE (run_ref, page_number) = (%s, 2)
                """, (run.run_ref,))
        else:
            connection.execute("""
                UPDATE thalion.pdf_page_observation SET transcript = %s WHERE (run_ref, page_number) = (%s, 1)
                """, (b"!" + PAGE_TEXT[1:], run.run_ref))
        connection.execute("ALTER TABLE thalion.pdf_page_observation ENABLE TRIGGER pdf_page_observation_immutable")
    assert command(client, owner, uri).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
