from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import pytest

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.lifecycle.transcripts import REPAIR_HISTORY_FIELD
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.transport.local import LocalProfile

from test_disposition_verification import original
from test_evidence import evidence_db, review
from test_evidence_transport import private_json
from test_original_export import approve, command, request
from test_pdf_correction import TRANSCRIPT, propose, view
from test_pdf_correction_review import decide, preview
from test_pdf_processing import PAGE_TEXT
from test_pdf_repair import repair_lease
from test_pdf_repair_approval import approve_batch, compare_batch, permit_review, stage_batch
from test_pdf_review import pdf_review
from test_pdf_transcript_archive import SCOPE, admit_archive, open_transcript, page_grants
from test_rule_replay import rehearsal_clone
from test_runtime import open_database, runtime_db
from test_source_revocations import independent_authority


NEW_TRANSCRIPT = "Travel allowance 650 CNY."


def approve_repair(pdf_review, client, reviewer, batch):
    permit_review(pdf_review, reviewer)
    receipts = compare_batch(client, batch, reviewer)
    approved = approve_batch(client, batch, reviewer, receipts)
    assert approved.status_code == 200, approved.text
    return approved.json()["decision_id"], receipts


def grant_archive(pdf_review, version):
    db, profile, _, *_ = pdf_review
    client, owner, reviewer, who = admit_archive(pdf_review, version)
    grants = page_grants(db, version)
    assert len(grants) == 2
    private_json(profile.root / "transcript-archive-grants.json", {who: grants})
    return client, owner, reviewer, who, grants


def test_repaired_pdf_archive_preserves_bounded_exact_history_and_rechecks_its_grants(
    pdf_review, postgres_server, tmp_path,
):
    db, profile, service, *_ = pdf_review
    connection, tenant, database_url, *_ = db
    _, version, first, replacement, client, quality_reviewer, author = stage_batch(pdf_review)
    client, owner, independent, _ = admit_archive(pdf_review, version)
    assert request(client, owner, version, scope=SCOPE).status_code == 409
    assert request(client, owner, version, scope="original_and_rebuild").status_code == 409
    first_approval, first_receipts = approve_repair(pdf_review, client, quality_reviewer, replacement)
    stopped = review(db, replacement, decision="quarantined")
    proposed = propose(client, replacement, author, view(client, replacement, author, 2), page=2, transcript=NEW_TRANSCRIPT)
    assert proposed.status_code == 200, proposed.text
    correction = proposed.json()["correction_id"]
    comparison = preview(client, correction, quality_reviewer)
    assert comparison.status_code == 200, comparison.text
    accepted = decide(client, correction, quality_reviewer, comparison.json()["request_id"])
    assert accepted.status_code == 200, accepted.text
    newest = processing.repair_pdf_job(
        connection, repair_lease(db, version), db[-1], replaces=replacement.run_ref, basis_ref=uuid4(),
    )
    last_approval, last_receipts = approve_repair(pdf_review, client, quality_reviewer, newest)
    client, owner, independent, who, grants = grant_archive(pdf_review, version)
    uri = open_transcript(client, owner, independent, version)
    key = uuid4().hex
    assert command(client, owner, uri, key=key).status_code == 403
    path = profile.root / "repair-history-archive-grants.json"
    private_json(path, {who: list(grants)})
    assert command(client, owner, uri, key=key).status_code == 403
    private_json(path, {who: [str(version.version_ref), *grants]})
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)

    checked = []

    def inspect(credential, check):
        checked.append({(str(scope.object_id), scope.revision) for scope in check.scopes if REPAIR_HISTORY_FIELD in scope.fields})
        return profile.check_archive_source(credential, check)

    service.check_archive_source = inspect
    sealed = command(client, owner, uri, key=key)
    assert sealed.status_code == 200, sealed.text
    summary = sealed.json()
    payload, pin_digest = connection.execute("""
        SELECT package.archive_bytes, request.repair_history_digest
        FROM thalion.synthetic_export_package AS package JOIN thalion.synthetic_export_request AS request USING (export_ref)
        """).fetchone()
    expected_original = original(db, version).read_bytes()
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        history_bytes = archive.read("repair-history.json")
        history = json.loads(history_bytes)
        assert manifest["format"] == "thalion.synthetic-pdf-transcript-archive.v2" and not manifest["restorable"]
        assert manifest["repair_history_sha256"] == pin_digest.hex() == sha256(history_bytes).hexdigest()
        assert history["run_id"] == str(newest.run_ref)
        base, intermediate, current = history["runs"]
        assert [item["run_id"] for item in history["runs"]] == [str(run.run_ref) for run in (first, replacement, newest)]
        assert [item["manifest_sha256"] for item in history["runs"]] == [
            run.manifest_digest.hex() for run in (first, replacement, newest)
        ]
        assert base["pages"][1]["reason"] == "empty" and "passage_id" not in base["pages"][1]
        assert current["replaces_run_id"] == intermediate["run_id"] and intermediate["replaces_run_id"] == base["run_id"]
        assert current["pages"][1]["ocr_decision_id"] == accepted.json()["decision_id"]
        assert intermediate["pages"][1]["sha256"] == sha256(TRANSCRIPT.encode()).hexdigest()
        first_decisions = {item["outcome"]: item for item in intermediate["decisions"]}
        final_decision, = current["decisions"]
        assert first_decisions["quarantined"]["decision_id"] == str(stopped)
        for actual, decision_id, receipts in (
            (first_decisions["approved"], first_approval, first_receipts), (final_decision, last_approval, last_receipts),
        ):
            assert actual["decision_id"] == decision_id
            assert [page["request_id"] for page in actual["pages"]] == receipts
            assert all(len(bytes.fromhex(page["payload_sha256"])) == 32 for page in actual["pages"])
        assert current["corrections"][0]["correction_id"] == correction
        assert current["corrections"][0]["preview_request_id"] == comparison.json()["request_id"]
        assert current["corrections"][0]["transcript_sha256"] == sha256(NEW_TRANSCRIPT.encode()).hexdigest()
        assert all("member" not in page for run in history["runs"] for page in run["pages"])
        assert TRANSCRIPT.encode() not in history_bytes and NEW_TRANSCRIPT.encode() not in history_bytes
        transcription = json.loads(archive.read("transcription.json"))
        assert transcription["run_id"] == history["run_id"]
        assert [archive.read(page["member"]) for page in transcription["pages"]] == [PAGE_TEXT, NEW_TRANSCRIPT.encode()]
        assert archive.read("original.pdf") == expected_original
    required = {(str(version.version_ref), None)} | {
        (page["passage_id"], page["excerpt_revision"])
        for run in history["runs"] for page in run["pages"] if "passage_id" in page
    }
    assert checked and all(probe == required for probe in checked)

    pin = archive_rehearsal.ArchivePin(
        tenant.org_id, tenant.space_id, UUID(summary["package_id"]), bytes.fromhex(summary["archive_sha256"]),
    )
    scratch = tmp_path / "repaired-pdf-stage"
    scratch.mkdir(mode=0o700)
    with rehearsal_clone(connection, database_url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as material:
            assert material.scope == SCOPE and material.store.read(material.asset) == expected_original
        review((staged, *db[1:]), newest, decision="quarantined")
        with pytest.raises(archive_rehearsal.ArchiveRejected):
            with archive_rehearsal.stage_original(staged, pin, payload, scratch):
                pytest.fail("A quarantined repaired PDF was staged.")
    assert list(scratch.iterdir()) == []
    private_json(path, {who: [str(version.version_ref)]})
    assert command(client, owner, uri, key=key).status_code == 403


@pytest.mark.parametrize(("altered", "expected"), [("review_proof", 409), ("page_receipts", 503)])
def test_repaired_pdf_archive_rejects_changed_pinned_evidence(pdf_review, altered, expected):
    db, profile, _, *_ = pdf_review
    connection, version, _, repaired, client, quality_reviewer, _ = stage_batch(pdf_review)
    approve_repair(pdf_review, client, quality_reviewer, repaired)
    client, owner, reviewer, who, grants = grant_archive(pdf_review, version)
    opened = request(client, owner, version, scope=SCOPE)
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    private_json(profile.root / "repair-history-archive-grants.json", {who: [str(version.version_ref), *grants]})
    with connection.transaction():
        if altered == "review_proof":
            connection.execute("ALTER TABLE thalion.pdf_ocr_review_decision DISABLE TRIGGER pdf_ocr_review_decision_immutable")
            connection.execute("UPDATE thalion.pdf_ocr_review_decision SET proof_digest = %s", (b"x" * 32,))
            connection.execute("ALTER TABLE thalion.pdf_ocr_review_decision ENABLE TRIGGER pdf_ocr_review_decision_immutable")
        else:
            connection.execute("ALTER TABLE thalion.quality_decision DISABLE TRIGGER quality_decision_immutable")
            connection.execute("""
                UPDATE thalion.quality_decision
                SET pdf_repair_page_requests = ARRAY[pdf_repair_page_requests[1], pdf_repair_page_requests[1]]
                WHERE run_ref = %s
                """, (repaired.run_ref,))
            connection.execute("ALTER TABLE thalion.quality_decision ENABLE TRIGGER quality_decision_immutable")
    assert command(client, owner, f"/{export_id}/seal").status_code == expected
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_repaired_pdf_archive_rechecks_separate_source_revocation_on_retries(pdf_review, independent_authority):
    db, profile, service, *_ = pdf_review
    connection, tenant, *_ = db
    authority, url, authority_ref = independent_authority
    _, version, _, repaired, client, quality_reviewer, _ = stage_batch(pdf_review)
    approve_repair(pdf_review, client, quality_reviewer, repaired)
    client, owner, reviewer, who, grants = grant_archive(pdf_review, version)
    path = profile.root / "repair-history-archive-grants.json"
    private_json(path, {who: [str(version.version_ref), *grants]})
    before = path.read_bytes()
    source_revocations.enroll_space(authority, authority_ref, tenant.space_ref)
    source = source_revocations.SourceRevocationAuthority(lambda: open_database(url), authority_ref)
    service.check_archive_source = LocalProfile(profile.root, revocations=source).check_archive_source

    uri = open_transcript(client, owner, reviewer, version)
    key = uuid4().hex
    initial = command(client, owner, uri, key=key)
    assert initial.status_code == 200, initial.text
    assert command(client, owner, uri, key=key).json()["package_id"] == initial.json()["package_id"]
    source_revocations.revoke(
        authority, authority_ref, tenant.space_ref, UUID(who), UUID(next(iter(grants))), "archive", basis_ref=uuid4(),
    )
    assert command(client, owner, uri, key=key).status_code == 403
    fresh = open_transcript(client, owner, reviewer, version)
    assert command(client, owner, fresh).status_code == 403
    assert path.read_bytes() == before
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (1,)
