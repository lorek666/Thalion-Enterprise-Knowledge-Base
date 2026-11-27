from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import psycopg
from psycopg import sql
import pytest

from enterprise_kb.database import local_connection_factory, upgrade
from enterprise_kb.modules.evidence import processing, quality_restrictions
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.sources import restriction_log, source_revocations
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore

from conftest import temporary_database
from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import assert_empty, endpoint, rebuild, rule_log
from test_deletion_tombstone import REGISTER, approved, register as register_tombstone, submitted
from test_disposition_verification import original
from test_evidence import evidence_db, review
from test_evidence_transport import private_json
from test_feedback_work import admit
from test_holds import decide
from test_original_export import approve, command, request
from test_pdf_correction import fixture_page
from test_pdf_repair import approve_page, repair_lease
from test_pdf_repair_approval import stage_batch
from test_pdf_repair_archive import approve_repair, grant_archive
from test_pdf_review import pdf_review
from test_pdf_transcript_archive import page_grants, pdf_transcript
from test_rule_restriction_log import stop
from test_runtime import open_database, runtime_db
from test_sources import register


@pytest.fixture
def pdf_rebuild_environment(pdf_review, empty_rehearsal, rule_log, postgres_server, tmp_path_factory):
    _, tenant, *_ = pdf_review[0]
    scratch = tmp_path_factory.mktemp("pdf-rebuild")
    with temporary_database(postgres_server) as source_url:
        upgrade(source_url)
        with open_database(source_url) as source_writer:
            source_ref = endpoint(source_writer)
            source_revocations.enroll_space(source_writer, source_ref, tenant.space_ref)
            source = source_revocations.SourceRevocationAuthority(lambda: open_database(source_url), source_ref)
            yield (*empty_rehearsal, scratch, source, rule_log), source_writer


def confirm_rule_history(db, log):
    authority, tenant, _, source_ref, store = db
    unrelated = register(authority, tenant, source_ref, store, key="pdf-control", object_key="another-rule")
    decision = stop(authority, tenant, unrelated.version_ref)
    assert restriction_log.deliver_pending(authority, log, tenant.org_id).confirmed == (decision,)


def rebuild_bundle(environment, db, version, export, response):
    (target, url, scratch, source, log), source_writer = environment
    authority, tenant, *_ = db
    assert response.status_code == 200, response.text
    assert response.json()["restorable"] is False
    payload, digest = authority.execute("""
        SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package WHERE export_ref = %s
        """, (export,)).fetchone()
    assert digest == sha256(payload).digest() == bytes.fromhex(response.json()["archive_sha256"])
    permit = archive_rehearsal.RebuildPermit(
        tenant.org_id, tenant.space_id, UUID(export), version.version_ref, digest, target.info.dbname,
    )
    return (target, url, permit, payload, scratch, source, log), source_writer


@pytest.fixture
def pdf_rebuild_bundle(pdf_transcript, pdf_rebuild_environment):
    db, profile, _, client, owner, reviewer, who, version, run = pdf_transcript
    authority, tenant, *_ = db
    review(db, run)
    log = pdf_rebuild_environment[0][-1]
    confirm_rule_history(db, log)
    assert quality_restrictions.deliver_pending(authority, log, tenant.org_id).status == "ok"
    opened = request(client, owner, version, scope="original_and_rebuild")
    assert opened.status_code == 200, opened.text
    export = opened.json()["export_id"]
    assert approve(client, reviewer, export).status_code == 200
    uri = f"/{export}/seal"
    private_json(profile.root / "transcript-archive-grants.json", {who: page_grants(db, version)})
    assert command(client, owner, uri).status_code == 403
    private_json(profile.root / "rebuild-archive-grants.json", {who: [str(version.version_ref)]})
    return rebuild_bundle(pdf_rebuild_environment, db, version, export, command(client, owner, uri))


def test_pdf_rebuild_preserves_physical_pages_without_enabling_reads(pdf_rebuild_bundle, pdf_transcript):
    bundle, _ = pdf_rebuild_bundle
    target, url, permit, payload, scratch, *_ = bundle
    db, *_, version, run = pdf_transcript
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-pdf-version-rebuild.v1"
        transcription = json.loads(archive.read("transcription.json"))
        pages = transcription["pages"]
        assert [page["page"] for page in pages] == [1, 2, 3]
        assert {page["passage_id"]: page["excerpt_revision"] for page in pages if "member" in page} == page_grants(db, version)
        texts = [archive.read(page["member"]) if "member" in page else None for page in pages]
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(target, permit, payload, scratch)
    assert_empty(bundle)

    restored = rebuild(bundle, db[0])

    assert restored.store.read(restored.asset) == original(db, version).read_bytes()
    assert target.execute("SELECT media_type FROM thalion.asset").fetchone() == ("application/pdf",)
    assert dict(target.execute("""
        SELECT object_type, public_id FROM thalion.object_identity
        WHERE object_type IN ('source', 'document', 'document_version')
        """).fetchall()) == {"source": db[3], "document": version.document_ref, "document_version": version.version_ref}
    assert target.execute("""
        SELECT version_ref, run_ref, transcription, page_transcripts FROM thalion.archive_pdf_rebuild
        """).fetchone() == (version.version_ref, run.run_ref, transcription, texts)
    assert target.execute("SELECT lifecycle FROM thalion.space").fetchone() == ("archived",)
    assert target.execute("SELECT version_ref, archive_digest FROM thalion.archive_rebuild_rule_check").fetchone() == (
        version.version_ref, permit.digest,
    )
    for table in ("processing_run", "quality_decision", "passage_excerpt", "synthetic_export_approval", "rule_effectivity"):
        assert target.execute(sql.SQL("SELECT count(*) FROM thalion.{}").format(sql.Identifier(table))).fetchone() == (0,)
    original_employees = db[0].execute("SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal'").fetchall()
    restored_employees = target.execute("SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal'").fetchall()
    assert not set(original_employees) & set(restored_employees)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        target.execute("UPDATE thalion.archive_pdf_rebuild SET transcription = '{}'::jsonb")
    with pytest.raises(psycopg.OperationalError, match="rehearsal"):
        local_connection_factory(url)()
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="requires an empty"):
        rebuild(bundle, db[0])


@pytest.mark.parametrize("condition", [
    "forged_digest", "not_fenced", "missing_quality", "revoked_page", "unconfirmed_withdrawal",
    "withdrawn", "hold", "tombstone", "quarantine", "disk",
])
def test_pdf_rebuild_leaves_no_state_if_rejected(pdf_rebuild_bundle, pdf_transcript, pdf_review, monkeypatch, condition):
    bundle, source_writer = pdf_rebuild_bundle
    target, url, permit, payload, scratch, source, log = bundle
    db, *_, who, version, run = pdf_transcript
    authority, tenant, *_ = db
    if condition == "forged_digest":
        forged = BytesIO()
        with ZipFile(BytesIO(payload)) as archive, ZipFile(forged, "w") as tampered:
            for name in archive.namelist():
                tampered.writestr(name, b"altered" if name.startswith("transcript/") else archive.read(name))
        payload = forged.getvalue()
        permit = replace(permit, digest=sha256(payload).digest())
    elif condition == "not_fenced":
        target.execute(sql.SQL("ALTER DATABASE {} RESET thalion.restore_rehearsal").format(
            sql.Identifier(target.info.dbname),
        ))
    elif condition == "missing_quality":
        log.execute("ALTER TABLE thalion.rule_log_entry DISABLE TRIGGER rule_log_entry_immutable")
        log.execute("DELETE FROM thalion.rule_log_entry WHERE payload ->> 'kind' = 'quality_baseline'")
    elif condition == "revoked_page":
        source_revocations.revoke(
            source_writer, source.authority_ref, tenant.space_ref, UUID(who),
            UUID(next(iter(page_grants(db, version)))), "archive", basis_ref=uuid4(),
        )
    elif condition in {"unconfirmed_withdrawal", "withdrawn"}:
        decision = stop(authority, tenant, version.version_ref)
        if condition == "withdrawn":
            assert restriction_log.deliver_pending(authority, log, tenant.org_id).confirmed == (decision,)
    elif condition == "hold":
        _, _, _, client, (_, reviewer), _ = pdf_review
        assert decide(client, reviewer, version.version_ref).status_code == 200
    elif condition == "tombstone":
        _, _, _, client, (owner, reviewer), credentials = pdf_review
        case = submitted(client, owner, credentials, db[3], version)
        approval = approved(client, reviewer, credentials, case)
        admit(credentials, reviewer, REGISTER)
        response = register_tombstone(client, reviewer, case, approval)
        assert response.status_code == 200, response.text
        decision = UUID(response.json()["tombstone_id"])
        assert restriction_log.deliver_pending(authority, log, tenant.org_id).confirmed == (decision,)
    elif condition == "quarantine":
        review(db, run, decision="quarantined")
        assert quality_restrictions.deliver_pending(authority, log, tenant.org_id).status == "ok"
    else:
        stage = SyntheticOriginalStore.stage

        def fail_after_write(store, *args):
            stage(store, *args)
            raise OSError("simulated staging failure")

        monkeypatch.setattr(SyntheticOriginalStore, "stage", fail_after_write)
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        rebuild((target, url, permit, payload, scratch, source, log), authority)
    assert_empty(bundle)
    assert target.execute("SELECT count(*) FROM thalion.archive_pdf_rebuild").fetchone() == (0,)


def seal_repaired_pdf(pdf_review, environment, *, automatic=False):
    db, profile, *_ = pdf_review
    authority, tenant, *_ = db
    if automatic:
        _, _, version, ancestor, client, quality_reviewer, author = fixture_page(pdf_review, b"", b"")
        assert ancestor.outcome == "quarantined"
        for page in (1, 2):
            approve_page(pdf_review, ancestor, client, quality_reviewer, author, page)
        run = processing.repair_pdf_job(
            authority, repair_lease(db, version), db[-1], replaces=ancestor.run_ref, basis_ref=uuid4(),
        )
    else:
        _, version, ancestor, run, client, quality_reviewer, _ = stage_batch(pdf_review)
    approve_repair(pdf_review, client, quality_reviewer, run)
    log = environment[0][-1]
    quality_delivery = quality_restrictions.deliver_pending(authority, log, tenant.org_id)
    assert quality_delivery.status == "ok"
    assert len(quality_delivery.confirmed) == 1
    if automatic:
        assert quality_delivery.confirmed == (ancestor.run_ref,)
    confirm_rule_history(db, log)
    client, owner, reviewer, who, grants = grant_archive(pdf_review, version)
    opened = request(client, owner, version, scope="original_and_rebuild")
    assert opened.status_code == 200, opened.text
    export = opened.json()["export_id"]
    assert approve(client, reviewer, export).status_code == 200
    uri = f"/{export}/seal"
    private_json(profile.root / "rebuild-archive-grants.json", {who: [str(version.version_ref)]})
    assert command(client, owner, uri).status_code == 403
    private_json(profile.root / "repair-history-archive-grants.json", {who: [str(version.version_ref), *grants]})
    return rebuild_bundle(environment, db, version, export, command(client, owner, uri)), version, ancestor, run, who


@pytest.mark.parametrize("automatic", [False, True], ids=["manual-quarantine", "processing-quarantine"])
def test_repaired_pdf_rebuild_preserves_whole_batch_history_instead_of_live_approval(
    pdf_review, pdf_rebuild_environment, automatic,
):
    (bundle, _), version, ancestor, run, _ = seal_repaired_pdf(pdf_review, pdf_rebuild_environment, automatic=automatic)
    target, _, permit, payload, scratch, *_ = bundle
    db = pdf_review[0]
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-pdf-version-rebuild.v2"
        history_bytes = archive.read("repair-history.json")
        assert manifest["repair_history_sha256"] == sha256(history_bytes).hexdigest()
        history = json.loads(history_bytes)
        predecessor, current = history["runs"]
        assert predecessor["run_id"] == str(ancestor.run_ref)
        assert (predecessor["outcome"], predecessor["reason"]) == (ancestor.outcome, ancestor.reason)
        assert [decision["outcome"] for decision in predecessor["decisions"]] == ([] if automatic else ["quarantined"])
        assert current["replaces_run_id"] == str(ancestor.run_ref)
        assert [item["page"] for item in current["decisions"][0]["pages"]] == [1, 2]
        assert {item["page"]: item["decision_id"] for item in current["corrections"]} == {
            page["page"]: page["ocr_decision_id"] for page in current["pages"] if "ocr_decision_id" in page
        }
        transcription = json.loads(archive.read("transcription.json"))
        texts = [archive.read(page["member"]) for page in transcription["pages"]]
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(target, permit, payload, scratch)
    assert_empty(bundle)

    restored = rebuild(bundle, db[0])

    assert restored.store.read(restored.asset) == original(db, version).read_bytes()
    assert target.execute("""
        SELECT version_ref, run_ref, transcription, page_transcripts, repair_history FROM thalion.archive_pdf_rebuild
        """).fetchone() == (version.version_ref, run.run_ref, transcription, texts, history)
    assert target.execute("""
        SELECT quality_generation FROM thalion.archive_rebuild_rule_check WHERE version_ref = %s
        """, (version.version_ref,)).fetchone() == (2,)
    for table in ("processing_run", "quality_decision", "pdf_ocr_review_decision", "pdf_page_preview", "rule_effectivity"):
        assert target.execute(sql.SQL("SELECT count(*) FROM thalion.{}").format(sql.Identifier(table))).fetchone() == (0,)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        target.execute("UPDATE thalion.archive_pdf_rebuild SET repair_history = NULL")


@pytest.mark.parametrize("condition", ["automatic_unattested_ancestor", "stale_quality_log", "revoked_page", "current_quarantine"])
def test_repaired_pdf_rebuild_refuses_incomplete_or_superseded_independent_evidence(pdf_review, pdf_rebuild_environment, condition):
    (bundle, source_writer), version, ancestor, run, who = seal_repaired_pdf(
        pdf_review, pdf_rebuild_environment, automatic=condition == "automatic_unattested_ancestor",
    )
    db = pdf_review[0]
    authority, tenant, *_ = db
    target, _, _, _, _, source, log = bundle
    if condition == "automatic_unattested_ancestor":
        assert authority.execute("SELECT count(*) FROM thalion.quality_decision WHERE outcome = 'quarantined'").fetchone() == (0,)
        log.execute("ALTER TABLE thalion.rule_log_entry DISABLE TRIGGER rule_log_entry_immutable")
        log.execute("DELETE FROM thalion.rule_log_entry WHERE decision_ref = %s", (ancestor.run_ref,))
        error = "independent quality history"
    elif condition == "stale_quality_log":
        log.execute("ALTER TABLE thalion.rule_log_entry DISABLE TRIGGER rule_log_entry_immutable")
        log.execute("DELETE FROM thalion.rule_log_entry WHERE payload ->> 'kind' = 'quality_quarantine'")
        error = "independent quality history"
    elif condition == "revoked_page":
        source_revocations.revoke(
            source_writer, source.authority_ref, tenant.space_ref, UUID(who),
            UUID(next(iter(page_grants(db, version)))), "archive", basis_ref=uuid4(),
        )
        error = "source revocation"
    else:
        review(db, run, decision="quarantined")
        assert quality_restrictions.deliver_pending(authority, log, tenant.org_id).status == "ok"
        error = "fenced rehearsal"
    with pytest.raises(archive_rehearsal.ArchiveRejected, match=error):
        rebuild(bundle, authority)
    assert_empty(bundle)
    assert target.execute("SELECT count(*) FROM thalion.archive_pdf_rebuild").fetchone() == (0,)
