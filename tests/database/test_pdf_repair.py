from dataclasses import replace
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.runtime.jobs import JobSpec, LeaseLost, enqueue_job

from test_effectivity import BEGIN, approve, record
from test_evidence import claim, evidence_db, review
from test_external_calls import expire
from test_pdf_correction import TRANSCRIPT, fixture_page, propose, view
from test_pdf_correction_review import DECIDE, PREVIEW, decide, preview
from test_pdf_processing import PAGE_TEXT, text_page
from test_pdf_review import pdf_review
from test_runtime import runtime_db


def approve_page(pdf_review, run, client, reviewer, author, page):
    credentials = pdf_review[-1]
    credentials[reviewer] = replace(
        credentials[reviewer], operations=credentials[reviewer].operations | {DECIDE, PREVIEW},
    )
    proposed = propose(client, run, author, view(client, run, author, page), page=page)
    assert proposed.status_code == 200, proposed.text
    correction = proposed.json()["correction_id"]
    compared = preview(client, correction, reviewer)
    assert compared.status_code == 200, compared.text
    decided = decide(client, correction, reviewer, compared.json()["request_id"])
    assert decided.status_code == 200, decided.text
    return UUID(decided.json()["decision_id"])


def repair_lease(db, version):
    connection, tenant, *_ = db
    revision, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
               parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE profile = 'pdf_pages_v1' ORDER BY configuration_revision DESC LIMIT 1
        RETURNING configuration_revision
    """).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, revision))
    return claim(db)


def test_ocr_repair_preserves_exact_page_identity_and_keeps_new_batch_unapproved(pdf_review):
    db = pdf_review[0]
    connection, _, version, original, client, reviewer, author = fixture_page(pdf_review, text_page(PAGE_TEXT), b"")
    old_approval = review(db, original)
    quarantine = review(db, original, decision="quarantined")
    decision = approve_page(pdf_review, original, client, reviewer, author, 2)
    lease, basis = repair_lease(db, version), uuid4()

    repaired = processing.repair_pdf_job(connection, lease, db[-1], replaces=original.run_ref, basis_ref=basis)
    assert (repaired.outcome, repaired.passage_count) == ("pending_review", 2)
    assert repaired.manifest_digest != original.manifest_digest
    assert connection.execute("""
        SELECT replaces_run_ref, repair_basis_ref, manifest_digest FROM thalion.processing_run WHERE run_ref = %s
    """, (repaired.run_ref,)).fetchone() == (original.run_ref, basis, repaired.manifest_digest)
    assert connection.execute("""
        SELECT page_number, method, transcript, reason, repair_decision_ref
        FROM thalion.pdf_page_observation WHERE run_ref = %s ORDER BY page_number
    """, (repaired.run_ref,)).fetchall() == [
        (1, "text_layer", PAGE_TEXT, None, None), (2, "ocr", TRANSCRIPT.encode(), None, decision),
    ]
    assert connection.execute("""
        SELECT transcript, reason FROM thalion.pdf_page_observation WHERE run_ref = %s AND page_number = 2
    """, (original.run_ref,)).fetchone() == (None, "empty")
    excerpts = connection.execute("""
        SELECT passage.pdf_page, passage.passage_id, excerpt.excerpt_revision, excerpt.content_digest
        FROM thalion.passage AS passage JOIN thalion.passage_excerpt AS excerpt USING (passage_id)
        ORDER BY passage.pdf_page, excerpt.excerpt_revision
    """).fetchall()
    assert len(excerpts) == 3 and excerpts[0][:2] == excerpts[1][:2]
    assert [row[2:] for row in excerpts] == [
        (1, sha256(PAGE_TEXT).digest()), (2, sha256(PAGE_TEXT).digest()), (1, sha256(TRANSCRIPT.encode()).digest()),
    ]
    with pytest.raises(processing.QualityConflict):
        review(db, repaired)
    assert set(connection.execute("SELECT decision_ref FROM thalion.quality_decision").fetchall()) == {
        (old_approval,), (quarantine,),
    }
    assert connection.execute("SELECT state, result_ref FROM thalion.job WHERE job_id = %s", (lease.job_id,)).fetchone() == (
        "succeeded", repaired.run_ref,
    )


def test_ocr_repair_requires_every_failed_page_to_have_an_approved_correction(pdf_review):
    db = pdf_review[0]
    connection, _, version, original, client, reviewer, author = fixture_page(pdf_review, b"", b"")
    approve_page(pdf_review, original, client, reviewer, author, 1)
    lease = repair_lease(db, version)
    with pytest.raises(processing.QualityConflict):
        processing.repair_pdf_job(connection, lease, db[-1], replaces=original.run_ref, basis_ref=uuid4())
    assert connection.execute("SELECT run_ref FROM thalion.processing_run").fetchall() == [(original.run_ref,)]
    approve_page(pdf_review, original, client, reviewer, author, 2)
    repaired = processing.repair_pdf_job(connection, lease, db[-1], replaces=original.run_ref, basis_ref=uuid4())
    assert repaired.passage_count == 2


def test_ocr_repair_not_committed_when_version_withdrawn_during_original_read(pdf_review, monkeypatch):
    db = pdf_review[0]
    store = db[-1]
    connection, tenant, version, original, client, reviewer, author = fixture_page(pdf_review, b"")
    approve_page(pdf_review, original, client, reviewer, author, 1)
    lease = repair_lease(db, version)
    approve(connection, tenant, version, BEGIN)
    read = store.read

    def withdraw(asset):
        payload = read(asset)
        effectivity.stop_synthetic_rule(
            connection, record(connection, tenant, "stop_rule_use", "withdraw-while-repairing"),
            tenant.space_id, version.version_ref, "withdrawn", uuid4(),
        )
        return payload

    monkeypatch.setattr(store, "read", withdraw)
    with pytest.raises(processing.ProcessingNotAdmitted):
        processing.repair_pdf_job(connection, lease, store, replaces=original.run_ref, basis_ref=uuid4())
    assert connection.execute("SELECT run_ref FROM thalion.processing_run").fetchall() == [(original.run_ref,)]
    assert connection.execute("SELECT count(*) FROM thalion.passage_excerpt").fetchone() == (0,)


def test_expired_ocr_repair_attempt_cannot_seal_after_lease_is_reclaimed(pdf_review, monkeypatch):
    db = pdf_review[0]
    store = db[-1]
    connection, _, version, original, client, reviewer, author = fixture_page(pdf_review, b"")
    approve_page(pdf_review, original, client, reviewer, author, 1)
    old_lease = repair_lease(db, version)
    read = store.read
    replacements = []

    def reclaim(asset):
        payload = read(asset)
        expire(connection, old_lease)
        replacements.append(claim(db))
        return payload

    with monkeypatch.context() as patch:
        patch.setattr(store, "read", reclaim)
        with pytest.raises(LeaseLost):
            processing.repair_pdf_job(connection, old_lease, store, replaces=original.run_ref, basis_ref=uuid4())
    assert connection.execute("SELECT run_ref FROM thalion.processing_run").fetchall() == [(original.run_ref,)]
    repaired = processing.repair_pdf_job(connection, replacements[0], store, replaces=original.run_ref, basis_ref=uuid4())
    assert repaired.passage_count == 1


def test_pdf_repair_seal_rejects_inconsistent_transcript_even_with_matching_excerpt(pdf_review, monkeypatch):
    db = pdf_review[0]
    connection, _, version, original, client, reviewer, author = fixture_page(pdf_review, b"")
    approve_page(pdf_review, original, client, reviewer, author, 1)
    lease = repair_lease(db, version)
    load = processing._pdf_repair_candidate

    def inconsistent(*args, **kwargs):
        candidate = load(*args, **kwargs)
        return replace(candidate, pages=(replace(candidate.pages[0], transcript=b"Different synthetic transcript"),))

    with monkeypatch.context() as patch:
        patch.setattr(processing, "_pdf_repair_candidate", inconsistent)
        with pytest.raises(errors.CheckViolation, match="all exact approved pages"):
            processing.repair_pdf_job(connection, lease, db[-1], replaces=original.run_ref, basis_ref=uuid4())
    assert connection.execute("SELECT run_ref FROM thalion.processing_run").fetchall() == [(original.run_ref,)]
    assert connection.execute("SELECT count(*) FROM thalion.passage_excerpt").fetchone() == (0,)
    assert connection.execute("SELECT state FROM thalion.job WHERE job_id = %s", (lease.job_id,)).fetchone() == ("running",)
