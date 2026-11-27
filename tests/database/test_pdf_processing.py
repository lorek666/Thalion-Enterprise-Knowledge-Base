from contextlib import closing
from hashlib import sha256
import os
from pathlib import Path
import shutil
from zlib import compress

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import processing
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from test_evidence import claim, evidence_db, review
from test_runtime import runtime_db
from test_sources import register


PAGE_TEXT = b"Travel allowance 600 CNY"


def pdf_document(*pages, pixels=None):
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    image_ref = b""
    if pixels is not None:
        width, height, payload = pixels
        encoded = compress(payload)
        objects.append(
            b"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray "
            b"/BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n" % (width, height, len(encoded))
            + encoded + b"\nendstream"
        )
        image_ref = b"/XObject << /Scan 4 0 R >>"
    refs = []
    for content in pages:
        page_ref = len(objects) + 1
        refs.append(b"%d 0 R" % page_ref)
        objects.extend((
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 420 120] "
            b"/Resources << /Font << /F1 3 0 R >> %s >> /Contents %d 0 R >>" % (image_ref, page_ref + 1),
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        ))
    objects[1] = b"<< /Type /Pages /Count %d /Kids [%s] >>" % (len(refs), b" ".join(refs))
    payload = bytearray(b"%PDF-1.5\n")
    offsets = []
    for position, body in enumerate(objects, 1):
        offsets.append(len(payload))
        payload.extend(b"%d 0 obj\n" % position + body + b"\nendobj\n")
    xref = len(payload)
    payload.extend(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        payload.extend(b"%010d 00000 n \n" % offset)
    payload.extend(b"trailer\n<< /Root 1 0 R /Size %d >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref))
    return bytes(payload)


def text_page(text):
    return b"BT /F1 26 Tf 24 48 Td (" + text + b") Tj ET"


def register_pdf(db, payload):
    connection, tenant, _, source, store = db
    return register(
        connection, tenant, source, store, key="register-pdf", payload=payload,
        digest=sha256(payload).digest(), media_type="application/pdf",
    )


def test_pdf_records_physical_pages_and_exact_transcripts_without_granting_read_access(evidence_db):
    pytest.importorskip("pypdfium2")
    connection, tenant, _, _, store = evidence_db
    payload = pdf_document(text_page(PAGE_TEXT), text_page(b"Exception: no reimbursement"))
    version = register_pdf(evidence_db, payload)
    assert not register_pdf(evidence_db, payload).created
    lease = claim(evidence_db)
    with pytest.raises(processing.ProcessingNotAdmitted):
        processing.process_markdown_job(connection, lease, store)
    run = processing.process_evidence_job(connection, lease, store)
    assert (run.outcome, run.passage_count) == ("pending_review", 2)
    assert connection.execute("""
        SELECT page_number, method, transcript, reason FROM thalion.pdf_page_observation WHERE run_ref = %s
        ORDER BY page_number
        """, (run.run_ref,)).fetchall() == [
        (1, "text_layer", PAGE_TEXT, None), (2, "text_layer", b"Exception: no reimbursement", None),
    ]
    assert connection.execute("""
        SELECT passage.pdf_page, excerpt.excerpt_revision, excerpt.content_digest
        FROM thalion.passage AS passage JOIN thalion.passage_excerpt AS excerpt USING (passage_id)
        WHERE excerpt.run_ref = %s ORDER BY passage.pdf_page
        """, (run.run_ref,)).fetchall() == [
        (1, 1, sha256(PAGE_TEXT).digest()), (2, 1, sha256(b"Exception: no reimbursement").digest()),
    ]
    with pytest.raises(processing.ProcessingNotAdmitted):
        review(evidence_db, run, principal_id=tenant.other_actor_id)
    review(evidence_db, run)
    assert processing.list_approved_passages(connection, tenant.org_id, tenant.space_id, version.version_ref) == ()
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.pdf_page_observation SET transcript = %s", (b"Changed",))


def test_pdf_missing_ocr_dependency_leaves_job_retryable_without_sealed_candidate(evidence_db):
    pytest.importorskip("pypdfium2")
    connection, _, _, _, store = evidence_db
    register_pdf(evidence_db, pdf_document(text_page(PAGE_TEXT), b""))
    lease = claim(evidence_db)
    with pytest.raises(processing.ProcessingDependencyUnavailable):
        processing.process_evidence_job(connection, lease, store)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert connection.execute("SELECT state FROM thalion.job WHERE job_id = %s", (lease.job_id,)).fetchone() == ("running",)


def test_pdf_reprocessing_keeps_page_identity_and_does_not_inherit_approval(evidence_db):
    pytest.importorskip("pypdfium2")
    connection, tenant, _, _, store = evidence_db
    version = register_pdf(evidence_db, pdf_document(text_page(PAGE_TEXT)))
    first_lease = claim(evidence_db)
    first = processing.process_evidence_job(connection, first_lease, store)
    review(evidence_db, first)
    newer, = connection.execute("""
        INSERT INTO thalion.processing_config_revision
            (configuration_revision, parser_version, profile, locator_revision)
        SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
               parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE configuration_revision = %s
        RETURNING configuration_revision
        """, (first_lease.spec.configuration_revision,)).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, newer))
    later = processing.process_evidence_job(connection, claim(evidence_db), store)
    rows = connection.execute("""
        SELECT identity.public_id, excerpt.excerpt_revision, excerpt.run_ref, excerpt.content_digest
        FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.object_identity AS identity ON identity.object_type = 'passage'
          AND (identity.org_id, identity.space_id, identity.object_id) = (excerpt.org_id, excerpt.space_id, excerpt.passage_id)
        ORDER BY excerpt.excerpt_revision
        """).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == rows[1][0]
    assert [row[1:] for row in rows] == [
        (1, first.run_ref, sha256(PAGE_TEXT).digest()), (2, later.run_ref, sha256(PAGE_TEXT).digest()),
    ]
    assert connection.execute("SELECT run_ref FROM thalion.quality_decision").fetchall() == [(first.run_ref,)]


def test_pdf_malformed_document_has_no_reviewable_excerpt(evidence_db):
    pytest.importorskip("pypdfium2")
    connection, _, _, _, store = evidence_db
    register_pdf(evidence_db, b"%PDF-1.5\ninvalid synthetic document")
    run = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert (run.outcome, run.reason, run.passage_count) == ("quarantined", "unsupported_structure", 0)
    assert connection.execute("SELECT pdf_page_count FROM thalion.processing_run").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.pdf_page_observation").fetchone() == (0,)
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, run)


def test_pdf_real_ocr_seals_scan_and_accounts_for_unreadable_page(evidence_db):
    if os.environ.get("THALION_PDF_E2E") != "1":
        pytest.skip("Set THALION_PDF_E2E=1 with pinned Tesseract and trained data.")
    pdfium = pytest.importorskip("pypdfium2")
    from enterprise_kb.modules.evidence.pdf_evidence import Tesseract

    executable = Path(shutil.which("tesseract") or pytest.fail("Tesseract must be installed."))
    tessdata = Path(os.environ["THALION_TESSDATA_DIR"])
    with pdfium.PdfDocument(pdf_document(text_page(PAGE_TEXT))) as native:
        with closing(native[0]) as page, closing(page.render(scale=3, grayscale=True)) as bitmap:
            pixels = b"".join(
                bytes(bitmap.buffer[offset:offset + bitmap.width])
                for offset in range(0, bitmap.height * bitmap.stride, bitmap.stride)
            )
            scan = pdf_document(
                text_page(b"Policy text layer"), b"q 420 0 0 120 0 0 cm /Scan Do Q", b"",
                pixels=(bitmap.width, bitmap.height, pixels),
            )
    connection, _, _, _, store = evidence_db
    register_pdf(evidence_db, scan)
    result = processing.process_evidence_job(
        connection, claim(evidence_db), store, pdf_ocr=Tesseract(executable, tessdata),
    )
    assert (result.outcome, result.passage_count) == ("pending_review", 2)
    rows = connection.execute("""
        SELECT page_number, method, transcript, reason, ocr_profile_digest FROM thalion.pdf_page_observation
        WHERE run_ref = %s ORDER BY page_number
        """, (result.run_ref,)).fetchall()
    assert rows[0] == (1, "text_layer", b"Policy text layer", None, None)
    assert rows[1][:4] == (2, "ocr", PAGE_TEXT, None)
    assert len(rows[1][4]) == 32
    assert rows[2] == (3, "ocr", None, "empty", rows[1][4])
