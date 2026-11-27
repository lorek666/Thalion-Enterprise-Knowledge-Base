from hashlib import sha256
import json
from uuid import UUID

from psycopg.rows import dict_row

from enterprise_kb.modules.access.delivery import EvidenceScope
from enterprise_kb.modules.evidence.pdf_evidence import MAX_PAGE_BYTES, MAX_PAGES, PROFILE, PageObservation
from enterprise_kb.modules.evidence.processing import pdf_processing_manifest, pdf_repair_manifest
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.lifecycle.transcripts import (
    MAX_REPAIR_LOCATIONS, MAX_REPAIR_RUNS, REPAIR_HISTORY_FIELD, TRANSCRIPT_FIELD, current_transcript,
)


PDF_TRANSCRIPT_FORMAT = "thalion.synthetic-pdf-transcript-archive.v1"
PDF_REPAIR_TRANSCRIPT_FORMAT = "thalion.synthetic-pdf-transcript-archive.v2"


def _page_rows(connection, org_id, space_id, version_id, run):
    return connection.execute("""
        WITH excerpts AS (
            SELECT passage.pdf_page, identity.public_id, excerpt.excerpt_revision, passage.locator_revision,
                   excerpt.content_digest
            FROM thalion.passage_excerpt AS excerpt
            JOIN thalion.passage AS passage USING (org_id, space_id, version_id, passage_id)
            LEFT JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                 (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
            WHERE (excerpt.org_id, excerpt.space_id, excerpt.version_id, excerpt.run_ref) = (%s, %s, %s, %s)
        ), pages AS (
            SELECT page_number, method, transcript, reason, ocr_profile_digest, repair_decision_ref
            FROM thalion.pdf_page_observation WHERE run_ref = %s
        )
        SELECT page_number, method, transcript, reason, ocr_profile_digest, repair_decision_ref,
               public_id, excerpt_revision, locator_revision, content_digest
        FROM pages FULL JOIN excerpts ON excerpts.pdf_page = pages.page_number
        ORDER BY page_number LIMIT %s
        """, (org_id, space_id, version_id, run, run, MAX_PAGES + 1)).fetchall()


def _load_run(connection, scope, run_ref, digest):
    with connection.cursor(row_factory=dict_row) as cursor:
        run = cursor.execute("""
            SELECT run_ref, configuration_revision, manifest_digest, passage_count, pdf_page_count, reason, outcome,
                   replaces_run_ref, rollback_run_ref, repair_basis_ref, contract_revision,
                   config.parser_version, config.locator_revision
            FROM thalion.processing_run AS run
            JOIN thalion.processing_config_revision AS config USING (configuration_revision)
            WHERE (run.org_id, run.space_id, run.version_id, run.run_ref) = (%s, %s, %s, %s)
              AND run.input_digest = %s AND config.profile = %s AND run.pdf_page_count IS NOT NULL
            """, (*scope, run_ref, digest, PROFILE)).fetchone()
    if (
        run is None or not 1 <= run["pdf_page_count"] <= MAX_PAGES
        or not 0 <= run["passage_count"] <= run["pdf_page_count"]
        or run["outcome"] != ("pending_review" if run["passage_count"] else "quarantined")
        or run["rollback_run_ref"] is not None
        or (run["replaces_run_ref"] is None) != (run["repair_basis_ref"] is None)
        or (run["replaces_run_ref"] is not None and run["passage_count"] != run["pdf_page_count"])
    ):
        raise DispositionInventoryUnavailable("PDF archive processing metadata is incomplete or inconsistent.")
    return run


def _load_pages(connection, scope, target, run):
    rows = _page_rows(connection, *scope, run["run_ref"])
    if [row[0] for row in rows] != list(range(1, run["pdf_page_count"] + 1)):
        raise DispositionInventoryUnavailable("The archive requires every physical PDF page exactly once.")

    observations, entries, refs = [], [], set()
    for number, method, text, failure, profile, repair, ref, revision, locator, digest in rows:
        entry = {
            "page": number, "method": method, "reason": failure,
            "ocr_profile_sha256": profile.hex() if profile else None,
        }
        if repair is not None:
            if run["replaces_run_ref"] is None:
                raise DispositionInventoryUnavailable("Unrepaired PDF archives cannot include OCR correction records.")
            entry["ocr_decision_id"] = str(repair)
        if text is None:
            if any(value is not None for value in (ref, revision, locator, digest, repair)):
                raise DispositionInventoryUnavailable("A failed PDF page has an unexpected transcript revision.")
        else:
            if (
                ref is None or ref in refs or not revision or locator != run["locator_revision"]
                or not 0 < len(text) <= MAX_PAGE_BYTES or sha256(text).digest() != digest
            ):
                raise DispositionInventoryUnavailable("A PDF page does not match its exact transcript revision.")
            refs.add(ref)
            entry.update(passage_id=str(ref), excerpt_revision=revision, locator_revision=locator,
                         sha256=digest.hex())
        observations.append((PageObservation(number, method, text, failure, profile, repair), digest))
        entries.append(entry)
    manifest = pdf_processing_manifest(
        target["version_ref"], target["content_digest"], run["configuration_revision"], run["outcome"], run["reason"],
        observations,
    )
    pages = tuple(page for page, _ in observations)
    if run["replaces_run_ref"] is not None:
        manifest = pdf_repair_manifest(manifest, run["replaces_run_ref"], run["repair_basis_ref"], pages)
    if len(refs) != run["passage_count"] or manifest != run["manifest_digest"]:
        raise DispositionInventoryUnavailable("The PDF transcript manifest does not match the sealed pages.")
    return pages, entries


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def archive_pdf_transcription(connection, org_id, space_id, target):
    scope = (org_id, space_id, target["version_id"])
    run_ref, configuration, manifest, _ = current_transcript(connection, *scope, target["transcript_run_ref"])
    run = _load_run(connection, scope, run_ref, target["content_digest"])
    if (run["replaces_run_ref"] is None) != (target.get("repair_history_digest") is None):
        raise DispositionConflict("The selected PDF archive has different repair history requirements.")
    pages, entries = _load_pages(connection, scope, target, run)
    scopes, members = [], {}
    for page, entry in zip(pages, entries, strict=True):
        if page.transcript is not None:
            ref = entry["passage_id"]
            member = f"transcript/{ref}.txt"
            entry["member"] = member
            members[member] = page.transcript
            scopes.append(EvidenceScope(
                space_id, target["source_id"], UUID(ref), frozenset({TRANSCRIPT_FIELD}), entry["excerpt_revision"],
            ))
    members["transcription.json"] = _encode({
        "run_id": str(run_ref), "manifest_sha256": manifest.hex(), "configuration_revision": configuration, "pages": entries,
    })
    return members, scopes


def _quality_history(connection, scope, run):
    decisions = connection.execute("""
        SELECT outcome, decision_ref, basis_ref, reviewer_id, pdf_repair_page_requests, pdf_repair_proof_digest
        FROM thalion.quality_decision
        WHERE (org_id, space_id, version_id, run_ref) = (%s, %s, %s, %s)
        ORDER BY outcome
        """, (*scope, run["run_ref"])).fetchall()
    history = []
    for outcome, ref, basis, reviewer, requests, proof in decisions:
        entry = {"outcome": outcome, "decision_id": str(ref), "basis_id": str(basis)}
        if outcome == "approved" and run["replaces_run_ref"] is not None:
            if requests is None or len(requests) != run["pdf_page_count"] or proof is None:
                raise DispositionInventoryUnavailable("A repaired PDF approval is missing whole-batch evidence.")
            receipts = connection.execute("""
                SELECT preview.page_number, preview.request_id, preview.payload_digest
                FROM unnest(%s::uuid[]) WITH ORDINALITY AS requested(request_id, page_number)
                JOIN thalion.pdf_page_preview AS preview USING (request_id, page_number)
                JOIN thalion.request_record AS request USING (org_id, request_id)
                WHERE (preview.org_id, preview.space_id, preview.version_id, preview.run_ref) = (%s, %s, %s, %s)
                  AND preview.correction_ref IS NULL AND preview.repair_safety_epochs IS NOT NULL
                  AND request.principal_id = %s AND request.outcome = 'succeeded'
                  AND (request.operation, request.destination) = ('preview_pdf_repair_page', 'local_workspace')
                ORDER BY preview.page_number
                """, (requests, *scope, run["run_ref"], reviewer)).fetchall()
            if [request for _, request, _ in receipts] != requests:
                raise DispositionInventoryUnavailable("A repaired PDF approval has different physical-page receipts.")
            entry.update(proof_sha256=proof.hex(), pages=[
                {"page": number, "request_id": str(request), "payload_sha256": digest.hex()}
                for number, request, digest in receipts
            ])
        history.append(entry)
    return history


def _correction_history(connection, scope, prior, updated, pages, previous_entries, current_entries):
    if (
        prior["configuration_revision"] >= updated["configuration_revision"]
        or any(prior[key] != updated[key] for key in ("contract_revision", "parser_version", "locator_revision", "pdf_page_count"))
        or any(
            "passage_id" in before and (
                before["passage_id"] != after.get("passage_id") or before["excerpt_revision"] >= after["excerpt_revision"]
            )
            for before, after in zip(previous_entries, current_entries, strict=True)
        )
    ):
        raise DispositionInventoryUnavailable("A PDF repair does not preserve its chronological page identities.")
    expected = connection.execute("""
        SELECT page_number, method, transcript, reason, ocr_profile_digest, repair_decision_ref, changed
        FROM thalion.pdf_repair_pages(%s) ORDER BY page_number
        """, (prior["run_ref"],)).fetchall()
    if tuple(PageObservation(*row[:-1]) for row in expected) != pages:
        raise DispositionInventoryUnavailable("A PDF repair does not match its predecessor and approved OCR corrections.")
    changed = {row[5] for row in expected if row[6]}
    if not changed:
        raise DispositionInventoryUnavailable("A repaired PDF has no approved changed page.")
    rows = connection.execute("""
        SELECT decision.page_number, decision.decision_ref, decision.correction_ref, decision.basis_ref,
               decision.preview_request_id, decision.proof_digest, correction.basis_ref, correction.proposed_digest,
               correction.preview_request_id, proposed.payload_digest, reviewed.payload_digest
        FROM thalion.pdf_ocr_review_decision AS decision
        JOIN thalion.pdf_ocr_correction AS correction
          USING (org_id, space_id, version_id, run_ref, page_number, correction_ref)
        JOIN thalion.pdf_page_preview AS proposed USING (org_id, space_id, version_id, run_ref, page_number)
        JOIN thalion.pdf_page_preview AS reviewed USING (org_id, space_id, version_id, run_ref, page_number)
        WHERE (decision.org_id, decision.space_id, decision.version_id, decision.run_ref) = (%s, %s, %s, %s)
          AND decision.decision_ref = ANY(%s::uuid[]) AND decision.outcome = 'approved'
          AND proposed.request_id = correction.preview_request_id AND proposed.correction_ref IS NULL
          AND reviewed.request_id = decision.preview_request_id AND reviewed.correction_ref = correction.correction_ref
          AND decision.reviewer_id <> correction.author_id
        ORDER BY decision.page_number
        """, (*scope, prior["run_ref"], list(changed))).fetchall()
    if len(rows) != len(changed) or any(current_entries[row[0] - 1].get("sha256") != row[7].hex() for row in rows):
        raise DispositionInventoryUnavailable("Required PDF OCR correction provenance is unavailable.")
    return [
        {"page": number, "decision_id": str(decision), "correction_id": str(correction),
         "review_basis_id": str(review_basis), "preview_request_id": str(review_preview), "proof_sha256": proof.hex(),
         "proposal_basis_id": str(proposal_basis), "transcript_sha256": transcript.hex(),
         "original_preview_request_id": str(original_preview), "original_preview_sha256": original_digest.hex(),
         "review_preview_sha256": review_digest.hex()}
        for (number, decision, correction, review_basis, review_preview, proof, proposal_basis, transcript,
             original_preview, original_digest, review_digest) in rows
    ]


def pdf_repair_history(connection, org_id, space_id, target, run_ref):
    scope = (org_id, space_id, target["version_id"])
    original_digest = target["content_digest"]
    run = _load_run(connection, scope, run_ref, original_digest)
    if run["replaces_run_ref"] is None:
        return None, ()
    history, successor = [], None
    protected = {(target["version_ref"], None)}
    capacity = MAX_REPAIR_LOCATIONS
    while True:
        if len(history) >= MAX_REPAIR_RUNS or run["pdf_page_count"] > capacity:
            raise DispositionConflict("The PDF repair history exceeds its bounded archive scope.")
        capacity -= run["pdf_page_count"]
        pages, entries = _load_pages(connection, scope, target, run)
        protected.update(
            (UUID(page["passage_id"]), page["excerpt_revision"]) for page in entries if "passage_id" in page
        )
        decisions = _quality_history(connection, scope, run)
        outcomes = {entry["outcome"] for entry in decisions}
        replaced = run["replaces_run_ref"]
        if successor is None:
            if outcomes != {"approved"}:
                raise DispositionConflict("The current PDF repair is not available under whole-batch approval.")
        else:
            updated, successor_pages, successor_entries, output = successor
            if run["outcome"] != "quarantined" and "quarantined" not in outcomes:
                raise DispositionInventoryUnavailable("The replaced PDF batch has no sealed quarantine.")
            output["corrections"] = _correction_history(
                connection, scope, run, updated, successor_pages, entries, successor_entries,
            )
        output = {
            "run_id": str(run["run_ref"]), "configuration_revision": run["configuration_revision"],
            "contract_revision": run["contract_revision"], "manifest_sha256": run["manifest_digest"].hex(),
            "parser_version": run["parser_version"], "locator_revision": run["locator_revision"],
            "outcome": run["outcome"], "reason": run["reason"], "pages": entries, "decisions": decisions,
            "replaces_run_id": str(replaced) if replaced else None,
            "repair_basis_id": str(run["repair_basis_ref"]) if replaced else None, "corrections": [],
        }
        history.append(output)
        if replaced is None:
            break
        successor = (run, pages, entries, output)
        run = _load_run(connection, scope, replaced, original_digest)
    scopes = tuple(
        EvidenceScope(space_id, target["source_id"], ref, frozenset({REPAIR_HISTORY_FIELD}), revision)
        for ref, revision in sorted(protected, key=lambda item: (item[0], item[1] or 0))
    )
    return _encode({"run_id": str(run_ref), "runs": history[::-1]}), scopes
