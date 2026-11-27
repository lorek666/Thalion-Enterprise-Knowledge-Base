from base64 import b64encode
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json

from enterprise_kb.modules.access.delivery import (
    AuthorizationUnavailable, DeliveryCandidate, EvidenceScope, LocalAuthorization, SafetyEpochs, authorize_delivery,
)
from enterprise_kb.modules.access.policy import PDF_PAGE_FIELDS, PDF_PAGE_PREVIEW_ACCESS
from enterprise_kb.modules.access.travel import _read_bindings
from enterprise_kb.modules.operations.context import command_for, require_scope
from enterprise_kb.modules.sources.registry import SourceWrite
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event

from . import pdf_evidence, processing


PREVIEW, PURPOSE, DESTINATION = PDF_PAGE_PREVIEW_ACCESS
SUBMIT_CORRECTION = "submit_pdf_ocr_correction"
PREVIEW_CORRECTION = "preview_pdf_ocr_correction"
DECIDE_CORRECTION = "decide_pdf_ocr_correction"
PREVIEW_REPAIR = "preview_pdf_repair_page"
APPROVE_REPAIR = processing.PDF_REPAIR_APPROVAL_OPERATION
CORRECTION_PREVIEW_WINDOW = timedelta(minutes=5)


def _lock_batch(connection, call, run_ref, role):
    row = connection.execute("""
        SELECT identity.public_id, run.contract_revision, run.pdf_page_count, run.outcome
        FROM thalion.processing_run AS run
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (run.org_id, run.space_id, 'document_version', run.version_id)
        WHERE (run.org_id, run.space_id, run.run_ref) = (%s, %s, %s)
          AND run.pdf_page_count IS NOT NULL
    """, (call.org_id, call.space_id, run_ref)).fetchone()
    if row is None:
        raise processing.ProcessingNotAdmitted("The PDF review batch is not in scope.")
    version_ref = row[0]
    original = processing._lock_original(connection, call.org_id, call.space_id, version_ref, call.principal_id, role=role)
    return original, row


def _original_access(connection, call, context, original, version_ref, check_authority):
    source_id, revision, *epochs = connection.execute("""
        SELECT source.source_id, source.local_policy_revision,
               organization.safety_epoch, space.safety_epoch, source.safety_epoch
        FROM thalion.document_version AS version
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.organization AS organization USING (org_id)
        WHERE version.version_id = %s
    """, (original.version_id,)).fetchone()
    if revision is None:
        raise processing.ProcessingNotAdmitted("No current local policy authorizes the original PDF page.")
    scope = EvidenceScope(call.space_id, source_id, version_ref, PDF_PAGE_FIELDS)
    dependencies = {scope: SafetyEpochs(*epochs)}

    def load_local(_):
        return LocalAuthorization(dependencies, _read_bindings(
            connection, context, call.space_id, source_id, revision, lock=True,
        ))

    def authorize(payload):
        decision = authorize_delivery(
            context, DeliveryCandidate(payload, dependencies), check_authority=check_authority, load_local=load_local,
        )
        if decision.status == "dependency_unavailable":
            raise AuthorizationUnavailable("The original PDF source authority is unavailable.")
        if decision.status != "succeeded":
            raise processing.ProcessingNotAdmitted("Current read rights do not cover this original PDF.")
        return decision

    authorize(b"")
    return authorize, revision, epochs


def _current_page(connection, original, contract_revision, run_ref, page_number):
    current = connection.execute("""
        SELECT run_ref FROM thalion.processing_run WHERE version_id = %s
        ORDER BY configuration_revision DESC LIMIT 1
    """, (original.version_id,)).fetchone()
    if current != (run_ref,) or original.contract_revision != contract_revision:
        raise processing.QualityConflict("The exact PDF page is not in the current manifest.")
    page = connection.execute("""
        SELECT method, transcript, ocr_profile_digest, reason
        FROM thalion.pdf_page_observation WHERE (run_ref, page_number) = (%s, %s)
    """, (run_ref, page_number)).fetchone()
    if page is None:
        raise processing.QualityConflict("The exact PDF page is not in the current manifest.")
    return page


def _preview_payload(call, original, version_ref, run_ref, page_number, expected_pages, store):
    try:
        png = pdf_evidence.render_review_page(store.read(original.asset), page_number, expected_pages)
    except pdf_evidence.PdfDependencyUnavailable as error:
        raise AuthorizationUnavailable("The registered PDF cannot be rendered for review.") from error
    return {
        "request_id": str(call.request_id), "version_id": str(version_ref), "run_id": str(run_ref),
        "page_number": page_number, "png_base64": b64encode(png).decode("ascii"),
    }


def _seal_preview(
    connection, call, original, run_ref, page_number, revision, delivery, *, correction_ref=None, repair_epochs=None,
):
    connection.execute("""
        INSERT INTO thalion.pdf_page_preview (
            org_id, space_id, version_id, run_ref, page_number, request_id,
            policy_revision, payload_digest, proof_digest, checked_at, valid_until, correction_ref, repair_safety_epochs
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (call.org_id, call.space_id, original.version_id, run_ref, page_number, call.request_id, revision,
          bytes.fromhex(delivery.payload_sha256), sha256(delivery.authority_proof_ref.encode()).digest(),
          delivery.checked_at, delivery.valid_until, correction_ref, repair_epochs))
    return delivery.payload, delivery.valid_until


def preview(connection, call, context, run_ref, page_number, store, check_authority, *, allow_author=False):
    require_scope(connection, call, PREVIEW, destination=DESTINATION)
    original, (version_ref, contract_revision, expected_pages, _) = _lock_batch(
        connection, call, run_ref, "pdf_preview" if allow_author else "reviewer",
    )
    authorize, revision, _ = _original_access(connection, call, context, original, version_ref, check_authority)
    _current_page(connection, original, contract_revision, run_ref, page_number)
    payload = _preview_payload(call, original, version_ref, run_ref, page_number, expected_pages, store)
    delivery = authorize(json.dumps(payload, separators=(",", ":")).encode("ascii"))
    return _seal_preview(connection, call, original, run_ref, page_number, revision, delivery)


def submit_correction(connection, call, context, run_ref, page_number, preview_ref, basis_ref, text, store, check_authority):
    require_scope(connection, call, SUBMIT_CORRECTION, destination=DESTINATION)
    if not isinstance(text, str):
        raise ValueError("An OCR correction requires a bounded transcription.")
    transcript, reason = pdf_evidence._bounded_text(text)
    if reason is not None:
        raise ValueError("An OCR correction requires a bounded transcription.")
    original, (version_ref, contract_revision, _, outcome) = _lock_batch(connection, call, run_ref, "pdf_author")
    authorize, policy_revision, _ = _original_access(
        connection, call, replace(context, operation=PREVIEW), original, version_ref, check_authority,
    )
    method, previous, ocr_profile, _ = _current_page(connection, original, contract_revision, run_ref, page_number)
    if method != "ocr" or ocr_profile is None or previous == transcript or (outcome != "quarantined" and not connection.execute(
        "SELECT 1 FROM thalion.quality_decision WHERE run_ref = %s AND outcome = 'quarantined'", (run_ref,),
    ).fetchone()):
        raise processing.QualityConflict("The current OCR page must be quarantined and the transcript must change.")
    if not connection.execute("""
        SELECT 1 FROM thalion.pdf_page_preview AS preview
        JOIN thalion.request_record AS request USING (org_id, request_id)
        WHERE (preview.org_id, preview.space_id, preview.version_id, preview.run_ref, preview.page_number,
               preview.request_id, preview.policy_revision) = (%s, %s, %s, %s, %s, %s, %s)
          AND (request.principal_id, request.client_id, request.operation, request.destination, request.outcome)
            = (%s, %s, %s, %s, 'succeeded')
          AND request.delegated_principal_id IS NULL AND preview.checked_at > clock_timestamp() - %s
    """, (call.org_id, call.space_id, original.version_id, run_ref, page_number, preview_ref, policy_revision,
          call.principal_id, context.client_id, PREVIEW, DESTINATION, CORRECTION_PREVIEW_WINDOW)).fetchone():
        raise processing.QualityConflict("A recent preview of this exact page by the correction author is required.")
    store.read(original.asset)
    command = command_for(call, SUBMIT_CORRECTION, (
        str(run_ref), page_number, str(preview_ref), str(basis_ref), sha256(transcript).hexdigest(),
    ))
    delivery = authorize(command.input_digest)

    def apply(transaction):
        correction, = transaction.execute("""
            INSERT INTO thalion.pdf_ocr_correction (
                org_id, space_id, version_id, run_ref, page_number, author_id, preview_request_id, request_id,
                basis_ref, proposed_transcript, proof_digest
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING correction_ref
        """, (call.org_id, call.space_id, original.version_id, run_ref, page_number, call.principal_id,
              preview_ref, call.request_id, basis_ref, transcript, sha256(delivery.authority_proof_ref.encode()).digest())).fetchone()
        append_event(transaction, call.org_id, "evidence.pdf_correction.submitted", version_ref, space_id=call.space_id)
        return correction

    receipt = execute_command(connection, command, apply)
    return {"correction_id": str(receipt.result_ref)}, delivery.valid_until


def _lock_correction(connection, call, operation, correction_ref):
    require_scope(connection, call, operation, destination=DESTINATION)
    correction = connection.execute("""
        SELECT run_ref, page_number, author_id
        FROM thalion.pdf_ocr_correction
        WHERE (org_id, space_id, correction_ref) = (%s, %s, %s)
    """, (call.org_id, call.space_id, correction_ref)).fetchone()
    if correction is None or correction[2] == call.principal_id:
        raise processing.ProcessingNotAdmitted("An independent reviewer is required for this OCR correction.")
    run_ref, page_number, _ = correction
    original, batch = _lock_batch(connection, call, run_ref, "reviewer")
    return original, batch, run_ref, page_number


def preview_correction(connection, call, context, correction_ref, store, check_authority):
    original, (version_ref, contract_revision, expected_pages, _), run_ref, page_number = _lock_correction(
        connection, call, PREVIEW_CORRECTION, correction_ref,
    )
    authorize, revision, _ = _original_access(
        connection, call, replace(context, operation=PREVIEW), original, version_ref, check_authority,
    )
    _, previous, _, reason = _current_page(connection, original, contract_revision, run_ref, page_number)
    proposed, = connection.execute(
        "SELECT proposed_transcript FROM thalion.pdf_ocr_correction WHERE correction_ref = %s", (correction_ref,),
    ).fetchone()
    payload = _preview_payload(call, original, version_ref, run_ref, page_number, expected_pages, store)
    payload.update(
        correction_id=str(correction_ref), previous_transcript=previous.decode("utf-8") if previous else None,
        previous_reason=reason, proposed_transcript=proposed.decode("utf-8"),
    )
    delivery = authorize(json.dumps(payload, separators=(",", ":")).encode("ascii"))
    return _seal_preview(connection, call, original, run_ref, page_number, revision, delivery, correction_ref=correction_ref)


def decide_correction(connection, call, context, correction_ref, preview_ref, outcome, basis_ref, store, check_authority):
    original, (version_ref, contract_revision, _, _), run_ref, page_number = _lock_correction(
        connection, call, DECIDE_CORRECTION, correction_ref,
    )
    authorize, revision, _ = _original_access(
        connection, call, replace(context, operation=PREVIEW), original, version_ref, check_authority,
    )
    _current_page(connection, original, contract_revision, run_ref, page_number)
    sealed = connection.execute("""
        SELECT preview.payload_digest, preview.checked_at
        FROM thalion.pdf_page_preview AS preview
        JOIN thalion.request_record AS request USING (org_id, request_id)
        WHERE (preview.org_id, preview.request_id, preview.correction_ref, preview.policy_revision) = (%s, %s, %s, %s)
          AND (request.principal_id, request.client_id, request.operation, request.destination, request.outcome)
            = (%s, %s, %s, %s, 'succeeded')
          AND request.delegated_principal_id IS NULL AND preview.checked_at > clock_timestamp() - %s
    """, (call.org_id, preview_ref, correction_ref, revision, call.principal_id, context.client_id,
          PREVIEW_CORRECTION, DESTINATION, CORRECTION_PREVIEW_WINDOW)).fetchone()
    if sealed is None:
        raise processing.QualityConflict("A recent comparison of this exact correction by the reviewer is required.")
    store.read(original.asset)
    command = command_for(call, DECIDE_CORRECTION, (
        str(correction_ref), str(preview_ref), sealed[0].hex(), outcome, str(basis_ref),
    ))
    delivery = authorize(command.input_digest)
    valid_until = min(delivery.valid_until, sealed[1] + CORRECTION_PREVIEW_WINDOW)

    def apply(transaction):
        decision = transaction.execute("""
            INSERT INTO thalion.pdf_ocr_review_decision (
                correction_ref, org_id, space_id, version_id, run_ref, page_number, reviewer_id,
                preview_request_id, request_id, outcome, basis_ref, proof_digest
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING RETURNING decision_ref
        """, (correction_ref, call.org_id, call.space_id, original.version_id, run_ref, page_number, call.principal_id,
              preview_ref, call.request_id, outcome, basis_ref, sha256(delivery.authority_proof_ref.encode()).digest())).fetchone()
        if decision is None:
            raise processing.QualityConflict("The correction already has a decision or its page has an approved correction.")
        append_event(transaction, call.org_id, "evidence.pdf_correction.decided", version_ref, space_id=call.space_id)
        return decision[0]

    receipt = execute_command(connection, command, apply)
    return {"decision_id": str(receipt.result_ref), "outcome": outcome}, valid_until


def _lock_repair_review(connection, call, operation, run_ref):
    require_scope(connection, call, operation, destination=DESTINATION)
    run = processing._lock_quality_run(connection, call.org_id, call.space_id, call.principal_id, run_ref)
    if run.original.media_type != pdf_evidence.MEDIA_TYPE or run.replaces is None:
        raise processing.QualityConflict("This is not a reviewable PDF repair.")
    if connection.execute("""
        SELECT 1 FROM thalion.pdf_page_observation AS page
        JOIN thalion.pdf_ocr_review_decision AS decision ON decision.decision_ref = page.repair_decision_ref
        JOIN thalion.pdf_ocr_correction AS correction USING (correction_ref)
        WHERE page.run_ref = %s AND correction.author_id = %s
    """, (run_ref, call.principal_id)).fetchone():
        raise processing.ProcessingNotAdmitted("A reviewer cannot approve their own contribution to a PDF repair.")
    return run


def preview_repair_page(connection, call, context, run_ref, page_number, store, check_authority):
    run = _lock_repair_review(connection, call, PREVIEW_REPAIR, run_ref)
    authorize, policy, epochs = _original_access(
        connection, call, replace(context, operation=PREVIEW), run.original, run.version_ref, check_authority,
    )
    page = connection.execute("""
        SELECT run.pdf_page_count, page.transcript, page.repair_decision_ref IS NOT NULL
        FROM thalion.processing_run AS run JOIN thalion.pdf_page_observation AS page USING (run_ref)
        WHERE (run.run_ref, page.page_number) = (%s, %s) AND page.transcript IS NOT NULL
    """, (run_ref, page_number)).fetchone()
    if page is None:
        raise processing.QualityConflict("This physical page is not in the PDF repair.")
    page_count, transcript, corrected = page
    payload = _preview_payload(call, run.original, run.version_ref, run_ref, page_number, page_count, store)
    payload.update(
        page_count=page_count, replaces_run_id=str(run.replaces), manifest_sha256=run.manifest.hex(),
        transcript=transcript.decode("utf-8"), corrected=corrected,
    )
    delivery = authorize(json.dumps(payload, separators=(",", ":")).encode("ascii"))
    return _seal_preview(connection, call, run.original, run_ref, page_number, policy, delivery, repair_epochs=epochs)


def approve_repair(connection, call, context, run_ref, preview_refs, basis_ref, store, check_authority):
    run = _lock_repair_review(connection, call, APPROVE_REPAIR, run_ref)
    authorize, _, _ = _original_access(
        connection, call, replace(context, operation=PREVIEW), run.original, run.version_ref, check_authority,
    )
    review_until, = connection.execute(
        "SELECT thalion.pdf_repair_review_until(%s, %s, %s)",
        (run_ref, call.request_id, list(preview_refs)),
    ).fetchone()
    if review_until is None:
        raise processing.QualityConflict("Every page requires a recent comparison in physical page order.")
    store.read(run.original.asset)
    command = command_for(call, APPROVE_REPAIR, (
        str(run_ref), run.manifest.hex(), *map(str, preview_refs), str(basis_ref),
    ))
    delivery = authorize(command.input_digest)
    approval = processing._PdfRepairApproval(preview_refs, sha256(delivery.authority_proof_ref.encode()).digest())
    write = SourceWrite(call.org_id, call.principal_id, call.request_id, call.key)
    decision = processing._decide_quality(
        connection, write, call.space_id, run_ref, run.manifest, "approved", basis_ref, pdf_approval=approval,
    )
    return {"decision_id": str(decision), "outcome": "approved"}, min(review_until, delivery.valid_until)
