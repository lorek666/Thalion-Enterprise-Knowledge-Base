from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json

from enterprise_kb.modules.access.delivery import (
    AuthorizationUnavailable, DeliveryCandidate, EvidenceScope, LocalAuthorization, SafetyEpochs, authorize_delivery,
)
from enterprise_kb.modules.access.policy import REPAIR_PREVIEW_ACCESS
from enterprise_kb.modules.access.travel import _read_bindings
from enterprise_kb.modules.operations.context import require_scope
from enterprise_kb.modules.sources.originals import OriginalIntegrityError
from enterprise_kb.modules.sources.registry import SourceWrite

from . import docx_evidence, processing


PREVIEW, PURPOSE, DESTINATION = REPAIR_PREVIEW_ACCESS
DECIDE = processing.QUALITY_OPERATION
FIELDS = frozenset({"excerpt", "location"})
PREVIEW_WINDOW = timedelta(minutes=5)
MAX_CHANGES = 128
MAX_EXCERPT_BYTES = 256 * 1024


def _current_run(connection, call, operation, run_ref):
    require_scope(connection, call, operation, destination=DESTINATION)
    run = processing._lock_quality_run(connection, call.org_id, call.space_id, call.principal_id, run_ref)
    if run.replaces is None:
        raise processing.QualityConflict("This is not a repaired evidence candidate.")
    if run.original.media_type == docx_evidence.MEDIA_TYPE and processing._docx_run_has_cells(connection, run_ref):
        raise processing.QualityConflict("DOCX table repairs require the whole-batch review.")
    guard = "docx_repair_admitted" if run.original.media_type == docx_evidence.MEDIA_TYPE else "markdown_repair_admitted"
    admitted, = connection.execute(
        f"SELECT thalion.{guard}(%s, %s, %s, %s, %s)",
        (run.original.version_id, run.configuration, run.replaces, run.baseline, run_ref),
    ).fetchone()
    if not admitted:
        raise processing.QualityConflict("The repair or its baseline is no longer admitted.")
    return run


def _changes(connection, run, run_ref):
    rows = connection.execute(
        """
        WITH locations AS (
            SELECT excerpt.run_ref, excerpt.passage_id, identity.public_id, excerpt.excerpt_revision,
                   excerpt.content_digest, passage.paragraph, passage.byte_start, passage.byte_end,
                   passage.heading_path, passage.docx_paragraph
            FROM thalion.passage_excerpt AS excerpt
            JOIN thalion.passage AS passage USING (passage_id)
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
               = (passage.org_id, passage.space_id, 'passage', passage.passage_id)
            WHERE excerpt.run_ref IN (%s, %s)
        ), prior AS (
            SELECT * FROM locations WHERE run_ref = %s
        ), proposed AS (
            SELECT * FROM locations WHERE run_ref = %s
        )
        SELECT coalesce(prior.public_id, proposed.public_id),
               prior.excerpt_revision, prior.content_digest, prior.paragraph, prior.byte_start, prior.byte_end,
               prior.heading_path, prior.docx_paragraph,
               proposed.excerpt_revision, proposed.content_digest, proposed.paragraph, proposed.byte_start, proposed.byte_end,
               proposed.heading_path, proposed.docx_paragraph
        FROM prior FULL JOIN proposed USING (passage_id)
        WHERE prior.content_digest IS DISTINCT FROM proposed.content_digest
        ORDER BY coalesce(prior.byte_start, proposed.byte_start, prior.docx_paragraph, proposed.docx_paragraph),
                 coalesce(prior.public_id, proposed.public_id)
        LIMIT %s
        """,
        (run.replaces, run_ref, run.replaces, run_ref, MAX_CHANGES + 1),
    ).fetchall()
    changes = [(ref, row[:7], row[7:]) for ref, *row in rows]
    changed_bytes = sum(side[4] - side[3] for _, before, after in changes for side in (before, after) if side[3] is not None)
    if not rows or len(rows) > MAX_CHANGES or changed_bytes > MAX_EXCERPT_BYTES:
        raise processing.QualityConflict("A complete difference is not available within the review limit.")
    return changes


def _difference(connection, call, context, run, run_ref, store, check_authority):
    changes = _changes(connection, run, run_ref)
    docx = run.original.media_type == docx_evidence.MEDIA_TYPE
    source_id, policy_revision, *epochs = connection.execute(
        """
        SELECT source.source_id, source.local_policy_revision,
               org.safety_epoch, space.safety_epoch, source.safety_epoch
        FROM thalion.document_version AS version
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.organization AS org USING (org_id)
        WHERE version.version_id = %s
        """,
        (run.original.version_id,),
    ).fetchone()
    if policy_revision is None:
        raise processing.ProcessingNotAdmitted("No current policy authorizes review of these excerpts.")
    context = replace(context, operation=PREVIEW)
    dependencies = {
        EvidenceScope(call.space_id, source_id, ref, FIELDS, side[0]): SafetyEpochs(*epochs)
        for ref, before, after in changes for side in (before, after) if side[0] is not None
    }

    def load_local(_):
        return LocalAuthorization(dependencies, _read_bindings(
            connection, context, call.space_id, source_id, policy_revision, lock=True,
        ), exact_allow_scopes=frozenset(dependencies) if docx else frozenset())

    def authorize(payload):
        decision = authorize_delivery(
            context, DeliveryCandidate(payload, dependencies), check_authority=check_authority, load_local=load_local,
        )
        if decision.status == "dependency_unavailable":
            raise AuthorizationUnavailable("The repair source authority is unavailable.")
        if decision.status != "succeeded":
            raise processing.ProcessingNotAdmitted("The current reviewer cannot read all changed excerpts.")
        return decision

    authorize(b"")
    original = store.read(run.original.asset)
    docx_locations = {
        (ref, side[0]): processing.ApprovedDocxParagraph(ref, tuple(side[5]), side[2], side[6], side[0], side[1])
        for ref, before, after in changes for side in (before, after) if docx and side[0] is not None
    }
    docx_excerpts = processing.resolve_docx_paragraphs(original, tuple(docx_locations.values())) if docx else {}
    if sum(map(len, docx_excerpts.values())) > MAX_EXCERPT_BYTES:
        raise processing.QualityConflict("A complete DOCX difference is not available within the review limit.")

    def item(ref, values):
        revision, digest, paragraph, start, end, path, ordinal = values
        if revision is None:
            return None
        if docx:
            return {
                "revision": revision, "paragraph": paragraph, "document_paragraph": ordinal, "heading_path": path,
                "excerpt": docx_excerpts[docx_locations[ref, revision]].decode("utf-8"),
            }
        excerpt = original[start:end]
        if not 0 <= start < end <= len(original) or sha256(excerpt).digest() != digest:
            raise OriginalIntegrityError("A repair excerpt does not match its sealed location.")
        return {
            "revision": revision, "paragraph": paragraph, "byte_start": start, "byte_end": end,
            "excerpt": excerpt.decode("utf-8"),
        }

    difference = {
        "version_id": str(run.version_ref), "run_id": str(run_ref), "replaces_run_id": str(run.replaces),
        "rollback_run_id": str(run.baseline) if run.baseline else None, "manifest_sha256": run.manifest.hex(),
        "changes": [{"passage_id": str(ref), "before": item(ref, before), "after": item(ref, after)}
                    for ref, before, after in changes],
    }
    encoded = json.dumps(difference, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return difference, authorize(encoded)


def preview(connection, call, context, run_ref, store, check_authority):
    with connection.transaction():
        run = _current_run(connection, call, PREVIEW, run_ref)
        if connection.execute(
            "SELECT 1 FROM thalion.quality_decision WHERE run_ref = %s", (run_ref,),
        ).fetchone():
            raise processing.QualityConflict("A decided repair cannot be previewed again.")
        difference, delivery = _difference(connection, call, context, run, run_ref, store, check_authority)
        expires = datetime.now(UTC) + PREVIEW_WINDOW
        preview_ref, = connection.execute(
            """
            INSERT INTO thalion.repair_review_preview (
                org_id, space_id, version_id, run_ref, replaces_run_ref, reviewer_id, request_id,
                difference_digest, proof_digest, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING preview_ref
            """,
            (call.org_id, call.space_id, run.original.version_id, run_ref, run.replaces, call.principal_id, call.request_id,
             bytes.fromhex(delivery.payload_sha256), sha256(delivery.authority_proof_ref.encode()).digest(), expires),
        ).fetchone()
        return {
            "preview_id": str(preview_ref), "expires_at": expires.isoformat(), "difference": difference,
        }, delivery.valid_until


def decide(connection, call, context, run_ref, preview_ref, outcome, basis_ref, store, check_authority):
    with connection.transaction():
        run = _current_run(connection, call, DECIDE, run_ref)
        sealed = connection.execute(
            """
            SELECT preview.difference_digest, preview.expires_at
            FROM thalion.repair_review_preview AS preview
            JOIN thalion.request_record AS request USING (org_id, request_id)
            WHERE (preview.org_id, preview.space_id, preview.run_ref, preview.replaces_run_ref, preview.reviewer_id,
                   preview.preview_ref) = (%s, %s, %s, %s, %s, %s)
              AND request.operation = %s AND request.outcome = 'succeeded'
              AND request.client_id = %s
            """,
            (call.org_id, call.space_id, run_ref, run.replaces, call.principal_id, preview_ref, PREVIEW, context.client_id),
        ).fetchone()
        if sealed is None or datetime.now(UTC) >= sealed[1]:
            raise processing.QualityConflict("A current preview by this reviewer is required.")
        if outcome == "approved" and connection.execute(
            "SELECT 1 FROM thalion.quality_decision WHERE run_ref = %s AND outcome = 'quarantined'", (run_ref,),
        ).fetchone():
            raise processing.QualityConflict("A quarantined repair cannot be approved.")
        _, delivery = _difference(connection, call, context, run, run_ref, store, check_authority)
        if sealed[0] != bytes.fromhex(delivery.payload_sha256):
            raise processing.QualityConflict("The exact repair difference has changed.")
        write = SourceWrite(call.org_id, call.principal_id, call.request_id, call.key)
        decision_ref = processing._decide_quality(
            connection, write, call.space_id, run_ref, run.manifest, outcome, basis_ref, preview_ref=preview_ref,
        )
        if datetime.now(UTC) >= min(sealed[1], delivery.valid_until):
            raise AuthorizationUnavailable("The repair decision did not finish within the authorization window.")
        return {"decision_id": str(decision_ref), "outcome": outcome}
