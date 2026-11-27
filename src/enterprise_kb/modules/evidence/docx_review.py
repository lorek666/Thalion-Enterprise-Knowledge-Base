from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from uuid import UUID

from enterprise_kb.modules.access.delivery import (
    AuthorizationUnavailable, DeliveryCandidate, EvidenceScope, LocalAuthorization, SafetyEpochs, authorize_delivery,
)
from enterprise_kb.modules.access.policy import DOCX_PREVIEW_ACCESS, MAX_LOCAL_POLICY_RULES, WORKSPACE_EVIDENCE_FIELDS
from enterprise_kb.modules.access.travel import _read_bindings
from enterprise_kb.modules.operations.context import require_scope
from enterprise_kb.modules.sources.originals import OriginalIntegrityError
from enterprise_kb.modules.sources.registry import SourceWrite

from . import csv_evidence, docx_evidence, processing


PREVIEW, PURPOSE, DESTINATION = DOCX_PREVIEW_ACCESS
DECIDE = processing.DOCX_QUALITY_OPERATION
PREVIEW_WINDOW = timedelta(minutes=5)
MAX_REVIEW_BYTES = 32 * 1024 * 1024
TABLE_BATCH_FORMAT = "table-batch-v1"


@dataclass(frozen=True)
class _CellLocator:
    ref: UUID
    path: tuple[str, ...]
    table: int
    row: int
    column: int
    revision: int
    digest: bytes
    header_digest: bytes
    reason: str | None
    role: str | None


def _current_batch(connection, call, operation, run_ref):
    require_scope(connection, call, operation, destination=DESTINATION)
    run = processing._lock_quality_run(connection, call.org_id, call.space_id, call.principal_id, run_ref)
    if run.original.media_type != docx_evidence.MEDIA_TYPE:
        raise processing.ProcessingNotAdmitted("This is not an admitted DOCX batch.")
    if run.replaces is not None:
        if not processing._docx_run_has_cells(connection, run_ref):
            raise processing.ProcessingNotAdmitted("DOCX paragraph repairs require a difference review.")
        admitted, = connection.execute("SELECT thalion.docx_repair_admitted(%s, %s, %s, %s, %s)", (
            run.original.version_id, run.configuration, run.replaces, run.baseline, run_ref,
        )).fetchone()
        if not admitted:
            raise processing.QualityConflict("The DOCX repair or its baseline is no longer admitted.")
    source, policy, *epochs = connection.execute("""
        SELECT source.source_id, source.local_policy_revision, organization.safety_epoch, space.safety_epoch, source.safety_epoch
        FROM thalion.document_version AS version
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.organization AS organization USING (org_id)
        WHERE version.version_id = %s
    """, (run.original.version_id,)).fetchone()
    return run, source, policy, epochs


def _review_tables(candidate, locators):
    sealed = {(cell.table, cell.row, cell.column): cell for cell in locators}
    tables = []
    for table in candidate.tables:
        rows = []
        for row, unit in zip(table.rows, table.units, strict=True):
            roles = dict(zip(unit.columns, csv_evidence.AMOUNT_ROLES))
            cells = []
            for column, (header, value) in enumerate(zip(table.headers, row.values, strict=True), start=1):
                cell = sealed.pop((table.ordinal, row.record_number, column), None)
                role = roles.get(column)
                if cell is None or (cell.path, cell.digest, cell.header_digest, cell.reason, cell.role) != (
                    table.heading_path, processing._docx_cell_digest(header, value), sha256(header.encode("utf-8")).digest(),
                    unit.reason, role,
                ):
                    raise OriginalIntegrityError("The DOCX cell does not match the sealed batch.")
                cells.append({"passage_id": str(cell.ref), "column_number": column, "excerpt_revision": cell.revision,
                              "excerpt": value, "role": role})
            rows.append({"row_number": row.record_number, "reason": unit.reason, "cells": cells})
        tables.append({"table_number": table.ordinal, "heading_path": table.heading_path, "headers": table.headers,
                       "rows": rows})
    if sealed:
        raise OriginalIntegrityError("The DOCX original does not include all sealed cells.")
    return tables


def batch_locations(connection, org_id, space_id, version_id, run_ref, count):
    rows = connection.execute("""
        SELECT identity.public_id, passage.kind, passage.heading_path, passage.paragraph, passage.docx_paragraph,
               excerpt.excerpt_revision, excerpt.content_digest, passage.docx_table, passage.docx_row,
               passage.docx_column, excerpt.docx_header_digest, unit.reason, member.role
        FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (org_id, space_id, version_id, passage_id)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (passage.org_id, passage.space_id, 'passage', passage.passage_id)
        LEFT JOIN thalion.evidence_unit AS unit
          ON (unit.run_ref, unit.docx_table, unit.record_number) = (excerpt.run_ref, passage.docx_table, passage.docx_row)
        LEFT JOIN thalion.evidence_unit_member AS member
          ON (member.unit_ref, member.passage_id, member.excerpt_revision) =
             (unit.unit_ref, excerpt.passage_id, excerpt.excerpt_revision)
        WHERE (excerpt.org_id, excerpt.space_id, excerpt.version_id, excerpt.run_ref) = (%s, %s, %s, %s)
          AND passage.kind IN ('docx_paragraph', 'docx_cell')
        ORDER BY passage.docx_table NULLS FIRST, passage.docx_paragraph, passage.docx_row, passage.docx_column LIMIT %s
    """, (org_id, space_id, version_id, run_ref, count + 1)).fetchall()
    if count != len(rows):
        raise OriginalIntegrityError("The sealed DOCX batch does not contain all declared locations.")
    return rows


def _review_locations(connection, call, version_id, run_ref):
    count, = connection.execute("SELECT passage_count FROM thalion.processing_run WHERE run_ref = %s", (run_ref,)).fetchone()
    if not 1 <= count <= MAX_LOCAL_POLICY_RULES:
        raise processing.QualityConflict("The complete DOCX batch exceeds the exact review scope limit.")
    try:
        return batch_locations(connection, call.org_id, call.space_id, version_id, run_ref, count)
    except OriginalIntegrityError as error:
        raise processing.QualityConflict(str(error)) from None


def resolve_batch(candidate, rows):
    locations = []
    cells = []
    for ref, kind, path, paragraph, ordinal, revision, digest, table, row, column, header, reason, role in rows:
        if kind == "docx_paragraph":
            locations.append(processing.ApprovedDocxParagraph(ref, tuple(path), paragraph, ordinal, revision, digest))
        elif table is not None:
            cells.append(_CellLocator(ref, tuple(path), table, row, column, revision, digest, header, reason, role))
    if candidate.outcome != "pending_review" or len(candidate.passages) != len(locations):
        raise OriginalIntegrityError("The DOCX original does not match the sealed batch.")
    excerpts = processing._resolve_docx_paragraphs(candidate, locations)
    paragraphs = [{
        "passage_id": str(part.passage_ref), "document_paragraph": part.document_paragraph,
        "excerpt_revision": part.revision, "location": {"heading_path": part.heading_path, "paragraph": part.paragraph},
        "excerpt": excerpts[part].decode("utf-8"),
    } for part in locations]
    return paragraphs, _review_tables(candidate, cells)


def describe_location(location):
    if location is None:
        return None
    _, _, path, paragraph, ordinal, revision, digest, table, row, column, header, reason, role = location
    side = {"heading_path": path, "revision": revision, "excerpt_sha256": digest.hex()}
    if table is None:
        return side | {"paragraph": paragraph, "document_paragraph": ordinal}
    return side | {"table": table, "row": row, "column": column, "header_sha256": header.hex(),
                   "reason": reason, "role": role}


def _repair_changes(prior, proposed):
    before = {part[0]: part for part in prior}
    after = {part[0]: part for part in proposed}
    changes = []
    historical_scopes = []
    for ref in dict.fromkeys((*after, *before)):
        old, new = before.get(ref), after.get(ref)
        if old is not None and new is not None and (old[1:5], old[6:]) == (new[1:5], new[6:]):
            continue
        changes.append({"passage_id": str(ref), "before": describe_location(old), "after": describe_location(new)})
        if old is not None:
            historical_scopes.append((ref, old[5]))
    if not changes or len(before.keys() | after.keys()) > MAX_LOCAL_POLICY_RULES:
        raise processing.QualityConflict("The complete DOCX repair comparison is unavailable within the review limit.")
    return changes, historical_scopes


def _material(connection, call, context, current, run_ref, store, check_authority, *, allow_tables=True):
    run, source, policy, epochs = current
    if policy is None:
        raise processing.ProcessingNotAdmitted("No current local policy authorizes this DOCX review.")
    rows = _review_locations(connection, call, run.original.version_id, run_ref)
    changes, historical_scopes = (), ()
    if run.replaces is not None:
        prior = _review_locations(connection, call, run.original.version_id, run.replaces)
        changes, historical_scopes = _repair_changes(prior, rows)
    context = replace(context, operation=PREVIEW)
    reviewed = [(part[0], part[5]) for part in rows]
    scopes = {
        EvidenceScope(call.space_id, source, ref, WORKSPACE_EVIDENCE_FIELDS, revision): SafetyEpochs(*epochs)
        for ref, revision in (*reviewed, *historical_scopes)
    }

    def load_local(_):
        bindings = _read_bindings(connection, context, call.space_id, source, policy, lock=True)
        return LocalAuthorization(scopes, bindings, exact_allow_scopes=frozenset(scopes))

    def authorize(payload):
        result = authorize_delivery(context, DeliveryCandidate(payload, scopes),
                                    check_authority=check_authority, load_local=load_local)
        if result.status == "dependency_unavailable":
            raise AuthorizationUnavailable("The DOCX review authority is unavailable.")
        if result.status != "succeeded":
            raise processing.ProcessingNotAdmitted("Current review rights do not cover the entire DOCX batch.")
        return result

    authorize(run.manifest)
    if not allow_tables and any(part[1] == "docx_cell" for part in rows):
        raise processing.QualityConflict("The requesting client must support the full DOCX table batch format.")
    candidate = docx_evidence.parse_docx(store.read(run.original.asset), amount_columns=run.original.docx_amount_columns)
    paragraphs, tables = resolve_batch(candidate, rows)
    batch = {
        "version_id": str(run.version_ref), "run_id": str(run_ref), "manifest_sha256": run.manifest.hex(),
        "paragraphs": paragraphs,
    }
    if tables:
        batch["tables"] = tables
    if run.replaces is not None:
        basis, = connection.execute(
            "SELECT repair_basis_ref FROM thalion.processing_run WHERE run_ref = %s", (run_ref,),
        ).fetchone()
        batch["repair"] = {
            "replaces_run_id": str(run.replaces), "rollback_run_id": str(run.baseline) if run.baseline else None,
            "repair_basis_id": str(basis), "changes": changes,
        }
    payload = json.dumps(batch, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_REVIEW_BYTES:
        raise processing.QualityConflict("The complete DOCX review exceeds the preview limit.")
    return batch, authorize(payload)


def preview(connection, call, context, run_ref, store, check_authority, *, allow_tables=False):
    current = _current_batch(connection, call, PREVIEW, run_ref)
    run, _, policy, epochs = current
    if connection.execute("SELECT 1 FROM thalion.quality_decision WHERE run_ref = %s", (run_ref,)).fetchone():
        raise processing.QualityConflict("A decided DOCX batch is not pending review.")
    batch, delivery = _material(connection, call, context, current, run_ref, store, check_authority, allow_tables=allow_tables)
    expires = delivery.checked_at + PREVIEW_WINDOW
    connection.execute("""
        INSERT INTO thalion.docx_quality_preview (
            org_id, space_id, version_id, run_ref, request_id, policy_revision, safety_epochs,
            batch_digest, proof_digest, checked_at, expires_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (call.org_id, call.space_id, run.original.version_id, run_ref, call.request_id, policy, epochs,
          bytes.fromhex(delivery.payload_sha256), sha256(delivery.authority_proof_ref.encode()).digest(),
          delivery.checked_at, expires))
    return {"preview_id": str(call.request_id), "expires_at": expires.isoformat(), "batch": batch}, delivery.valid_until


def decide(connection, call, context, run_ref, preview_ref, outcome, basis_ref, store, check_authority):
    current = _current_batch(connection, call, DECIDE, run_ref)
    run, _, policy, epochs = current
    receipt = connection.execute("""
        SELECT preview.batch_digest, preview.expires_at
        FROM thalion.docx_quality_preview AS preview JOIN thalion.request_record AS request USING (org_id, request_id)
        WHERE (preview.org_id, preview.space_id, preview.version_id, preview.run_ref, preview.request_id)
            = (%s, %s, %s, %s, %s)
          AND preview.policy_revision = %s AND preview.safety_epochs = %s::bigint[]
          AND (request.principal_id, request.client_id, request.operation, request.destination, request.outcome)
            = (%s, %s, %s, %s, 'succeeded')
          AND request.delegated_principal_id IS NULL AND request.configuration_revision = %s
          AND preview.expires_at > clock_timestamp()
    """, (call.org_id, call.space_id, run.original.version_id, run_ref, preview_ref, policy, epochs,
          call.principal_id, context.client_id, PREVIEW, DESTINATION, call.configuration_revision)).fetchone()
    if receipt is None:
        raise processing.QualityConflict("A current preview by the same reviewer and client is required.")
    _, delivery = _material(connection, call, context, current, run_ref, store, check_authority)
    if receipt[0] != bytes.fromhex(delivery.payload_sha256) or datetime.now(UTC) >= receipt[1]:
        raise processing.QualityConflict("The exact DOCX review preview changed or expired.")
    write = SourceWrite(call.org_id, call.principal_id, call.request_id, call.key)
    decision = processing._decide_quality(
        connection, write, call.space_id, run_ref, run.manifest, outcome, basis_ref, docx_preview=preview_ref,
    )
    return {"decision_id": str(decision), "outcome": outcome}, min(receipt[1], delivery.valid_until)
