from dataclasses import dataclass, field
from datetime import timedelta
from hashlib import sha256
from typing import Literal
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus

from enterprise_kb.modules.sources.originals import (
    ObjectStorageOriginalStore, OriginalAsset, OriginalIntegrityError, SyntheticOriginalStore,
)
from enterprise_kb.modules.sources.registry import (
    SourceWrite, _command, _digest, _register_identity, has_source_delete_isolation,
    sql_admitted_admission, sql_issuer_matches_admission, sql_storage_matches_admission,
    store_admission,
)
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import JobLease, _lock_current_job, _require_read_committed, claim_job, complete_job, retry_job

from . import csv_evidence, docx_evidence, multiformat_evidence, pdf_evidence
from .markdown import LOCATOR_REVISION, PARSER_VERSION, PROFILE, MarkdownPassage, parse_markdown


MAX_CSV_EVIDENCE_CELLS = 1024
DOCX_QUALITY_OPERATION = "decide_docx_quality"


class ProcessingNotAdmitted(Exception):
    pass


class ProcessingDependencyUnavailable(Exception):
    pass


class QualityConflict(Exception):
    pass


QUALITY_OPERATION = "decide_evidence_quality"
PDF_REPAIR_APPROVAL_OPERATION = "approve_pdf_repair"
STATUS_OPERATION = "read_source_processing_status"


@dataclass(frozen=True)
class ProcessingResult:
    run_ref: UUID
    manifest_digest: bytes
    outcome: str
    reason: str | None
    passage_count: int


@dataclass(frozen=True)
class ApprovedPassage:
    passage_ref: UUID
    heading_path: tuple[str, ...] = field(repr=False)
    paragraph: int
    kind: str
    byte_start: int
    byte_end: int
    revision: int
    digest: bytes


@dataclass(frozen=True)
class ApprovedCsvCell:
    passage_ref: UUID
    record_number: int
    column_number: int
    revision: int
    digest: bytes


@dataclass(frozen=True)
class ApprovedPdfPage:
    passage_ref: UUID
    run_ref: UUID
    page_number: int
    revision: int
    digest: bytes


@dataclass(frozen=True)
class ApprovedDocxParagraph:
    passage_ref: UUID
    heading_path: tuple[str, ...] = field(repr=False)
    paragraph: int
    document_paragraph: int
    revision: int
    digest: bytes


@dataclass(frozen=True)
class ApprovedStructuredPassage:
    passage_ref: UUID
    kind: str
    structured_locator: str
    heading_path: tuple[str, ...] = field(repr=False)
    paragraph: int
    revision: int
    digest: bytes
    extracted_text: str = field(repr=False)


@dataclass(frozen=True)
class ApprovedDocxCell:
    passage_ref: UUID
    heading_path: tuple[str, ...] = field(repr=False)
    table_number: int
    row_number: int
    column_number: int
    revision: int
    digest: bytes
    header_digest: bytes


@dataclass(frozen=True)
class ApprovedDocxMember:
    role: str
    cell: ApprovedDocxCell


@dataclass(frozen=True)
class ApprovedDocxUnit:
    unit_ref: UUID
    table_number: int
    row_number: int
    amount_columns: tuple[str, str, str, str] = field(repr=False)
    members: tuple[ApprovedDocxMember, ...]


@dataclass(frozen=True)
class ApprovedCsvMember:
    role: str
    cell: ApprovedCsvCell
    is_alternative: bool = False


@dataclass(frozen=True)
class ApprovedCsvUnit:
    unit_ref: UUID
    record_number: int
    members: tuple[ApprovedCsvMember, ...]


def _csv_cell_digest(header: str, value: str) -> bytes:
    return _digest("csv_cell.v1", header, value)


def resolve_csv_cell(payload: bytes, cell: ApprovedCsvCell) -> tuple[str, str]:
    return resolve_csv_cells(payload, (cell,))[0]


def resolve_csv_cells(payload: bytes, cells: tuple[ApprovedCsvCell, ...]) -> tuple[tuple[str, str], ...]:
    candidate = csv_evidence.parse_csv(payload)
    if candidate.outcome != "pending_review":
        raise OriginalIntegrityError("The CSV original cannot be parsed.")
    materials = []
    for cell in cells:
        row_index = cell.record_number - 2
        column_index = cell.column_number - 1
        if not (0 <= row_index < len(candidate.rows) and 0 <= column_index < len(candidate.headers)):
            raise OriginalIntegrityError("The approved CSV location is not present.")
        row = candidate.rows[row_index]
        header, value = candidate.headers[column_index], row.values[column_index]
        if row.record_number != cell.record_number or _csv_cell_digest(header, value) != cell.digest:
            raise OriginalIntegrityError("The CSV cell does not match the approved location and revision.")
        materials.append((header, value))
    return tuple(materials)


def resolve_pdf_transcripts(connection: Connection, pages: tuple[ApprovedPdfPage, ...]) -> dict[ApprovedPdfPage, bytes]:
    if not pages:
        return {}
    rows = connection.execute("""
        SELECT page.run_ref, page.page_number, page.transcript
        FROM unnest(%s::uuid[], %s::integer[]) AS requested(run_ref, page_number)
        JOIN thalion.pdf_page_observation AS page USING (run_ref, page_number)
    """, ([page.run_ref for page in pages], [page.page_number for page in pages])).fetchall()
    sealed = {(run, number): transcript for run, number, transcript in rows}
    transcripts = {}
    for page in pages:
        transcript = sealed.get((page.run_ref, page.page_number))
        if transcript is None or sha256(transcript).digest() != page.digest:
            raise OriginalIntegrityError("The PDF transcript does not match the approved page revision.")
        transcripts[page] = transcript
    return transcripts


def resolve_structured_excerpts(
    payload: bytes,
    media_type: str,
    locations: tuple[ApprovedStructuredPassage, ...],
) -> dict[ApprovedStructuredPassage, bytes]:
    if not locations:
        return {}
    if media_type in multiformat_evidence.IMAGE_MEDIA_TYPES:
        if not multiformat_evidence.validate_image_magic(payload, media_type):
            raise OriginalIntegrityError("The stored image original failed format verification.")
        resolved: dict[ApprovedStructuredPassage, bytes] = {}
        for loc in locations:
            encoded = loc.extracted_text.encode("utf-8")
            if sha256(encoded).digest() != loc.digest:
                raise OriginalIntegrityError("The sealed image OCR excerpt does not match its digest.")
            resolved[loc] = encoded
        return resolved
    candidate = multiformat_evidence.parse_structured(payload, media_type)
    if candidate.reason is not None:
        raise OriginalIntegrityError("The stored original cannot reproduce approved structured passages.")
    by_locator = {(p.kind, p.structured_locator): p for p in candidate.passages}
    resolved = {}
    for loc in locations:
        matched = by_locator.get((loc.kind, loc.structured_locator))
        if matched is None or matched.digest != loc.digest:
            raise OriginalIntegrityError("A structured excerpt does not match its approved original.")
        resolved[loc] = matched.text.encode("utf-8")
    return resolved


def resolve_structured_excerpt(payload: bytes, media_type: str, location: ApprovedStructuredPassage) -> bytes:
    return resolve_structured_excerpts(payload, media_type, (location,))[location]


def resolve_docx_paragraph(payload: bytes, location: ApprovedDocxParagraph) -> bytes:
    return resolve_docx_paragraphs(payload, (location,))[location]


def resolve_docx_paragraphs(
    payload: bytes, locations: tuple[ApprovedDocxParagraph, ...],
) -> dict[ApprovedDocxParagraph, bytes]:
    return _resolve_docx_paragraphs(docx_evidence.parse_docx(payload), locations)


def _resolve_docx_paragraphs(candidate, locations):
    paragraphs = {part.document_paragraph: part for part in candidate.passages}
    excerpts = {}
    for location in locations:
        part = paragraphs.get(location.document_paragraph)
        if part is None or (part.heading_path, part.paragraph, part.digest) != (
            location.heading_path, location.paragraph, location.digest,
        ):
            raise OriginalIntegrityError("The DOCX paragraph does not match the approved location and revision.")
        excerpts[location] = part.text
    return excerpts


def resolve_docx_units(payload: bytes, units: tuple[ApprovedDocxUnit, ...]) -> dict[ApprovedDocxCell, tuple[str, str]]:
    if not units:
        return {}
    layouts = {unit.amount_columns for unit in units}
    if len(layouts) != 1:
        raise OriginalIntegrityError("DOCX row evidence requires one exact source layout.")
    candidate = docx_evidence.parse_docx(payload, amount_columns=units[0].amount_columns)
    tables = {table.ordinal: table for table in candidate.tables}
    verified = {}
    for unit in units:
        table = tables.get(unit.table_number)
        row_index = unit.row_number - 2
        if table is None or not 0 <= row_index < len(table.rows) or len(unit.members) != len(csv_evidence.AMOUNT_ROLES):
            raise OriginalIntegrityError("The original does not contain the complete approved DOCX evidence row.")
        row = table.rows[row_index]
        observed = table.units[row_index]
        expected_roles = dict(zip(csv_evidence.AMOUNT_ROLES, observed.columns))
        if observed.reason is not None or {member.role for member in unit.members} != expected_roles.keys():
            raise OriginalIntegrityError("The approved DOCX row does not match the original evidence roles.")
        for member in unit.members:
            cell = member.cell
            column = expected_roles[member.role]
            header, value = table.headers[column - 1], row.values[column - 1]
            if (cell.table_number, cell.row_number, cell.column_number, cell.heading_path, cell.digest, cell.header_digest) != (
                table.ordinal, row.record_number, column, table.heading_path,
                _docx_cell_digest(header, value), sha256(header.encode("utf-8")).digest(),
            ):
                raise OriginalIntegrityError("A DOCX evidence member does not match its approved location and content.")
            verified[cell] = (header, value)
    return verified


@dataclass(frozen=True)
class _Original:
    version_id: int
    contract_revision: int
    media_type: str
    asset: OriginalAsset
    csv_amount_layout: csv_evidence.AmountLayout | None
    docx_amount_columns: tuple[str, str, str, str] | None
    admission: str = "synthetic_only"


def _read_original(
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
    original: _Original,
) -> bytes:
    if store_admission(store) != original.admission:
        raise ProcessingNotAdmitted("Original store admission mode does not match source contract.")
    return store.read(original.asset)


@dataclass(frozen=True)
class _QualityRun:
    version_ref: UUID
    original: _Original
    configuration: int
    manifest: bytes
    replaces: UUID | None
    baseline: UUID | None


def read_source_processing_status(
    connection: Connection, org_id: int, space_id: int, owner_id: int, version_ref: UUID,
) -> str:
    original = connection.execute(
        f"""
        SELECT version.version_id, source.contract_revision, asset.content_digest,
               version.source_id, version.document_id
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.document AS document
          ON (document.org_id, document.space_id, document.source_id, document.document_id)
           = (version.org_id, version.space_id, version.source_id, version.document_id)
        JOIN thalion.asset AS asset
          ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
           = (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id) = (version.org_id, version.space_id, version.source_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
          AND source.owner_principal_id = %s AND source.lifecycle = 'active'
          AND {sql_admitted_admission('contract.admission')}
          AND {sql_storage_matches_admission('asset.storage_kind', 'contract.admission')}
        FOR SHARE OF source, document
        """,
        (org_id, space_id, version_ref, owner_id),
    ).fetchone()
    if original is None:
        raise ProcessingNotAdmitted("The exact synthetic version is not available to this owner.")
    version_id, contract_revision, digest, source_id, document_id = original
    delete_clause = (
        "OR thalion.document_source_deleted(%(org)s, %(space)s, %(source)s, %(document)s)"
        if has_source_delete_isolation(connection)
        else ""
    )
    state, = connection.execute(
        f"""
        SELECT CASE
          WHEN EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = %(version)s)
            {delete_clause}
            OR EXISTS (
                SELECT 1 FROM thalion.current_version_hold WHERE version_id = %(version)s AND action = 'establish'
            ) THEN 'blocked'
          WHEN job.job_id IS NULL THEN 'not_scheduled'
          WHEN job.state = 'running' AND attempt.lease_expires_at > clock_timestamp() THEN 'processing'
          WHEN job.state IN ('queued', 'running') THEN 'queued'
          WHEN run.run_ref IS NULL THEN NULL
          WHEN run.contract_revision <> %(contract)s THEN 'blocked'
          WHEN run.outcome = 'quarantined' OR EXISTS (
            SELECT 1 FROM thalion.quality_decision WHERE run_ref = run.run_ref AND outcome = 'quarantined'
          ) THEN 'quarantined'
          WHEN EXISTS (
            SELECT 1 FROM thalion.quality_decision WHERE run_ref = run.run_ref AND outcome = 'approved'
          ) THEN 'quality_approved'
          ELSE 'pending_review'
        END
        FROM (VALUES (1)) AS selected(singleton)
        LEFT JOIN LATERAL (
            SELECT job_id, state, generation, result_ref FROM thalion.job
            WHERE (org_id, space_id, target_ref, stage, input_digest)
                = (%(org)s, %(space)s, %(ref)s, 'parse', %(digest)s)
            ORDER BY configuration_revision DESC LIMIT 1
        ) AS job ON true
        LEFT JOIN thalion.job_attempt AS attempt
          ON (attempt.org_id, attempt.job_id, attempt.generation, attempt.outcome)
           = (%(org)s, job.job_id, job.generation, 'running')
        LEFT JOIN thalion.processing_run AS run
          ON (run.version_id, run.run_ref, run.job_id) = (%(version)s, job.result_ref, job.job_id)
         AND job.state = 'succeeded'
        """,
        {"org": org_id, "space": space_id, "ref": version_ref, "version": version_id,
         "source": source_id, "document": document_id, "contract": contract_revision, "digest": digest},
    ).fetchone()
    if state is None:
        raise ProcessingDependencyUnavailable("The current parse job has no corresponding completed run.")
    return state


def count_review_backlogs(connection: Connection, org_id: int, space_id: int) -> tuple[int, int]:
    delete_clause = (
        "AND NOT thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
        if has_source_delete_isolation(connection)
        else ""
    )
    quality_pending, ocr_pages_pending = connection.execute(
        f"""
        WITH current_runs AS (
            SELECT current.run_ref, current.outcome, version.org_id, version.space_id
            FROM thalion.document_version AS version
            JOIN thalion.space AS space USING (org_id, space_id)
            JOIN thalion.source AS source USING (org_id, space_id, source_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (source.org_id, source.space_id, source.source_id, source.contract_revision)
            JOIN thalion.asset AS asset
              ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
               = (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
            CROSS JOIN LATERAL (
                SELECT run_ref, contract_revision, outcome
                FROM thalion.processing_run WHERE version_id = version.version_id
                ORDER BY configuration_revision DESC LIMIT 1
            ) AS current
            WHERE (version.org_id, version.space_id) = (%s, %s)
              AND space.lifecycle = 'active' AND source.lifecycle = 'active'
              AND {sql_admitted_admission('contract.admission')}
              AND {sql_storage_matches_admission('asset.storage_kind', 'contract.admission')}
              AND current.contract_revision = contract.revision
              AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = version.version_id)
              {delete_clause}
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.current_version_hold AS hold
                  WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                      = (version.org_id, version.space_id, version.version_id, 'establish')
              )
        )
        SELECT (
            SELECT count(*) FROM current_runs AS current
            WHERE current.outcome = 'pending_review'
              AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision WHERE run_ref = current.run_ref)
        ), (
            SELECT count(DISTINCT (correction.run_ref, correction.page_number))
            FROM current_runs JOIN thalion.pdf_ocr_correction AS correction USING (org_id, space_id, run_ref)
            WHERE NOT EXISTS (
                SELECT 1 FROM thalion.pdf_ocr_review_decision WHERE correction_ref = correction.correction_ref
            ) AND NOT EXISTS (
                SELECT 1 FROM thalion.pdf_ocr_review_decision AS approved
                WHERE (approved.run_ref, approved.page_number, approved.outcome)
                    = (correction.run_ref, correction.page_number, 'approved')
            )
        )
        """, (org_id, space_id),
    ).fetchone()
    return quality_pending, ocr_pages_pending


def _lock_original(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID, actor_id: int,
    *, role: Literal["processor", "reviewer", "pdf_author", "pdf_preview"] = "processor",
) -> _Original:
    row = connection.execute(
        f"""
        SELECT version.version_id, contract.revision, asset.media_type, asset.storage_key,
               asset.content_digest, asset.byte_length, to_jsonb(contract)->'csv_amount_columns',
               to_jsonb(contract)->'csv_exception_link_columns', to_jsonb(contract)->'csv_alternate_columns',
               to_jsonb(contract)->'docx_amount_columns', contract.admission
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.document AS doc ON doc.document_id = version.document_id
        JOIN thalion.asset AS asset ON asset.asset_id = version.asset_id
        JOIN thalion.source AS source ON source.source_id = version.source_id
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS actor ON actor.org_id = contract.org_id AND actor.principal_id = %s
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND {sql_admitted_admission('contract.admission')}
          AND {sql_storage_matches_admission('asset.storage_kind', 'contract.admission')}
          AND actor.principal_type = %s
          AND {sql_issuer_matches_admission('actor.authority_issuer', 'contract.admission')}
          AND NOT actor.disabled
          AND CASE %s
              WHEN 'processor' THEN actor.principal_id = contract.processor_id
              WHEN 'reviewer' THEN actor.principal_id = contract.quality_reviewer_id
              WHEN 'pdf_author' THEN asset.media_type = 'application/pdf'
                    AND actor.principal_id <> contract.quality_reviewer_id
              WHEN 'pdf_preview' THEN asset.media_type = 'application/pdf' AND contract.quality_reviewer_id IS NOT NULL
          END
        FOR SHARE OF source, space, actor
        FOR UPDATE OF doc
        """,
        (
            actor_id, org_id, space_id, version_ref,
            "service" if role == "processor" else "employee", role,
        ),
    ).fetchone()
    delete_clause = (
        "OR thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
        if has_source_delete_isolation(connection)
        else ""
    )
    if row is None or connection.execute(
        f"""
        SELECT 1 FROM thalion.document_version AS version
        WHERE (version.org_id, version.space_id, version.version_id) = (%s, %s, %s)
          AND (
              EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = version.version_id)
              {delete_clause}
          )
        LIMIT 1
        """,
        (org_id, space_id, row[0]),
    ).fetchone():
        raise ProcessingNotAdmitted("The current source does not admit this evidence operation.")
    if (role == "processor" or row[2] in (docx_evidence.MEDIA_TYPE, pdf_evidence.MEDIA_TYPE)) and connection.execute("""
        SELECT 1 FROM thalion.current_version_hold
        WHERE (org_id, space_id, version_id, action) = (%s, %s, %s, 'establish')
        """, (org_id, space_id, row[0])).fetchone():
        raise ProcessingNotAdmitted("A held original cannot be processed or reviewed.")
    layout = csv_evidence.AmountLayout(
        *row[6], exception_link=tuple(row[7]) if row[7] else None,
        alternate_columns=tuple(row[8]) if row[8] else None,
    ) if row[6] else None
    return _Original(*row[:3], OriginalAsset(*row[3:6]), layout, tuple(row[9]) if row[9] is not None else None, row[10])


def _prepare_original(connection: Connection, lease: JobLease) -> _Original:
    spec = lease.spec
    original = _lock_original(connection, spec.org_id, spec.space_id, spec.target_ref, lease.worker_id)
    config = connection.execute(
        """
        SELECT parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = %s
        """,
        (spec.configuration_revision,),
    ).fetchone()
    expected = {
        "text/markdown": (PARSER_VERSION, PROFILE, LOCATOR_REVISION),
        "text/csv": (csv_evidence.PARSER_VERSION, csv_evidence.PROFILE, csv_evidence.LOCATOR_REVISION),
        pdf_evidence.MEDIA_TYPE: (pdf_evidence.PARSER_VERSION, pdf_evidence.PROFILE, pdf_evidence.LOCATOR_REVISION),
        docx_evidence.MEDIA_TYPE: (docx_evidence.PARSER_VERSION, docx_evidence.PROFILE, docx_evidence.LOCATOR_REVISION),
        **{
            mt: (multiformat_evidence.PARSER_VERSION, prof, multiformat_evidence.LOCATOR_REVISION)
            for mt, prof in multiformat_evidence.PROFILES.items()
        },
    }.get(original.media_type)
    if original.asset.digest != spec.input_digest or expected is None or config != expected:
        raise ProcessingNotAdmitted("The lease does not match the original and admitted parser configuration.")
    return original


def process_markdown_job(
    connection: Connection, lease: JobLease, store: SyntheticOriginalStore,
) -> ProcessingResult:
    return process_evidence_job(connection, lease, store, expected_media_type="text/markdown")


def process_registered_version(
    connection: Connection, version_ref: UUID, processor_ref: UUID, store: SyntheticOriginalStore,
    *, pdf_ocr: pdf_evidence.Tesseract | None = None,
) -> tuple[str, UUID | None]:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Original reads must occur outside business transactions.")
    with connection.transaction():
        candidates = connection.execute("""
            SELECT job.org_id, job.space_id, job.job_id, job.result_ref, processor.object_id
            FROM thalion.job AS job
            JOIN thalion.object_identity AS processor ON processor.org_id = job.org_id
            WHERE (job.target_ref, job.stage, processor.object_type, processor.public_id) =
                  (%s, 'parse', 'principal', %s)
              AND EXISTS (
                  SELECT 1 FROM thalion.request_job AS linked
                  JOIN thalion.command_receipt AS receipt USING (org_id, request_id)
                  WHERE (linked.org_id, linked.job_id, receipt.operation, receipt.result_ref) =
                        (job.org_id, job.job_id, 'register_version', job.target_ref)
              )
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.external_call_budget AS budget
                  WHERE (budget.org_id, budget.job_id) = (job.org_id, job.job_id)
              )
            LIMIT 2
            """, (version_ref, processor_ref)).fetchall()
        if len(candidates) != 1:
            raise ProcessingNotAdmitted("An exact registered version and its initial parse job are required.")
        org_id, space_id, job_id, result_ref, processor_id = candidates[0]
        _lock_original(connection, org_id, space_id, version_ref, processor_id)
        if result_ref is not None:
            return "already_processed", result_ref
        lease = claim_job(connection, org_id, "parse", processor_id, timedelta(minutes=2), job_id=job_id)
    if lease is None:
        return "not_claimable", None
    try:
        result = process_evidence_job(connection, lease, store, pdf_ocr=pdf_ocr)
    except (OriginalIntegrityError, ProcessingDependencyUnavailable, ProcessingNotAdmitted):
        retry_job(connection, lease, delay=timedelta(seconds=30))
        raise
    return result.outcome, result.run_ref


def process_evidence_job(
    connection: Connection, lease: JobLease, store: SyntheticOriginalStore, *, expected_media_type: str | None = None,
    pdf_ocr: pdf_evidence.Tesseract | None = None,
) -> ProcessingResult:
    if lease.spec.stage != "parse":
        raise ProcessingNotAdmitted("The lease is not for parsing.")
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Original reads must occur outside business transactions.")
    with connection.transaction():
        _lock_current_job(connection, lease)
        original = _prepare_original(connection, lease)
        if expected_media_type is not None and original.media_type != expected_media_type:
            raise ProcessingNotAdmitted("The original does not match the required media type.")
    payload = _read_original(store, original)
    if original.media_type == "text/csv":
        return _record_csv_candidate(connection, lease, original, csv_evidence.parse_csv(payload))
    if original.media_type == docx_evidence.MEDIA_TYPE:
        return _record_docx_candidate(connection, lease, original, docx_evidence.parse_docx(
            payload, amount_columns=original.docx_amount_columns,
        ))
    if original.media_type == pdf_evidence.MEDIA_TYPE:
        try:
            candidate = pdf_evidence.parse_pdf(payload, ocr=pdf_ocr)
        except pdf_evidence.PdfDependencyUnavailable as error:
            raise ProcessingDependencyUnavailable(str(error)) from None
        return _record_pdf_candidate(connection, lease, original, candidate)
    if original.media_type in multiformat_evidence.STRUCTURED_MEDIA_TYPES:
        try:
            candidate = multiformat_evidence.parse_structured(payload, original.media_type, ocr=pdf_ocr)
        except multiformat_evidence.ImageOcrUnavailable as error:
            raise ProcessingDependencyUnavailable(str(error)) from None
        return _record_structured_candidate(connection, lease, original, candidate)
    return _record_markdown_candidate(connection, lease, original, parse_markdown(payload))


@dataclass(frozen=True)
class _EvidenceRepair:
    replaces: UUID
    rollback_to: UUID | None
    basis_ref: UUID


def _require_literal_repair(connection, lease, original, repair):
    guard = "docx_repair_admitted" if original.media_type == docx_evidence.MEDIA_TYPE else "markdown_repair_admitted"
    admitted, = connection.execute(
        f"SELECT thalion.{guard}(%s, %s, %s, %s)",
        (original.version_id, lease.spec.configuration_revision, repair.replaces, repair.rollback_to),
    ).fetchone()
    if not admitted:
        raise QualityConflict("The repair requires the current quarantine and, for rollback, an approved baseline.")


def repair_markdown_job(
    connection: Connection, lease: JobLease, store: SyntheticOriginalStore,
    *, replaces: UUID, basis_ref: UUID, rollback_to: UUID | None = None,
) -> ProcessingResult:
    return _repair_literal_job(connection, lease, store, "text/markdown", _EvidenceRepair(replaces, rollback_to, basis_ref))


def repair_docx_job(
    connection: Connection, lease: JobLease, store: SyntheticOriginalStore,
    *, replaces: UUID, basis_ref: UUID, rollback_to: UUID | None = None, allow_tables: bool = False,
) -> ProcessingResult:
    return _repair_literal_job(
        connection, lease, store, docx_evidence.MEDIA_TYPE,
        _EvidenceRepair(replaces, rollback_to, basis_ref), allow_tables=allow_tables,
    )


def _docx_run_has_cells(connection, run_ref):
    return connection.execute("SELECT thalion.docx_run_has_cells(%s)", (run_ref,)).fetchone()[0]


def _repair_literal_job(connection, lease, store, media_type, repair, *, allow_tables=False):
    if lease.spec.stage != "parse":
        raise ProcessingNotAdmitted("The lease is not for parsing.")
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Original reads must occur outside business transactions.")
    with connection.transaction():
        _lock_current_job(connection, lease)
        original = _prepare_original(connection, lease)
        if original.media_type != media_type:
            raise ProcessingNotAdmitted("This repair does not match the original media type.")
        _require_literal_repair(connection, lease, original, repair)
        if media_type == docx_evidence.MEDIA_TYPE and not allow_tables and any(
            _docx_run_has_cells(connection, ref) for ref in (repair.replaces, repair.rollback_to) if ref is not None
        ):
            raise QualityConflict("A DOCX table repair requires explicit whole-table processing.")
    payload = _read_original(store, original)
    if media_type == docx_evidence.MEDIA_TYPE:
        candidate = docx_evidence.parse_docx(payload, amount_columns=original.docx_amount_columns)
        if candidate.outcome != "pending_review" or bool(candidate.tables) != allow_tables:
            raise QualityConflict("The DOCX repair must produce a reviewable batch in the requested format.")
        return _record_docx_candidate(connection, lease, original, candidate, repair=repair)
    candidate = parse_markdown(payload)
    if candidate.outcome != "pending_review":
        raise QualityConflict("The repaired Markdown must produce a reviewable candidate.")
    return _record_markdown_candidate(connection, lease, original, candidate, repair=repair)


def _pdf_repair_candidate(connection, lease, original, repair, *, submitted_ref=None):
    admitted, = connection.execute(
        "SELECT thalion.pdf_repair_admitted(%s, %s, %s, %s)",
        (original.version_id, lease.spec.configuration_revision, repair.replaces, submitted_ref),
    ).fetchone()
    if not admitted:
        raise QualityConflict("A PDF repair requires the current quarantined batch and a compatible new revision.")
    rows = connection.execute("""
        SELECT page_number, method, transcript, reason, ocr_profile_digest, repair_decision_ref, changed
        FROM thalion.pdf_repair_pages(%s) ORDER BY page_number
    """, (repair.replaces,)).fetchall()
    if not any(row[-1] for row in rows) or any(row[2] is None for row in rows):
        raise QualityConflict("A PDF repair requires a change and a complete set of transcribed pages.")
    return pdf_evidence.PdfCandidate(tuple(pdf_evidence.PageObservation(*row[:-1]) for row in rows))


def repair_pdf_job(
    connection: Connection, lease: JobLease, store: SyntheticOriginalStore, *, replaces: UUID, basis_ref: UUID,
) -> ProcessingResult:
    if lease.spec.stage != "parse":
        raise ProcessingNotAdmitted("The lease is not for PDF repair.")
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Original reads must occur outside business transactions.")
    repair = _EvidenceRepair(replaces, None, basis_ref)
    with connection.transaction():
        _lock_current_job(connection, lease)
        original = _prepare_original(connection, lease)
        if original.media_type != pdf_evidence.MEDIA_TYPE:
            raise ProcessingNotAdmitted("This repair requires a PDF original.")
        candidate = _pdf_repair_candidate(connection, lease, original, repair)
    _read_original(store, original)
    return _record_pdf_candidate(connection, lease, original, candidate, repair=repair)


def _record_markdown_candidate(
    connection, lease, original, candidate, *, passage_refs=None, restored_run_ref=None, repair=None,
):
    spec = lease.spec
    manifest = _digest(
        "markdown_manifest.v1", str(spec.target_ref), spec.input_digest.hex(),
        spec.configuration_revision, candidate.outcome, candidate.reason,
        [
            (part.heading_path, part.paragraph, part.kind, part.byte_start, part.byte_end, part.digest.hex())
            for part in candidate.passages
        ],
    )

    def write_passages(scope):
        if passage_refs is None:
            for part in candidate.passages:
                _write_passage(*scope, part)
        else:
            for part, ref in zip(candidate.passages, passage_refs, strict=True):
                _write_passage(*scope, part, public_id=ref)

    return _record_candidate(
        connection, lease, original, manifest, candidate.outcome, candidate.reason, len(candidate.passages),
        write_passages, restored_run_ref=restored_run_ref, repair=repair,
    )


def _record_csv_candidate(connection, lease, original, candidate):
    if len(candidate.rows) * len(candidate.headers) > MAX_CSV_EVIDENCE_CELLS:
        candidate = csv_evidence.CsvCandidate("quarantined", "size_limit")
    spec = lease.spec
    layout = original.csv_amount_layout
    unit_headers = set()
    if layout and layout.alternate_columns:
        unit_headers = {
            header for pair in zip(layout.headers, layout.alternate_columns, strict=True)
            if pair[1] in candidate.headers for header in pair
        }
    header_digests = {header: sha256(header.encode("utf-8")).digest() for header in unit_headers}
    parts = tuple(
        (
            row.record_number, column, _csv_cell_digest(header, value),
            (header_digests[header], _digest("csv_equivalence.v1", str(spec.target_ref), row.record_number, value))
            if header in header_digests else None,
        )
        for row in candidate.rows
        for column, (header, value) in enumerate(zip(candidate.headers, row.values, strict=True), start=1)
    )
    units = csv_evidence.amount_units(candidate, layout) if layout else ()
    grouping = ((
        "csv_amount_units.v1", layout.headers,
        [(unit.record_number, unit.columns, unit.reason) for unit in units],
    ),) if layout else ()
    if layout and layout.exception_link:
        grouping = ((
            "csv_amount_units.v2", layout.headers, layout.exception_link,
            [(unit.record_number, unit.columns, unit.reason, unit.exception_record) for unit in units],
        ),)
    if layout and layout.alternate_columns:
        grouping = ((
            "csv_amount_units.v3", layout.headers, layout.exception_link, layout.alternate_columns,
            [(unit.record_number, unit.columns, unit.reason, unit.exception_record, unit.alternatives) for unit in units],
        ),)
    manifest = _digest(
        "csv_manifest.v1", str(spec.target_ref), spec.input_digest.hex(), spec.configuration_revision,
        candidate.outcome, candidate.reason, [(record, column, digest.hex()) for record, column, digest, _ in parts],
        *grouping,
    )

    def write_passages(scope):
        for part in parts:
            _write_csv_cell(*scope, *part)
        for unit in units:
            _write_csv_unit(scope[0], scope[-1], unit)

    return _record_candidate(
        connection, lease, original, manifest, candidate.outcome, candidate.reason, len(parts), write_passages,
    )


def _docx_cell_digest(header: str, value: str) -> bytes:
    return _digest("docx_cell.v1", header, value)


def docx_candidate_cells(candidate):
    return tuple(
        (table.ordinal, row.record_number, column, table.heading_path, _docx_cell_digest(header, value),
         sha256(header.encode("utf-8")).digest())
        for table in candidate.tables for row in table.rows
        for column, (header, value) in enumerate(zip(table.headers, row.values, strict=True), start=1)
    )


def docx_processing_manifest(version_ref, input_digest, configuration, amount_columns, candidate, cells):
    return docx_manifest_from_locations(
        version_ref, input_digest, configuration, amount_columns, candidate.outcome, candidate.reason,
        [(part.document_paragraph, part.heading_path, part.paragraph, part.digest.hex()) for part in candidate.passages],
        cells, [(table.ordinal, unit.record_number, unit.columns, unit.reason)
                for table in candidate.tables for unit in table.units],
    )


def docx_manifest_from_locations(version_ref, input_digest, configuration, amount_columns, outcome, reason, paragraphs, cells, units):
    table_manifest = ((
        amount_columns,
        [(table, row, column, path, digest.hex()) for table, row, column, path, digest, _ in cells],
        units,
    ),) if cells else ()
    return _digest(
        "docx_manifest.v2" if cells else "docx_manifest.v1",
        str(version_ref), input_digest.hex(), configuration, outcome, reason, paragraphs, *table_manifest,
    )


def docx_repair_manifest(manifest, replaces, baseline, basis):
    return _digest("docx_repair.v1", manifest.hex(), str(replaces), str(baseline) if baseline else None, str(basis))


def _record_structured_candidate(
    connection, lease, original, candidate: multiformat_evidence.StructuredCandidate, *, restored_run_ref=None,
):
    spec = lease.spec
    outcome = "pending_review" if (candidate.reason is None and candidate.passages) else "quarantined"
    reason = candidate.reason if outcome == "quarantined" else None
    manifest = _digest(
        "structured_manifest.v1",
        str(spec.target_ref),
        spec.input_digest.hex(),
        spec.configuration_revision,
        candidate.media_type,
        outcome,
        reason,
        [
            (p.kind, p.structured_locator, list(p.heading_path), p.paragraph, p.digest.hex())
            for p in candidate.passages
        ],
    )

    def write_passages(scope):
        transaction, org_id, space_id, version_id, _ = scope
        for part in candidate.passages:
            location = (version_id, multiformat_evidence.LOCATOR_REVISION, part.kind, part.structured_locator)
            descriptor = (list(part.heading_path), part.paragraph)
            inserted = transaction.execute("""
                INSERT INTO thalion.passage (
                    org_id, space_id, version_id, locator_revision, kind, structured_locator, heading_path, paragraph
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (version_id, locator_revision, kind, structured_locator)
                    WHERE kind IN ('xlsx_row', 'pptx_slide', 'html_block', 'image_ocr')
                DO NOTHING
                RETURNING passage_id
            """, (org_id, space_id, *location, *descriptor)).fetchone()
            if inserted:
                passage_id, = inserted
                _register_identity(transaction, org_id, space_id, "passage", passage_id)
            else:
                passage_id, *old_descriptor = transaction.execute("""
                    SELECT passage_id, heading_path, paragraph FROM thalion.passage
                    WHERE (version_id, locator_revision, kind, structured_locator) = (%s, %s, %s, %s)
                """, location).fetchone()
                if tuple(old_descriptor) != descriptor:
                    raise QualityConflict("A changed structured location descriptor requires a new locator revision.")
            _write_excerpt(*scope, passage_id, part.digest, extracted_text=part.text)

    return _record_candidate(
        connection, lease, original, manifest, outcome, reason,
        len(candidate.passages), write_passages, restored_run_ref=restored_run_ref,
    )


def _record_docx_candidate(
    connection, lease, original, candidate, *, repair=None, passage_refs=None, cell_refs=None, restored_run_ref=None,
):
    spec = lease.spec
    cells = docx_candidate_cells(candidate)
    manifest = docx_processing_manifest(
        spec.target_ref, spec.input_digest, spec.configuration_revision, original.docx_amount_columns, candidate, cells,
    )
    if repair is not None:
        manifest = docx_repair_manifest(manifest, repair.replaces, repair.rollback_to, repair.basis_ref)

    def write_passages(scope):
        transaction, org_id, space_id, version_id, _ = scope
        for index, part in enumerate(candidate.passages):
            public_id = passage_refs[index] if passage_refs is not None else None
            location = (version_id, docx_evidence.LOCATOR_REVISION, part.document_paragraph)
            descriptor = (list(part.heading_path), part.paragraph)
            inserted = transaction.execute("""
                INSERT INTO thalion.passage (
                    org_id, space_id, version_id, locator_revision, docx_paragraph, heading_path, paragraph, kind
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'docx_paragraph')
                ON CONFLICT (version_id, locator_revision, docx_paragraph) WHERE kind = 'docx_paragraph' DO NOTHING
                RETURNING passage_id
                """, (org_id, space_id, *location, *descriptor)).fetchone()
            if inserted:
                passage_id, = inserted
                _register_identity(transaction, org_id, space_id, "passage", passage_id, public_id=public_id)
            else:
                if public_id is not None:
                    raise QualityConflict("Archive reconstruction cannot replace an existing DOCX passage identity.")
                passage_id, *old_descriptor = transaction.execute("""
                    SELECT passage_id, heading_path, paragraph FROM thalion.passage WHERE kind = 'docx_paragraph'
                      AND (version_id, locator_revision, docx_paragraph) = (%s, %s, %s)
                    """, location).fetchone()
                if tuple(old_descriptor) != descriptor:
                    raise QualityConflict("A changed DOCX location descriptor requires a new locator revision.")
            _write_excerpt(*scope, passage_id, part.digest)
        for index, cell in enumerate(cells):
            cell_public_id = cell_refs[index] if cell_refs is not None else None
            _write_docx_cell(*scope, *cell, public_id=cell_public_id)
        for table in candidate.tables:
            for unit in table.units:
                _write_docx_unit(transaction, scope[-1], table.ordinal, unit)

    return _record_candidate(
        connection, lease, original, manifest, candidate.outcome, candidate.reason,
        len(candidate.passages) + len(cells), write_passages, restored_run_ref=restored_run_ref, repair=repair,
    )


def _write_docx_cell(
    connection, org_id, space_id, version_id, run_ref, table, row, column, path, digest, header_digest, *, public_id=None,
):
    location = (version_id, docx_evidence.LOCATOR_REVISION, table, row, column)
    inserted = connection.execute("""
        INSERT INTO thalion.passage (
            org_id, space_id, version_id, locator_revision, docx_table, docx_row, docx_column, heading_path, kind
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'docx_cell')
        ON CONFLICT (version_id, locator_revision, docx_table, docx_row, docx_column) WHERE kind = 'docx_cell' DO NOTHING
        RETURNING passage_id
    """, (org_id, space_id, *location, list(path))).fetchone()
    if inserted is not None:
        passage_id, = inserted
        _register_identity(connection, org_id, space_id, "passage", passage_id, public_id=public_id)
    else:
        if public_id is not None:
            raise QualityConflict("Archive reconstruction cannot replace an existing DOCX cell identity.")
        passage_id, old_path = connection.execute("""
            SELECT passage_id, heading_path FROM thalion.passage WHERE kind = 'docx_cell'
              AND (version_id, locator_revision, docx_table, docx_row, docx_column) = (%s, %s, %s, %s, %s)
        """, location).fetchone()
        if tuple(old_path) != path:
            raise QualityConflict("A changed DOCX location descriptor requires a new locator revision.")
    _write_excerpt(connection, org_id, space_id, version_id, run_ref, passage_id, digest, docx_header_digest=header_digest)


def _write_docx_unit(connection, run_ref, table, unit: csv_evidence.AmountUnitCandidate):
    unit_ref, = connection.execute("""
        INSERT INTO thalion.evidence_unit (run_ref, docx_table, record_number, reason)
        VALUES (%s, %s, %s, %s) RETURNING unit_ref
    """, (run_ref, table, unit.record_number, unit.reason)).fetchone()
    if unit.reason is not None:
        return
    connection.execute("""
        INSERT INTO thalion.evidence_unit_member (unit_ref, run_ref, role, passage_id, excerpt_revision)
        SELECT %s, excerpt.run_ref, expected.role, excerpt.passage_id, excerpt.excerpt_revision
        FROM unnest(%s::text[], %s::integer[]) AS expected(role, column_number)
        JOIN thalion.passage AS passage ON passage.docx_column = expected.column_number
            AND (passage.kind, passage.docx_table, passage.docx_row) = ('docx_cell', %s, %s)
        JOIN thalion.passage_excerpt AS excerpt USING (passage_id)
        WHERE excerpt.run_ref = %s AND expected.column_number IS NOT NULL
    """, (unit_ref, list(csv_evidence.AMOUNT_ROLES), list(unit.columns), table, unit.record_number, run_ref))


def _record_candidate(
    connection, lease, original, manifest, outcome, reason, passage_count, write_passages,
    *, restored_run_ref=None, repair=None, pdf_page_count=None,
):
    spec = lease.spec

    def apply(transaction):
        if _prepare_original(transaction, lease) != original:
            raise ProcessingNotAdmitted("Source admission changed while parsing.")
        extra_columns, extra_slots, extra_values = "", "", ()
        if repair is not None:
            if pdf_page_count is None:
                _require_literal_repair(transaction, lease, original, repair)
            extra_columns = ", replaces_run_ref, rollback_run_ref, repair_basis_ref"
            extra_slots = ", %s, %s, %s"
            extra_values = (repair.replaces, repair.rollback_to, repair.basis_ref)
        if pdf_page_count is not None:
            extra_columns += ", pdf_page_count"
            extra_slots += ", %s"
            extra_values += (pdf_page_count,)
        run_ref = transaction.execute(
            f"""
            INSERT INTO thalion.processing_run (
                org_id, space_id, version_id, contract_revision, job_id, generation,
                configuration_revision, input_digest, manifest_digest, outcome, reason, passage_count, run_ref{extra_columns}
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s::uuid, gen_random_uuid()){extra_slots})
            RETURNING run_ref
            """,
            (
                spec.org_id, spec.space_id, original.version_id, original.contract_revision,
                lease.job_id, lease.generation, spec.configuration_revision, spec.input_digest,
                manifest, outcome, reason, passage_count, restored_run_ref, *extra_values,
            ),
        ).fetchone()[0]
        write_passages((transaction, spec.org_id, spec.space_id, original.version_id, run_ref))
        if repair is not None and original.media_type == docx_evidence.MEDIA_TYPE:
            same_prior, same_baseline = transaction.execute(
                "SELECT thalion.docx_runs_match(%s, %s), thalion.docx_runs_match(%s, %s)",
                (repair.replaces, run_ref, repair.rollback_to, run_ref),
            ).fetchone()
            if same_prior or (repair.rollback_to is not None and not same_baseline):
                raise QualityConflict("A DOCX repair must change the prior evidence and reproduce any selected baseline.")
        append_event(
            transaction, spec.org_id, "evidence.candidate.recorded", spec.target_ref, space_id=spec.space_id,
        )
        if repair is not None:
            append_event(
                transaction, spec.org_id, "evidence.repair.recorded", spec.target_ref, space_id=spec.space_id,
            )
        return run_ref

    run_ref = complete_job(connection, lease, apply)
    return ProcessingResult(run_ref, manifest, outcome, reason, passage_count)


def pdf_processing_manifest(version_ref, original_digest, configuration, outcome, reason, pages):
    return _digest(
        "pdf_manifest.v1", str(version_ref), original_digest.hex(), configuration, outcome, reason,
        [(page.number, page.method, page.reason, digest.hex() if digest else None,
          page.ocr_profile_digest.hex() if page.ocr_profile_digest else None) for page, digest in pages],
    )


def pdf_repair_manifest(manifest, replaces, basis_ref, pages):
    return _digest(
        "pdf_repair_manifest.v1", manifest.hex(), str(replaces), str(basis_ref),
        [(page.number, str(page.repair_decision_ref) if page.repair_decision_ref else None) for page in pages],
    )


def _record_pdf_candidate(connection, lease, original, candidate, *, repair=None):
    spec = lease.spec
    pages = tuple(
        (page, sha256(page.transcript).digest() if page.transcript is not None else None) for page in candidate.pages
    )
    count = sum(digest is not None for _, digest in pages)
    outcome = "pending_review" if count else "quarantined"
    manifest = pdf_processing_manifest(
        spec.target_ref, spec.input_digest, spec.configuration_revision, outcome, candidate.reason, pages,
    )
    if repair is not None:
        manifest = pdf_repair_manifest(manifest, repair.replaces, repair.basis_ref, candidate.pages)

    def write_pages(scope):
        transaction, org_id, space_id, version_id, run_ref = scope
        if repair is not None and _pdf_repair_candidate(
            transaction, lease, original, repair, submitted_ref=run_ref,
        ) != candidate:
            raise QualityConflict("The approved OCR corrections changed while the original was read.")
        for page, digest in pages:
            transaction.execute("""
                INSERT INTO thalion.pdf_page_observation (
                    run_ref, page_number, method, transcript, reason, ocr_profile_digest, repair_decision_ref
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (run_ref, page.number, page.method, page.transcript, page.reason, page.ocr_profile_digest,
                  page.repair_decision_ref))
            if digest is None:
                continue
            location = (version_id, pdf_evidence.LOCATOR_REVISION, page.number)
            inserted = transaction.execute("""
                INSERT INTO thalion.passage (org_id, space_id, version_id, locator_revision, pdf_page, kind)
                VALUES (%s, %s, %s, %s, %s, 'pdf_page')
                ON CONFLICT (version_id, locator_revision, pdf_page) WHERE kind = 'pdf_page' DO NOTHING
                RETURNING passage_id
                """, (org_id, space_id, *location)).fetchone()
            if inserted:
                passage_id, = inserted
                _register_identity(transaction, org_id, space_id, "passage", passage_id)
            else:
                passage_id, = transaction.execute("""
                    SELECT passage_id FROM thalion.passage WHERE kind = 'pdf_page'
                      AND (version_id, locator_revision, pdf_page) = (%s, %s, %s)
                    """, location).fetchone()
            _write_excerpt(*scope, passage_id, digest)

    return _record_candidate(
        connection, lease, original, manifest, outcome, candidate.reason, count, write_pages,
        pdf_page_count=len(pages), repair=repair,
    )


def _write_passage(
    connection: Connection, org_id: int, space_id: int, version_id: int, run_ref: UUID, part: MarkdownPassage,
    *, public_id: UUID | None = None,
):
    location = (version_id, LOCATOR_REVISION, part.byte_start, part.byte_end)
    descriptor = (list(part.heading_path), part.paragraph, part.kind)
    inserted = connection.execute(
        """
        INSERT INTO thalion.passage (
            org_id, space_id, version_id, locator_revision, byte_start, byte_end,
            heading_path, paragraph, kind
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (version_id, locator_revision, byte_start, byte_end) DO NOTHING
        RETURNING passage_id
        """,
        (org_id, space_id, *location, *descriptor),
    ).fetchone()
    if inserted is not None:
        passage_id = inserted[0]
        _register_identity(connection, org_id, space_id, "passage", passage_id, public_id=public_id)
    else:
        if public_id is not None:
            raise QualityConflict("Archive reconstruction cannot replace an existing passage identity.")
        passage_id, *old_descriptor = connection.execute(
            """
            SELECT passage_id, heading_path, paragraph, kind FROM thalion.passage
            WHERE (version_id, locator_revision, byte_start, byte_end) = (%s, %s, %s, %s)
            """,
            location,
        ).fetchone()
        if tuple(old_descriptor) != descriptor:
            raise QualityConflict("A changed location descriptor requires a new locator revision.")
    _write_excerpt(connection, org_id, space_id, version_id, run_ref, passage_id, part.digest)


def _write_csv_cell(
    connection, org_id, space_id, version_id, run_ref, record_number, column_number, digest, equivalence,
):
    location = (version_id, csv_evidence.LOCATOR_REVISION, record_number, column_number)
    inserted = connection.execute("""
        INSERT INTO thalion.passage (org_id, space_id, version_id, locator_revision, csv_record, csv_column, kind)
        VALUES (%s, %s, %s, %s, %s, %s, 'csv_cell')
        ON CONFLICT (version_id, locator_revision, csv_record, csv_column) WHERE kind = 'csv_cell' DO NOTHING
        RETURNING passage_id
    """, (org_id, space_id, *location)).fetchone()
    if inserted is not None:
        passage_id, = inserted
        _register_identity(connection, org_id, space_id, "passage", passage_id)
    else:
        passage_id, = connection.execute("""
            SELECT passage_id FROM thalion.passage WHERE kind = 'csv_cell'
              AND (version_id, locator_revision, csv_record, csv_column) = (%s, %s, %s, %s)
        """, location).fetchone()
    _write_excerpt(connection, org_id, space_id, version_id, run_ref, passage_id, digest, equivalence)


def _write_excerpt(
    connection, org_id, space_id, version_id, run_ref, passage_id, digest, equivalence=None,
    *, docx_header_digest=None, extracted_text: str | None = None,
):
    columns = ", csv_header_digest, csv_value_digest" if equivalence else ""
    values = ", %s, %s" if equivalence else ""
    parameters = equivalence or ()
    if docx_header_digest is not None:
        columns += ", docx_header_digest"
        values += ", %s"
        parameters += (docx_header_digest,)
    if extracted_text is not None:
        columns += ", extracted_text"
        values += ", %s"
        parameters += (extracted_text,)
    connection.execute(
        f"""
        INSERT INTO thalion.passage_excerpt (
            org_id, space_id, version_id, passage_id, excerpt_revision, run_ref, content_digest{columns}
        )
        SELECT %s, %s, %s, %s, COALESCE(max(excerpt_revision), 0) + 1, %s, %s{values}
        FROM thalion.passage_excerpt WHERE passage_id = %s
        """,
        (org_id, space_id, version_id, passage_id, run_ref, digest, *parameters, passage_id),
    )


def _write_csv_unit(connection, run_ref, unit: csv_evidence.AmountUnitCandidate):
    if unit.exception_record is None:
        unit_ref, = connection.execute("""
            INSERT INTO thalion.evidence_unit (run_ref, record_number, reason) VALUES (%s, %s, %s)
            RETURNING unit_ref
        """, (run_ref, unit.record_number, unit.reason)).fetchone()
    else:
        unit_ref, = connection.execute("""
            INSERT INTO thalion.evidence_unit (run_ref, record_number, exception_record_number)
            VALUES (%s, %s, %s) RETURNING unit_ref
        """, (run_ref, unit.record_number, unit.exception_record)).fetchone()
    if unit.reason is not None:
        return
    roles = csv_evidence.AMOUNT_ROLES
    if unit.exception_record is not None:
        roles += csv_evidence.EXCEPTION_LINK_ROLES
    members = tuple(zip(roles, unit.columns, strict=False)) + unit.alternatives
    records = [unit.exception_record if unit.exception_record is not None and role in ("exception", "exception_key")
               else unit.record_number for role, _ in members]
    alternate_column = ", is_alternative" if unit.alternatives else ""
    alternate_value = ", expected.is_alternative" if unit.alternatives else ""
    alternate_arg = ", %s::boolean[]" if unit.alternatives else ""
    alternate_flags = (
        ([False] * len(unit.columns) + [True] * len(unit.alternatives),) if unit.alternatives else ()
    )
    connection.execute(f"""
        INSERT INTO thalion.evidence_unit_member (unit_ref, run_ref, role, passage_id, excerpt_revision{alternate_column})
        SELECT %s, excerpt.run_ref, expected.role, excerpt.passage_id, excerpt.excerpt_revision{alternate_value}
        FROM unnest(%s::text[], %s::integer[], %s::integer[]{alternate_arg})
            AS expected(role, column_number, record_number{alternate_column})
        JOIN thalion.passage AS passage ON passage.csv_column = expected.column_number
            AND passage.csv_record = expected.record_number
        JOIN thalion.passage_excerpt AS excerpt USING (passage_id)
        WHERE excerpt.run_ref = %s AND passage.kind = 'csv_cell'
    """, (unit_ref, [role for role, _ in members], [column for _, column in members], records, *alternate_flags, run_ref))


def _lock_quality_run(connection, org_id, space_id, principal_id, run_ref) -> _QualityRun:
    row = connection.execute(
        """
        SELECT identity.public_id, run.configuration_revision, run.manifest_digest,
               run.outcome, run.contract_revision,
               (to_jsonb(run)->>'replaces_run_ref')::uuid, (to_jsonb(run)->>'rollback_run_ref')::uuid
        FROM thalion.processing_run AS run JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (run.org_id, run.space_id, 'document_version', run.version_id)
        WHERE run.org_id = %s AND run.space_id = %s AND run.run_ref = %s
        """,
        (org_id, space_id, run_ref),
    ).fetchone()
    if row is None:
        raise ProcessingNotAdmitted("The evidence run is not registered in this scope.")
    version_ref, config, manifest, parse_outcome, contract_revision, replaces, baseline = row
    original = _lock_original(connection, org_id, space_id, version_ref, principal_id, role="reviewer")
    latest = connection.execute(
        """
        SELECT run_ref FROM thalion.processing_run WHERE version_id = %s
        ORDER BY configuration_revision DESC LIMIT 1
        """,
        (original.version_id,),
    ).fetchone()
    if latest != (run_ref,) or contract_revision != original.contract_revision or parse_outcome != "pending_review":
        raise QualityConflict("The candidate is not current or reviewable.")
    return _QualityRun(version_ref, original, config, manifest, replaces, baseline)


def decide_quality(
    connection: Connection, context: SourceWrite, space_id: int, run_ref: UUID, manifest_digest: bytes,
    outcome: Literal["approved", "quarantined"], basis_ref: UUID,
) -> UUID:
    return _decide_quality(connection, context, space_id, run_ref, manifest_digest, outcome, basis_ref)


@dataclass(frozen=True)
class _PdfRepairApproval:
    page_requests: tuple[UUID, ...]
    proof_digest: bytes


def _decide_quality(
    connection: Connection, context: SourceWrite, space_id: int, run_ref: UUID, manifest_digest: bytes,
    outcome: Literal["approved", "quarantined"], basis_ref: UUID, *, preview_ref: UUID | None = None,
    pdf_approval: _PdfRepairApproval | None = None, docx_preview: UUID | None = None,
) -> UUID:
    if outcome not in ("approved", "quarantined") or len(manifest_digest) != 32:
        raise ValueError("A quality decision requires a valid outcome and manifest digest.")
    operation = (
        DOCX_QUALITY_OPERATION if docx_preview is not None
        else PDF_REPAIR_APPROVAL_OPERATION if pdf_approval is not None else QUALITY_OPERATION
    )
    with connection.transaction():
        _require_read_committed(connection)
        require_open_request(
            connection, context.org_id, context.request_id, context.principal_id, None, operation=operation,
        )
        run = _lock_quality_run(connection, context.org_id, space_id, context.principal_id, run_ref)
        if run.manifest != manifest_digest:
            raise QualityConflict("The candidate is not bound to this manifest.")
        if outcome == "approved" and run.original.media_type == docx_evidence.MEDIA_TYPE and docx_preview is None:
            if connection.execute("""
                SELECT 1 FROM thalion.passage_excerpt AS excerpt
                JOIN thalion.passage AS passage USING (passage_id)
                WHERE excerpt.run_ref = %s AND passage.kind = 'docx_cell' LIMIT 1
            """, (run_ref,)).fetchone() is not None:
                raise QualityConflict("Approving DOCX tables requires a current whole-batch preview.")
        if outcome == "approved" and run.replaces is not None:
            if run.original.media_type == pdf_evidence.MEDIA_TYPE and pdf_approval is None:
                raise QualityConflict("Approving a PDF repair requires current whole-batch review.")
            if run.original.media_type != pdf_evidence.MEDIA_TYPE and preview_ref is None and not (
                docx_preview is not None and _docx_run_has_cells(connection, run_ref)
            ):
                raise QualityConflict("Approving a repair requires a current difference preview.")

        def apply(transaction):
            rows = dict(transaction.execute(
                "SELECT outcome, decision_ref FROM thalion.quality_decision WHERE run_ref = %s",
                (run_ref,),
            ).fetchall())
            if docx_preview is not None and rows:
                raise QualityConflict("This DOCX batch already has a quality decision.")
            if outcome in rows or ("quarantined" in rows and outcome == "approved"):
                raise QualityConflict("The existing quality decision cannot be replaced or reopened.")
            columns, slot, preview = ("", "", ()) if preview_ref is None else (
                ", repair_preview_ref", ", %s", (preview_ref,),
            )
            if pdf_approval is not None:
                columns, slot = ", pdf_repair_page_requests, pdf_repair_proof_digest", ", %s, %s"
                preview = (list(pdf_approval.page_requests), pdf_approval.proof_digest)
            if docx_preview is not None:
                columns, slot, preview = ", docx_preview_request", ", %s", (docx_preview,)
            decision_ref = transaction.execute(
                f"""
                INSERT INTO thalion.quality_decision (
                    org_id, space_id, version_id, run_ref, reviewer_id, request_id, basis_ref, outcome{columns}
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s{slot}) RETURNING decision_ref
                """,
                (
                    context.org_id, space_id, run.original.version_id, run_ref, context.principal_id,
                    context.request_id, basis_ref, outcome, *preview,
                ),
            ).fetchone()[0]
            append_event(
                transaction, context.org_id, "evidence.quality.decided", run.version_ref, space_id=space_id,
            )
            return decision_ref

        binding = (str(preview_ref),) if preview_ref is not None else ()
        if pdf_approval is not None:
            binding = tuple(map(str, pdf_approval.page_requests))
        if docx_preview is not None:
            binding = (str(docx_preview),)
        command = _command(
            context, operation, run.configuration, _digest(
                str(run_ref), manifest_digest.hex(), outcome, str(basis_ref), *binding,
            ),
        )
        result = execute_command(connection, command, apply).result_ref
        if result is None:
            raise RuntimeError("Evidence quality decision did not return a reference.")
        return result


def quarantine_exact_excerpt(
    connection: Connection, context: SourceWrite, space_id: int, passage_ref: UUID, revision: int, basis_ref: UUID,
) -> UUID:
    with connection.transaction():
        run = connection.execute(
            """
            SELECT run.run_ref, run.manifest_digest FROM thalion.object_identity AS passage
            JOIN thalion.passage_excerpt AS excerpt
              ON (excerpt.org_id, excerpt.space_id, excerpt.passage_id) = (passage.org_id, passage.space_id, passage.object_id)
            JOIN thalion.processing_run AS run ON run.run_ref = excerpt.run_ref
            WHERE (passage.org_id, passage.space_id, passage.public_id, passage.object_type) = (%s, %s, %s, 'passage')
              AND excerpt.excerpt_revision = %s
            """, (context.org_id, space_id, passage_ref, revision),
        ).fetchone()
        if run is None:
            raise QualityConflict("The exact excerpt revision is unavailable for quality review.")
        return decide_quality(connection, context, space_id, *run, "quarantined", basis_ref)


def list_approved_passages(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID,
    *, passage_ref: UUID | None = None, limit: int | None = None,
) -> tuple[ApprovedPassage, ...]:
    """Return internal locators, not a read grant, content, or a public response."""
    rows = _approved_locations(connection, org_id, space_id, version_ref, passage_ref, limit, format_kind="markdown")
    return tuple(
        ApprovedPassage(ref, tuple(path), paragraph, kind, start, end, revision, digest)
        for ref, revision, digest, path, paragraph, kind, start, end in rows
    )


def list_approved_csv_cells(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID,
    *, passage_ref: UUID | None = None, limit: int | None = None,
) -> tuple[ApprovedCsvCell, ...]:
    """Project exact approved cell locators without returning headers, values, or read grants."""
    rows = _approved_locations(connection, org_id, space_id, version_ref, passage_ref, limit, format_kind="csv")
    return tuple(ApprovedCsvCell(ref, record, column, revision, digest)
                 for ref, revision, digest, record, column in rows)


def list_approved_pdf_pages(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID,
    *, passage_ref: UUID | None = None, limit: int | None = None,
) -> tuple[ApprovedPdfPage, ...]:
    """Project exact approved page locators without fetching the sealed transcripts."""
    rows = _approved_locations(connection, org_id, space_id, version_ref, passage_ref, limit, format_kind="pdf")
    return tuple(ApprovedPdfPage(ref, run, page, revision, digest) for ref, revision, digest, run, page in rows)


def list_approved_structured_passages(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID,
    *, passage_ref: UUID | None = None, limit: int | None = None,
) -> tuple[ApprovedStructuredPassage, ...]:
    """Return internal structured format locators (xlsx/pptx/html/image_ocr), not an employee read grant."""
    rows = _approved_locations(connection, org_id, space_id, version_ref, passage_ref, limit, format_kind="structured")
    return tuple(
        ApprovedStructuredPassage(ref, kind, loc, tuple(path), paragraph, revision, digest, extracted_text)
        for ref, revision, digest, kind, loc, path, paragraph, extracted_text in rows
    )


def list_approved_docx_paragraphs(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID,
    *, passage_ref: UUID | None = None, limit: int | None = None,
) -> tuple[ApprovedDocxParagraph, ...]:
    """Return internal DOCX locators, not an employee read grant."""
    rows = _approved_locations(connection, org_id, space_id, version_ref, passage_ref, limit, format_kind="docx")
    return tuple(ApprovedDocxParagraph(ref, tuple(path), paragraph, ordinal, revision, digest)
                 for ref, revision, digest, path, paragraph, ordinal in rows)


def list_approved_csv_units(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID,
    *, passage_ref: UUID | None = None,
) -> tuple[ApprovedCsvUnit, ...]:
    """Return complete approved group locators, not content or read grants."""
    rows = _approved_locations(connection, org_id, space_id, version_ref, passage_ref, None, format_kind="csv", units=True)
    grouped = {}
    for ref, revision, digest, record, column, unit_ref, anchor_record, role, is_alternative in rows:
        member = ApprovedCsvMember(role, ApprovedCsvCell(ref, record, column, revision, digest), is_alternative)
        grouped.setdefault((unit_ref, anchor_record), []).append(member)
    return tuple(ApprovedCsvUnit(ref, record, tuple(members)) for (ref, record), members in grouped.items())


def list_approved_docx_units(
    connection: Connection, org_id: int, space_id: int, version_ref: UUID, *, passage_ref: UUID | None = None,
) -> tuple[ApprovedDocxUnit, ...]:
    """Project approved complete row locators, not content or permission to read it."""
    rows = _approved_locations(connection, org_id, space_id, version_ref, passage_ref, None, format_kind="docx_table", units=True)
    grouped = {}
    for ref, revision, digest, path, table, row, column, header_digest, layout, unit_ref, _, role, _ in rows:
        cell = ApprovedDocxCell(ref, tuple(path), table, row, column, revision, digest, header_digest)
        grouped.setdefault((unit_ref, table, row, tuple(layout)), []).append(ApprovedDocxMember(role, cell))
    return tuple(ApprovedDocxUnit(ref, table, row, layout, tuple(members))
                 for (ref, table, row, layout), members in grouped.items())


def _approved_locations(connection, org_id, space_id, version_ref, passage_ref, limit, *, format_kind, units=False):
    fields, ordering, locator = {
        "csv": ("passage.csv_record, passage.csv_column", "passage.csv_record, passage.csv_column", "passage.kind = 'csv_cell'"),
        "pdf": ("excerpt.run_ref, passage.pdf_page", "passage.pdf_page", "passage.kind = 'pdf_page'"),
        "docx": ("passage.heading_path, passage.paragraph, passage.docx_paragraph", "passage.docx_paragraph",
                 "passage.kind = 'docx_paragraph'"),
        "docx_table": (
            "passage.heading_path, passage.docx_table, passage.docx_row, passage.docx_column, "
            "excerpt.docx_header_digest, contract.docx_amount_columns",
            "passage.docx_table, passage.docx_row, passage.docx_column", "passage.kind = 'docx_cell'",
        ),
        "markdown": (
            "passage.heading_path, passage.paragraph, passage.kind, passage.byte_start, passage.byte_end",
            "passage.byte_start", "passage.byte_start IS NOT NULL",
        ),
        "structured": (
            "passage.kind, passage.structured_locator, passage.heading_path, passage.paragraph, excerpt.extracted_text",
            "passage.paragraph, passage.structured_locator",
            "passage.kind IN ('xlsx_row', 'pptx_slide', 'html_block', 'image_ocr') AND excerpt.extracted_text IS NOT NULL",
        ),
    }[format_kind]
    unit_join = ""
    contract_join = ""
    hold_check = ""
    reference_check = "AND (%s::uuid IS NULL OR passage_ref.public_id = %s)"
    if units:
        fields += """, unit.unit_ref, unit.record_number, member.role,
            coalesce((to_jsonb(member)->>'is_alternative')::boolean, false) AS is_alternative"""
        if format_kind == "csv":
            ordering = "unit.record_number, (passage.csv_record <> unit.record_number), is_alternative, passage.csv_column"
        unit_join = """
        JOIN thalion.evidence_unit_member AS member
          ON (member.run_ref, member.passage_id, member.excerpt_revision)
           = (excerpt.run_ref, excerpt.passage_id, excerpt.excerpt_revision)
        JOIN thalion.evidence_unit AS unit ON unit.unit_ref = member.unit_ref AND unit.reason IS NULL
        """
        reference_check = """
          AND (%s::uuid IS NULL OR EXISTS (
              SELECT 1 FROM thalion.object_identity AS requested
              JOIN thalion.evidence_unit_member AS target ON target.passage_id = requested.object_id
              WHERE (requested.org_id, requested.space_id, requested.object_type, requested.public_id)
                = (version.org_id, version.space_id, 'passage', %s)
                AND target.unit_ref = unit.unit_ref
          ))
        """
    if format_kind == "docx_table":
        contract_join = """
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, current_run.contract_revision)
        """
    if units or format_kind == "docx":
        hold_check = """
          AND NOT EXISTS (
              SELECT 1 FROM thalion.current_version_hold AS hold
              WHERE (hold.org_id, hold.space_id, hold.version_id) = (version.org_id, version.space_id, version.version_id)
                AND hold.action = 'establish'
          )
        """
    if format_kind == "docx":
        hold_check += """
          AND NOT EXISTS (
              SELECT 1 FROM thalion.passage_excerpt AS batch_excerpt
              JOIN thalion.passage AS batch_passage USING (passage_id)
              WHERE batch_excerpt.run_ref = current_run.run_ref AND batch_passage.kind = 'docx_cell'
          )
        """
    delete_clause = (
        "AND NOT thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
        if has_source_delete_isolation(connection)
        else ""
    )
    return connection.execute(
        f"""
        SELECT passage_ref.public_id, excerpt.excerpt_revision, excerpt.content_digest, {fields}
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source AS source ON source.source_id = version.source_id
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN LATERAL (
            SELECT run_ref, contract_revision FROM thalion.processing_run WHERE version_id = version.version_id
            ORDER BY configuration_revision DESC LIMIT 1
        ) AS current_run ON current_run.contract_revision = source.contract_revision
        JOIN thalion.passage_excerpt AS excerpt ON excerpt.run_ref = current_run.run_ref
        JOIN thalion.passage AS passage ON passage.passage_id = excerpt.passage_id
        JOIN thalion.object_identity AS passage_ref
          ON (passage_ref.org_id, passage_ref.space_id, passage_ref.object_type, passage_ref.object_id)
           = (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
        {unit_join}
        {contract_join}
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
          {reference_check}
          AND {locator}
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = version.version_id)
          {delete_clause}
          AND EXISTS (SELECT 1 FROM thalion.quality_decision
                      WHERE run_ref = current_run.run_ref AND outcome = 'approved')
          AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision
                          WHERE run_ref = current_run.run_ref AND outcome = 'quarantined')
        {hold_check}
        ORDER BY {ordering} LIMIT %s
        """,
        (org_id, space_id, version_ref, passage_ref, passage_ref, limit),
    ).fetchall()
