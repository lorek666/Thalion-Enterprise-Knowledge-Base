from contextlib import ExitStack
from dataclasses import dataclass, field
from hashlib import sha256
from io import BytesIO
import json
from typing import Literal
from uuid import UUID
from zipfile import BadZipFile, ZipFile

from psycopg import Connection, Error

from enterprise_kb.modules.evidence import docx_evidence, multiformat_evidence, pdf_evidence
from enterprise_kb.modules.sources.originals import ObjectStorageOriginalStore, OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.runtime.audit import RequestAuditConflict, require_open_request
from enterprise_kb.runtime.commands import IdempotencyConflict

from . import registry


MAX_BATCH_FILES = 20
MAX_BATCH_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
UPLOAD = "upload_source_batch"
LIST_BATCHES = "list_source_ingest_batches"
DESTINATION = "internal_sources"
PAGE_SIZE = 20
DOCX_PARTS = frozenset({"[Content_Types].xml", "word/document.xml"})


class BatchNotAdmitted(Exception):
    pass


@dataclass(frozen=True)
class IngestFile:
    display_name: str
    version_label: str
    object_key: str
    incarnation: str
    source_version_key: str
    payload: bytes = field(repr=False)
    confirm_new_version: bool = False
    file_name: str = ""


@dataclass(frozen=True)
class IngestOutcome:
    position: int
    display_name: str
    status: Literal["registered", "duplicate", "needs_confirmation", "rejected"]
    media_type: str | None = None
    digest: bytes | None = None
    document_ref: UUID | None = None
    version_ref: UUID | None = None
    reason: str | None = None


@dataclass(frozen=True)
class _Existing:
    document_ref: UUID
    version_ref: UUID
    digest: bytes
    media_type: str


def list_synthetic_batches(
    connection: Connection, org_id: int, space_id: int, owner_id: int, source_ref: UUID,
    after: UUID | None,
) -> dict:
    selected = connection.execute(
        f"""
        SELECT source.source_id
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS owner
          ON (owner.org_id, owner.principal_id) = (source.org_id, source.owner_principal_id)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
          AND source.owner_principal_id = %s AND source.lifecycle = 'active'
          AND {registry.sql_admitted_admission('contract.admission')}
          AND {registry.sql_issuer_matches_admission('owner.authority_issuer', 'contract.admission')}
        FOR SHARE OF source
        """,
        (org_id, space_id, source_ref, owner_id),
    ).fetchone()
    if selected is None:
        raise registry.SourceNotAdmitted("The batch ledger requires current ownership of the synthetic source.")
    scope = org_id, space_id, selected[0]
    created_at = None
    if after is not None:
        anchor = connection.execute(
            """
            SELECT created_at FROM thalion.source_ingest_batch
            WHERE (org_id, space_id, source_id, batch_ref) = (%s, %s, %s, %s)
            """,
            (*scope, after),
        ).fetchone()
        if anchor is None:
            raise ValueError("The batch cursor is not in the requested source.")
        created_at = anchor[0]
    rows = connection.execute(
        """
        WITH page AS (
            SELECT org_id, space_id, batch_ref, created_at, completed_at, item_count
            FROM thalion.source_ingest_batch
            WHERE (org_id, space_id, source_id) = (%s, %s, %s)
              AND (created_at, batch_ref) < (
                  COALESCE(%s::timestamptz, 'infinity'), COALESCE(%s::uuid, '00000000-0000-0000-0000-000000000000')
              )
            ORDER BY created_at DESC, batch_ref DESC
            LIMIT %s
        )
        SELECT page.batch_ref, page.created_at, page.completed_at, page.item_count,
               item.position, item.display_name, item.status, item.media_type,
               item.document_ref, item.version_ref, item.reason
        FROM page
        LEFT JOIN thalion.source_ingest_item AS item USING (org_id, space_id, batch_ref)
        ORDER BY page.created_at DESC, page.batch_ref DESC, item.position
        """,
        (*scope, created_at, after, PAGE_SIZE + 1),
    ).fetchall()
    batches = {}
    for batch_ref, created, completed, count, position, title, status, media, document, version, reason in rows:
        if batch_ref not in batches:
            batches[batch_ref] = {
                "batch_id": str(batch_ref), "created_at": created.isoformat(),
                "completed_at": completed.isoformat() if completed is not None else None,
                "item_count": count, "files": [],
            }
        if position is not None:
            batches[batch_ref]["files"].append({
                "position": position, "title": title, "status": status, "media_type": media,
                "document_id": str(document) if document is not None else None,
                "version_id": str(version) if version is not None else None, "reason": reason,
            })
    page = list(batches.values())[:PAGE_SIZE]
    return {
        "source_id": str(source_ref), "batches": page,
        "next_cursor": page[-1]["batch_id"] if len(batches) > PAGE_SIZE else None,
    }


def _detect(payload: bytes, file_name: str = "") -> str:
    if not payload or len(payload) > MAX_FILE_BYTES:
        raise ValueError("empty" if not payload else "too_large")
    suffix = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    if file_name and suffix not in {"pdf", "docx", "xlsx", "pptx", "html", "htm", "png", "jpg", "jpeg", "md", "markdown"}:
        raise ValueError("unsupported_media")
    if payload.startswith(b"%PDF-"):
        if file_name and suffix != "pdf":
            raise ValueError("unsupported_media")
        return pdf_evidence.MEDIA_TYPE
    if payload.startswith(multiformat_evidence.PNG_MAGIC):
        if file_name and suffix != "png":
            raise ValueError("unsupported_media")
        return multiformat_evidence.PNG_MEDIA_TYPE
    if payload.startswith(multiformat_evidence.JPEG_MAGIC):
        if file_name and suffix not in {"jpg", "jpeg"}:
            raise ValueError("unsupported_media")
        return multiformat_evidence.JPEG_MEDIA_TYPE
    if payload.startswith(b"PK\x03\x04"):
        if file_name and suffix not in {"docx", "xlsx", "pptx"}:
            raise ValueError("unsupported_media")
        try:
            with ZipFile(BytesIO(payload)) as archive:
                names = frozenset(archive.namelist())
        except (BadZipFile, ValueError):
            raise ValueError("unsupported_media") from None
        if DOCX_PARTS <= names and (not file_name or suffix == "docx"):
            return docx_evidence.MEDIA_TYPE
        if multiformat_evidence.XLSX_PARTS <= names and (not file_name or suffix == "xlsx"):
            return multiformat_evidence.XLSX_MEDIA_TYPE
        if multiformat_evidence.PPTX_PARTS <= names and (not file_name or suffix == "pptx"):
            return multiformat_evidence.PPTX_MEDIA_TYPE
        raise ValueError("unsupported_media")
    if b"\0" in payload:
        raise ValueError("unsupported_media")
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("unsupported_media") from None
    if suffix in {"html", "htm"}:
        return multiformat_evidence.HTML_MEDIA_TYPE
    if file_name and suffix not in {"md", "markdown"}:
        raise ValueError("unsupported_media")
    return "text/markdown"


def _existing(connection: Connection, org_id: int, space_id: int, source_id: int, key: str, incarnation: str,
              label: str | None = None, version_key: str | None = None, limit: int | None = None) -> tuple[_Existing, ...]:
    rows = connection.execute(
        """
        SELECT doc_ref.public_id, ver_ref.public_id, asset.content_digest, asset.media_type
        FROM thalion.document AS document
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.source_id, version.document_id)
           = (document.org_id, document.space_id, document.source_id, document.document_id)
        JOIN thalion.asset AS asset
          ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
           = (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
        JOIN thalion.object_identity AS doc_ref
          ON (doc_ref.org_id, doc_ref.space_id, doc_ref.object_type, doc_ref.object_id)
           = (document.org_id, document.space_id, 'document', document.document_id)
        JOIN thalion.object_identity AS ver_ref
          ON (ver_ref.org_id, ver_ref.space_id, ver_ref.object_type, ver_ref.object_id)
           = (version.org_id, version.space_id, 'document_version', version.version_id)
        WHERE (document.org_id, document.space_id, document.source_id, document.source_object_key, document.incarnation)
            = (%s, %s, %s, %s, %s)
          AND (%s::text IS NULL OR version.version_label = %s)
          AND (%s::text IS NULL OR version.source_version_key = %s)
        ORDER BY version.registration_sequence DESC LIMIT %s
        """,
        (org_id, space_id, source_id, key, incarnation, label, label, version_key, version_key, limit),
    ).fetchall()
    return tuple(_Existing(*row) for row in rows)


def _lock_key(org_id: int, space_id: int, source_ref: UUID, key: str, incarnation: str) -> int:
    material = f"{org_id}:{space_id}:{source_ref}:{key}:{incarnation}".encode()
    return int.from_bytes(sha256(material).digest()[:8], "big", signed=True)


def ingest_batch(
    connection: Connection,
    context: registry.SourceWrite,
    space_id: int,
    source_ref: UUID,
    files: tuple[IngestFile, ...],
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
    *,
    actor_id: int | None = None,
    upload_request_id: UUID | None = None,
) -> tuple[IngestOutcome, ...]:
    if not 1 <= len(files) <= MAX_BATCH_FILES:
        raise BatchNotAdmitted("A batch requires between 1 and 20 files.")
    if sum(len(item.payload) for item in files) > MAX_BATCH_BYTES:
        raise BatchNotAdmitted("The batch exceeds 32 MiB.")
    probe = files[0]
    with connection.transaction():
        source_id, _ = registry._admit_version(
            connection, context,
            registry.SourceVersion(
                space_id, source_ref, 1, probe.object_key, probe.incarnation, probe.source_version_key,
                probe.display_name, probe.version_label, b"\0" * 32, "text/markdown",
            ),
            store=store,
        )
    actor_id = actor_id or context.principal_id
    with connection.transaction():
        batch_ref = _open_batch(connection, context, space_id, source_id, actor_id, files)
        if upload_request_id is not None:
            require_open_request(connection, context.org_id, upload_request_id, actor_id, None, operation=UPLOAD)
            require_open_request(connection, context.org_id, context.request_id, context.principal_id, None, operation="register_version")
            recorded = connection.execute(
                """
                INSERT INTO thalion.source_ingest_attempt (org_id, space_id, batch_ref, upload_request_id, collector_request_id)
                SELECT upload.org_id, upload.scope_space_id, %s, upload.request_id, collector.request_id
                FROM thalion.request_record AS upload JOIN thalion.request_record AS collector USING (org_id, scope_space_id)
                WHERE (upload.org_id, upload.scope_space_id, upload.request_id, collector.request_id) = (%s, %s, %s, %s)
                  AND upload.destination = %s AND collector.destination = %s
                  AND upload.configuration_revision = collector.configuration_revision
                RETURNING upload_request_id
                """, (batch_ref, context.org_id, space_id, upload_request_id, context.request_id, DESTINATION, DESTINATION),
            ).fetchone()
            if recorded is None:
                raise RequestAuditConflict("Ingest attempt requires matching scoped upload and collector requests.")
    lock = int.from_bytes(batch_ref.bytes[:8], "big", signed=True)
    connection.execute("SELECT pg_advisory_lock(%s)", (lock,))
    try:
        outcomes = _stored_outcomes(connection, context.org_id, space_id, batch_ref)
        for position, item in enumerate(files):
            if position in outcomes:
                continue
            with ExitStack() as item_scope:
                outcome = _ingest_one(
                    connection, context, space_id, source_id, source_ref, batch_ref, position, item, store, item_scope,
                )
                _record_item(connection, context.org_id, space_id, batch_ref, outcome)
            outcomes[position] = outcome
        with connection.transaction():
            connection.execute(
                """
                UPDATE thalion.source_ingest_batch SET completed_at = clock_timestamp()
                WHERE (org_id, space_id, batch_ref) = (%s, %s, %s) AND completed_at IS NULL
                """,
                (context.org_id, space_id, batch_ref),
            )
        return tuple(outcomes[position] for position in range(len(files)))
    finally:
        connection.execute("SELECT pg_advisory_unlock(%s)", (lock,))


def _batch_digest(files: tuple[IngestFile, ...]) -> bytes:
    material = [
        [
            position, item.file_name, item.display_name, item.version_label, item.object_key,
            item.incarnation, item.source_version_key, sha256(item.payload).hexdigest(), item.confirm_new_version,
        ]
        for position, item in enumerate(files)
    ]
    return sha256(json.dumps(material, separators=(",", ":")).encode()).digest()


def _open_batch(
    connection, context, space_id, source_id, actor_id, files: tuple[IngestFile, ...],
) -> UUID:
    input_digest = _batch_digest(files)
    with connection.transaction():
        inserted = connection.execute(
            """
            INSERT INTO thalion.source_ingest_batch (
                org_id, space_id, source_id, actor_id, request_id, key_digest, input_digest,
                item_count, total_bytes
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (org_id, actor_id, key_digest) DO NOTHING
            RETURNING batch_ref
            """,
            (
                context.org_id, space_id, source_id, actor_id, context.request_id,
                sha256(context.idempotency_key.encode()).digest(), input_digest,
                len(files), sum(len(item.payload) for item in files),
            ),
        ).fetchone()
        if inserted is not None:
            return inserted[0]
        stored = connection.execute(
            """
            SELECT batch_ref, space_id, source_id, input_digest FROM thalion.source_ingest_batch
            WHERE (org_id, actor_id, key_digest) = (%s, %s, %s)
            """,
            (context.org_id, actor_id, sha256(context.idempotency_key.encode()).digest()),
        ).fetchone()
    if stored is None:
        raise registry.SourceNotAdmitted("The ingest batch cannot be resumed.")
    if stored[1:] != (space_id, source_id, input_digest):
        raise IdempotencyConflict("The idempotency key already names a different source or files.")
    return stored[0]


def _stored_outcomes(connection, org_id, space_id, batch_ref) -> dict[int, IngestOutcome]:
    rows = connection.execute(
        """
        SELECT position, display_name, status, media_type, digest, document_ref, version_ref, reason
        FROM thalion.source_ingest_item
        WHERE (org_id, space_id, batch_ref) = (%s, %s, %s) ORDER BY position
        """,
        (org_id, space_id, batch_ref),
    ).fetchall()
    return {row[0]: IngestOutcome(*row) for row in rows}


def _record_item(connection, org_id, space_id, batch_ref, outcome: IngestOutcome):
    with connection.transaction():
        connection.execute(
            """
            INSERT INTO thalion.source_ingest_item (
                org_id, space_id, batch_ref, position, display_name, media_type, digest,
                status, document_ref, version_ref, reason
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                org_id, space_id, batch_ref, outcome.position, outcome.display_name, outcome.media_type,
                outcome.digest, outcome.status, outcome.document_ref, outcome.version_ref, outcome.reason,
            ),
        )


def _ingest_one(
    connection, context, space_id, source_id, source_ref, batch_ref, position, item: IngestFile, store,
    item_scope: ExitStack,
) -> IngestOutcome:
    try:
        media_type = _detect(item.payload, item.file_name)
        digest = sha256(item.payload).digest()
        if not (
            1 <= len(item.display_name.strip()) <= 300
            and 1 <= len(item.version_label.strip()) <= 128
        ):
            raise ValueError("invalid_metadata")
        registry._validate_keys(item.object_key, item.incarnation, item.source_version_key)
    except (ValueError, registry.SourceNotAdmitted) as error:
        return IngestOutcome(position, item.display_name, "rejected", reason=str(error) or "invalid_metadata")

    lock = _lock_key(context.org_id, space_id, source_ref, item.object_key, item.incarnation)
    connection.execute("SELECT pg_advisory_lock(%s)", (lock,))
    item_scope.callback(connection.execute, "SELECT pg_advisory_unlock(%s)", (lock,))
    try:
        if registry._is_document_source_deleted(
            connection, (context.org_id, space_id, source_id), item.object_key, item.incarnation,
        ):
            return IngestOutcome(
                position, item.display_name, "rejected", media_type, digest, reason="source_deleted",
            )
        existing = _existing(
            connection, context.org_id, space_id, source_id, item.object_key, item.incarnation,
            label=item.version_label,
        )
        same = next((row for row in existing if row.digest == digest and row.media_type == media_type), None)
        if same is not None:
            return IngestOutcome(
                position, item.display_name, "duplicate", media_type, digest, same.document_ref, same.version_ref,
            )
        conflicting = existing[0] if existing else None
        if conflicting is not None:
            return IngestOutcome(
                position, item.display_name, "needs_confirmation", media_type, digest,
                conflicting.document_ref, conflicting.version_ref, "version_label_changed_content",
            )
        reused = _existing(
            connection, context.org_id, space_id, source_id, item.object_key, item.incarnation,
            version_key=item.source_version_key,
        )
        if reused:
            if (reused[0].digest, reused[0].media_type) == (digest, media_type):
                return IngestOutcome(
                    position, item.display_name, "duplicate", media_type, digest,
                    reused[0].document_ref, reused[0].version_ref,
                )
            return IngestOutcome(
                position, item.display_name, "needs_confirmation", media_type, digest,
                reused[0].document_ref, reused[0].version_ref, "version_key_changed_content",
            )
        if not item.confirm_new_version:
            latest = _existing(connection, context.org_id, space_id, source_id, item.object_key, item.incarnation, limit=1)
            if latest and (latest[0].digest, latest[0].media_type) != (digest, media_type):
                return IngestOutcome(
                    position, item.display_name, "needs_confirmation", media_type, digest,
                    latest[0].document_ref, latest[0].version_ref, "new_version_confirmation_required",
                )

        write = registry.SourceWrite(
            context.org_id, context.principal_id, context.request_id,
            f"source-ingest:{batch_ref}:{position}",
        )
        version = registry.SourceVersion(
            space_id, source_ref, 1, item.object_key, item.incarnation, item.source_version_key,
            item.display_name, item.version_label, digest, media_type,
        )
        registered = item_scope.enter_context(
            registry._synthetic_version_registration(connection, write, version, item.payload, store),
        )
        return IngestOutcome(
            position, item.display_name, "registered" if registered.created else "duplicate",
            media_type, digest, registered.document_ref, registered.version_ref,
        )
    except registry.SourceDeletedConflict:
        return IngestOutcome(position, item.display_name, "rejected", media_type, digest, reason="source_deleted")
    except registry.VersionConflict:
        reused = _existing(
            connection, context.org_id, space_id, source_id, item.object_key, item.incarnation,
            version_key=item.source_version_key,
        )
        if not reused:
            return IngestOutcome(position, item.display_name, "rejected", media_type, digest, reason="not_admitted")
        return IngestOutcome(
            position, item.display_name, "needs_confirmation", media_type, digest,
            reused[0].document_ref, reused[0].version_ref, "version_key_changed_content",
        )
    except (registry.SourceNotAdmitted, OriginalIntegrityError, ValueError):
        return IngestOutcome(position, item.display_name, "rejected", media_type, digest, reason="not_admitted")
    except Error:
        return IngestOutcome(position, item.display_name, "rejected", media_type, digest, reason="dependency_unavailable")
