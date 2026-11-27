from dataclasses import dataclass, field
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus

from enterprise_kb.runtime.audit import RequestAuditConflict
from enterprise_kb.runtime.commands import IdempotencyConflict, execute_command

from . import registry
from .ingest import MAX_BATCH_BYTES, MAX_BATCH_FILES
from .originals import ObjectStorageOriginalStore, SyntheticOriginalStore


COMMIT = "commit_source_change"
READ = "read_source_sync_position"


class CursorConflict(Exception):
    pass


@dataclass(frozen=True)
class SyncSource:
    space_id: int
    source_ref: UUID
    contract_revision: int


@dataclass(frozen=True)
class PageOriginal:
    version: registry.SourceVersion
    payload: bytes = field(repr=False)


@dataclass(frozen=True)
class SourcePage:
    previous: UUID | None
    through: UUID
    items: tuple[PageOriginal, ...]


@dataclass(frozen=True)
class PageReceipt:
    through: UUID
    sequence: int
    version_refs: tuple[UUID, ...]


def _admit(connection, context, source, operation, *, store: SyntheticOriginalStore | ObjectStorageOriginalStore | None = None):
    if connection.execute("""
        SELECT 1 FROM thalion.request_record
        WHERE (org_id, request_id, principal_id, scope_space_id, operation) = (%s, %s, %s, %s, %s)
          AND delegated_principal_id IS NULL AND outcome IS NULL
          AND destination = 'internal_sources' AND ingress = 'internal'
        FOR SHARE
    """, (context.org_id, context.request_id, context.principal_id, source.space_id, operation)).fetchone() is None:
        raise RequestAuditConflict("Sync requires an open, scoped internal request.")
    expected_admission = registry.store_admission(store) if store is not None else None
    source_id, namespace = registry._current_collector_scope(
        connection,
        context,
        source.space_id,
        source.source_ref,
        source.contract_revision,
        expected_admission=expected_admission,
    )
    return (context.org_id, source.space_id, source_id, source.contract_revision), namespace


def _head(connection, scope):
    return connection.execute("""
        SELECT sequence, through_cursor FROM thalion.source_sync_page
        WHERE (org_id, space_id, source_id, contract_revision) = (%s, %s, %s, %s)
        ORDER BY sequence DESC LIMIT 1
    """, scope).fetchone() or (0, None)


def _received(connection, scope, through, digest):
    row = connection.execute("""
        SELECT sequence, input_digest, item_count FROM thalion.source_sync_page
        WHERE (org_id, space_id, source_id, contract_revision, through_cursor) = (%s, %s, %s, %s, %s)
    """, (*scope, through)).fetchone()
    if row is None:
        return None
    sequence, saved_digest, count = row
    if saved_digest != digest:
        raise IdempotencyConflict("The source position already has different page data.")
    refs = tuple(ref for ref, in connection.execute("""
        SELECT identity.public_id FROM thalion.source_sync_page_item AS item
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (item.org_id, item.space_id, 'document_version', item.version_id)
        WHERE (item.org_id, item.space_id, item.source_id, item.contract_revision, item.sequence) =
              (%s, %s, %s, %s, %s)
        ORDER BY item.position
    """, (*scope, sequence)))
    if len(refs) != count:
        raise RuntimeError("The committed source page is missing item receipts.")
    return PageReceipt(through, sequence, refs)


def _lock_existing_documents(connection, scope, items):
    keys = {(item.version.object_key, item.version.incarnation) for item in items}
    if keys:
        object_keys, incarnations = zip(*sorted(keys), strict=True)
        connection.execute("""
            SELECT document.document_id FROM thalion.document AS document
            JOIN unnest(%s::text[], %s::text[]) AS wanted(object_key, incarnation)
              ON (document.source_object_key, document.incarnation) = (wanted.object_key, wanted.incarnation)
            WHERE (document.org_id, document.space_id, document.source_id) = (%s, %s, %s)
            ORDER BY document.document_id FOR UPDATE OF document
        """, (list(object_keys), list(incarnations), *scope)).fetchall()


def read_content_position(connection: Connection, context: registry.SourceWrite, source: SyncSource) -> UUID | None:
    with connection.transaction():
        scope, _ = _admit(connection, context, source, READ)
        return _head(connection, scope)[1]


def commit_content_page(
    connection: Connection, context: registry.SourceWrite, source: SyncSource,
    page: SourcePage, store: SyntheticOriginalStore | ObjectStorageOriginalStore,
) -> PageReceipt:
    if not connection.autocommit or connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Sync requires an independent connection with autocommit for original prewrites.")
    if not isinstance(page.through, UUID) or (page.previous is not None and not isinstance(page.previous, UUID)):
        raise ValueError("A synthetic content page requires opaque UUID positions.")
    if page.previous == page.through or not isinstance(page.items, tuple) or len(page.items) > MAX_BATCH_FILES:
        raise ValueError("The synthetic content page must be bounded and advance its position.")
    source_fields = (source.space_id, source.source_ref, source.contract_revision)
    total_bytes = 0
    for item in page.items:
        version = item.version
        if (version.space_id, version.source_ref, version.contract_revision) != source_fields:
            raise ValueError("A content page can only name originals in its own source and contract.")
        registry._validate_original(version, item.payload)
        total_bytes += len(item.payload)
        if total_bytes > MAX_BATCH_BYTES:
            raise ValueError("The synthetic content page exceeds its byte limit.")

    storage_kind = registry.store_storage_kind(store)
    with connection.transaction():
        scope, namespace = _admit(connection, context, source, COMMIT, store=store)
        materials = tuple(
            registry._original_identity(*scope[:2], namespace, item.version) for item in page.items
        )
        digest = registry._digest(
            "source_content_page.v1", source.contract_revision, str(source.source_ref),
            str(page.previous) if page.previous is not None else None, str(page.through),
            [(material, item.version.display_name, item.version.version_label)
             for material, item in zip(materials, page.items, strict=True)],
        )
        _, current = _head(connection, scope)
        existing = _received(connection, scope, page.through, digest)
        if existing is None and current != page.previous:
            raise CursorConflict("The page does not follow the current source content position.")
        if existing is None:
            for item in page.items:
                if registry._is_document_source_deleted(
                    connection, scope[:3], item.version.object_key, item.version.incarnation,
                ):
                    raise registry.SourceDeletedConflict(
                        "A content page cannot re-deliver an explicitly deleted source document incarnation.",
                    )
        known = () if existing is not None else tuple(
            registry._find_version(
                connection, (*scope[:3], item.version.object_key, item.version.incarnation),
                item.version.source_version_key,
            )
            for item in page.items
        )
    assets = () if existing is not None else tuple(
        registry._stage_original(original, material, item.version, item.payload, store)
        for original, material, item in zip(known, materials, page.items, strict=True)
    )
    command = registry._command(context, COMMIT, source.contract_revision, digest)

    def apply(transaction):
        if _received(transaction, scope, page.through, digest) is not None:
            return page.through
        sequence, current = _head(transaction, scope)
        if current != page.previous:
            raise CursorConflict("The page does not follow the current source content position.")
        _lock_existing_documents(transaction, scope[:3], page.items)
        version_refs = tuple(
            registry._record_original(
                transaction, context, scope[:3], item.version, asset, storage_kind=storage_kind,
            ).version_ref
            for item, asset in zip(page.items, assets, strict=True)
        )
        transaction.execute("""
            INSERT INTO thalion.source_sync_page (
                org_id, space_id, source_id, contract_revision, sequence, through_cursor, previous_cursor,
                request_id, input_digest, item_count
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (*scope, sequence + 1, page.through, page.previous, context.request_id, digest, len(version_refs)))
        transaction.execute("""
            INSERT INTO thalion.source_sync_page_item (
                org_id, space_id, source_id, contract_revision, sequence, position, document_id, version_id
            )
            SELECT %s, %s, %s, %s, %s, entry.position - 1, version.document_id, version.version_id
            FROM unnest(%s::uuid[]) WITH ORDINALITY AS entry(ref, position)
            JOIN thalion.object_identity AS identity ON identity.public_id = entry.ref
                AND identity.object_type = 'document_version'
            JOIN thalion.document_version AS version
              ON (version.org_id, version.space_id, version.version_id) =
                 (identity.org_id, identity.space_id, identity.object_id)
        """, (*scope, sequence + 1, list(version_refs)))
        return page.through

    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        registry._lock_source_content(connection, source.source_ref)
        if _admit(connection, context, source, COMMIT, store=store) != (scope, namespace):
            raise registry.SourceNotAdmitted("Source admission changed during storage.")
        receipt = execute_command(connection, command, apply)
        committed = _received(connection, scope, page.through, digest)
        if committed is None or receipt.result_ref != committed.through:
            raise RuntimeError("The source command did not record the expected position.")
        return committed
