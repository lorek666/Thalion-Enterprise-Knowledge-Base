from dataclasses import dataclass, field
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from enterprise_kb.runtime.commands import IdempotencyConflict, execute_command

from . import registry, sync


COMMIT = "reconcile_source_inventory"
READ = "read_source_inventory_position"
MAX_INVENTORY_ENTRIES = 1000


class InventoryConflict(Exception):
    pass


@dataclass(frozen=True)
class InventoryEntry:
    object_key: str = field(repr=False)
    incarnation: str = field(repr=False)
    source_version_key: str = field(repr=False)
    digest: bytes = field(repr=False)


@dataclass(frozen=True)
class InventoryManifest:
    snapshot_ref: UUID
    previous: UUID | None
    content_position: UUID | None
    expected_count: int
    expected_digest: bytes


@dataclass(frozen=True)
class InventoryDifference:
    object_key: str = field(repr=False)
    incarnation: str = field(repr=False)
    source_version_key: str | None = field(repr=False)
    kind: str


@dataclass(frozen=True)
class InventoryReceipt:
    snapshot_ref: UUID
    sequence: int
    matched_count: int
    differences: tuple[InventoryDifference, ...] = field(repr=False)


def _canonical_inventory(entries: tuple[InventoryEntry, ...]) -> tuple[InventoryEntry, ...]:
    if not isinstance(entries, tuple) or len(entries) > MAX_INVENTORY_ENTRIES:
        raise ValueError("A synthetic inventory requires a bounded immutable manifest.")
    keys = set()
    for entry in entries:
        if not isinstance(entry, InventoryEntry) or not isinstance(entry.digest, bytes) or len(entry.digest) != 32:
            raise ValueError("A synthetic inventory entry requires an exact SHA-256 digest.")
        registry._validate_keys(entry.object_key, entry.incarnation, entry.source_version_key)
        key = (entry.object_key, entry.incarnation)
        if key in keys:
            raise ValueError("The inventory has multiple entries for one object incarnation.")
        keys.add(key)
    return tuple(sorted(entries, key=lambda entry: (entry.object_key, entry.incarnation)))


def _digest_inventory(ordered):
    return registry._digest("synthetic_source_inventory.v1", [
        (entry.object_key, entry.incarnation, entry.source_version_key, entry.digest.hex()) for entry in ordered
    ])


def inventory_digest(entries: tuple[InventoryEntry, ...]) -> bytes:
    return _digest_inventory(_canonical_inventory(entries))


def _current_inventory(connection, scope):
    return connection.execute("""
        SELECT sequence, snapshot_ref FROM thalion.source_inventory_receipt
        WHERE (org_id, space_id, source_id, contract_revision) = (%s, %s, %s, %s)
        ORDER BY sequence DESC LIMIT 1
    """, scope).fetchone() or (0, None)


def _received_inventory(connection, scope, snapshot_ref, digest):
    row = connection.execute("""
        SELECT sequence, input_digest, matched_count, differences
        FROM thalion.source_inventory_receipt
        WHERE (org_id, space_id, source_id, contract_revision, snapshot_ref) = (%s, %s, %s, %s, %s)
    """, (*scope, snapshot_ref)).fetchone()
    if row is None:
        return None
    sequence, input_digest, matched_count, differences = row
    if input_digest != digest:
        raise IdempotencyConflict("The source snapshot already identifies a different inventory.")
    return InventoryReceipt(snapshot_ref, sequence, matched_count, tuple(InventoryDifference(*item) for item in differences))


def _compare_inventory(connection, scope, entries):
    keys = [entry.object_key for entry in entries]
    incarnations = [entry.incarnation for entry in entries]
    versions = [entry.source_version_key for entry in entries]
    digests = [entry.digest for entry in entries]
    rows = connection.execute("""
        WITH expected AS (
            SELECT * FROM unnest(%s::text[], %s::text[], %s::text[], %s::bytea[])
              AS entry(object_key, incarnation, version_key, digest)
        ), local_documents AS MATERIALIZED (
            SELECT org_id, space_id, source_id, document_id, source_object_key AS object_key, incarnation
            FROM thalion.document AS local
            WHERE (local.org_id, local.space_id, local.source_id) = (%s, %s, %s)
              AND EXISTS (
                  SELECT 1 FROM thalion.document_version AS registered
                  WHERE (registered.org_id, registered.space_id, registered.source_id, registered.document_id) =
                        (local.org_id, local.space_id, local.source_id, local.document_id)
                    AND registered.contract_revision = %s
              )
            ORDER BY source_object_key, incarnation LIMIT %s
        )
        SELECT COALESCE(expected.object_key, doc.object_key), COALESCE(expected.incarnation, doc.incarnation),
               expected.version_key, CASE
                 WHEN expected.object_key IS NULL THEN 'not_enumerated'
                 WHEN asset.asset_id IS NULL THEN 'version_not_registered'
                 WHEN asset.content_digest <> expected.digest THEN 'digest_mismatch'
               END, doc.document_id IS NOT NULL
        FROM expected FULL JOIN local_documents AS doc USING (object_key, incarnation)
        LEFT JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.source_id, version.document_id, version.source_version_key) =
             (doc.org_id, doc.space_id, doc.source_id, doc.document_id, expected.version_key)
         AND version.contract_revision = %s
        LEFT JOIN thalion.asset AS asset
          ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id) =
             (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
        ORDER BY 1, 2
    """, (keys, incarnations, versions, digests, *scope, MAX_INVENTORY_ENTRIES + 1, scope[3])).fetchall()
    if sum(has_local for *_, has_local in rows) > MAX_INVENTORY_ENTRIES:
        raise InventoryConflict("The local inventory exceeds the synthetic reconciliation limit.")
    return sum(row[3] is None for row in rows), [list(row[:4]) for row in rows if row[3] is not None]


def read_inventory_position(connection: Connection, context: registry.SourceWrite, source: sync.SyncSource) -> UUID | None:
    with connection.transaction():
        scope, _ = sync._admit(connection, context, source, READ)
        return _current_inventory(connection, scope)[1]


def reconcile_inventory(
    connection: Connection, context: registry.SourceWrite, source: sync.SyncSource,
    manifest: InventoryManifest, entries: tuple[InventoryEntry, ...],
) -> InventoryReceipt:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Inventory reconciliation requires an independent transaction.")
    if (
        not isinstance(manifest.snapshot_ref, UUID)
        or any(position is not None and not isinstance(position, UUID) for position in (manifest.previous, manifest.content_position))
        or manifest.previous == manifest.snapshot_ref
        or type(manifest.expected_count) is not int or not 0 <= manifest.expected_count <= MAX_INVENTORY_ENTRIES
        or not isinstance(manifest.expected_digest, bytes) or len(manifest.expected_digest) != 32
    ):
        raise ValueError("A synthetic inventory requires bounded counts, a digest, and opaque positions.")
    ordered = _canonical_inventory(entries)
    if len(ordered) != manifest.expected_count or _digest_inventory(ordered) != manifest.expected_digest:
        raise InventoryConflict("The supplied inventory does not match its complete synthetic manifest.")
    digest = registry._digest(
        "reconcile_source_inventory.v1", str(source.source_ref), source.contract_revision, str(manifest.snapshot_ref),
        str(manifest.previous) if manifest.previous is not None else None,
        str(manifest.content_position) if manifest.content_position is not None else None,
        manifest.expected_count, manifest.expected_digest.hex(),
    )
    command = registry._command(context, COMMIT, source.contract_revision, digest)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        registry._lock_source_content(connection, source.source_ref)
        scope, _ = sync._admit(connection, context, source, COMMIT)

        def apply(transaction):
            if _received_inventory(transaction, scope, manifest.snapshot_ref, digest) is not None:
                return manifest.snapshot_ref
            sequence, current = _current_inventory(transaction, scope)
            if current != manifest.previous or sync._head(transaction, scope)[1] != manifest.content_position:
                raise InventoryConflict("The inventory does not follow both current source positions.")
            matched, differences = _compare_inventory(transaction, scope, ordered)
            transaction.execute("""
                INSERT INTO thalion.source_inventory_receipt (
                    org_id, space_id, source_id, contract_revision, sequence, snapshot_ref, previous_snapshot_ref,
                    content_position, request_id, input_digest, inventory_digest, entry_count, matched_count, differences
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (*scope, sequence + 1, manifest.snapshot_ref, manifest.previous, manifest.content_position,
                  context.request_id, digest, manifest.expected_digest, manifest.expected_count, matched, Jsonb(differences)))
            return manifest.snapshot_ref

        receipt = execute_command(connection, command, apply)
        result = _received_inventory(connection, scope, manifest.snapshot_ref, digest)
        if result is None or result.snapshot_ref != receipt.result_ref:
            raise RuntimeError("Reconciliation did not record the expected source snapshot.")
        return result
