from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from psycopg import Connection

from enterprise_kb.database import rehearsal_marker
from enterprise_kb.modules.lifecycle.backup_inventory import MAX_AUDIT_ENTRIES
from enterprise_kb.modules.lifecycle.disposition import DispositionInventoryUnavailable
from enterprise_kb.modules.sources.originals import MAX_SYNTHETIC_BYTES
from enterprise_kb.modules.sources.restriction_log import _log_ref, _require_idle


MAX_STORES = 8
MAX_AGE = timedelta(hours=24)


@dataclass(frozen=True)
class BackupManifest:
    ref: UUID
    generation: int
    digest: bytes
    byte_length: int
    stores: tuple[bytes, ...]
    copies: tuple[tuple[UUID, bytes], ...]
    expires_at: datetime


def _require_catalogue(connection, authority_ref):
    if (
        connection.info.hostaddr not in {"127.0.0.1", "::1"}
        or rehearsal_marker(connection) is not None or _log_ref(connection) != authority_ref
        or connection.execute("SELECT 1 FROM thalion.organization LIMIT 1").fetchone() is not None
    ):
        raise DispositionInventoryUnavailable("A pinned, separate synthetic backup catalogue is required.")


def _valid_manifest(digest, byte_length, stores, refs, bindings):
    return (
        isinstance(digest, bytes) and len(digest) == 32
        and type(byte_length) is int and 0 < byte_length <= MAX_SYNTHETIC_BYTES
        and 1 <= len(stores) <= MAX_STORES and all(isinstance(store, bytes) and len(store) == 32 for store in stores)
        and len(set(stores)) == len(stores)
        and len(refs) == len(bindings) <= MAX_AUDIT_ENTRIES and all(isinstance(ref, UUID) for ref in refs)
        and len(set(refs)) == len(refs) and all(binding in stores for binding in bindings)
    )


def publish_manifest(
    connection: Connection, authority_ref: UUID, space_ref: UUID, version_ref: UUID, *,
    digest: bytes, byte_length: int, expected_generation: int, stores: Mapping[bytes, tuple[UUID, ...]],
    valid_for: timedelta = timedelta(hours=1),
) -> UUID:
    locations = list(stores)
    refs, bindings = [], []
    for store, copies in stores.items():
        if len(refs) + len(copies) > MAX_AUDIT_ENTRIES:
            raise ValueError("The manifest exceeds the copy limit.")
        refs.extend(copies)
        bindings.extend([store] * len(copies))
    if (
        not _valid_manifest(digest, byte_length, locations, refs, bindings)
        or type(expected_generation) is not int or not 0 <= expected_generation < 2**63 - 1
        or not timedelta(0) < valid_for <= MAX_AGE
    ):
        raise ValueError("Invalid synthetic backup manifest.")
    _require_idle(connection)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        _require_catalogue(connection, authority_ref)
        result = connection.execute("""
            INSERT INTO thalion.synthetic_backup_manifest (
                space_ref, version_ref, generation, content_digest, byte_length, stores, backup_refs, copy_stores, expires_at
            )
            SELECT %s, %s, %s, %s, %s, %s, %s, %s, statement_timestamp() + %s
            WHERE %s = (
                SELECT coalesce(max(generation), 0) FROM thalion.synthetic_backup_manifest
                WHERE (space_ref, version_ref) = (%s, %s)
            )
            ON CONFLICT (space_ref, version_ref, generation) DO NOTHING RETURNING manifest_ref
            """, (space_ref, version_ref, expected_generation + 1, digest, byte_length, locations, refs, bindings,
                  valid_for, expected_generation, space_ref, version_ref)).fetchone()
        if result is None:
            raise DispositionInventoryUnavailable("The backup catalogue generation changed.")
        return result[0]


def _head(connection, space_ref, version_ref):
    return connection.execute("""
        SELECT manifest_ref, generation, content_digest, byte_length, stores, backup_refs, copy_stores,
               expires_at, expires_at > clock_timestamp()
        FROM thalion.synthetic_backup_manifest
        WHERE (space_ref, version_ref) = (%s, %s) ORDER BY generation DESC LIMIT 1
        """, (space_ref, version_ref)).fetchone()


@contextmanager
def pinned_manifest(connection: Connection, authority_ref: UUID, space_ref: UUID, version_ref: UUID, manifest_ref: UUID):
    _require_idle(connection)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
        _require_catalogue(connection, authority_ref)
        head = _head(connection, space_ref, version_ref)
        if head is None or head[0] != manifest_ref or not head[-1]:
            raise DispositionInventoryUnavailable("The pinned backup manifest is not current.")
        ref, generation, digest, length, stores, refs, bindings, expires_at, _ = head
        if not _valid_manifest(digest, length, stores, refs, bindings):
            raise DispositionInventoryUnavailable("The current backup manifest is invalid.")
        yield BackupManifest(ref, generation, digest, length, tuple(stores), tuple(zip(refs, bindings, strict=True)), expires_at)
        if _head(connection, space_ref, version_ref) != head:
            raise DispositionInventoryUnavailable("The backup catalogue changed or expired during reconciliation.")
