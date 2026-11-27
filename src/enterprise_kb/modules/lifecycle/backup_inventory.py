from hashlib import sha256
import os
from pathlib import Path
import stat
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.lifecycle.disposition import DESTINATION, DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, command_for, require_scope
from enterprise_kb.modules.sources.originals import MAX_SYNTHETIC_BYTES, OriginalIntegrityError, SyntheticOriginalStore, verify_payload
from enterprise_kb.modules.sources.registry import sql_storage_matches_admission
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


REGISTER_BACKUP = "register_synthetic_backup_copy"
MAX_AUDIT_ENTRIES = 500
MAX_AUDIT_BYTES = 128 * 1024 * 1024


def backup_key(backup: UUID) -> str:
    return sha256(backup.bytes).hexdigest()


def _metadata(details):
    return (details.st_dev, details.st_ino, details.st_mode, details.st_uid, details.st_nlink, details.st_size,
            details.st_ctime_ns, details.st_mtime_ns)


def _is_backup_file(details, length):
    return (stat.S_ISREG(details.st_mode) and details.st_uid == os.geteuid() and not details.st_mode & 0o377
            and details.st_nlink == 1 and 0 < length == details.st_size <= MAX_SYNTHETIC_BYTES)


def _verify_file(directory, key, digest, length):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(key, flags, dir_fd=directory), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not _is_backup_file(before, length):
            raise OriginalIntegrityError("The backup copy is not a separate private regular file.")
        payload = stream.read(length + 1)
        after = os.stat(key, dir_fd=directory, follow_symlinks=False)
        if _metadata(before) != _metadata(after):
            raise DispositionInventoryUnavailable("The backup changed during verification.")
        if len(payload) != length:
            raise OriginalIntegrityError("The backup length changed during verification.")
        verify_payload(payload, digest)


def _entries(directory):
    opened = os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory)
    try:
        with os.scandir(opened) as entries:
            result = {}
            for entry in entries:
                if len(result) >= MAX_AUDIT_ENTRIES:
                    raise DispositionInventoryUnavailable("The backup directory exceeds the audit entry limit.")
                result[entry.name] = entry.stat(follow_symlinks=False)
            return result
    finally:
        os.close(opened)


class SyntheticBackupStore:
    def __init__(self, root: Path, originals: SyntheticOriginalStore):
        self.root = root.resolve(strict=True)
        if self.root.is_relative_to(originals.root) or originals.root.is_relative_to(self.root):
            raise ValueError("The backup and original directories must be separate.")
        descriptor = self._open_directory()
        os.close(descriptor)

    def _open_directory(self):
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        details = os.fstat(descriptor)
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            os.close(descriptor)
            raise ValueError("The synthetic backup directory must be private.")
        return descriptor

    def _identity(self, directory: int) -> bytes:
        details = os.fstat(directory)
        return sha256(f"{self.root}:{details.st_dev}:{details.st_ino}".encode()).digest()

    def identity(self) -> bytes:
        directory = self._open_directory()
        try:
            return self._identity(directory)
        finally:
            os.close(directory)

    def verify(self, backup: UUID, digest: bytes, length: int) -> bytes:
        try:
            directory = self._open_directory()
            try:
                _verify_file(directory, backup_key(backup), digest, length)
                return self._identity(directory)
            finally:
                os.close(directory)
        except (OSError, ValueError, OriginalIntegrityError):
            raise DispositionInventoryUnavailable("The registered source and backup bytes could not be matched.") from None

    def is_absent(self, backup: UUID, store_identity: bytes) -> bool:
        try:
            directory = self._open_directory()
            try:
                before = os.fstat(directory)
                if self._identity(directory) != store_identity:
                    raise DispositionInventoryUnavailable("The scheduled backup directory could not be identified.")
                try:
                    os.stat(backup_key(backup), dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    after = self.root.stat(follow_symlinks=False)
                    if (before.st_dev, before.st_ino, before.st_ctime_ns, before.st_mtime_ns) != (
                        after.st_dev, after.st_ino, after.st_ctime_ns, after.st_mtime_ns,
                    ):
                        raise DispositionInventoryUnavailable("The backup directory changed during observation.")
                    return True
                return False
            finally:
                os.close(directory)
        except (OSError, ValueError):
            raise DispositionInventoryUnavailable("The scheduled backup directory could not be checked.") from None

    def audit(self, registered):
        try:
            directory = self._open_directory()
            try:
                identity = self._identity(directory)
                root_before = _metadata(os.fstat(directory))
                entries = _entries(directory)
                expected = {key: (digest, length) for key, (bound, digest, length) in registered.items() if bound == identity}
                states = {}
                scanned_bytes = 0
                for key, (digest, length) in expected.items():
                    details = entries.get(key)
                    if details is None:
                        states[key] = "missing"
                    elif not _is_backup_file(details, length):
                        states[key] = "invalid"
                    else:
                        scanned_bytes += length
                        if scanned_bytes > MAX_AUDIT_BYTES:
                            raise DispositionInventoryUnavailable("The backup directory exceeds the audit byte limit.")
                        try:
                            _verify_file(directory, key, digest, length)
                        except OriginalIntegrityError:
                            states[key] = "invalid"
                        else:
                            states[key] = "verified"
                if ({name: _metadata(details) for name, details in _entries(directory).items()}
                        != {name: _metadata(details) for name, details in entries.items()}
                        or _metadata(self.root.stat(follow_symlinks=False)) != root_before):
                    raise DispositionInventoryUnavailable("The backup directory changed during the audit.")
                unknown = sorted(sha256(os.fsencode(name)).hexdigest() for name in entries.keys() - expected.keys())
                return identity, states, unknown
            finally:
                os.close(directory)
        except (OSError, ValueError):
            raise DispositionInventoryUnavailable("The private backup directory could not be audited.") from None


def register_backup_copy(
    connection: Connection, call: OperationsCall, version_ref: UUID, backup: UUID, store: SyntheticBackupStore | None,
) -> dict:
    with connection.transaction():
        require_scope(connection, call, REGISTER_BACKUP, destination=DESTINATION)
        scope = (call.org_id, call.space_id)
        target = connection.execute(
            f"""
            SELECT version.version_id, asset.asset_id, asset.content_digest, asset.byte_length
            FROM thalion.object_identity AS identity
            JOIN thalion.document_version AS version
              ON (version.org_id, version.space_id, version.version_id) = (identity.org_id, identity.space_id, identity.object_id)
            JOIN thalion.asset AS asset
              ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id) =
                 (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
            JOIN thalion.source AS source
              ON (source.org_id, source.space_id, source.source_id) = (version.org_id, version.space_id, version.source_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
                 (source.org_id, source.space_id, source.source_id, source.contract_revision)
            WHERE (identity.org_id, identity.space_id, identity.public_id, identity.object_type) = (%s, %s, %s, 'document_version')
              AND {sql_storage_matches_admission('asset.storage_kind', 'contract.admission')}
            """, (*scope, version_ref),
        ).fetchone()
        if target is None or not connection.execute(
            "SELECT thalion.lock_local_hold_target(%s, %s, %s, %s)", (*scope, target[0], call.principal_id),
        ).fetchone()[0]:
            raise OperationsNotAdmitted("A current independent synthetic backup custodian is required.")
        version, asset, digest, length = target
        command = command_for(call, REGISTER_BACKUP, (str(version_ref), str(backup)))

        def apply(transaction):
            if store is None:
                raise DispositionInventoryUnavailable("No private synthetic backup directory is configured.")
            store_identity = store.verify(backup, digest, length)
            registered = transaction.execute(
                """
                INSERT INTO thalion.synthetic_backup_copy (
                    org_id, space_id, version_id, backup_ref, asset_id, content_digest, byte_length, recorded_by, request_id, store_identity
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (backup_ref) DO NOTHING RETURNING backup_ref
                """, (*scope, version, backup, asset, digest, length, call.principal_id, call.request_id, store_identity),
            ).fetchone()
            if registered is None:
                raise DispositionConflict("This backup identity has already been registered.")
            append_event(transaction, call.org_id, "lifecycle.synthetic_backup.registered", version_ref, space_id=call.space_id)
            return registered[0]

        result = execute_command(connection, command, apply).result_ref
        return {"backup_id": str(result), "state": "registered", "executable": False}
