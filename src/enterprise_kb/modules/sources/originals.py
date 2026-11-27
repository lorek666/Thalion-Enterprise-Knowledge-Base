from dataclasses import dataclass, field
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
from tempfile import NamedTemporaryFile

from enterprise_kb.ports.contracts import ObjectStoragePort, ObjectStorageUnavailable


MAX_SYNTHETIC_BYTES = 16 * 1024 * 1024
STORAGE_KEY = re.compile(r"[0-9a-f]{64}")


class OriginalIntegrityError(Exception):
    pass


@dataclass(frozen=True)
class OriginalAsset:
    key: str = field(repr=False)
    digest: bytes
    byte_length: int


def verify_payload(payload: bytes, digest: bytes):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_SYNTHETIC_BYTES:
        raise OriginalIntegrityError("A synthetic original requires bounded, immutable bytes.")
    if sha256(payload).digest() != digest:
        raise OriginalIntegrityError("Original bytes do not match the admitted digest.")


class SyntheticOriginalStore:
    """Private file storage for isolated development, not an ingestion or download endpoint."""

    storage_kind: str = "synthetic_file"
    contract_admission: str = "synthetic_only"

    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        details = self.root.stat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
        ):
            raise ValueError("The synthetic storage root must be a private directory.")

    def _path(self, key: str) -> Path:
        if STORAGE_KEY.fullmatch(key) is None:
            raise OriginalIntegrityError("Invalid synthetic storage key.")
        return self.root / key

    def stage(self, key: str, digest: bytes, payload: bytes) -> OriginalAsset:
        verify_payload(payload, digest)
        destination = self._path(key)
        asset = OriginalAsset(key, digest, len(payload))
        try:
            with NamedTemporaryFile(dir=self.root, prefix=".staging-") as file:
                file.write(payload)
                file.flush()
                os.fchmod(file.fileno(), 0o400)
                os.fsync(file.fileno())
                try:
                    os.link(file.name, destination)
                except FileExistsError:
                    pass
            self.read(asset)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            raise OriginalIntegrityError("Unable to durably stage the synthetic original.") from None
        return asset

    def read(self, asset: OriginalAsset) -> bytes:
        path = self._path(asset.key)
        if not 0 < asset.byte_length <= MAX_SYNTHETIC_BYTES:
            raise OriginalIntegrityError("Invalid original length.")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as file:
                details = os.fstat(file.fileno())
                if not stat.S_ISREG(details.st_mode) or details.st_size != asset.byte_length:
                    raise OriginalIntegrityError("The stored object is not the registered original.")
                payload = file.read(asset.byte_length + 1)
        except OSError:
            raise OriginalIntegrityError("The registered original is unavailable.") from None
        if len(payload) != asset.byte_length:
            raise OriginalIntegrityError("The original length changed during the read.")
        verify_payload(payload, asset.digest)
        return payload


class ObjectStorageOriginalStore:
    """OriginalStore bridge backed by an approved ObjectStoragePort."""

    def __init__(self, port: ObjectStoragePort):
        port_admission = getattr(port, "admission", None)
        port_storage_kind = getattr(port, "storage_kind", None)
        if port_admission == "production_approved":
            contract_admission = "production_approved"
            expected_kind = "https_object_store"
        elif port_admission == "synthetic_local":
            contract_admission = "synthetic_only"
            expected_kind = "synthetic_file"
        else:
            raise ValueError(f"Unsupported object storage port admission: {port_admission!r}.")
        if port_storage_kind != expected_kind:
            raise ValueError(
                f"Object storage port storage_kind {port_storage_kind!r} does not match admission {port_admission!r}."
            )
        self.port = port
        self.contract_admission = contract_admission
        self.storage_kind = port_storage_kind

    def stage(self, key: str, digest: bytes, payload: bytes) -> OriginalAsset:
        if STORAGE_KEY.fullmatch(key) is None:
            raise OriginalIntegrityError("Invalid original storage key.")
        verify_payload(payload, digest)
        try:
            stored_digest = self.port.write_immutable(key, payload)
        except (ObjectStorageUnavailable, ValueError):
            raise OriginalIntegrityError("Unable to write immutable original to object storage.") from None
        if stored_digest != digest:
            raise OriginalIntegrityError("Object storage digest mismatch on write.")
        return OriginalAsset(key, digest, len(payload))

    def read(self, asset: OriginalAsset) -> bytes:
        if STORAGE_KEY.fullmatch(asset.key) is None:
            raise OriginalIntegrityError("Invalid original storage key.")
        if not 0 < asset.byte_length <= MAX_SYNTHETIC_BYTES:
            raise OriginalIntegrityError("Invalid original length.")
        try:
            payload = self.port.read_verified(asset.key, asset.digest, asset.byte_length)
        except (ObjectStorageUnavailable, ValueError):
            raise OriginalIntegrityError("The registered original is unavailable in object storage.") from None
        if len(payload) != asset.byte_length:
            raise OriginalIntegrityError("The original length changed during the read.")
        verify_payload(payload, asset.digest)
        return payload
