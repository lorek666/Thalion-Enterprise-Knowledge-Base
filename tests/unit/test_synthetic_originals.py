from hashlib import sha256

import pytest

from enterprise_kb.modules.sources import originals
from enterprise_kb.modules.sources.originals import (
    OriginalAsset,
    OriginalIntegrityError,
    SyntheticOriginalStore,
)


KEY = "a" * 64
PAYLOAD = b"synthetic original"
ASSET = OriginalAsset(KEY, sha256(PAYLOAD).digest(), len(PAYLOAD))


def test_synthetic_storage_refuses_shared_directories(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match="private"):
        SyntheticOriginalStore(tmp_path)


def test_storage_does_not_follow_or_replace_an_existing_alias(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    other = tmp_path / "unrelated"
    other.write_bytes(PAYLOAD)
    (root / KEY).symlink_to(other)
    store = SyntheticOriginalStore(root)
    with pytest.raises(OriginalIntegrityError):
        store.read(ASSET)
    with pytest.raises(OriginalIntegrityError):
        store.stage(KEY, ASSET.digest, PAYLOAD)
    assert (root / KEY).is_symlink()
    assert other.read_bytes() == PAYLOAD


def test_storage_refuses_mismatched_existing_bytes_of_the_same_length(tmp_path):
    other_payload = bytes(len(PAYLOAD))
    (tmp_path / KEY).write_bytes(other_payload)
    store = SyntheticOriginalStore(tmp_path)
    with pytest.raises(OriginalIntegrityError, match="digest"):
        store.stage(KEY, ASSET.digest, PAYLOAD)
    assert (tmp_path / KEY).read_bytes() == other_payload
    assert sorted(path.name for path in tmp_path.iterdir()) == [KEY]


def test_first_stage_verifies_the_bytes_in_the_committed_file(tmp_path, monkeypatch):
    def corrupt_publication(temporary, destination):
        destination.write_bytes(bytes(len(PAYLOAD)))

    monkeypatch.setattr(originals.os, "link", corrupt_publication)
    store = SyntheticOriginalStore(tmp_path)
    with pytest.raises(OriginalIntegrityError, match="digest"):
        store.stage(KEY, ASSET.digest, PAYLOAD)
    assert sorted(path.name for path in tmp_path.iterdir()) == [KEY]
