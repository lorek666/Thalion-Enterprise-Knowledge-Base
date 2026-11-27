from hashlib import sha256
import json
import os
import stat
import subprocess
import sys
from uuid import uuid4

import pytest

from enterprise_kb.backup_audit import reconcile
from enterprise_kb.modules.lifecycle import backup_inventory as backup_storage
from enterprise_kb.modules.lifecycle.disposition import DispositionInventoryUnavailable

from test_backup_expiry import observe, registered_copy, schedule, withdraw_for_due_backup
from test_backup_inventory import REGISTER, backup_inventory, register, store_copy
from test_disposition_cases import candidate
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, transport
from test_feedback_work import admit
from test_runtime import runtime_db
from test_travel_search import corpus


@pytest.fixture
def report_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("private-backup-audits")
    directory.chmod(0o700)
    return directory


def audit(db, backups, reports):
    _, _, database_url, _, originals = db
    return subprocess.run([
        sys.executable, "-I", "-m", "enterprise_kb.backup_audit", "--originals", str(originals.root),
        "--backups", str(backups), "--report-dir", str(reports),
    ], env=os.environ | {"THALION_DATABASE_URL": database_url}, capture_output=True, text=True, check=False)


def report(result, reports, expected):
    assert result.returncode == expected, result.stderr
    assert not result.stderr
    summary = json.loads(result.stdout)
    file = reports / f"backup-audit-{summary['report_id']}.json"
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    raw = file.read_bytes()
    assert sha256(raw).hexdigest() == summary["report_sha256"]
    detail = json.loads(raw)
    assert summary["counts"] == detail["counts"] and summary["status"] == detail["status"]
    assert detail["executable"] is False and detail["restore_authorized"] is False
    return detail


def test_read_only_audit_detects_missing_unregistered_and_changed_bytes(backup_inventory, report_dir):
    ((client, db, (_, reviewer), credentials, _, *_), _, (version, *_)), root = backup_inventory
    admit(credentials, reviewer, REGISTER)
    payload = original(db, version).read_bytes()
    present, missing, changed, aliased = [uuid4() for _ in range(4)]
    files = {backup: store_copy(root, backup, payload) for backup in (present, missing, changed, aliased)}
    for backup in files:
        assert register(client, reviewer, version, backup).status_code == 200
    matched = report(audit(db, root, report_dir), report_dir, 0)
    assert matched["status"] == "matched" and matched["counts"] == {"verified": 4}
    files[missing].unlink()
    files[changed].unlink()
    store_copy(root, changed, b"!" + payload[1:])
    files[aliased].unlink()
    files[aliased].symlink_to(original(db, version))
    unknown = root / "unregistered-sensitive-name"
    unknown.write_bytes(b"unregistered fixture")
    result = audit(db, root, report_dir)
    mismatches = report(result, report_dir, 2)
    assert mismatches["counts"] == {"verified": 1, "missing": 1, "invalid": 2, "unregistered": 1}
    assert {item["backup_id"]: item["state"] for item in mismatches["registrations"]} == {
        str(present): "verified", str(missing): "missing", str(changed): "invalid", str(aliased): "invalid",
    }
    assert mismatches["unregistered_name_sha256"] == [sha256(os.fsencode(unknown.name)).hexdigest()]
    assert unknown.name not in result.stdout and str(present) not in result.stdout
    assert files[aliased].is_symlink() and unknown.read_bytes() == b"unregistered fixture"


def test_expired_absence_and_reappearance_are_distinct_from_destruction(registered_copy, report_dir):
    client, db, _, reviewer, version, backup, file = registered_copy
    expiry = withdraw_for_due_backup(db, version)
    assert schedule(client, reviewer, backup, expiry).status_code == 200
    file.unlink()
    assert observe(client, reviewer, backup).status_code == 200
    absent = report(audit(db, file.parent, report_dir), report_dir, 0)
    assert absent["counts"] == {"absence_observed": 1}
    assert absent["registrations"][0]["withdrawn"] is True
    store_copy(file.parent, backup, original(db, version).read_bytes())
    reappeared = report(audit(db, file.parent, report_dir), report_dir, 2)
    assert reappeared["counts"] == {"reappeared": 1}


def test_other_directory_and_unsafe_destination_cannot_produce_clean_audit(registered_copy, report_dir, tmp_path_factory):
    _, db, _, _, _, backup, file = registered_copy
    other = tmp_path_factory.mktemp("other-audited-backups")
    other.chmod(0o700)
    store_copy(other, backup, file.read_bytes())
    other_report = report(audit(db, other, report_dir), report_dir, 2)
    assert other_report["counts"] == {"other_directory": 1, "unregistered": 1}
    inside_backups = file.parent / "reports"
    inside_backups.mkdir(mode=0o700)
    refused = audit(db, file.parent, inside_backups)
    assert refused.returncode == 1 and not refused.stdout
    assert not list(inside_backups.iterdir())


def test_over_limit_directory_produces_no_report(registered_copy, report_dir):
    _, db, _, _, _, _, file = registered_copy
    for index in range(backup_storage.MAX_AUDIT_ENTRIES):
        (file.parent / f"unknown-{index}").touch(mode=0o600)
    refused = audit(db, file.parent, report_dir)
    assert refused.returncode == 1 and not refused.stdout
    assert not list(report_dir.iterdir())


def test_file_changed_after_byte_check_invalidates_whole_observation(registered_copy, evidence_transport, monkeypatch):
    _, db, _, _, _, backup, file = registered_copy
    connection, *_ = db
    service, *_ = evidence_transport
    verify = backup_storage._verify_file

    def change_after_read(*arguments):
        assert connection.execute("SHOW transaction_read_only").fetchone() == ("on",)
        assert connection.execute("SHOW transaction_isolation").fetchone() == ("repeatable read",)
        verify(*arguments)
        payload = file.read_bytes()
        file.unlink()
        store_copy(file.parent, backup, b"!" + payload[1:])

    monkeypatch.setattr(backup_storage, "_verify_file", change_after_read)
    with pytest.raises(DispositionInventoryUnavailable, match="changed during the audit"):
        reconcile(connection, service.backup_store)
