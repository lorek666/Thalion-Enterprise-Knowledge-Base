from hashlib import sha256
import os
import subprocess
import sys
from uuid import uuid4

from psycopg import errors
import pytest

from enterprise_kb import backup_audit
from enterprise_kb.database import upgrade
from enterprise_kb.modules.lifecycle import backup_catalogue
from enterprise_kb.modules.lifecycle.backup_inventory import SyntheticBackupStore
from enterprise_kb.modules.lifecycle.disposition import DispositionInventoryUnavailable

from test_backup_inventory import REGISTER, backup_inventory, register, store_copy
from test_backup_reconciliation import report, report_dir
from test_disposition_cases import candidate
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, transport
from test_feedback_work import admit
from test_runtime import open_database, runtime_db
from test_travel_search import corpus


@pytest.fixture
def catalogue(independent_database_url, backup_inventory, evidence_transport, tmp_path_factory):
    ((client, db, (_, reviewer), credentials, _, *_), _, (version, *_)), _ = backup_inventory
    service, *_ = evidence_transport
    admit(credentials, reviewer, REGISTER)
    second = tmp_path_factory.mktemp("second-private-backups")
    second.chmod(0o700)
    stores = (service.backup_store, SyntheticBackupStore(second, service.store))
    upgrade(independent_database_url)
    with open_database(independent_database_url) as authority:
        endpoint, = authority.execute("SELECT log_ref FROM thalion.rule_log_endpoint").fetchone()
        yield client, db, reviewer, version, stores, service, authority, endpoint, independent_database_url


def issue(catalogue, copies, *, generation=0, digest=None):
    _, db, _, version, stores, _, authority, endpoint, _ = catalogue
    payload = original(db, version).read_bytes()
    return backup_catalogue.publish_manifest(
        authority, endpoint, db[1].space_ref, version.version_ref,
        digest=digest or sha256(payload).digest(), byte_length=len(payload), expected_generation=generation,
        stores={store.identity(): tuple(refs) for store, refs in zip(stores, copies, strict=True)},
    )


def put(catalogue, store, ref, *, enrolled=True, payload=None):
    client, db, reviewer, version, stores, service, *_ = catalogue
    data = original(db, version).read_bytes() if payload is None else payload
    file = store_copy(stores[store].root, ref, data)
    if enrolled:
        service.backup_store = stores[store]
        assert register(client, reviewer, version, ref).status_code == 200
    return file


def audit(catalogue, manifest, report_dir, *, which=(0, 1), authority_ref=None, authority_url=None, version_ref=None):
    _, db, _, version, stores, _, _, endpoint, url = catalogue
    return subprocess.run([
        sys.executable, "-I", "-m", "enterprise_kb.backup_audit",
        "--originals", str(db[4].root), "--report-dir", str(report_dir),
        "--catalogue-ref", str(authority_ref or endpoint), "--manifest-id", str(manifest),
        "--space-id", str(db[1].space_ref), "--version-id", str(version_ref or version.version_ref),
        *(arg for index in which for arg in ("--backups", str(stores[index].root))),
    ], env=os.environ | {
        "THALION_DATABASE_URL": db[2], "THALION_BACKUP_CATALOGUE_URL": authority_url or url,
    }, capture_output=True, text=True, check=False)


def test_catalogue_matches_actual_copies_in_distinct_directories_without_claiming_disposal(catalogue, report_dir):
    first, second = uuid4(), uuid4()
    expected = [put(catalogue, 0, first), put(catalogue, 1, second)]
    manifest = issue(catalogue, [(first,), (second,)])
    detail = report(audit(catalogue, manifest, report_dir), report_dir, 0)
    assert detail["manifest_id"] == str(manifest) and detail["generation"] == 1
    assert detail["counts"] == {"verified": 2}
    assert set(detail["remaining_copy_ids"]) == {str(first), str(second)}
    assert {item["backup_id"]: item["catalogue_observation"] for item in detail["registrations"]} == {
        str(first): "verified", str(second): "verified",
    }
    assert all(file.read_bytes() for file in expected)
    assert catalogue[1][0].execute("SELECT count(*) FROM thalion.synthetic_backup_copy").fetchone() == (2,)


def test_catalogue_discrepancies_preserve_copies_but_never_pass_on_a_clean_subset(catalogue, report_dir):
    catalogue_only, local_only, different_binding, observed_bad = (uuid4() for _ in range(4))
    put(catalogue, 0, local_only)
    put(catalogue, 0, different_binding)
    put(catalogue, 0, catalogue_only, enrolled=False)
    verified = put(catalogue, 1, observed_bad)
    verified.unlink()
    put(catalogue, 1, observed_bad, enrolled=False, payload=b"!" + original(catalogue[1], catalogue[3]).read_bytes()[1:])
    unknown = catalogue[4][1].root / "not-an-attributable-copy"
    unknown.write_bytes(b"fixture")
    manifest = issue(catalogue, [(catalogue_only,), (different_binding, observed_bad)])
    detail = report(audit(catalogue, manifest, report_dir), report_dir, 2)
    rows = {item["backup_id"]: item for item in detail["registrations"]}
    assert {key: value["state"] for key, value in rows.items()} == {
        str(catalogue_only): "catalogue_only", str(local_only): "local_only",
        str(different_binding): "binding_mismatch", str(observed_bad): "invalid",
    }
    assert rows[str(catalogue_only)]["catalogue_observation"] == "verified"
    assert rows[str(different_binding)]["catalogue_observation"] == "missing"
    assert rows[str(different_binding)]["registered_observation"] == "verified"
    assert list(detail["unregistered_name_sha256"].values()) == [[sha256(os.fsencode(unknown.name)).hexdigest()]]
    incomplete = report(audit(catalogue, manifest, report_dir, which=(0,)), report_dir, 2)
    assert incomplete["unobserved_stores"] == [catalogue[4][1].identity().hex()]
    assert set(incomplete["remaining_copy_ids"]) == set(rows)


def test_catalogue_requires_explicit_current_pin_and_exact_version_bytes(catalogue, report_dir):
    _, db, _, _, _, _, authority, _, _ = catalogue
    first = issue(catalogue, [(), ()])
    current = issue(catalogue, [(), ()], generation=1)
    assert current != first
    with pytest.raises(DispositionInventoryUnavailable, match="generation"):
        issue(catalogue, [(), ()], generation=1)
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        authority.execute("TRUNCATE thalion.synthetic_backup_manifest")
    for untrusted in (
        audit(catalogue, first, report_dir),
        audit(catalogue, current, report_dir, authority_ref=uuid4()),
        audit(catalogue, current, report_dir, authority_url=db[2]),
        audit(catalogue, current, report_dir, version_ref=uuid4()),
    ):
        assert untrusted.returncode == 1 and not untrusted.stdout
    wrong = issue(catalogue, [(), ()], generation=2, digest=bytes(32))
    refused = audit(catalogue, wrong, report_dir)
    assert refused.returncode == 1 and not refused.stdout
    assert not list(report_dir.iterdir())


def test_expired_catalogue_head_cannot_be_used_or_replaced_by_an_older_pin(catalogue, report_dir):
    _, _, _, _, _, _, authority, _, _ = catalogue
    first = issue(catalogue, [(), ()])
    assert report(audit(catalogue, first, report_dir), report_dir, 0)["counts"] == {}
    expired, = authority.execute("""
        INSERT INTO thalion.synthetic_backup_manifest (
            space_ref, version_ref, generation, content_digest, byte_length, stores, backup_refs, copy_stores,
            recorded_at, expires_at
        )
        SELECT space_ref, version_ref, generation + 1, content_digest, byte_length, stores, backup_refs, copy_stores,
               statement_timestamp() - interval '2 hours', statement_timestamp() - interval '1 hour'
        FROM thalion.synthetic_backup_manifest WHERE manifest_ref = %s
        RETURNING manifest_ref
        """, (first,)).fetchone()
    existing = set(report_dir.iterdir())
    for pin in (expired, first):
        refused = audit(catalogue, pin, report_dir)
        assert refused.returncode == 1 and not refused.stdout
    assert set(report_dir.iterdir()) == existing


def test_catalogue_head_change_during_scan_invalidates_the_reports(catalogue, monkeypatch):
    _, db, _, version, stores, _, authority, endpoint, url = catalogue
    manifest = issue(catalogue, [(), ()])
    scan = SyntheticBackupStore.audit
    changed = []

    def advance(store, expected):
        if not changed:
            with open_database(url) as writer:
                changed.append(issue((*catalogue[:6], writer, endpoint, url), [(), ()], generation=1))
        return scan(store, expected)

    monkeypatch.setattr(SyntheticBackupStore, "audit", advance)
    with pytest.raises(DispositionInventoryUnavailable, match="changed"):
        backup_audit.reconcile_catalogue(
            db[0], authority, stores, authority_ref=endpoint,
            space_ref=db[1].space_ref, version_ref=version.version_ref, manifest_ref=manifest,
        )
    assert len(changed) == 1 and changed[0] != manifest
