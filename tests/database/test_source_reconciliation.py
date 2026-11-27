from dataclasses import replace
from hashlib import sha256
import json
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.sources import registry, sync
from enterprise_kb.runtime.audit import RequestAuditConflict
from enterprise_kb.runtime.commands import IdempotencyConflict

from test_runtime import open_database, runtime_db
from test_source_sync import sync_request
from test_sources import CONTENT, OTHER_CONTENT, candidate, register, source_db


def manifest(reconciliation, entries, *, previous=None, content_position=None):
    return reconciliation.InventoryManifest(
        uuid4(), previous, content_position, len(entries), reconciliation.inventory_digest(entries),
    )


def reconcile(reconciliation, connection, tenant, source, declared, entries):
    request = sync_request(connection, tenant, operation=reconciliation.COMMIT)
    return reconciliation.reconcile_inventory(connection, request, source, declared, entries)


def checkpoint(reconciliation, connection, tenant, source):
    request = sync_request(connection, tenant, operation=reconciliation.READ)
    return reconciliation.read_inventory_position(connection, request, source)


def test_inventory_requires_complete_exact_snapshot_and_keeps_content_position_separate(source_db):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, url, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    present = candidate(tenant, source_ref)
    omitted = replace(present, object_key="not-enumerated")
    page = sync.SourcePage(None, uuid4(), (
        sync.PageOriginal(present, CONTENT), sync.PageOriginal(omitted, CONTENT),
    ))
    registered = sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
    entries = (
        reconciliation.InventoryEntry(present.object_key, present.incarnation, present.source_version_key, present.digest),
        reconciliation.InventoryEntry("not-imported", "first", "rev-a", sha256(OTHER_CONTENT).digest()),
    )
    declared = manifest(reconciliation, entries, content_position=page.through)
    with pytest.raises(reconciliation.InventoryConflict):
        reconcile(reconciliation, connection, tenant, source, declared, entries[:1])
    with pytest.raises(reconciliation.InventoryConflict):
        reconcile(reconciliation, connection, tenant, source, declared, (
            entries[0], replace(entries[1], digest=sha256(CONTENT).digest()),
        ))
    assert checkpoint(reconciliation, connection, tenant, source) is None
    result = reconcile(reconciliation, connection, tenant, source, declared, entries)
    assert result.snapshot_ref == declared.snapshot_ref and result.matched_count == 1
    assert {(item.object_key, item.kind) for item in result.differences} == {
        ("not-imported", "version_not_registered"), ("not-enumerated", "not_enumerated"),
    }
    assert checkpoint(reconciliation, connection, tenant, source) == declared.snapshot_ref
    with open_database(url) as resumed:
        assert reconcile(reconciliation, resumed, tenant, source, declared, entries[::-1]) == result
        content_request = sync_request(resumed, tenant, operation=sync.READ)
        assert sync.read_content_position(resumed, content_request, source) == page.through
    assert connection.execute("SELECT count(*) FROM thalion.rule_use_stop").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.job").fetchone() == (2,)
    assert len(registered.version_refs) == 2


def test_inventory_rejects_conflicting_history_and_records_same_key_digest_difference(source_db):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, _, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    version = candidate(tenant, source_ref)
    page = sync.SourcePage(None, uuid4(), (sync.PageOriginal(version, CONTENT),))
    sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
    entries = (reconciliation.InventoryEntry(
        version.object_key, version.incarnation, version.source_version_key, sha256(OTHER_CONTENT).digest(),
    ),)
    declared = manifest(reconciliation, entries, content_position=page.through)
    assert reconcile(reconciliation, connection, tenant, source, declared, entries).differences[0].kind == "digest_mismatch"
    changed = (replace(entries[0], digest=version.digest),)
    with pytest.raises(IdempotencyConflict):
        reconcile(reconciliation, connection, tenant, source, replace(
            declared, expected_digest=reconciliation.inventory_digest(changed),
        ), changed)
    with pytest.raises(reconciliation.InventoryConflict):
        reconcile(reconciliation, connection, tenant, source, manifest(
            reconciliation, changed, content_position=page.through,
        ), changed)
    delayed = manifest(reconciliation, changed, previous=declared.snapshot_ref, content_position=page.through)
    next_page = sync.SourcePage(page.through, uuid4(), ())
    sync.commit_content_page(connection, sync_request(connection, tenant), source, next_page, store)
    with pytest.raises(reconciliation.InventoryConflict):
        reconcile(reconciliation, connection, tenant, source, delayed, changed)
    assert checkpoint(reconciliation, connection, tenant, source) == declared.snapshot_ref
    current = manifest(reconciliation, changed, previous=declared.snapshot_ref, content_position=next_page.through)
    assert reconcile(reconciliation, connection, tenant, source, current, changed).differences == ()
    assert checkpoint(reconciliation, connection, tenant, source) == current.snapshot_ref
    assert reconcile(reconciliation, connection, tenant, source, declared, entries).snapshot_ref == declared.snapshot_ref
    assert checkpoint(reconciliation, connection, tenant, source) == current.snapshot_ref


def test_inventory_admission_and_duplicate_keys_fail_closed(source_db):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, _, source_ref, _ = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    declared = manifest(reconciliation, ())
    wrong_request = sync_request(connection, tenant)
    with pytest.raises(RequestAuditConflict):
        reconciliation.reconcile_inventory(connection, wrong_request, source, declared, ())
    outsider = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=reconciliation.COMMIT)
    with pytest.raises(registry.SourceNotAdmitted):
        reconciliation.reconcile_inventory(connection, outsider, source, declared, ())
    entry = reconciliation.InventoryEntry("same-key", "first", "rev-a", sha256(CONTENT).digest())
    with pytest.raises(ValueError):
        reconciliation.inventory_digest((entry, replace(entry, source_version_key="rev-b")))
    assert checkpoint(reconciliation, connection, tenant, source) is None
    assert reconcile(reconciliation, connection, tenant, source, declared, ()).differences == ()


def test_inventory_does_not_acknowledge_a_failed_commit(source_db):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, _, source_ref, _ = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    declared = manifest(reconciliation, ())
    request = sync_request(connection, tenant, operation=reconciliation.COMMIT)
    connection.execute("""
        CREATE FUNCTION thalion.inject_inventory_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'synthetic deferred inventory failure';
        END;
        $$;
        CREATE CONSTRAINT TRIGGER reject_inventory_commit
        AFTER INSERT ON thalion.source_inventory_receipt
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
        EXECUTE FUNCTION thalion.inject_inventory_commit_failure();
    """)
    with pytest.raises(errors.RaiseException, match="synthetic deferred inventory failure"):
        reconciliation.reconcile_inventory(connection, request, source, declared, ())
    assert checkpoint(reconciliation, connection, tenant, source) is None
    assert connection.execute(
        "SELECT count(*) FROM thalion.command_receipt WHERE request_id = %s", (request.request_id,),
    ).fetchone() == (0,)
    connection.execute("DROP TRIGGER reject_inventory_commit ON thalion.source_inventory_receipt")
    assert reconciliation.reconcile_inventory(connection, request, source, declared, ()).sequence == 1


def test_oversized_local_inventory_is_not_reported_as_complete(source_db, monkeypatch):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, _, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    version = candidate(tenant, source_ref)
    page = sync.SourcePage(None, uuid4(), (
        sync.PageOriginal(version, CONTENT),
        sync.PageOriginal(replace(version, object_key="second-local-object"), CONTENT),
    ))
    sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
    monkeypatch.setattr(reconciliation, "MAX_INVENTORY_ENTRIES", 1)
    declared = manifest(reconciliation, (), content_position=page.through)
    with pytest.raises(reconciliation.InventoryConflict, match="local inventory exceeds"):
        reconcile(reconciliation, connection, tenant, source, declared, ())
    assert checkpoint(reconciliation, connection, tenant, source) is None


def test_inventory_does_not_match_or_infer_omissions_from_old_contract_versions(source_db):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, _, source_ref, store = source_db
    old_source = sync.SyncSource(tenant.space_id, source_ref, 1)
    version = candidate(tenant, source_ref)
    page = sync.SourcePage(None, uuid4(), (
        sync.PageOriginal(version, CONTENT),
        sync.PageOriginal(replace(version, object_key="old-scope-only"), CONTENT),
    ))
    sync.commit_content_page(connection, sync_request(connection, tenant), old_source, page, store)
    with connection.transaction():
        connection.execute("""
            INSERT INTO thalion.source_contract_revision
                (org_id, space_id, source_id, revision, admission, collector_id, object_namespace)
            SELECT org_id, space_id, source_id, 2, admission, collector_id, object_namespace
            FROM thalion.source_contract_revision WHERE revision = 1
        """)
        connection.execute("UPDATE thalion.source SET contract_revision = 2")
    current_source = replace(old_source, contract_revision=2)
    current_version = replace(
        version, contract_revision=2, source_version_key="new-revision",
        digest=sha256(OTHER_CONTENT).digest(),
    )
    current_page = sync.SourcePage(None, uuid4(), (sync.PageOriginal(current_version, OTHER_CONTENT),))
    sync.commit_content_page(connection, sync_request(connection, tenant), current_source, current_page, store)
    entries = (reconciliation.InventoryEntry(
        version.object_key, version.incarnation, version.source_version_key, version.digest,
    ),)
    declared = manifest(reconciliation, entries, content_position=current_page.through)
    result = reconcile(reconciliation, connection, tenant, current_source, declared, entries)
    assert result.matched_count == 0
    assert [(item.object_key, item.kind) for item in result.differences] == [
        (version.object_key, "version_not_registered"),
    ]
    entries = (replace(entries[0], source_version_key=current_version.source_version_key, digest=current_version.digest),)
    declared = manifest(
        reconciliation, entries, previous=declared.snapshot_ref, content_position=current_page.through,
    )
    current = reconcile(reconciliation, connection, tenant, current_source, declared, entries)
    assert current.matched_count == 1 and current.differences == ()


def test_inventory_serializes_with_single_version_registration(source_db, monkeypatch):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, url, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    version = candidate(tenant, source_ref)
    entries = (reconciliation.InventoryEntry(
        version.object_key, version.incarnation, version.source_version_key, version.digest,
    ),)
    compare = reconciliation._compare_inventory

    def check_serialized(transaction, scope, ordered):
        result = compare(transaction, scope, ordered)
        with open_database(url) as other:
            other.execute("SET lock_timeout = '100ms'")
            with pytest.raises(errors.LockNotAvailable):
                register(other, tenant, source_ref, store)
        return result

    monkeypatch.setattr(reconciliation, "_compare_inventory", check_serialized)
    result = reconcile(reconciliation, connection, tenant, source, manifest(reconciliation, entries), entries)
    assert result.differences[0].kind == "version_not_registered"
    assert register(connection, tenant, source_ref, store, key="after-reconciliation").created


@pytest.mark.parametrize("differences", [
    [],
    {},
    [["invalid key", "first", "rev-a", "digest_mismatch"]],
    [["object", "first", "rev-a", "unknown_state"]],
    [["object", "first", None, "version_not_registered"]],
    [["object", "first", "rev-a", "version_not_registered", "extra"]],
    [[42, "first", "rev-a", "version_not_registered"]],
    [{"kind": "version_not_registered"}],
    [
        ["object", "first", "rev-a", "version_not_registered"],
        ["object", "first", None, "not_enumerated"],
    ],
    [
        ["object", "first", "rev-a", "version_not_registered"],
        ["another-object", "first", "rev-a", "not_enumerated"],
    ],
])
def test_inventory_checkpoint_rejects_invalid_difference_records(source_db, differences):
    from enterprise_kb.modules.sources import reconciliation

    connection, tenant, _, source_ref, _ = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    request = sync_request(connection, tenant, operation=reconciliation.COMMIT)
    with pytest.raises(errors.CheckViolation):
        connection.execute("""
            INSERT INTO thalion.source_inventory_receipt (
                org_id, space_id, source_id, contract_revision, sequence, snapshot_ref,
                request_id, input_digest, inventory_digest, entry_count, matched_count, differences
            )
            SELECT org_id, space_id, source_id, revision, 1, %s, %s, %s, %s, 1, 0, %s::jsonb
            FROM thalion.source_contract_revision
        """, (uuid4(), request.request_id, bytes(32), bytes(32), json.dumps(differences)))
    assert checkpoint(reconciliation, connection, tenant, source) is None
