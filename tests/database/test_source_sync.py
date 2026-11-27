from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import date
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.sources import registry
from enterprise_kb.runtime.audit import RequestAuditConflict, RequestStart, start_request
from enterprise_kb.runtime.commands import IdempotencyConflict

from test_runtime import open_database, register_tenant, runtime_db
from test_sources import CONTENT, OTHER_CONTENT, candidate, request_for, source_db, source_for


def sync_request(connection, tenant, *, key=None, principal_id=None, space_id=None, operation="commit_source_change"):
    principal_id = principal_id or tenant.worker_id
    request_id = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request_id, principal_id, None, "synthetic-sync-test", operation, "internal_sources",
        date(2026, 11, 23), 1, space_id=space_id or tenant.space_id, ingress="internal",
    ))
    return registry.SourceWrite(tenant.org_id, principal_id, request_id, key or str(request_id))


def counts(connection):
    return connection.execute("""
        SELECT (SELECT count(*) FROM thalion.document_version),
               (SELECT count(*) FROM thalion.job),
               (SELECT count(*) FROM thalion.outbox_event WHERE event_type = 'sources.version.registered')
    """).fetchone()


def test_content_page_persists_resume_position_and_exact_receipts(source_db):
    from enterprise_kb.modules.sources import sync

    connection, tenant, url, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    first = sync.SourcePage(None, uuid4(), (sync.PageOriginal(candidate(tenant, source_ref), CONTENT),))
    second = sync.SourcePage(first.through, uuid4(), (
        sync.PageOriginal(candidate(tenant, source_ref, source_version_key="rev-b", version_label="B",
                                    digest=sha256(OTHER_CONTENT).digest()), OTHER_CONTENT),
    ))
    read = sync_request(connection, tenant, operation="read_source_sync_position")
    assert sync.read_content_position(connection, read, source) is None
    receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, first, store)
    assert receipt.through == first.through and receipt.sequence == 1 and len(receipt.version_refs) == 1
    assert counts(connection) == (1, 1, 1)

    with open_database(url) as resumed:
        read_again = sync_request(resumed, tenant, operation="read_source_sync_position")
        assert sync.read_content_position(resumed, read_again, source) == first.through
        assert sync.commit_content_page(resumed, sync_request(resumed, tenant), source, first, store) == receipt
        newer = sync.commit_content_page(resumed, sync_request(resumed, tenant), source, second, store)
        assert newer.sequence == 2 and newer.through == second.through
        assert newer.version_refs != receipt.version_refs
        assert sync.commit_content_page(resumed, sync_request(resumed, tenant), source, first, store) == receipt
        assert sync.read_content_position(resumed, read_again, source) == second.through
    assert counts(connection) == (2, 2, 2)
    assert connection.execute("SELECT count(*) FROM thalion.rule_effectivity").fetchone() == (0,)


def test_page_write_failure_does_not_advance_cursor_or_leave_partial_versions(source_db, monkeypatch):
    from enterprise_kb.modules.sources import sync

    connection, tenant, _, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    first = sync.SourcePage(None, uuid4(), ())
    command = sync_request(connection, tenant)
    sync.commit_content_page(connection, command, source, first, store)
    version = candidate(tenant, source_ref)
    second = sync.SourcePage(first.through, uuid4(), (
        sync.PageOriginal(version, CONTENT),
        sync.PageOriginal(replace(version, object_key="policy-24"), CONTENT),
    ))
    write = registry._write_version

    def fail_second(transaction, context, scope, document_id, version, asset, **kwargs):
        if version.object_key == "policy-24":
            assert counts(transaction) == (1, 1, 1)
            raise RuntimeError("synthetic page failure")
        return write(transaction, context, scope, document_id, version, asset, **kwargs)

    page_request = sync_request(connection, tenant)
    with monkeypatch.context() as patches:
        patches.setattr(registry, "_write_version", fail_second)
        with pytest.raises(RuntimeError, match="synthetic page failure"):
            sync.commit_content_page(connection, page_request, source, second, store)
    assert counts(connection) == (0, 0, 0)
    assert connection.execute("SELECT count(*) FROM thalion.source_sync_page").fetchone() == (1,)
    read = sync_request(connection, tenant, operation="read_source_sync_position")
    assert sync.read_content_position(connection, read, source) == first.through
    result = sync.commit_content_page(connection, page_request, source, second, store)
    assert len(result.version_refs) == 2 and counts(connection) == (2, 2, 2)


def test_page_commit_failure_does_not_acknowledge_the_new_position(source_db):
    from enterprise_kb.modules.sources import sync

    connection, tenant, _, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    page = sync.SourcePage(None, uuid4(), (sync.PageOriginal(candidate(tenant, source_ref), CONTENT),))
    request = sync_request(connection, tenant)
    connection.execute("""
        CREATE FUNCTION thalion.inject_source_page_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'synthetic deferred page failure';
        END;
        $$;
        CREATE CONSTRAINT TRIGGER reject_source_page_commit
        AFTER INSERT ON thalion.source_sync_page_item
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
        EXECUTE FUNCTION thalion.inject_source_page_commit_failure();
    """)
    with pytest.raises(errors.RaiseException, match="synthetic deferred page failure"):
        sync.commit_content_page(connection, request, source, page, store)
    assert counts(connection) == (0, 0, 0)
    assert connection.execute("""
        SELECT (SELECT count(*) FROM thalion.source_sync_page),
               (SELECT count(*) FROM thalion.command_receipt WHERE request_id = %s)
    """, (request.request_id,)).fetchone() == (0, 0)
    read = sync_request(connection, tenant, operation=sync.READ)
    assert sync.read_content_position(connection, read, source) is None
    connection.execute("DROP TRIGGER reject_source_page_commit ON thalion.source_sync_page_item")
    assert sync.commit_content_page(connection, request, source, page, store).sequence == 1


def test_concurrent_exact_page_is_replayed_if_it_commits_during_preflight(source_db, monkeypatch):
    from enterprise_kb.modules.sources import sync

    connection, tenant, url, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    page = sync.SourcePage(None, uuid4(), (sync.PageOriginal(candidate(tenant, source_ref), CONTENT),))
    head = sync._head
    concurrent_receipt = None

    def interleave(transaction, scope):
        nonlocal concurrent_receipt
        if transaction is connection and concurrent_receipt is None:
            with open_database(url) as winner:
                request = sync_request(winner, tenant)
                concurrent_receipt = sync.commit_content_page(winner, request, source, page, store)
        return head(transaction, scope)

    monkeypatch.setattr(sync, "_head", interleave)
    receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
    assert concurrent_receipt is not None and receipt == concurrent_receipt
    assert counts(connection) == (1, 1, 1)


def test_page_locks_documents_in_export_order_but_keeps_input_receipt_order(source_db, monkeypatch):
    from enterprise_kb.modules.sources import sync

    connection, tenant, url, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    first = candidate(tenant, source_ref)
    second = replace(first, object_key="policy-24")
    initial = sync.SourcePage(None, uuid4(), (sync.PageOriginal(first, CONTENT), sync.PageOriginal(second, CONTENT)))
    sync.commit_content_page(connection, sync_request(connection, tenant), source, initial, store)
    document_ids = dict(connection.execute(
        "SELECT source_object_key, document_id FROM thalion.document"
    ).fetchall())
    descending_keys = sorted(document_ids, key=document_ids.__getitem__, reverse=True)
    pending = sync.SourcePage(initial.through, uuid4(), tuple(
        sync.PageOriginal(replace(first, object_key=key, source_version_key="rev-b"), CONTENT)
        for key in descending_keys
    ))
    write = registry._write_version

    def check_locks(transaction, *args, **kwargs):
        with open_database(url) as observer:
            for document_id in document_ids.values():
                with pytest.raises(errors.LockNotAvailable), observer.transaction():
                    observer.execute("SELECT document_id FROM thalion.document WHERE document_id = %s FOR SHARE NOWAIT",
                                     (document_id,))
        return write(transaction, *args, **kwargs)

    monkeypatch.setattr(registry, "_write_version", check_locks)
    receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, pending, store)
    keys = tuple(key for key, in connection.execute("""
        SELECT document.source_object_key FROM unnest(%s::uuid[]) WITH ORDINALITY AS entry(ref, position)
        JOIN thalion.object_identity AS identity ON identity.public_id = entry.ref
        JOIN thalion.document_version AS version ON version.version_id = identity.object_id
        JOIN thalion.document AS document USING (document_id)
        ORDER BY entry.position
    """, (list(receipt.version_refs),)))
    assert keys == tuple(descending_keys)


def test_database_rejects_incomplete_and_late_source_page_items(source_db):
    from enterprise_kb.modules.sources import sync

    connection, tenant, _, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    first = sync.SourcePage(None, uuid4(), (sync.PageOriginal(candidate(tenant, source_ref), CONTENT),))
    sync.commit_content_page(connection, sync_request(connection, tenant), source, first, store)
    request = sync_request(connection, tenant)
    with pytest.raises(errors.CheckViolation):
        connection.execute("""
            INSERT INTO thalion.source_sync_page (
                org_id, space_id, source_id, contract_revision, sequence, through_cursor,
                previous_cursor, request_id, input_digest, item_count
            )
            SELECT org_id, space_id, source_id, contract_revision, 2, %s,
                   through_cursor, %s, input_digest, 1
            FROM thalion.source_sync_page
        """, (uuid4(), request.request_id))
    with pytest.raises(errors.CheckViolation):
        connection.execute("""
            INSERT INTO thalion.source_sync_page_item (
                org_id, space_id, source_id, contract_revision, sequence, position, document_id, version_id
            )
            SELECT org_id, space_id, source_id, contract_revision, sequence, 1, document_id, version_id
            FROM thalion.source_sync_page_item
        """)


def test_stale_and_changed_pages_are_rejected_and_a_concurrent_branch_cannot_win_twice(source_db):
    from enterprise_kb.modules.sources import sync

    connection, tenant, url, source_ref, store = source_db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    first = sync.SourcePage(None, uuid4(), ())
    key = "first-page"
    first_receipt = sync.commit_content_page(connection, sync_request(connection, tenant, key=key), source, first, store)
    original = sync.PageOriginal(candidate(tenant, source_ref), CONTENT)
    with pytest.raises(IdempotencyConflict):
        sync.commit_content_page(connection, sync_request(connection, tenant), source, replace(first, items=(original,)), store)
    with pytest.raises(IdempotencyConflict):
        sync.commit_content_page(
            connection, sync_request(connection, tenant, key=key), source, sync.SourcePage(first.through, uuid4(), ()), store,
        )
    with pytest.raises(sync.CursorConflict):
        sync.commit_content_page(
            connection, sync_request(connection, tenant), source, sync.SourcePage(None, uuid4(), ()), store,
        )
    assert not list(store.root.iterdir())

    barrier = Barrier(2, timeout=5)

    def commit_branch():
        with open_database(url) as concurrent:
            request = sync_request(concurrent, tenant)
            page = sync.SourcePage(first.through, uuid4(), (original,))
            barrier.wait()
            try:
                return sync.commit_content_page(concurrent, request, source, page, store)
            except sync.CursorConflict:
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(commit_branch) for _ in range(2)]
        winners = [result for future in futures if (result := future.result(timeout=15)) is not None]
    assert len(winners) == 1 and winners[0].sequence == 2
    assert counts(connection) == (1, 1, 1)
    assert sync.commit_content_page(connection, sync_request(connection, tenant), source, first, store) == first_receipt


def test_scope_and_collector_are_rechecked_before_registration(source_db, monkeypatch):
    from enterprise_kb.modules.sources import sync

    connection, tenant, url, source_ref, store = source_db
    other = register_tenant(connection, "Other sync tenant")
    other_source = source_for(connection, other)
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    item = sync.PageOriginal(candidate(tenant, source_ref), CONTENT)
    page = sync.SourcePage(None, uuid4(), (item,))
    with pytest.raises(registry.SourceNotAdmitted):
        sync.commit_content_page(connection, sync_request(connection, tenant, principal_id=tenant.other_worker_id), source, page, store)
    with pytest.raises(RequestAuditConflict):
        sync.commit_content_page(connection, sync_request(connection, other), source, page, store)
    with pytest.raises(ValueError):
        sync.commit_content_page(
            connection, sync_request(connection, tenant), source,
            replace(page, items=(replace(item, version=candidate(other, other_source)),)), store,
        )
    assert not list(store.root.iterdir())

    stage = store.stage

    def suspend_after_storage(*args):
        saved = stage(*args)
        with open_database(url) as change:
            change.execute("UPDATE thalion.source SET lifecycle = 'suspended' WHERE source_key = 'travel-files' AND org_id = %s",
                           (tenant.org_id,))
        return saved

    monkeypatch.setattr(store, "stage", suspend_after_storage)
    with pytest.raises(registry.SourceNotAdmitted):
        sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
    assert counts(connection) == (0, 0, 0)
    assert connection.execute("SELECT count(*) FROM thalion.source_sync_page").fetchone() == (0,)


def test_source_pages_and_receipts_stay_within_their_space(source_db):
    from enterprise_kb.modules.sources import sync

    connection, tenant, _, source_ref, store = source_db
    with connection.transaction():
        sibling_id, = connection.execute("""
            INSERT INTO thalion.space (org_id, name, classification, owner_principal_id)
            VALUES (%s, 'Sibling', 'internal', %s) RETURNING space_id
        """, (tenant.org_id, tenant.actor_id)).fetchone()
        connection.execute("""
            INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id)
            VALUES (%s, %s, 'space', %s)
        """, (tenant.org_id, sibling_id, sibling_id))
    sibling = replace(tenant, space_id=sibling_id)
    collector = request_for(connection, sibling, sibling.actor_id, "sibling-source", "register_source_contract")
    sibling_ref = registry.register_synthetic_source(
        connection, collector, sibling_id,
        registry.SyntheticSource("travel-files", "travel-archive", sibling.worker_id),
    )
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    sibling_source = sync.SyncSource(sibling_id, sibling_ref, 1)
    cursor = uuid4()
    first = sync.SourcePage(None, cursor, (sync.PageOriginal(candidate(tenant, source_ref), CONTENT),))
    receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, first, store)
    sibling_read = sync_request(connection, sibling, operation=sync.READ)
    assert sync.read_content_position(connection, sibling_read, sibling_source) is None
    with pytest.raises(RequestAuditConflict):
        sync.read_content_position(connection, sibling_read, source)
    assert sync.commit_content_page(
        connection, sync_request(connection, sibling), sibling_source, sync.SourcePage(None, cursor, ()), store,
    ).version_refs == ()
    with pytest.raises(errors.ForeignKeyViolation):
        connection.execute("""
            INSERT INTO thalion.source_sync_page_item (
                org_id, space_id, source_id, contract_revision, sequence, position, document_id, version_id
            )
            SELECT page.org_id, page.space_id, page.source_id, page.contract_revision, page.sequence, 0,
                   version.document_id, version.version_id
            FROM thalion.source_sync_page AS page
            CROSS JOIN thalion.document_version AS version
            WHERE page.space_id = %s
        """, (sibling_id,))
    with pytest.raises(errors.ForeignKeyViolation):
        connection.execute("""
            INSERT INTO thalion.source_sync_page (
                org_id, space_id, source_id, contract_revision, sequence, through_cursor,
                previous_cursor, request_id, input_digest, item_count
            )
            SELECT org_id, space_id, source_id, contract_revision, 2, %s,
                   through_cursor, %s, input_digest, 0
            FROM thalion.source_sync_page WHERE space_id = %s
        """, (uuid4(), sibling_read.request_id, tenant.space_id))
    assert sync.commit_content_page(connection, sync_request(connection, tenant), source, first, store) == receipt
