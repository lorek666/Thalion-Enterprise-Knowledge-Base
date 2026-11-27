from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event
from uuid import uuid4

import pytest
from psycopg import OperationalError, errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.sources import (
    effectivity, reconciliation, registry, source_restrictions, source_revocations, sync,
)
from enterprise_kb.runtime.audit import RequestAuditConflict
from enterprise_kb.runtime.commands import IdempotencyConflict
from enterprise_kb.runtime.events import append_event

from test_effectivity import record
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_identity import migrate_to_revision
from test_runtime import open_database, register_tenant, runtime_db
from test_source_restrictions import positions, rotate_collector
from test_source_revocations import independent_authority, revocation_authority
from test_source_sync import sync_request
from test_sources import request_for, source_for
from test_travel_search import corpus, publish


def test_upgrade_preserves_content_inventory_and_restriction_receipts(database_url, tmp_path):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints
    from enterprise_kb.modules.sources.originals import SyntheticOriginalStore

    migrate_to_revision(database_url, "0100_source_restriction_receipts")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Legacy checkpoint")
        source = sync.SyncSource(tenant.space_id, source_for(connection, tenant), 1)
        store = SyntheticOriginalStore(tmp_path)
        page = sync.SourcePage(None, uuid4(), ())
        sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
        declared = reconciliation.InventoryManifest(uuid4(), None, page.through, 0, reconciliation.inventory_digest(()))
        reconciliation.reconcile_inventory(
            connection, sync_request(connection, tenant, operation=reconciliation.COMMIT), source, declared, (),
        )

        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert positions(connection, tenant, source) == (page.through, declared.snapshot_ref)
        read = sync_request(connection, tenant, operation=checkpoints.READ)
        assert checkpoints.read_permission_checkpoint(connection, read, source) is None


def test_permission_checkpoint_tracks_authority_generation_requires_source_receipts_and_never_relaxes_delivery(
    transport, evidence_transport, revocation_authority,
):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints
    from enterprise_kb.transport import local

    client, db, (employee, colleague), credentials, _, first, second = transport
    service, *_ = evidence_transport
    connection, tenant, url, source_ref, _ = db
    authority, trusted, profile = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    initial = positions(connection, tenant, source)
    read_req = sync_request(connection, tenant, operation=checkpoints.READ)
    assert checkpoints.read_permission_checkpoint(connection, read_req, source) is None

    c1 = uuid4()
    first_cp = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c1, None, trusted,
    )
    assert (
        first_cp.checkpoint_ref, first_cp.sequence, first_cp.authority_ref,
        first_cp.authority_generation, first_cp.acknowledged_count, first_cp.last_acknowledged_generation,
    ) == (c1, 1, trusted.authority_ref, 0, 0, None)
    assert checkpoints.read_permission_checkpoint(connection, read_req, source) == first_cp
    assert connection.execute("""
        SELECT event_type, object_ref FROM thalion.outbox_event WHERE event_id = %s
    """, (first_cp.outbox_ref,)).fetchone() == (checkpoints.EVENT, source_ref)

    c2 = uuid4()
    reconfirmed = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c2, c1, trusted,
    )
    assert (reconfirmed.sequence, reconfirmed.authority_generation, reconfirmed.acknowledged_count) == (2, 0, 0)

    rev1 = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    c3 = uuid4()
    with pytest.raises(checkpoints.PermissionCheckpointConflict):
        checkpoints.record_permission_checkpoint(
            connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c3, c2, trusted,
        )
    assert checkpoints.read_permission_checkpoint(connection, read_req, source) == reconfirmed

    source_restrictions.acknowledge_revocation(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, rev1.decision_ref, trusted,
    )
    third_cp = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c3, c2, trusted,
    )
    assert (
        third_cp.sequence, third_cp.authority_generation,
        third_cp.acknowledged_count, third_cp.last_acknowledged_generation,
    ) == (3, rev1.generation, 1, rev1.generation)

    unrelated = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        uuid4(), "evidence", basis_ref=uuid4(),
    )
    c4 = uuid4()
    fourth_cp = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c4, c3, trusted,
    )
    assert (
        fourth_cp.sequence, fourth_cp.authority_generation,
        fourth_cp.acknowledged_count, fourth_cp.last_acknowledged_generation,
    ) == (4, unrelated.generation, 1, rev1.generation)

    second_citation = f"/v1/passages/{second.passage_ref}"
    first_citation = f"/v1/passages/{first.passage_ref}"
    assert client.get(second_citation, headers=bearer(employee)).status_code == 200
    assert client.get(first_citation, headers=bearer(colleague)).status_code == 200
    source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        second.passage_ref, "evidence", basis_ref=uuid4(),
    )
    assert client.get(second_citation, headers=bearer(employee)).status_code == 404
    assert client.get(first_citation, headers=bearer(colleague)).status_code == 200

    def unavailable():
        raise OperationalError("Authority outage after checkpoint.")

    service.check_source = local.LocalProfile(
        profile.root, revocations=replace(trusted, connect=unavailable),
    ).check_source
    assert client.get(first_citation, headers=bearer(colleague)).status_code == 503
    service.check_source = profile.check_source
    assert client.get(first_citation, headers=bearer(colleague)).status_code == 200

    with open_database(url) as resumed:
        retry = sync_request(resumed, tenant, operation=checkpoints.COMMIT)
        assert checkpoints.record_permission_checkpoint(resumed, retry, source, c3, c2, trusted) == third_cp
        with pytest.raises(IdempotencyConflict):
            checkpoints.record_permission_checkpoint(resumed, retry, source, c3, c1, trusted)

    assert positions(connection, tenant, source) == initial
    assert connection.execute("""
        SELECT count(*) FROM thalion.outbox_event WHERE event_type = %s
    """, (checkpoints.EVENT,)).fetchone() == (4,)


def test_permission_checkpoint_fails_closed_on_authority_outage_and_invalid_callers(
    transport, revocation_authority,
):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints

    _, db, *_ = transport
    connection, tenant, _, source_ref, _ = db
    _, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    c1 = uuid4()

    outsider = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=checkpoints.COMMIT)
    with pytest.raises(registry.SourceNotAdmitted):
        checkpoints.record_permission_checkpoint(connection, outsider, source, c1, None, trusted)
    with pytest.raises(RequestAuditConflict):
        checkpoints.record_permission_checkpoint(connection, sync_request(connection, tenant), source, c1, None, trusted)
    with pytest.raises(ValueError):
        checkpoints.record_permission_checkpoint(
            connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c1, c1, trusted,
        )
    with pytest.raises(checkpoints.PermissionCheckpointConflict):
        checkpoints.record_permission_checkpoint(
            connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c1, uuid4(), trusted,
        )

    def unavailable():
        raise OperationalError("The isolated authority is unavailable.")

    with pytest.raises(AuthorizationUnavailable):
        checkpoints.record_permission_checkpoint(
            connection, sync_request(connection, tenant, operation=checkpoints.COMMIT),
            source, c1, None, replace(trusted, connect=unavailable),
        )
    assert connection.execute("SELECT count(*) FROM thalion.source_permission_checkpoint").fetchone() == (0,)
    assert connection.execute("""
        SELECT count(*) FROM thalion.outbox_event WHERE event_type = %s
    """, (checkpoints.EVENT,)).fetchone() == (0,)


def test_permission_checkpoint_continues_across_collector_rotation_without_resetting(
    transport, revocation_authority,
):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints

    _, db, (employee, _), credentials, _, first, second = transport
    connection, tenant, _, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    prior = sync.SyncSource(tenant.space_id, source_ref, 1)
    rev1 = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    source_restrictions.acknowledge_revocation(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        prior, rev1.decision_ref, trusted,
    )
    c1 = uuid4()
    first_cp = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), prior, c1, None, trusted,
    )

    current = rotate_collector(connection, tenant, prior)
    with pytest.raises(registry.SourceNotAdmitted):
        checkpoints.read_permission_checkpoint(
            connection, sync_request(connection, tenant, operation=checkpoints.READ), prior,
        )
    successor_read = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=checkpoints.READ)
    assert checkpoints.read_permission_checkpoint(connection, successor_read, current) == first_cp

    successor_commit = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=checkpoints.COMMIT)
    assert checkpoints.record_permission_checkpoint(connection, successor_commit, current, c1, None, trusted) == first_cp
    with pytest.raises(checkpoints.PermissionCheckpointConflict):
        checkpoints.record_permission_checkpoint(
            connection, sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=checkpoints.COMMIT),
            current, uuid4(), None, trusted,
        )

    rev2 = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        second.passage_ref, "evidence", basis_ref=uuid4(),
    )
    source_restrictions.acknowledge_revocation(
        connection, sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=source_restrictions.COMMIT),
        current, rev2.decision_ref, trusted,
    )
    c2 = uuid4()
    second_cp = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=checkpoints.COMMIT),
        current, c2, c1, trusted,
    )
    assert (
        second_cp.sequence, second_cp.authority_generation,
        second_cp.acknowledged_count, second_cp.last_acknowledged_generation,
    ) == (2, rev2.generation, 2, rev2.generation)
    assert connection.execute("""
        SELECT contract_revision FROM thalion.source_permission_checkpoint ORDER BY sequence
    """).fetchall() == [(1,), (2,)]
    assert connection.execute("""
        SELECT count(*) FROM thalion.outbox_event WHERE event_type = %s
    """, (checkpoints.EVENT,)).fetchone() == (2,)


def test_waiting_for_local_source_lock_does_not_block_new_authoritative_revocations(
    transport, revocation_authority, monkeypatch,
):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints

    _, db, (employee, _), credentials, _, first, _ = transport
    connection, tenant, url, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    reached_local_lock = Event()
    lock_source = registry._lock_source_content

    def signal_then_lock(transaction, ref):
        reached_local_lock.set()
        lock_source(transaction, ref)

    def advance():
        with open_database(url) as worker:
            req = sync_request(worker, tenant, operation=checkpoints.COMMIT)
            return checkpoints.record_permission_checkpoint(worker, req, source, uuid4(), None, trusted)

    monkeypatch.setattr(registry, "_lock_source_content", signal_then_lock)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with connection.transaction():
            lock_source(connection, source_ref)
            pending = executor.submit(advance)
            assert reached_local_lock.wait(timeout=3)
            authority.execute("SET lock_timeout = '250ms'")
            later = source_revocations.revoke(
                authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
                first.passage_ref, "evidence", basis_ref=uuid4(),
            )
            assert later.generation == 1 and not pending.done()
        receipt = pending.result(timeout=5)
        assert receipt.authority_generation == 0 and receipt.acknowledged_count == 0


def test_stale_snapshot_cannot_record_checkpoint_behind_newer_acknowledged_revocation(
    transport, revocation_authority, monkeypatch,
):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints

    _, db, (employee, _), credentials, _, first, _ = transport
    connection, tenant, url, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    lock_source = registry._lock_source_content
    injected = False

    def acknowledge_newer_before_lock(transaction, ref):
        nonlocal injected
        if not injected:
            injected = True
            decision = source_revocations.revoke(
                authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
                first.passage_ref, "evidence", basis_ref=uuid4(),
            )
            with open_database(url) as other:
                source_restrictions.acknowledge_revocation(
                    other, sync_request(other, tenant, operation=source_restrictions.COMMIT),
                    source, decision.decision_ref, trusted,
                )
        lock_source(transaction, ref)

    monkeypatch.setattr(registry, "_lock_source_content", acknowledge_newer_before_lock)
    with pytest.raises(checkpoints.PermissionCheckpointConflict):
        checkpoints.record_permission_checkpoint(
            connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, uuid4(), None, trusted,
        )
    assert connection.execute("SELECT count(*) FROM thalion.source_permission_checkpoint").fetchone() == (0,)


def test_concurrent_checkpoint_branches_allow_only_one_winner(transport, revocation_authority):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints

    _, db, *_ = transport
    connection, tenant, url, source_ref, _ = db
    _, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    barrier = Barrier(2)

    def worker(ref):
        with open_database(url) as conn:
            req = sync_request(conn, tenant, operation=checkpoints.COMMIT)
            barrier.wait(timeout=5)
            return checkpoints.record_permission_checkpoint(conn, req, source, ref, None, trusted)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, uuid4()), pool.submit(worker, uuid4())]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(("ok", future.result(timeout=5)))
            except checkpoints.PermissionCheckpointConflict:
                outcomes.append(("conflict", None))
    assert sorted(kind for kind, _ in outcomes) == ["conflict", "ok"]
    assert connection.execute("SELECT count(*) FROM thalion.source_permission_checkpoint").fetchone() == (1,)


def test_database_enforces_checkpoint_monotonicity_immutability_and_atomic_rollback(
    transport, revocation_authority,
):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints

    _, db, (employee, _), credentials, _, first, _ = transport
    connection, tenant, _, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    rev1 = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    source_restrictions.acknowledge_revocation(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, rev1.decision_ref, trusted,
    )
    c1 = uuid4()
    cp1 = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT), source, c1, None, trusted,
    )

    source_id, = connection.execute("""
        SELECT object_id FROM thalion.object_identity
        WHERE (org_id, space_id, object_type, public_id) = (%s, %s, 'source', %s)
    """, (tenant.org_id, tenant.space_id, source_ref)).fetchone()

    for bad_seq, bad_prev, bad_auth, bad_stream, bad_gen, bad_count, bad_last, bad_event, bad_target in (
        (2, c1, uuid4(), cp1.authority_stream_ref, 1, 1, 1, checkpoints.EVENT, source_ref),
        (2, c1, cp1.authority_ref, uuid4(), 1, 1, 1, checkpoints.EVENT, source_ref),
        (2, c1, cp1.authority_ref, cp1.authority_stream_ref, 0, 0, None, checkpoints.EVENT, source_ref),
        (2, c1, cp1.authority_ref, cp1.authority_stream_ref, 2, 0, None, checkpoints.EVENT, source_ref),
        (2, c1, cp1.authority_ref, cp1.authority_stream_ref, 2, 1, 2, checkpoints.EVENT, source_ref),
        (2, c1, cp1.authority_ref, cp1.authority_stream_ref, 1, 1, 1, "sources.rule.stopped", source_ref),
        (2, c1, cp1.authority_ref, cp1.authority_stream_ref, 1, 1, 1, checkpoints.EVENT, first.passage_ref),
    ):
        req = sync_request(connection, tenant, operation=checkpoints.COMMIT)
        with pytest.raises(errors.CheckViolation), connection.transaction():
            outbox = append_event(connection, tenant.org_id, bad_event, bad_target, space_id=tenant.space_id)
            connection.execute("""
                INSERT INTO thalion.source_permission_checkpoint (
                    org_id, space_id, source_id, contract_revision, sequence, checkpoint_ref,
                    previous_checkpoint_ref, authority_ref, authority_stream_ref, authority_generation,
                    acknowledged_count, last_acknowledged_generation, request_id, input_digest, outbox_ref
                ) VALUES (%s, %s, %s, 1, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                tenant.org_id, tenant.space_id, source_id, bad_seq, uuid4(), bad_prev,
                bad_auth, bad_stream, bad_gen, bad_count, bad_last, req.request_id, bytes(32), outbox.event_id,
            ))

    for statement in (
        "UPDATE thalion.source_permission_checkpoint SET authority_generation = 99",
        "DELETE FROM thalion.source_permission_checkpoint",
        "TRUNCATE thalion.source_permission_checkpoint",
        f"UPDATE thalion.outbox_event SET event_type = 'sources.rule.stopped' WHERE event_id = '{cp1.outbox_ref}'",
        f"UPDATE thalion.outbox_event SET object_ref = '{first.passage_ref}' WHERE event_id = '{cp1.outbox_ref}'",
    ):
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            connection.execute(statement)

    c2 = uuid4()
    req = sync_request(connection, tenant, operation=checkpoints.COMMIT)
    connection.execute("""
        CREATE FUNCTION thalion.reject_synthetic_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'synthetic checkpoint failure'; END;
        $$;
        CREATE CONSTRAINT TRIGGER reject_synthetic_checkpoint AFTER INSERT ON thalion.source_permission_checkpoint
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.reject_synthetic_checkpoint();
    """)
    with pytest.raises(errors.RaiseException, match="synthetic checkpoint failure"):
        checkpoints.record_permission_checkpoint(connection, req, source, c2, c1, trusted)
    assert connection.execute("""
        SELECT (SELECT count(*) FROM thalion.source_permission_checkpoint),
               (SELECT count(*) FROM thalion.outbox_event WHERE event_type = %s),
               (SELECT count(*) FROM thalion.command_receipt WHERE request_id = %s)
    """, (checkpoints.EVENT, req.request_id)).fetchone() == (1, 1, 0)
    connection.execute("DROP TRIGGER reject_synthetic_checkpoint ON thalion.source_permission_checkpoint")
    assert checkpoints.record_permission_checkpoint(connection, req, source, c2, c1, trusted).sequence == 2


def test_permission_checkpoints_are_isolated_per_source_and_reject_switching_authority(
    transport, revocation_authority, postgres_server,
):
    from enterprise_kb.modules.sources import permission_checkpoints as checkpoints
    from conftest import temporary_database
    from test_archive_rule_checkpoint import endpoint

    _, db, (employee, _), credentials, _, first, _ = transport
    connection, tenant, _, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    first_source = sync.SyncSource(tenant.space_id, source_ref, 1)
    other_req = request_for(connection, tenant, tenant.actor_id, "second-source", "register_source_contract")
    other_ref = registry.register_synthetic_source(
        connection, other_req, tenant.space_id, registry.SyntheticSource("other", "other", tenant.worker_id),
    )
    second_source = sync.SyncSource(tenant.space_id, other_ref, 1)

    rev1 = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    other_cp = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT),
        second_source, uuid4(), None, trusted,
    )
    assert (other_cp.sequence, other_cp.authority_generation, other_cp.acknowledged_count) == (1, rev1.generation, 0)

    with pytest.raises(checkpoints.PermissionCheckpointConflict):
        checkpoints.record_permission_checkpoint(
            connection, sync_request(connection, tenant, operation=checkpoints.COMMIT),
            first_source, uuid4(), None, trusted,
        )
    source_restrictions.acknowledge_revocation(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        first_source, rev1.decision_ref, trusted,
    )

    with temporary_database(postgres_server) as rogue_url:
        upgrade(rogue_url)
        with open_database(rogue_url) as rogue_db:
            rogue_ref = endpoint(rogue_db)
            source_revocations.enroll_space(rogue_db, rogue_ref, tenant.space_ref)
            rogue = source_revocations.SourceRevocationAuthority(lambda: open_database(rogue_url), rogue_ref)
            with pytest.raises(checkpoints.PermissionCheckpointConflict):
                checkpoints.record_permission_checkpoint(
                    connection, sync_request(connection, tenant, operation=checkpoints.COMMIT),
                    first_source, uuid4(), None, rogue,
                )
            with pytest.raises(checkpoints.PermissionCheckpointConflict):
                checkpoints.record_permission_checkpoint(
                    connection, sync_request(connection, tenant, operation=checkpoints.COMMIT),
                    second_source, uuid4(), other_cp.checkpoint_ref, rogue,
                )

    first_cp = checkpoints.record_permission_checkpoint(
        connection, sync_request(connection, tenant, operation=checkpoints.COMMIT),
        first_source, uuid4(), None, trusted,
    )
    assert (first_cp.sequence, first_cp.authority_generation, first_cp.acknowledged_count) == (1, rev1.generation, 1)
