from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from uuid import UUID, uuid4

import pytest
from psycopg import OperationalError, errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.sources import effectivity, reconciliation, registry, source_revocations, sync
from enterprise_kb.runtime.audit import RequestAuditConflict
from enterprise_kb.runtime.commands import IdempotencyConflict

from test_deletion_tombstone import REGISTER, approved, register, submitted
from test_effectivity import record
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_identity import migrate_to_revision
from test_runtime import open_database, register_tenant, runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_source_sync import sync_request
from test_sources import request_for, source_for
from test_travel_search import corpus, publish


def positions(connection, tenant, source):
    content = sync_request(connection, tenant, operation=sync.READ)
    inventory = sync_request(connection, tenant, operation=reconciliation.READ)
    return (
        sync.read_content_position(connection, content, source),
        reconciliation.read_inventory_position(connection, inventory, source),
    )


def rotate_collector(connection, tenant, source):
    with connection.transaction():
        connection.execute("""
            INSERT INTO thalion.source_contract_revision (
                org_id, space_id, source_id, revision, admission, collector_id, object_namespace, approver_id
            )
            SELECT contract.org_id, contract.space_id, contract.source_id, 2, contract.admission, %s,
                   contract.object_namespace, contract.approver_id
            FROM thalion.source_contract_revision AS contract
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                 (contract.org_id, contract.space_id, 'source', contract.source_id)
            WHERE identity.public_id = %s AND contract.revision = 1
        """, (tenant.other_worker_id, source.source_ref))
        connection.execute("""
            UPDATE thalion.source SET contract_revision = 2
            FROM thalion.object_identity AS identity
            WHERE (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                  (source.org_id, source.space_id, 'source', source.source_id) AND identity.public_id = %s
        """, (source.source_ref,))
    return replace(source, contract_revision=2)


def test_upgrade_preserves_content_and_inventory_resume_positions(database_url, tmp_path):
    from enterprise_kb.modules.sources.originals import SyntheticOriginalStore

    migrate_to_revision(database_url, "0099_source_reconciliation")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Legacy sync")
        source = sync.SyncSource(tenant.space_id, source_for(connection, tenant), 1)
        store = SyntheticOriginalStore(tmp_path)
        page = sync.SourcePage(None, uuid4(), ())
        sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
        declared = reconciliation.InventoryManifest(uuid4(), None, page.through, 0, reconciliation.inventory_digest(()))
        request = sync_request(connection, tenant, operation=reconciliation.COMMIT)
        reconciliation.reconcile_inventory(connection, request, source, declared, ())

        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert positions(connection, tenant, source) == (page.through, declared.snapshot_ref)
        next_page = sync.SourcePage(page.through, uuid4(), ())
        assert sync.commit_content_page(connection, sync_request(connection, tenant), source, next_page, store).sequence == 2
        successor = replace(declared, snapshot_ref=uuid4(), previous=declared.snapshot_ref, content_position=next_page.through)
        request = sync_request(connection, tenant, operation=reconciliation.COMMIT)
        assert reconciliation.reconcile_inventory(connection, request, source, successor, ()).sequence == 2


def test_removal_binds_explicit_event_to_the_exact_existing_withdrawal(corpus):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    db, version, *_ = corpus
    connection, tenant, url, source_ref, store = db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    event = restrictions.Removal(uuid4(), "allowance", "first", "rev-a", "withdrawn", uuid4())
    context = sync_request(connection, tenant, operation=restrictions.COMMIT)
    initial = positions(connection, tenant, source)
    with pytest.raises(restrictions.RestrictionConflict):
        restrictions.acknowledge_removal(connection, context, source, event)

    decision = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "withdraw-allowance"),
        tenant.space_id, version.version_ref, "withdrawn", event.event_ref,
    )
    event = replace(event, decision_ref=decision)
    for invalid in (
        replace(event, event_ref=uuid4()), replace(event, kind="deleted"),
        replace(event, object_key="approval"), replace(event, incarnation="another"),
    ):
        with pytest.raises(restrictions.RestrictionConflict):
            restrictions.acknowledge_removal(connection, context, source, invalid)
    outsider = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=restrictions.COMMIT)
    with pytest.raises(registry.SourceNotAdmitted):
        restrictions.acknowledge_removal(connection, outsider, source, event)
    with pytest.raises(RequestAuditConflict):
        restrictions.acknowledge_removal(connection, sync_request(connection, tenant), source, event)

    result = restrictions.acknowledge_removal(connection, context, source, event)
    assert (result.event_ref, result.kind, result.target_ref) == (event.event_ref, "withdrawn", version.version_ref)
    assert restrictions.acknowledge_removal(connection, context, source, event) == result
    with open_database(url) as resumed:
        retry = sync_request(resumed, tenant, operation=restrictions.COMMIT)
        assert restrictions.acknowledge_removal(resumed, retry, source, event) == result
        with pytest.raises(IdempotencyConflict):
            restrictions.acknowledge_removal(resumed, retry, source, replace(event, kind="deleted"))
    assert positions(connection, tenant, source) == initial
    assert connection.execute("SELECT kind FROM thalion.rule_use_stop").fetchall() == [("withdrawn",)]
    assert connection.execute("""
        SELECT event_type, object_ref FROM thalion.outbox_event WHERE event_id = %s
    """, (result.outbox_ref,)).fetchone() == ("sources.restriction.acknowledged", version.version_ref)


@pytest.mark.parametrize("rotate_before_decision", [True, False])
def test_current_collector_can_acknowledge_a_withdrawal_of_a_historical_version(corpus, rotate_before_decision):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    db, version, *_ = corpus
    connection, tenant, _, source_ref, _ = db
    prior = sync.SyncSource(tenant.space_id, source_ref, 1)
    event_ref = uuid4()
    if rotate_before_decision:
        current = rotate_collector(connection, tenant, prior)
    decision = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "withdraw-historical"),
        tenant.space_id, version.version_ref, "withdrawn", event_ref,
    )
    if not rotate_before_decision:
        current = rotate_collector(connection, tenant, prior)
    event = restrictions.Removal(event_ref, "allowance", "first", "rev-a", "withdrawn", decision)
    old = sync_request(connection, tenant, operation=restrictions.COMMIT)
    request = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=restrictions.COMMIT)
    with pytest.raises(registry.SourceNotAdmitted):
        restrictions.acknowledge_removal(connection, old, current, event)
    with pytest.raises(registry.SourceNotAdmitted):
        restrictions.acknowledge_removal(connection, request, prior, event)
    result = restrictions.acknowledge_removal(connection, request, current, event)
    assert (result.target_ref, result.decision_ref) == (version.version_ref, decision)
    assert connection.execute("""
        SELECT contract_revision FROM thalion.source_restriction_receipt
    """).fetchone() == (2,)


def test_same_source_event_replays_without_a_second_outbox_after_collector_rotation(corpus):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    db, version, *_ = corpus
    connection, tenant, _, source_ref, _ = db
    prior = sync.SyncSource(tenant.space_id, source_ref, 1)
    event_ref = uuid4()
    decision = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "withdraw-before-rotation"),
        tenant.space_id, version.version_ref, "withdrawn", event_ref,
    )
    event = restrictions.Removal(event_ref, "allowance", "first", "rev-a", "withdrawn", decision)
    request = sync_request(connection, tenant, operation=restrictions.COMMIT)
    result = restrictions.acknowledge_removal(connection, request, prior, event)

    current = rotate_collector(connection, tenant, prior)
    with pytest.raises(registry.SourceNotAdmitted):
        restrictions.acknowledge_removal(connection, request, prior, event)
    successor = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=restrictions.COMMIT)
    assert restrictions.acknowledge_removal(connection, successor, current, event) == result
    assert connection.execute("""
        SELECT event_id FROM thalion.outbox_event WHERE event_type = 'sources.restriction.acknowledged'
    """).fetchall() == [(result.outbox_ref,)]
    assert connection.execute("SELECT contract_revision FROM thalion.source_restriction_receipt").fetchall() == [(1,)]


def test_deleted_source_acknowledgment_requires_tombstone_and_preserves_original(transport):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    client, db, (owner, reviewer), credentials, *_ = transport
    connection, tenant, _, source_ref, store = db
    version, _, _ = publish(db, "removed", "Synthetic removed", b"# Removed\n\nSynthetic text.\n")
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    event_ref = uuid4()
    case = submitted(client, owner, credentials, source_ref, version)
    approval = approved(client, reviewer, credentials, case, basis=event_ref)
    request = sync_request(connection, tenant, operation=restrictions.COMMIT)
    event = restrictions.Removal(event_ref, "removed", "first", "rev-a", "deleted", UUID(approval))
    with pytest.raises(restrictions.RestrictionConflict):
        restrictions.acknowledge_removal(connection, request, source, event)
    initial_bytes = {path.name: path.read_bytes() for path in store.root.iterdir()}
    admit(credentials, reviewer, REGISTER)
    tombstone = register(client, reviewer, case, approval)
    assert tombstone.status_code == 200, tombstone.text
    result = restrictions.acknowledge_removal(
        connection, request, source, replace(event, decision_ref=UUID(tombstone.json()["tombstone_id"])),
    )
    assert (result.kind, result.event_ref, result.target_ref) == ("deleted", event_ref, version.version_ref)
    assert {path.name: path.read_bytes() for path in store.root.iterdir()} == initial_bytes
    assert connection.execute("SELECT kind FROM thalion.rule_use_stop").fetchall() == [("deletion_blocked",)]


def test_permission_acknowledgment_checks_the_independent_exact_event_without_advancing_other_positions(
    transport, revocation_authority,
):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    client, db, (employee, colleague), credentials, _, first, _ = transport
    connection, tenant, url, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    initial = positions(connection, tenant, source)
    request = sync_request(connection, tenant, operation=restrictions.COMMIT)
    citation = f"/v1/passages/{first.passage_ref}"
    assert client.get(citation, headers=bearer(employee)).status_code == 200
    with pytest.raises(restrictions.RestrictionConflict):
        restrictions.acknowledge_revocation(connection, request, source, uuid4(), trusted)
    decision = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    assert client.get(citation, headers=bearer(employee)).status_code == 404
    other_request = request_for(connection, tenant, tenant.actor_id, "other-source", "register_source_contract")
    other_ref = registry.register_synthetic_source(
        connection, other_request, tenant.space_id, registry.SyntheticSource("other", "other", tenant.worker_id),
    )
    with pytest.raises(restrictions.RestrictionConflict):
        restrictions.acknowledge_revocation(connection, request, replace(source, source_ref=other_ref), decision.decision_ref, trusted)
    result = restrictions.acknowledge_revocation(connection, request, source, decision.decision_ref, trusted)
    assert (result.event_ref, result.kind, result.target_ref) == (
        decision.decision_ref, "permission_revoked", first.passage_ref,
    )
    assert (result.authority_ref, result.authority_generation) == (trusted.authority_ref, decision.generation)
    with open_database(url) as resumed:
        retry = sync_request(resumed, tenant, operation=restrictions.COMMIT)

        def shifted():
            connection = trusted.connect()
            connection.execute("SET TIME ZONE 'Asia/Shanghai'")
            return connection

        assert restrictions.acknowledge_revocation(
            resumed, retry, source, decision.decision_ref, replace(trusted, connect=shifted),
        ) == result
    assert positions(connection, tenant, source) == initial
    assert client.get(citation, headers=bearer(colleague)).status_code == 200
    assert connection.execute("SELECT count(*) FROM thalion.rule_use_stop").fetchone() == (0,)

    def unavailable():
        raise OperationalError("The isolated authority is unavailable.")

    with pytest.raises(AuthorizationUnavailable):
        restrictions.acknowledge_revocation(
            connection, request, source, decision.decision_ref, replace(trusted, connect=unavailable),
        )


def test_current_collector_can_acknowledge_a_revocation_of_a_historical_passage(transport, revocation_authority):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    _, db, (employee, _), credentials, _, first, _ = transport
    connection, tenant, _, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    source = rotate_collector(connection, tenant, sync.SyncSource(tenant.space_id, source_ref, 1))
    decision = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, credentials[employee].employee_ref,
        first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    request = sync_request(connection, tenant, principal_id=tenant.other_worker_id, operation=restrictions.COMMIT)
    result = restrictions.acknowledge_revocation(connection, request, source, decision.decision_ref, trusted)
    assert (result.target_ref, result.decision_ref) == (first.passage_ref, decision.decision_ref)
    assert connection.execute("""
        SELECT contract_revision FROM thalion.source_restriction_receipt
    """).fetchone() == (2,)


def test_waiting_for_local_source_does_not_delay_new_authoritative_revocations(
    transport, revocation_authority, monkeypatch,
):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    _, db, (employee, _), credentials, _, first, second = transport
    connection, tenant, url, source_ref, _ = db
    authority, trusted, _ = revocation_authority
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    employee_ref = credentials[employee].employee_ref
    decision = source_revocations.revoke(
        authority, trusted.authority_ref, tenant.space_ref, employee_ref,
        first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    reached_local_lock = Event()
    lock_source = registry._lock_source_content

    def signal_then_lock(transaction, ref):
        reached_local_lock.set()
        lock_source(transaction, ref)

    def acknowledge():
        with open_database(url) as worker:
            request = sync_request(worker, tenant, operation=restrictions.COMMIT)
            return restrictions.acknowledge_revocation(worker, request, source, decision.decision_ref, trusted)

    monkeypatch.setattr(registry, "_lock_source_content", signal_then_lock)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with connection.transaction():
            lock_source(connection, source_ref)
            pending = executor.submit(acknowledge)
            assert reached_local_lock.wait(timeout=3)
            authority.execute("SET lock_timeout = '250ms'")
            later = source_revocations.revoke(
                authority, trusted.authority_ref, tenant.space_ref, employee_ref,
                second.passage_ref, "evidence", basis_ref=uuid4(),
            )
            assert later.generation > decision.generation and not pending.done()
        assert pending.result(timeout=5).authority_generation == decision.generation


def test_acknowledged_restriction_outbox_retains_its_original_type_and_target(corpus):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    db, version, _, other_passage, *_ = corpus
    connection, tenant, _, source_ref, _ = db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    event_ref = uuid4()
    decision = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "withdraw-stable-outbox"),
        tenant.space_id, version.version_ref, "withdrawn", event_ref,
    )
    request = sync_request(connection, tenant, operation=restrictions.COMMIT)
    result = restrictions.acknowledge_removal(
        connection, request, source, restrictions.Removal(event_ref, "allowance", "first", "rev-a", "withdrawn", decision),
    )
    for event_type, target_ref in (
        ("sources.rule.stopped", result.target_ref), (restrictions.EVENT, other_passage.passage_ref),
    ):
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            connection.execute("""
                UPDATE thalion.outbox_event SET event_type = %s, object_ref = %s
                WHERE org_id = %s AND event_id = %s
            """, (event_type, target_ref, tenant.org_id, result.outbox_ref))


def test_database_rejects_removal_receipt_with_unrelated_basis(corpus):
    from enterprise_kb.modules.sources import source_restrictions as restrictions
    from enterprise_kb.runtime.events import append_event

    db, version, *_ = corpus
    connection, tenant, _, _, _ = db
    decision = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "withdraw-for-unrelated-basis"),
        tenant.space_id, version.version_ref, "withdrawn", uuid4(),
    )
    request = sync_request(connection, tenant, operation=restrictions.COMMIT)
    with pytest.raises(errors.CheckViolation), connection.transaction():
        outbox = append_event(connection, tenant.org_id, restrictions.EVENT, version.version_ref, space_id=tenant.space_id)
        connection.execute("""
            INSERT INTO thalion.source_restriction_receipt (
                org_id, space_id, source_id, contract_revision, event_ref, kind, target_ref,
                decision_ref, local_stop_ref, request_id, input_digest, outbox_ref
            )
            SELECT org_id, space_id, source_id, contract_revision, %s, 'withdrawn', %s,
                   decision_ref, decision_ref, %s, %s, %s
            FROM thalion.rule_use_stop WHERE decision_ref = %s
        """, (uuid4(), version.version_ref, request.request_id, bytes(32), outbox.event_id, decision))
    assert connection.execute("SELECT count(*) FROM thalion.source_restriction_receipt").fetchone() == (0,)


def test_restriction_receipt_and_outbox_roll_back_together(corpus):
    from enterprise_kb.modules.sources import source_restrictions as restrictions

    db, version, *_ = corpus
    connection, tenant, _, source_ref, _ = db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    event_ref = uuid4()
    decision = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "withdraw-rollback"),
        tenant.space_id, version.version_ref, "withdrawn", event_ref,
    )
    event = restrictions.Removal(event_ref, "allowance", "first", "rev-a", "withdrawn", decision)
    request = sync_request(connection, tenant, operation=restrictions.COMMIT)
    connection.execute("""
        CREATE FUNCTION thalion.reject_synthetic_ack() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'synthetic acknowledgment failure'; END;
        $$;
        CREATE CONSTRAINT TRIGGER reject_synthetic_ack AFTER INSERT ON thalion.source_restriction_receipt
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.reject_synthetic_ack();
    """)
    with pytest.raises(errors.RaiseException, match="synthetic acknowledgment failure"):
        restrictions.acknowledge_removal(connection, request, source, event)
    assert connection.execute("""
        SELECT (SELECT count(*) FROM thalion.source_restriction_receipt),
               (SELECT count(*) FROM thalion.outbox_event WHERE event_type = 'sources.restriction.acknowledged'),
               (SELECT count(*) FROM thalion.command_receipt WHERE request_id = %s)
    """, (request.request_id,)).fetchone() == (0, 0, 0)
    assert connection.execute("SELECT count(*) FROM thalion.rule_use_stop").fetchone() == (1,)
    connection.execute("DROP TRIGGER reject_synthetic_ack ON thalion.source_restriction_receipt")
    assert restrictions.acknowledge_removal(connection, request, source, event).event_ref == event_ref
