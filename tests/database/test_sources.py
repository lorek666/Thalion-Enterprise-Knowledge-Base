from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.sources import originals, registry
from enterprise_kb.runtime.audit import RequestAuditConflict
from enterprise_kb.runtime.commands import IdempotencyConflict
from enterprise_kb.runtime.events import pending_events
from enterprise_kb.runtime.jobs import claim_job

from test_runtime import (
    LEASE_FOR,
    command_for,
    open_command_request,
    open_database,
    register_tenant,
    runtime_db,
)


CONTENT = b"# Synthetic travel rules\nBook rail tickets in advance.\n"
OTHER_CONTENT = b"# Synthetic travel rules\nObtain written approval first.\n"


def request_for(connection, tenant, principal_id, key, operation):
    command = open_command_request(
        connection, replace(
            command_for(tenant), principal_id=principal_id, idempotency_key=key,
            operation=operation,
        ),
    )
    return registry.SourceWrite(
        command.org_id, command.principal_id, command.request_id, command.idempotency_key,
    )


def source_for(connection, tenant):
    context = request_for(connection, tenant, tenant.actor_id, "create-source", "register_source_contract")
    return registry.register_synthetic_source(
        connection, context, tenant.space_id,
        registry.SyntheticSource("travel-files", "travel-archive", tenant.worker_id),
    )


@pytest.fixture
def source_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    return (
        connection, tenant, database_url, source_for(connection, tenant),
        originals.SyntheticOriginalStore(tmp_path),
    )


def candidate(tenant, source_ref, **changes):
    return replace(
        registry.SourceVersion(
            tenant.space_id, source_ref, 1, "policy-23", "first", "rev-a",
            "Synthetic travel rules", "A", sha256(CONTENT).digest(),
        ),
        **changes,
    )


def register(connection, tenant, source_ref, store, *, key="register-version", payload=CONTENT, **changes):
    context = request_for(connection, tenant, tenant.worker_id, key, "register_version")
    return registry.register_synthetic_version(
        connection, context, candidate(tenant, source_ref, **changes), payload, store,
    )


def test_only_current_space_owner_can_enroll_the_synthetic_collector(runtime_db):
    connection, tenant, _ = runtime_db
    spec = registry.SyntheticSource("travel-files", "travel-archive", tenant.worker_id)
    employee = request_for(connection, tenant, tenant.other_actor_id, "wrong-owner", "register_source_contract")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_synthetic_source(connection, employee, tenant.space_id, spec)
    owner = request_for(connection, tenant, tenant.actor_id, "wrong-collector", "register_source_contract")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_synthetic_source(
            connection, owner, tenant.space_id, replace(spec, collector_id=tenant.other_actor_id)
        )
    source_ref = source_for(connection, tenant)
    assert source_for(connection, tenant) == source_ref
    assert connection.execute(
        "SELECT admission, object_namespace FROM thalion.source_contract_revision"
    ).fetchall() == [("synthetic_only", "travel-archive")]


def test_registration_commits_scoped_references_and_starts_one_parse_job(source_db):
    connection, tenant, _, source_ref, store = source_db
    result = register(connection, tenant, source_ref, store)
    replay = register(connection, tenant, source_ref, store)
    repeated_source_delivery = register(
        connection, tenant, source_ref, store, key="another-request", display_name="Renamed file",
    )
    assert result.created and not replay.created and not repeated_source_delivery.created
    assert result.version_ref == replay.version_ref == repeated_source_delivery.version_ref
    assert result.document_ref == repeated_source_delivery.document_ref
    assert result.sequence == 1
    assert [path.read_bytes() for path in store.root.iterdir()] == [CONTENT]
    assert connection.execute(
        "SELECT byte_length, content_digest FROM thalion.asset"
    ).fetchall() == [(len(CONTENT), sha256(CONTENT).digest())]
    assert connection.execute("SELECT display_name FROM thalion.document").fetchall() == [
        ("Synthetic travel rules",),
    ]
    events = pending_events(connection, tenant.org_id, "test-observer")
    assert [(event.event_type, event.object_ref, event.space_id) for event in events] == [
        ("sources.version.registered", result.version_ref, tenant.space_id),
    ]
    lease = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert (lease.spec.target_ref, lease.spec.input_digest) == (result.version_ref, result.digest)
    assert claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR) is None


def test_manual_commit_connection_stages_outside_transaction_and_commits_registration(source_db, monkeypatch):
    connection, tenant, database_url, source_ref, store = source_db
    context = request_for(connection, tenant, tenant.worker_id, "manual-commit-version", "register_version")
    version = candidate(tenant, source_ref)
    stage = store.stage

    with open_database(database_url) as manual:
        manual.autocommit = False

        def check_storage_boundary(*args):
            assert manual.info.transaction_status.name == "IDLE"
            return stage(*args)

        monkeypatch.setattr(store, "stage", check_storage_boundary)
        registered = registry.register_synthetic_version(manual, context, version, CONTENT, store)
        assert registered.created
        assert manual.info.transaction_status.name == "IDLE"
        assert connection.execute(
            "SELECT count(*) FROM thalion.object_identity WHERE public_id = %s",
            (registered.version_ref,),
        ).fetchone() == (1,)


def test_object_incarnation_and_source_version_are_distinct_from_display_labels(source_db):
    connection, tenant, _, source_ref, store = source_db
    first = register(connection, tenant, source_ref, store)
    same_label = register(
        connection, tenant, source_ref, store, key="new-version", source_version_key="rev-b",
        digest=sha256(OTHER_CONTENT).digest(), payload=OTHER_CONTENT,
    )
    reused_number = register(
        connection, tenant, source_ref, store, key="new-object", incarnation="second",
    )
    assert first.document_ref == same_label.document_ref != reused_number.document_ref
    assert len({first.version_ref, same_label.version_ref, reused_number.version_ref}) == 3
    assert (first.sequence, same_label.sequence, reused_number.sequence) == (1, 2, 1)
    assert sorted(path.read_bytes() for path in store.root.iterdir()) == sorted(
        [CONTENT, CONTENT, OTHER_CONTENT]
    )


def test_digest_mismatch_and_rebinding_cannot_overwrite_an_original(source_db):
    connection, tenant, _, source_ref, store = source_db
    first = register(connection, tenant, source_ref, store)
    with pytest.raises(originals.OriginalIntegrityError):
        register(connection, tenant, source_ref, store, payload=OTHER_CONTENT)
    with pytest.raises(registry.VersionConflict):
        register(
            connection, tenant, source_ref, store, key="different-command",
            digest=sha256(OTHER_CONTENT).digest(), payload=OTHER_CONTENT,
        )
    assert [path.read_bytes() for path in store.root.iterdir()] == [CONTENT]
    with pytest.raises(IdempotencyConflict):
        register(connection, tenant, source_ref, store, source_version_key="rev-b")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.document_version SET version_label = 'changed'")
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)
    assert register(connection, tenant, source_ref, store).version_ref == first.version_ref


def test_actor_scope_and_open_request_are_checked_before_storage(source_db):
    connection, tenant, _, source_ref, store = source_db
    version = candidate(tenant, source_ref)
    outsider = request_for(connection, tenant, tenant.other_worker_id, "bad-collector", "register_version")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_synthetic_version(connection, outsider, version, CONTENT, store)
    collector = request_for(connection, tenant, tenant.worker_id, "good-collector", "register_version")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_synthetic_version(
            connection, collector, replace(version, contract_revision=2), CONTENT, store,
        )
    with pytest.raises(RequestAuditConflict):
        registry.register_synthetic_version(
            connection, replace(collector, request_id=uuid4()), version, CONTENT, store,
        )
    second = register_tenant(connection, "Second synthetic tenant")
    foreign = request_for(connection, second, second.worker_id, "foreign", "register_version")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_synthetic_version(
            connection, foreign, replace(version, space_id=second.space_id), CONTENT, store,
        )
    assert list(store.root.iterdir()) == []


def test_public_identity_and_asset_cannot_be_moved_to_a_different_scope(source_db):
    connection, tenant, _, source_ref, store = source_db
    registered = register(connection, tenant, source_ref, store)
    second = register_tenant(connection, "Separate synthetic tenant")
    second_source_ref = source_for(connection, second)
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute(
            """
            UPDATE thalion.asset
            SET org_id = %s, space_id = %s,
                source_id = (SELECT object_id FROM thalion.object_identity WHERE public_id = %s)
            """,
            (second.org_id, second.space_id, second_source_ref),
        )
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute(
            "UPDATE thalion.object_identity SET space_id = %s WHERE public_id = %s",
            (second.space_id, registered.version_ref),
        )
    assert connection.execute(
        "SELECT org_id, space_id FROM thalion.asset"
    ).fetchone() == (tenant.org_id, tenant.space_id)


def test_revocation_between_storage_and_commit_does_not_register_version(source_db, monkeypatch):
    connection, tenant, database_url, source_ref, store = source_db
    original_stage = originals.SyntheticOriginalStore.stage

    def stage_then_disable(adapter, *args):
        assert connection.info.transaction_status.name == "IDLE"
        asset = original_stage(adapter, *args)
        with open_database(database_url) as independent:
            independent.execute("UPDATE thalion.source SET lifecycle = 'suspended'")
        return asset

    monkeypatch.setattr(originals.SyntheticOriginalStore, "stage", stage_then_disable)
    with pytest.raises(registry.SourceNotAdmitted):
        register(connection, tenant, source_ref, store)
    assert [path.read_bytes() for path in store.root.iterdir()] == [CONTENT]
    assert connection.execute("SELECT count(*) FROM thalion.asset").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (0,)
    assert pending_events(connection, tenant.org_id, "test-observer") == ()
    assert claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR) is None


def test_insert_failure_rolls_back_version_event_and_job_but_not_prewrite(source_db, monkeypatch):
    connection, tenant, _, source_ref, store = source_db
    enqueue = registry.enqueue_job

    def interrupt(transaction, *args, **kwargs):
        enqueue(transaction, *args, **kwargs)
        raise RuntimeError("synthetic interruption after arranging parse")

    with monkeypatch.context() as patch:
        patch.setattr(registry, "enqueue_job", interrupt)
        with pytest.raises(RuntimeError, match="interruption after arranging parse"):
            register(connection, tenant, source_ref, store)
    for table in ("asset", "document", "document_version", "outbox_event", "job", "request_job"):
        assert connection.execute(f"SELECT count(*) FROM thalion.{table}").fetchone() == (0,)
    assert [path.read_bytes() for path in store.root.iterdir()] == [CONTENT]
    result = register(connection, tenant, source_ref, store)
    assert result.created and result.sequence == 1
    assert len(list(store.root.iterdir())) == 1


def test_committed_original_missing_does_not_get_recreated_by_replay(source_db):
    connection, tenant, _, source_ref, store = source_db
    register(connection, tenant, source_ref, store)
    stored, = store.root.iterdir()
    stored.unlink()
    with pytest.raises(originals.OriginalIntegrityError):
        register(connection, tenant, source_ref, store, key="replay-missing")
    assert not stored.exists()


def test_concurrent_distinct_requests_register_one_version(source_db):
    connection, tenant, database_url, source_ref, store = source_db
    barrier = Barrier(2, timeout=5)

    def register_concurrently(key):
        with open_database(database_url) as independent:
            barrier.wait()
            return register(independent, tenant, source_ref, store, key=key)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(register_concurrently, ("concurrent-1", "concurrent-2")))
    assert sorted(result.created for result in results) == [False, True]
    assert results[0].version_ref == results[1].version_ref
    assert [path.read_bytes() for path in store.root.iterdir()] == [CONTENT]
    assert connection.execute("SELECT count(*) FROM thalion.job").fetchone() == (1,)
