from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import date
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pytest

from enterprise_kb.modules.sources import effectivity, originals, registry
from enterprise_kb.runtime.audit import RequestAuditConflict

from test_runtime import open_database, runtime_db
from test_sources import CONTENT, OTHER_CONTENT, register, request_for


BEFORE = date(2026, 10, 31)
SWITCH = date(2026, 11, 1)
AFTER = date(2026, 11, 22)
BEGIN = date(2026, 7, 1)


@pytest.fixture
def policy_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    context = request_for(
        connection, tenant, tenant.actor_id, "create-policy-source", "register_source_contract",
    )
    source = registry.register_synthetic_source(
        connection, context, tenant.space_id,
        registry.SyntheticSource(
            "travel-files", "travel-archive", tenant.worker_id, approver_id=tenant.other_actor_id,
        ),
    )
    store = originals.SyntheticOriginalStore(tmp_path)
    previous = register(connection, tenant, source, store, key="version-a")
    replacement = register(
        connection, tenant, source, store, key="version-b", source_version_key="rev-b",
        digest=sha256(OTHER_CONTENT).digest(), payload=OTHER_CONTENT, version_label="B",
    )
    return connection, tenant, database_url, previous, replacement


def record(connection, tenant, operation, key, *, principal_id=None, audit_operation=None):
    return request_for(
        connection, tenant, principal_id or tenant.other_actor_id, key, audit_operation or operation,
    )


def approve(
    connection, tenant, version, start, *, replaces=None, end=None, region=None,
    traveler_class=None, basis=None, principal_id=None, audit_operation=None,
):
    context = record(
        connection, tenant, "approve_effectivity", str(uuid4()),
        principal_id=principal_id, audit_operation=audit_operation,
    )
    return effectivity.approve_synthetic_rule(
        connection, context, tenant.space_id, version.version_ref,
        effectivity.Approval(start, end, region, traveler_class, basis or uuid4(), replaces),
    )


def select(connection, tenant, document_ref, business_date, region="shanghai", traveler_class="employee"):
    return effectivity.select_rule(
        connection, tenant.org_id, tenant.space_id, document_ref,
        business_date, region=region, traveler_class=traveler_class,
    )


def test_business_date_selects_approved_replacement_without_waiting_for_parse(policy_db):
    connection, tenant, _, previous, replacement = policy_db
    assert select(connection, tenant, previous.document_ref, BEFORE).status == "not_applicable"
    first = approve(connection, tenant, previous, BEGIN)
    second = approve(connection, tenant, replacement, SWITCH, end=AFTER, replaces=first)
    old = select(connection, tenant, previous.document_ref, BEFORE)
    current = select(connection, tenant, previous.document_ref, SWITCH)
    assert (old.status, old.version_ref, old.decision_ref, old.valid_to) == (
        "applicable", previous.version_ref, first, SWITCH,
    )
    assert (current.status, current.version_ref, current.decision_ref) == (
        "applicable", replacement.version_ref, second,
    )
    assert select(connection, tenant, previous.document_ref, AFTER).status == "not_applicable"
    assert connection.execute("SELECT DISTINCT state FROM thalion.job").fetchall() == [("queued",)]


def test_stopping_current_version_never_falls_back_or_revives_historical_reads(policy_db):
    connection, tenant, _, previous, replacement = policy_db
    first = approve(connection, tenant, previous, BEGIN)
    approve(connection, tenant, replacement, SWITCH, replaces=first)
    context = record(connection, tenant, "stop_rule_use", "suspend-b")
    effectivity.stop_synthetic_rule(
        connection, context, tenant.space_id, replacement.version_ref, "suspended", uuid4(),
    )
    stopped = select(connection, tenant, replacement.document_ref, AFTER)
    assert (stopped.status, stopped.version_ref, stopped.decision_ref) == ("suspended", None, None)
    assert select(connection, tenant, previous.document_ref, BEFORE).version_ref == previous.version_ref
    context = record(connection, tenant, "stop_rule_use", "withdraw-a")
    effectivity.stop_synthetic_rule(
        connection, context, tenant.space_id, previous.version_ref, "withdrawn", uuid4(),
    )
    historical = select(connection, tenant, previous.document_ref, BEFORE)
    assert (historical.status, historical.version_ref) == ("withdrawn", None)
    assert select(connection, tenant, previous.document_ref, AFTER).status == "suspended"
    with pytest.raises(effectivity.EffectivityConflict):
        approve(connection, tenant, replacement, AFTER, region="beijing")
    context = record(connection, tenant, "stop_rule_use", "withdraw-b")
    effectivity.stop_synthetic_rule(
        connection, context, tenant.space_id, replacement.version_ref, "withdrawn", uuid4(),
    )
    connection.execute("UPDATE thalion.source SET lifecycle = 'suspended'")
    assert select(connection, tenant, previous.document_ref, AFTER).status == "withdrawn"


def test_overlapping_conditions_are_not_resolved_by_registration_order(policy_db):
    connection, tenant, _, previous, replacement = policy_db
    first = approve(connection, tenant, previous, BEGIN, region="shanghai")
    with pytest.raises(effectivity.EffectivityConflict):
        approve(connection, tenant, replacement, SWITCH, region="shanghai")
    with pytest.raises(effectivity.EffectivityConflict):
        approve(connection, tenant, replacement, SWITCH, region="beijing", replaces=first)
    approve(connection, tenant, replacement, SWITCH, traveler_class="employee")
    ambiguous = select(connection, tenant, previous.document_ref, AFTER)
    assert (ambiguous.status, ambiguous.version_ref) == ("ambiguous", None)
    assert select(
        connection, tenant, previous.document_ref, AFTER, region="beijing",
    ).version_ref == replacement.version_ref


def test_only_designated_approver_with_matching_audit_operation_may_approve(policy_db):
    connection, tenant, _, previous, _ = policy_db
    for wrong_actor in (tenant.worker_id, tenant.actor_id):
        with pytest.raises(registry.SourceNotAdmitted):
            approve(connection, tenant, previous, BEGIN, principal_id=wrong_actor)
    with pytest.raises(RequestAuditConflict):
        approve(connection, tenant, previous, BEGIN, audit_operation="read_policy")
    assert connection.execute("SELECT count(*) FROM thalion.rule_effectivity").fetchone() == (0,)


def test_concurrent_approvals_with_same_condition_cannot_both_win(policy_db):
    connection, tenant, database_url, previous, replacement = policy_db
    barrier = Barrier(2, timeout=5)

    def run(version):
        with open_database(database_url) as worker:
            barrier.wait()
            try:
                approve(worker, tenant, version, BEGIN)
            except effectivity.EffectivityConflict:
                return False
            return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(run, (previous, replacement))) == [False, True]
    assert connection.execute("SELECT count(*) FROM thalion.rule_effectivity").fetchone() == (1,)
