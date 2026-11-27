from dataclasses import replace
from hashlib import sha256
import json
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.wiki import inputs

from test_effectivity import BEGIN, approve
from test_evidence import approved, evidence_db
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import BEFORE, corpus, publish, search


def compile_rule(employee):
    return replace(
        binding(employee), operation="assemble_wiki_inputs", purpose="wiki_compilation", destination="local_workspace",
    )


def assemble(db, direct=(), inherited=(), authority=None, employee=None):
    connection, tenant, _, _, store = db
    employee = employee or tenant.actor_id
    context = ingress(
        db, employee, BEFORE, operation="assemble_wiki_inputs", purpose="wiki_compilation", destination="local_workspace",
    )
    return inputs.prepare_wiki_inputs(
        connection, context, tenant.space_id, tuple((part.passage_ref, part.revision) for part in direct), inherited,
        store, region="shanghai", traveler_class="employee", check_authority=authority or authority_for({employee}),
    )


def test_seal_binds_actual_bytes_and_every_exact_excerpt(corpus):
    db, _, first, second, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, compile_rule(tenant.actor_id))
    result = assemble(db, (second, first))
    assert result.status == "succeeded"
    assert [part.strip() for part in json.loads(result.payload)] == ["上海住宿超标需审批。", "上海住宿限额。"]
    assert connection.execute(
        """
        SELECT digest.payload_digest, manifest.direct_count, manifest.parent_refs
        FROM thalion.input_manifest AS manifest JOIN thalion.delivery_record AS digest USING (check_id, org_id)
        WHERE manifest.manifest_ref = %s
        """,
        (result.manifest_ref,),
    ).fetchone() == (sha256(result.payload).digest(), 2, [])
    assert connection.execute(
        """
        SELECT passage_ref, excerpt_revision FROM thalion.input_manifest_entry
        WHERE manifest_ref = %s ORDER BY position
        """,
        (result.manifest_ref,),
    ).fetchall() == [(second.passage_ref, second.revision), (first.passage_ref, first.revision)]
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.input_manifest SET parent_refs = '{}' WHERE manifest_ref = %s", (result.manifest_ref,))


def test_employee_permission_is_not_wiki_compilation_permission(corpus):
    db, _, first, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, binding(tenant.actor_id), compile_rule(tenant.other_actor_id))
    rejected = assemble(db, (first,))
    assert (rejected.status, rejected.payload, rejected.manifest_ref) == ("rejected", None, None)
    assert assemble(db, (first,), employee=tenant.other_actor_id).status == "succeeded"
    assert search(db, "上海住宿", employee=tenant.other_actor_id).status == "no_evidence"
    assert connection.execute("SELECT count(*) FROM thalion.input_manifest").fetchone() == (1,)


def test_inheritance_expands_all_unquoted_inputs_and_rechecks_live_authority(corpus):
    db, _, first, second, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, compile_rule(tenant.actor_id))
    parent = assemble(db, (first, second))
    child = assemble(db, (first,), (parent.manifest_ref,))
    assert child.status == "succeeded" and child.payload == parent.payload
    assert connection.execute(
        "SELECT count(DISTINCT direct_digest), count(DISTINCT expanded_digest) FROM thalion.input_manifest",
    ).fetchone() == (2, 1)
    live = authority_for({tenant.actor_id})

    def revoke_unquoted(probe):
        allowed = live(probe)
        return replace(allowed, permitted_fields={
            scope: fields if scope.object_id != second.passage_ref else frozenset()
            for scope, fields in allowed.permitted_fields.items()
        })

    rejected = assemble(db, (first,), (child.manifest_ref,), authority=revoke_unquoted)
    assert (rejected.status, rejected.payload, rejected.manifest_ref) == ("rejected", None, None)
    assert connection.execute("SELECT count(*) FROM thalion.input_manifest").fetchone() == (2,)


def test_missing_or_different_authors_manifest_is_not_inherited(corpus):
    db, _, first, _, *_ = corpus
    _, tenant, *_ = db
    set_rules(db, compile_rule(tenant.actor_id), compile_rule(tenant.other_actor_id))
    parent = assemble(db, (first,))
    assert assemble(db, (first,), (uuid4(),)).status == "rejected"
    assert assemble(db, (), (parent.manifest_ref,), employee=tenant.other_actor_id).status == "rejected"


def test_final_authority_denial_or_outage_leaves_no_seal(corpus):
    db, _, first, _, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, compile_rule(tenant.actor_id))
    seen = []

    def fail_at_final(probe):
        seen.append(probe.payload_sha256)
        if len(seen) == 2:
            raise AuthorizationUnavailable()
        return authority_for({tenant.actor_id})(probe)

    result = assemble(db, (first,), authority=fail_at_final)
    assert (result.status, result.manifest_ref, result.payload) == ("dependency_unavailable", None, None)
    assert len(seen) == 2 and seen[0] != seen[1]
    assert connection.execute("SELECT count(*) FROM thalion.input_manifest").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_failed_seal_rolls_back_the_delivery_receipt(corpus):
    db, _, first, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, compile_rule(tenant.actor_id))
    connection.execute("ALTER TABLE thalion.input_manifest ADD CHECK (false)")
    failed = assemble(db, (first,))
    assert (failed.status, failed.manifest_ref, failed.payload) == ("dependency_unavailable", None, None)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_local_policy_change_after_eligibility_prevents_seal(corpus):
    db, _, first, *_ = corpus
    connection, tenant, database_url, source, store = db
    set_rules(db, compile_rule(tenant.actor_id))
    live = authority_for({tenant.actor_id})
    checks = 0

    def tighten_after_read(probe):
        nonlocal checks
        checks += 1
        if checks == 2:
            with open_database(database_url) as second_connection:
                set_rules((second_connection, tenant, database_url, source, store), expected=2)
        return live(probe)

    result = assemble(db, (first,), authority=tighten_after_read)
    assert (result.status, result.payload, result.manifest_ref) == ("input_changed", None, None)
    assert checks == 2
    assert connection.execute("SELECT count(*) FROM thalion.input_manifest").fetchone() == (0,)


def test_two_exact_locations_in_same_document_remain_distinct(evidence_db):
    connection, tenant, *_ = evidence_db
    version, _, _ = publish(evidence_db, "two-paragraphs", "Synthetic travel", b"# Travel\n\nApproval.\n\nException.\n")
    approve(connection, tenant, version, BEGIN)
    set_rules(evidence_db, compile_rule(tenant.actor_id))
    first, second = approved(evidence_db, version)
    result = assemble(evidence_db, (first, second))
    assert result.status == "succeeded"
    assert [part.strip() for part in json.loads(result.payload)] == ["Approval.", "Exception."]
    assert connection.execute(
        "SELECT count(DISTINCT passage_ref) FROM thalion.input_manifest_entry WHERE manifest_ref = %s",
        (result.manifest_ref,),
    ).fetchone() == (2,)
