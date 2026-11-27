import json
from dataclasses import replace
from hashlib import sha256
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access import travel
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.runtime.jobs import complete_job

from test_effectivity import AFTER, BEFORE, BEGIN, SWITCH, approve
from test_evidence import approved, claim, create_evidence_db, evidence_db, review
from test_identity import migrate_to_revision
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_sources import register, request_for


SEARCH_FIELDS = frozenset({"excerpt", "citation", "title", "location", "version"})


def publish(db, object_key, title, content, **kwargs):
    connection, tenant, _, source, store = db
    version = register(
        connection, tenant, source, store, key=str(uuid4()), object_key=object_key,
        display_name=title, digest=sha256(content).digest(), payload=content, **kwargs,
    )
    lease = claim(db)
    assert lease is not None, "The registered version has no claimable parse job."
    assert lease.spec.target_ref == version.version_ref
    run = processing.process_markdown_job(connection, lease, store)
    review(db, run)
    return version, approved(db, version)[0], run


@pytest.fixture
def corpus(evidence_db):
    connection, tenant, *_ = evidence_db
    allowance, first, _ = publish(evidence_db, "allowance", "住宿标准", "# 上海\n\n上海住宿限额。\n".encode())
    approval, second, run = publish(evidence_db, "approval", "受限审批说明", "# 差旅\n\n上海住宿超标需审批。\n".encode())
    decision = approve(connection, tenant, allowance, BEGIN)
    approve(connection, tenant, approval, BEGIN)
    return evidence_db, allowance, first, second, run, decision


def search(db, query, *, employee=None, authority=None, day=BEFORE, top_k=5, context=None, **options):
    connection, tenant, _, _, store = db
    employee = employee or tenant.actor_id
    return travel.search_travel(
        connection, context or ingress(db, employee, day, operation="search"), tenant.space_id,
        query, store, region="shanghai", traveler_class="employee", top_k=top_k,
        check_authority=authority or authority_for({employee}), **options,
    )


def test_search_seals_only_the_complete_delivered_payload_and_exact_dependencies(corpus):
    db, _, first, second, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    delivered = search(db, "上海住宿", context=context)
    assert delivered.status == "succeeded"
    payload = json.loads(delivered.payload)
    assert (payload["status"], payload["business_date"], payload["wiki"]) == ("hits", BEFORE.isoformat(), [])
    passages = payload["passages"]
    assert {part["passage_id"] for part in passages} == {str(first.passage_ref), str(second.passage_ref)}
    lodging = next(part for part in passages if part["passage_id"] == str(first.passage_ref))
    assert lodging["location"] == {"heading_path": ["上海"], "paragraph": 1}
    assert lodging["excerpt"].rstrip() == "上海住宿限额。"
    assert lodging["valid_from"] == BEGIN.isoformat()
    assert connection.execute(
        "SELECT request_id, dependency_count, payload_digest FROM thalion.delivery_record"
    ).fetchall() == [(context.request_id, 2, sha256(delivered.payload).digest())]
    assert connection.execute(
        "SELECT passage_ref, excerpt_revision FROM thalion.delivery_dependency ORDER BY position"
    ).fetchall() == [(first.passage_ref if part == lodging else second.passage_ref, 1) for part in passages]
    assert search(db, "上海住宿", context=context).payload is None


def test_only_fully_authorized_passages_are_ranked_and_top_k_does_not_count_denied(corpus):
    db, _, first, second, *_ = corpus
    _, tenant, *_ = db
    set_rules(
        db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        binding(tenant.actor_id, effect="deny", passage_ref=second.passage_ref),
        binding(tenant.other_actor_id, passage_ref=first.passage_ref),
    )
    payload = json.loads(search(db, "上海住宿 审批", top_k=1).payload)
    assert [part["passage_id"] for part in payload["passages"]] == [str(first.passage_ref)]
    assert "受限审批说明" not in str(payload)
    denied = search(db, "上海住宿", employee=tenant.other_actor_id)
    assert (denied.status, denied.payload) == ("no_evidence", None)


def test_source_denial_can_filter_a_hit_without_masquerading_as_an_outage(corpus):
    db, _, first, second, *_ = corpus
    _, tenant, *_ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    live = authority_for({tenant.actor_id})

    def partially_revoked(probe):
        return replace(live(probe), permitted_fields={
            scope: scope.fields if scope.object_id != second.passage_ref else frozenset()
            for scope in probe.scopes
        })

    payload = json.loads(search(db, "上海住宿 审批", top_k=1, authority=partially_revoked).payload)
    assert [part["passage_id"] for part in payload["passages"]] == [str(first.passage_ref)]

    def offline(probe):
        raise AuthorizationUnavailable("synthetic outage")

    result = search(db, "上海住宿", authority=offline)
    assert (result.status, result.payload) == ("dependency_unavailable", None)


def test_search_selects_business_version_before_evidence_and_never_falls_back(corpus):
    db, _, first, _, _, previous_decision = corpus
    connection, tenant, _, source, store = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    replacement = b"# Travel\n\nNew requirements.\n"
    version = register(
        connection, tenant, source, store, key="allowance-b", object_key="allowance",
        source_version_key="rev-b", version_label="B", digest=sha256(replacement).digest(), payload=replacement,
    )
    approve(connection, tenant, version, SWITCH, replaces=previous_decision)
    past = json.loads(search(db, "限额", day=BEFORE).payload)
    assert [part["passage_id"] for part in past["passages"]] == [str(first.passage_ref)]
    assert past["passages"][0]["valid_until"] == SWITCH.isoformat()
    assert search(db, "限额", day=AFTER).status == "no_evidence"


def test_search_rechecks_all_selected_dependencies_before_delivering(corpus):
    db, _, _, second, run, _ = corpus
    connection, tenant, database_url, source, store = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    live = authority_for({tenant.actor_id})
    proofs = []

    def quarantine_on_final_check(probe):
        proofs.append(probe)
        if len(proofs) == 2:
            assert second.passage_ref in {scope.object_id for scope in probe.scopes}
            with open_database(database_url) as other:
                review((other, tenant, database_url, source, store), run, decision="quarantined")
        return live(probe)

    result = search(db, "上海住宿", authority=quarantine_on_final_check)
    assert len(proofs) == 2
    assert result.status == "input_changed" and result.payload is None
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_search_dependency_record_failure_rolls_back_the_response(corpus):
    db, _, _, _, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    connection.execute("ALTER TABLE thalion.delivery_dependency ADD CHECK (position = 1)")
    result = search(db, "上海住宿")
    assert (result.status, result.payload) == ("dependency_unavailable", None)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_search_audit_rejects_a_response_with_missing_dependencies(corpus):
    db, _, _, _, *_ = corpus
    connection, tenant, *_ = db
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    with pytest.raises(errors.CheckViolation):
        connection.execute(
            """
            INSERT INTO thalion.delivery_record (
                check_id, org_id, request_id, dependency_count, payload_digest, proof_digest, checked_at, valid_until
            ) VALUES (%s, %s, %s, 2, %s, %s, statement_timestamp(), statement_timestamp() + interval '1 second')
            """,
            (uuid4(), tenant.org_id, context.request_id, bytes(32), bytes(32)),
        )


def test_search_cannot_rebind_a_read_or_another_employees_request(corpus):
    db, _, _, _, *_ = corpus
    _, tenant, *_ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    read_context = ingress(db, tenant.actor_id, BEFORE)
    mismatched_context = ingress(db, tenant.other_actor_id, BEFORE, operation="search")
    for context in (replace(read_context, operation="search"), replace(mismatched_context, principal_id=tenant.actor_id)):
        result = search(db, "上海住宿", context=context)
        assert (result.status, result.payload) == ("rejected", None)


def test_revocation_between_ranking_and_final_check_never_releases_partial_json(corpus):
    db, _, _, second, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    live = authority_for({tenant.actor_id})
    proofs = []

    def revoke_after_eligibility(probe):
        proofs.append(probe)
        proof = live(probe)
        if len(proofs) == 1:
            return proof
        return replace(proof, permitted_fields={
            scope: scope.fields if scope.object_id != second.passage_ref else frozenset()
            for scope in probe.scopes
        })

    result = search(db, "上海住宿", authority=revoke_after_eligibility)
    assert len(proofs) == 2 and proofs[0].check_id != proofs[1].check_id
    assert proofs[0].payload_sha256 != proofs[1].payload_sha256
    assert (result.status, result.payload, result.denied_scopes) == ("rejected", None, frozenset())
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_denied_originals_are_not_opened_and_empty_search_is_finalized(corpus, monkeypatch):
    db, _, first, _, *_ = corpus
    connection, tenant, _, _, store = db
    set_rules(db, replace(binding(tenant.actor_id, passage_ref=first.passage_ref), fields=SEARCH_FIELDS))
    read_assets = []
    read_original = store.read

    def read_and_count(asset):
        read_assets.append(asset)
        return read_original(asset)

    monkeypatch.setattr(store, "read", read_and_count)
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    result = search(db, "审批", context=context)
    assert (result.status, result.payload) == ("no_evidence", None)
    assert len(read_assets) == 1
    assert connection.execute(
        "SELECT outcome FROM thalion.request_record WHERE request_id = %s", (context.request_id,),
    ).fetchone() == ("no_evidence",)
    assert search(db, "限额", context=context).status == "rejected"


def record_legacy_excerpt(db, heading, text):
    connection, tenant, _, source, store = db
    payload = heading + text
    version = register(connection, tenant, source, store, payload=payload, digest=sha256(payload).digest())
    version_id, = connection.execute(
        "SELECT object_id FROM thalion.object_identity WHERE public_id = %s", (version.version_ref,),
    ).fetchone()
    scope = (tenant.org_id, tenant.space_id, version_id)
    lease = claim(db)
    assert lease is not None and lease.spec.target_ref == version.version_ref
    passage_ref = uuid4()

    def accept(transaction):
        run_ref, = transaction.execute(
            """
            INSERT INTO thalion.processing_run (
                org_id, space_id, version_id, contract_revision, job_id, generation, configuration_revision,
                input_digest, manifest_digest, outcome, passage_count
            ) VALUES (%s, %s, %s, 1, %s, %s, 1, %s, %s, 'pending_review', 1)
            RETURNING run_ref
            """,
            (*scope, lease.job_id, lease.generation, version.digest, sha256(text).digest()),
        ).fetchone()
        passage_id, = transaction.execute(
            """
            INSERT INTO thalion.passage (
                org_id, space_id, version_id, locator_revision, heading_path, paragraph, kind, byte_start, byte_end
            ) VALUES (%s, %s, %s, 1, ARRAY['Travel'], 1, 'paragraph', %s, %s) RETURNING passage_id
            """,
            (*scope, len(heading), len(payload)),
        ).fetchone()
        transaction.execute(
            "INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id, public_id) "
            "VALUES (%s, %s, 'passage', %s, %s)",
            (tenant.org_id, tenant.space_id, passage_id, passage_ref),
        )
        transaction.execute(
            "INSERT INTO thalion.passage_excerpt "
            "(org_id, space_id, version_id, passage_id, excerpt_revision, run_ref, content_digest) "
            "VALUES (%s, %s, %s, %s, 1, %s, %s)",
            (*scope, passage_id, run_ref, sha256(text).digest()),
        )
        return run_ref

    run_ref = complete_job(connection, lease, accept)
    review_request = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "decide_evidence_quality")
    connection.execute(
        "INSERT INTO thalion.quality_decision "
        "(org_id, space_id, version_id, run_ref, reviewer_id, request_id, basis_ref, outcome) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, 'approved')",
        (*scope, run_ref, tenant.actor_id, review_request.request_id, uuid4()),
    )
    return passage_ref


def test_migration_preserves_existing_single_passage_audit(database_url, tmp_path):
    migrate_to_revision(database_url, "0009_local_authorization")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "legacy-audit")
        db = create_evidence_db(connection, tenant, database_url, tmp_path)
        text = b"Approval needed.\n"
        passage_ref = record_legacy_excerpt(db, b"# Travel\n\n", text)
        set_rules(db, binding(tenant.actor_id))
        context = ingress(db, tenant.actor_id, BEFORE)
        check_id = uuid4()
        payload_digest = sha256(text).digest()
        connection.execute(
            """
            INSERT INTO thalion.delivery_record (
                check_id, org_id, request_id, space_id, source_id, passage_ref, excerpt_revision,
                policy_revision, organization_epoch, space_epoch, source_epoch,
                payload_digest, proof_digest, checked_at, valid_until
            ) SELECT %s, org_id, %s, space_id, source_id, %s, 1, local_policy_revision, 1, 1, safety_epoch,
                     %s, %s, statement_timestamp(), statement_timestamp() + interval '1 second'
              FROM thalion.source
            """,
            (check_id, context.request_id, passage_ref, payload_digest, bytes(32)),
        )
        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert connection.execute(
            """
            SELECT check_id, request_id, dependency_count, payload_digest, position,
                   passage_ref, excerpt_revision, policy_revision, source_epoch
            FROM thalion.delivery_record JOIN thalion.delivery_dependency USING (check_id, org_id)
            """,
        ).fetchall() == [(check_id, context.request_id, 1, payload_digest, 1, passage_ref, 1, 2, 2)]


def open_reference(db, passage_ref, *, day=AFTER, employee=None, authority=None):
    connection, tenant, _, _, store = db
    employee = employee or tenant.actor_id
    return travel.open_travel_reference(
        connection, ingress(db, employee, day), tenant.space_id, passage_ref, store,
        region="shanghai", traveler_class="employee", check_authority=authority or authority_for({employee}),
    )


def test_retained_reference_stays_on_its_version_after_ordinary_replacement(corpus):
    db, original, first, _, _, previous_decision = corpus
    connection, tenant, _, _, _ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    successor, successor_passage, _ = publish(
        db, "allowance", "住宿标准新版", b"# Travel\n\nDifferent allowance.\n", source_version_key="rev-b",
    )
    approve(connection, tenant, successor, SWITCH, replaces=previous_decision)
    previous = json.loads(open_reference(db, first.passage_ref).payload)["passage"]
    updated = json.loads(open_reference(db, successor_passage.passage_ref).payload)["passage"]
    assert (previous["version_id"], previous["valid_until"]) == (str(original.version_ref), SWITCH.isoformat())
    assert updated["version_id"] == str(successor.version_ref)
    assert open_reference(db, successor_passage.passage_ref, day=BEFORE).status == "rejected"
    assert open_reference(db, first.passage_ref, authority=authority_for(set())).status == "rejected"
    assert open_reference(db, first.passage_ref, employee=tenant.other_actor_id).status == "rejected"


def test_retained_reference_does_not_revive_a_stopped_version(corpus):
    db, original, first, *_ = corpus
    connection, tenant, _, _, _ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    assert open_reference(db, first.passage_ref).status == "succeeded"
    context = request_for(connection, tenant, tenant.other_actor_id, str(uuid4()), "stop_rule_use")
    effectivity.stop_synthetic_rule(
        connection, context, tenant.space_id, original.version_ref, "withdrawn", uuid4(),
    )
    for day in (BEFORE, AFTER):
        result = open_reference(db, first.passage_ref, day=day)
        assert (result.status, result.payload) == ("rejected", None)


def test_retained_reference_does_not_guess_between_historical_intervals(corpus):
    db, original, first, *_ = corpus
    connection, tenant, *_ = db
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    approve(connection, tenant, original, BEGIN, region="shanghai", end=SWITCH)
    ambiguous = open_reference(db, first.passage_ref)
    assert (ambiguous.status, ambiguous.payload) == ("rejected", None)
