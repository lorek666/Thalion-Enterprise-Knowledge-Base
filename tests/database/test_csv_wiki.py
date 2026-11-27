from dataclasses import replace
from hashlib import sha256
import json
from uuid import UUID

import pytest

from enterprise_kb.database import upgrade
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict
from enterprise_kb.modules.lifecycle.wiki_archives import select_wiki
from enterprise_kb.modules.wiki import drafts

from test_csv_delivery import permit
from test_csv_units import amount_db, process, units
from test_effectivity import BEFORE, BEGIN, approve
from test_evidence import create_evidence_db, review
from test_identity import migrate_to_revision
from test_persisted_access import authority_for, ingress, set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_travel_search import publish, search
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble, compile_rule
from test_wiki_publication import authorize, read_current


WORKSPACE_FIELDS = frozenset({"excerpt", "location"})


def publish_table(db):
    connection, tenant, *_ = db
    version, run = process(db)
    review(db, run)
    approve(connection, tenant, version, BEGIN)
    return run, tuple(tuple(member.cell for member in unit.members) for unit in units(db, version))


def role_rules(db, cells, *, fields=WORKSPACE_FIELDS):
    _, tenant, *_ = db
    return tuple(rule for cell in cells for rule in (
        replace(compile_rule(tenant.actor_id), passage_ref=cell.passage_ref, fields=fields),
        replace(compile_rule(tenant.other_actor_id), passage_ref=cell.passage_ref, fields=fields,
                operation="review_wiki_revision", purpose="wiki_review"),
        replace(compile_rule(tenant.other_actor_id), passage_ref=cell.passage_ref, fields=fields,
                operation="publish_wiki_revision", purpose="wiki_publication"),
        permit(tenant.actor_id, cell),
    ))


def exact(cells):
    return tuple((cell.passage_ref, cell.revision) for cell in cells)


def withhold(employee, cell, field=None):
    def decide(probe):
        proof = authority_for({employee})(probe)
        return replace(proof, permitted_fields={
            scope: (fields - {field} if field else frozenset()) if scope.object_id == cell.passage_ref else fields
            for scope, fields in proof.permitted_fields.items()
        })
    return decide


def test_wiki_seal_requires_a_complete_csv_group_and_current_location_permission(amount_db):
    connection, tenant, *_ = amount_db
    _, (group, _) = publish_table(amount_db)
    set_rules(amount_db, *role_rules(amount_db, group, fields=frozenset({"excerpt"})))
    assert assemble(amount_db, group).status == "rejected"
    set_rules(amount_db, *role_rules(amount_db, group), expected=2)
    assert assemble(amount_db, group[:-1]).status == "rejected"
    assert assemble(amount_db, group, authority=withhold(tenant.actor_id, group[1], "location")).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.input_manifest").fetchone() == (0,)

    prepared = assemble(amount_db, group)
    assert prepared.status == "succeeded"
    material = json.loads(prepared.payload)
    assert [entry["excerpt"] for entry in material] == ["600", "元/人·晚", "普通员工", "会议统一安排除外"]
    assert material[1]["location"] == {"row_id": 2, "columns": [{"column": 3, "header": "单位"}]}
    assert all(entry["source_type"] == "csv" and "title" not in entry for entry in material)
    assert connection.execute("""
        SELECT passage_ref, excerpt_revision, payload_digest
        FROM thalion.input_manifest_entry JOIN thalion.delivery_record USING (org_id, check_id)
        WHERE manifest_ref = %s ORDER BY position
    """, (prepared.manifest_ref,)).fetchall() == [
        (ref, revision, sha256(prepared.payload).digest()) for ref, revision in exact(group)
    ]
    inherited = assemble(amount_db, inherited=(prepared.manifest_ref,))
    assert inherited.status == "succeeded" and inherited.payload == prepared.payload


def test_wiki_citations_and_each_support_set_require_all_members_of_referenced_csv_groups(amount_db):
    connection, _, *_ = amount_db
    _, (group, _) = publish_table(amount_db)
    set_rules(amount_db, *role_rules(amount_db, group))
    seal = assemble(amount_db, group)
    workspace = (amount_db, seal, group[0], group[1])
    complete = exact(group)
    assert candidate(workspace, cited=complete[:1]).status == "rejected"
    split = drafts.WikiStatement("限额为 600。", (complete[:1], complete[1:]))
    assert candidate(workspace, cited=complete, statements=(split,)).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.wiki_revision").fetchone() == (0,)
    full = drafts.WikiStatement("普通员工限额为 600 元/人·晚，会议统一安排除外。", (complete,))
    assert candidate(workspace, cited=complete, statements=(full,)).status == "succeeded"


def test_csv_wiki_reads_original_only_after_preflight_and_rechecks_location_before_sealing(amount_db, monkeypatch):
    connection, tenant, _, _, store = amount_db
    _, (group, _) = publish_table(amount_db)
    set_rules(amount_db, *role_rules(amount_db, group))
    read = store.read
    reads = []

    def count_reads(asset):
        reads.append(asset)
        return read(asset)

    monkeypatch.setattr(store, "read", count_reads)
    denied = withhold(tenant.actor_id, group[1], "location")
    assert assemble(amount_db, group, authority=denied).status == "rejected"
    assert reads == []

    permitted = authority_for({tenant.actor_id})
    checks = []

    def revoke_after_preflight(probe):
        checks.append(probe.payload_sha256)
        assert {(scope.object_id, scope.revision) for scope in probe.scopes} == set(exact(group))
        return (permitted if len(checks) == 1 else denied)(probe)

    rejected = assemble(amount_db, group, authority=revoke_after_preflight)
    assert (rejected.status, rejected.payload, rejected.manifest_ref) == ("rejected", None, None)
    assert len(reads) == 1 and len(set(checks)) == 2
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_uncited_csv_group_revocation_hides_published_wiki_but_keeps_independent_evidence(amount_db):
    connection, tenant, *_ = amount_db
    run, (cited, unquoted) = publish_table(amount_db)
    anchor, markdown, _ = publish(amount_db, "approval", "审批规则", b"# Rules\n\n600 requires written approval.\n")
    approve(connection, tenant, anchor, BEGIN)
    set_rules(amount_db, permit(tenant.actor_id, markdown), *role_rules(amount_db, cited + unquoted))
    seal = assemble(amount_db, cited + unquoted)
    statement = drafts.WikiStatement("普通员工限额为 600 元/人·晚，会议统一安排除外。", (exact(cited),))
    draft = candidate((amount_db, seal, cited[0], unquoted[0]), cited=exact(cited), statements=(statement,))
    assert draft.status == "succeeded" and read_current(amount_db).payload is None
    blocked = withhold(tenant.other_actor_id, unquoted[1])
    assert preview(amount_db, draft.ref, authority=blocked).payload is None
    material = preview(amount_db, draft.ref)
    assert material.status == "succeeded"
    approved = submit(amount_db, draft.ref, material)
    assert approved.status == "succeeded"
    assert authorize(amount_db, draft.ref, approved.ref, authority=blocked).status == "rejected"
    published = authorize(amount_db, draft.ref, approved.ref)
    assert published.status == "succeeded" and read_current(amount_db).ref == draft.ref
    anchor_id, = connection.execute(
        "SELECT object_id FROM thalion.object_identity WHERE public_id = %s", (anchor.version_ref,),
    ).fetchone()
    with pytest.raises(DispositionConflict, match="complete input scope"):
        select_wiki(connection, tenant.org_id, tenant.space_id, anchor_id, draft.ref)

    request = ingress(amount_db, tenant.actor_id, BEFORE, operation="search", space_id=tenant.space_id)
    found = json.loads(search(amount_db, "600", include_wiki=True, context=request).payload)
    assert found["wiki"][0]["claims"] == [{
        "text": statement.text, "passage_ids": [str(ref) for ref, _ in exact(cited)],
    }]
    assert connection.execute("""
        SELECT dependency_count FROM thalion.wiki_publication_event
        JOIN thalion.delivery_record USING (org_id, check_id) WHERE publication_ref = %s
    """, (published.ref,)).fetchone() == (8,)
    dependency_count, visible_refs = connection.execute("""
        SELECT receipt.dependency_count, array_agg(dependency.passage_ref)
        FROM thalion.delivery_record AS receipt
        JOIN thalion.delivery_dependency AS dependency USING (check_id)
        JOIN thalion.delivery_citation USING (check_id, position)
        WHERE (receipt.request_id, receipt.wiki_publication_ref) = (%s, %s)
        GROUP BY receipt.check_id
    """, (UUID(found["request_id"]), published.ref)).fetchone()
    assert dependency_count == 9
    assert set(visible_refs) == {cell.passage_ref for cell in cited} | {markdown.passage_ref}
    revoked = withhold(tenant.actor_id, unquoted[1])
    assert read_current(amount_db, authority=revoked).payload is None
    recovered = json.loads(search(amount_db, "600", include_wiki=True, authority=revoked).payload)
    assert recovered["wiki"] == [] and len(recovered["passages"]) == 5
    review(amount_db, run, decision="quarantined")
    assert connection.execute("""
        SELECT reason FROM thalion.wiki_availability_event WHERE publication_ref = %s
    """, (published.ref,)).fetchall() == [("quarantined",)]
    assert read_current(amount_db).payload is None


def test_upgrade_from_csv_units_preserves_existing_markdown_wiki_inputs(database_url, tmp_path):
    migrate_to_revision(database_url, "0052_csv_evidence_units")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "legacy-wiki")
        db = create_evidence_db(connection, tenant, database_url, tmp_path)
        version, passage, _ = publish(db, "legacy", "审批规则", b"# Rules\n\nWritten approval required.\n")
        approve(connection, tenant, version, BEGIN)
        set_rules(db, compile_rule(tenant.actor_id))
        prior = assemble(db, (passage,))
        assert prior.status == "succeeded"

        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        inherited = assemble(db, inherited=(prior.manifest_ref,))
        assert inherited.status == "succeeded" and inherited.payload == prior.payload
        assert json.loads(inherited.payload) == ["Written approval required.\n"]
        assert candidate((db, inherited, passage, passage)).status == "succeeded"
