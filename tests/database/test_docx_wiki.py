from dataclasses import replace
from hashlib import sha256
import json
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.access.travel import authorize_travel_dependency_payload
from enterprise_kb.modules.evidence.processing import list_approved_docx_units
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict
from enterprise_kb.modules.lifecycle.wiki_archives import select_wiki
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.modules.wiki import drafts

from test_csv_wiki import WORKSPACE_FIELDS, exact, role_rules, withhold
from test_docx_review import docx_table_review
from test_docx_table_delivery import ready_docx_table
from test_evidence import evidence_db, review
from test_evidence_transport import bearer, evidence_transport, private_json, rpc, transport
from test_persisted_access import authority_for, set_rules
from test_runtime import runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_travel_search import BEFORE, corpus
from test_wiki_drafts import candidate, preview, request, submit
from test_wiki_inputs import assemble
from test_wiki_publication import authorize, read_current


@pytest.fixture
def wiki_row(ready_docx_table):
    _, db, version, _ = ready_docx_table
    connection, tenant, *_ = db
    unit, = list_approved_docx_units(connection, tenant.org_id, tenant.space_id, version.version_ref)
    members = {member.role: member.cell for member in unit.members}
    return db, tuple(members[role] for role in ("amount", "unit", "condition", "exception"))


def test_docx_wiki_inputs_require_complete_exact_rows_and_workplace_location_permission(wiki_row, monkeypatch):
    db, cells = wiki_row
    connection, tenant, _, _, store = db
    read = store.read
    reads = []

    def observe(asset):
        reads.append(asset)
        return read(asset)

    monkeypatch.setattr(store, "read", observe)
    assert assemble(db, cells).status == "rejected"
    set_rules(db, *role_rules(db, cells), expected=2)
    assert assemble(db, cells[:-1]).status == "rejected"
    assert assemble(db, (*cells[:-1], replace(cells[-1], revision=2))).status == "rejected"
    denied = withhold(tenant.actor_id, cells[-1], "location")
    assert assemble(db, cells, authority=denied).status == "rejected"
    assert reads == []

    live = authority_for({tenant.actor_id})
    checks = []

    def revoke_location(probe):
        checks.append(probe.payload_sha256)
        assert {(scope.object_id, scope.revision, scope.fields) for scope in probe.scopes} == {
            (ref, revision, WORKSPACE_FIELDS) for ref, revision in exact(cells)
        }
        return (live if len(checks) == 1 else denied)(probe)

    refused = assemble(db, cells, authority=revoke_location)
    assert (refused.status, refused.payload, refused.manifest_ref) == ("rejected", None, None)
    assert len(reads) == 1 and len(set(checks)) == 2
    assert connection.execute("SELECT count(*) FROM thalion.input_manifest").fetchone() == (0,)
    prepared = assemble(db, cells)
    assert prepared.status == "succeeded"
    material = json.loads(prepared.payload)
    assert [(item["source_type"], item["excerpt"], item["location"]) for item in material] == [
        ("docx", value, {"heading_path": ["差旅", "住宿"], "table": 1, "row_id": 2,
                         "columns": [{"column": column, "header": header}]})
        for value, column, header in (
            ("0600.50", 2, "上限"), ("元/人·晚", 3, "单位"), ("上海正式员工", 1, "适用人群"),
            ("会议统一安排除外。\n须另行审批。", 4, "例外"),
        )
    ]
    assert connection.execute("""
        SELECT passage_ref, excerpt_revision, payload_digest
        FROM thalion.input_manifest_entry JOIN thalion.delivery_record USING (org_id, check_id)
        WHERE manifest_ref = %s ORDER BY position
    """, (prepared.manifest_ref,)).fetchall() == [(ref, revision, sha256(prepared.payload).digest()) for ref, revision in exact(cells)]


def test_docx_wiki_rejects_partial_citations_and_support_sets_but_publishes_the_complete_row(wiki_row, transport):
    db, cells = wiki_row
    client, _, (owner, _), *_ = transport
    connection, *_ = db
    set_rules(db, *role_rules(db, cells), expected=2)
    sealed = assemble(db, cells)
    assert sealed.status == "succeeded"
    workspace = (db, sealed, cells[0], cells[-1])
    refs = exact(cells)
    assert candidate(workspace, cited=refs[:-1]).status == "rejected"
    split = drafts.WikiStatement("限额为 0600.50。", (refs[:1], refs[1:]))
    assert candidate(workspace, cited=refs, statements=(split,)).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.wiki_revision").fetchone() == (0,)

    statement = drafts.WikiStatement("上海正式员工限额为 0600.50 元/人·晚，会议统一安排除外。", (refs,))
    draft = candidate(workspace, cited=refs, statements=(statement,))
    assert draft.status == "succeeded"
    material = preview(db, draft.ref)
    approval = submit(db, draft.ref, material)
    assert approval.status == "succeeded"
    assert authorize(db, draft.ref, approval.ref).status == "succeeded"
    assert read_current(db).ref == draft.ref
    found = client.post("/v1/search", headers=bearer(owner), json={
        "query": "0600.50", "business_date": BEFORE.isoformat(), "include_wiki": True, "top_k": 4,
    }).json()
    assert found["wiki"][0]["claims"] == [{"text": statement.text, "passage_ids": [str(ref) for ref, _ in refs]}]


@pytest.mark.parametrize("partial", ["citations", "support_set"])
def test_database_rejects_partial_docx_wiki_groups_even_with_a_fresh_content_receipt(wiki_row, partial):
    db, cells = wiki_row
    connection, tenant, *_ = db
    set_rules(db, *role_rules(db, cells), expected=2)
    sealed = assemble(db, cells)
    assert sealed.status == "succeeded"
    refs = [[str(ref), revision] for ref, revision in exact(cells)]
    content = {"title": "差旅", "markdown": "限额见制度。", "citations": refs}
    if partial == "citations":
        content["citations"] = refs[:1]
    else:
        content["statements"] = [{"text": "限额为 0600.50。", "support_groups": [refs[:1], refs[1:]]}]
    payload = json.dumps(content).encode()
    receipt = authorize_travel_dependency_payload(
        connection, request(db, tenant.actor_id, "create_wiki_candidate"), tenant.space_id,
        region="shanghai", traveler_class="employee", check_authority=authority_for({tenant.actor_id}),
        resolve=lambda _: exact(cells), build_payload=lambda: payload,
    )
    assert receipt.status == "succeeded"
    connection.execute("INSERT INTO thalion.wiki (org_id, space_id, topic_key) VALUES (%s, %s, 'travel')",
                       (tenant.org_id, tenant.space_id))
    with pytest.raises(errors.CheckViolation, match="evidence groups complete"):
        connection.execute("""
            INSERT INTO thalion.wiki_revision (
                org_id, space_id, topic_key, author_id, reviewer_id, basis_ref, manifest_ref, input_digest, content, check_id
            ) SELECT org_id, space_id, 'travel', author_id, %s, %s, manifest_ref, expanded_digest, %s, %s
              FROM thalion.input_manifest WHERE manifest_ref = %s
        """, (tenant.other_actor_id, uuid4(), payload, receipt.check.check_id, sealed.manifest_ref))
    assert connection.execute("SELECT count(*) FROM thalion.wiki_revision").fetchone() == (0,)


def test_revoking_an_uncited_inherited_docx_cell_blocks_wiki_without_blocking_independent_markdown(
    wiki_row, transport, docx_table_review, revocation_authority,
):
    db, cells = wiki_row
    connection, tenant, *_ = db
    client, markdown_db, (owner, reviewer), credentials, _, markdown, _ = transport
    _, _, _, _, run = docx_table_review
    writer, authority, profile = revocation_authority
    set_rules(db, *role_rules(db, cells), expected=2)
    set_rules(markdown_db, *role_rules(markdown_db, (markdown,)), expected=2)
    private_json(profile.root / "source-grants.json", {
        str(credentials[token].employee_ref): [str(cell.passage_ref) for cell in (*cells, markdown)] for token in (owner, reviewer)
    })

    def author_check(probe):
        return profile.check_source(credentials[owner], probe)

    def reviewer_check(probe):
        return profile.check_source(credentials[reviewer], probe)

    parent = assemble(db, cells, authority=author_check)
    assert parent.status == "succeeded"
    expanded = assemble(db, (markdown,), (parent.manifest_ref,), authority=author_check)
    assert expanded.status == "succeeded"
    statement = drafts.WikiStatement("上海住宿限额另见差旅制度。", (exact((markdown,)),))
    draft = candidate((db, expanded, markdown, cells[-1]), statements=(statement,), authority=author_check)
    assert draft.status == "succeeded"
    material = preview(db, draft.ref, authority=reviewer_check)
    approval = submit(db, draft.ref, material, authority=reviewer_check)
    published = authorize(db, draft.ref, approval.ref, authority=reviewer_check)
    assert published.status == "succeeded"
    version_id, = connection.execute("""
        SELECT passage.version_id FROM thalion.object_identity AS identity
        JOIN thalion.passage AS passage ON (passage.org_id, passage.space_id, passage.passage_id)
                                        = (identity.org_id, identity.space_id, identity.object_id)
        WHERE identity.object_type = 'passage' AND identity.public_id = %s
    """, (markdown.passage_ref,)).fetchone()
    with pytest.raises(DispositionConflict, match="complete input scope"):
        select_wiki(connection, tenant.org_id, tenant.space_id, version_id, draft.ref)

    args = {"query": "上海住宿", "business_date": BEFORE.isoformat(), "include_wiki": True}
    before = client.post("/v1/search", headers=bearer(owner), json=args).json()
    assert before["wiki"][0]["claims"][0]["passage_ids"] == [str(markdown.passage_ref)]
    assert connection.execute("""
        SELECT dependency.passage_ref, dependency.excerpt_revision
        FROM thalion.delivery_dependency AS dependency JOIN thalion.delivery_record AS record USING (org_id, check_id)
        WHERE record.request_id = %s AND record.wiki_publication_ref = %s ORDER BY dependency.passage_ref
    """, (UUID(before["request_id"]), published.ref)).fetchall() == sorted(exact((*cells, markdown)))
    source_revocations.revoke(writer, authority.authority_ref, tenant.space_ref, credentials[owner].employee_ref,
                              cells[-1].passage_ref, "evidence", basis_ref=uuid4())
    assert read_current(db, authority=author_check).payload is None
    assert assemble(db, (markdown,), (expanded.manifest_ref,), authority=author_check).manifest_ref is None
    after = client.post("/v1/search", headers=bearer(owner), json=args).json()
    mcp = rpc(client, owner, "tools/call", name="search", arguments=args).json()["result"]["structuredContent"]
    assert after["wiki"] == mcp["wiki"] == []
    assert after["passages"] == mcp["passages"]
    assert [item["passage_id"] for item in after["passages"]] == [str(markdown.passage_ref)]
    review(db, run, decision="quarantined")
    assert connection.execute("SELECT reason FROM thalion.wiki_availability_event WHERE publication_ref = %s",
                              (published.ref,)).fetchall() == [("quarantined",)]
