from dataclasses import replace
from hashlib import sha256
import json
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.evidence.processing import list_approved_pdf_pages
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict
from enterprise_kb.modules.lifecycle.wiki_archives import select_wiki
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.modules.wiki import drafts
from enterprise_kb.transport.local import LocalProfile

from test_effectivity import BEGIN, approve
from test_evidence import evidence_db, review
from test_evidence_transport import bearer, evidence_transport, private_json, rpc, transport
from test_pdf_delivery import PRIVATE, SEARCH, permit, read_page
from test_pdf_processing import PAGE_TEXT, text_page
from test_pdf_review import stage_pdf
from test_persisted_access import authority_for, set_rules
from test_runtime import open_database, runtime_db
from test_source_revocations import independent_authority
from test_travel_search import corpus
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble, compile_rule
from test_wiki_publication import authorize, read_current


WORKSPACE_FIELDS = frozenset({"excerpt", "location"})


def pdf_pages(db):
    pytest.importorskip("pypdfium2")
    connection, tenant, *_ = db
    version, run = stage_pdf(db, text_page(PAGE_TEXT), text_page(PRIVATE))
    review(db, run)
    approve(connection, tenant, version, BEGIN)
    return version, run, list_approved_pdf_pages(connection, tenant.org_id, tenant.space_id, version.version_ref)


def test_pdf_wiki_workspace_requires_exact_page_and_location_on_both_checks(evidence_db, monkeypatch):
    connection, tenant, _, _, store = evidence_db
    _, _, (first, second) = pdf_pages(evidence_db)
    read = store.read
    reads = []

    def observe(asset):
        reads.append(asset)
        return read(asset)

    monkeypatch.setattr(store, "read", observe)
    broad = replace(compile_rule(tenant.actor_id), fields=WORKSPACE_FIELDS)
    set_rules(evidence_db, broad, replace(broad, passage_ref=first.passage_ref, fields=frozenset({"excerpt"})))
    assert assemble(evidence_db, (first,)).status == "rejected"
    assert reads == []
    set_rules(evidence_db, replace(broad, passage_ref=first.passage_ref), expected=2)
    assert assemble(evidence_db, (first, second)).status == "rejected"
    assert assemble(evidence_db, (replace(first, revision=2),)).status == "rejected"
    assert reads == []
    live = authority_for({tenant.actor_id})
    checked = []

    def remove_location_on_delivery(probe):
        checked.append(probe.payload_sha256)
        scope, = probe.scopes
        assert (scope.object_id, scope.revision, scope.fields) == (first.passage_ref, first.revision, WORKSPACE_FIELDS)
        result = live(probe)
        return result if len(checked) == 1 else replace(result, permitted_fields={scope: frozenset({"excerpt"})})

    denial = assemble(evidence_db, (first,), authority=remove_location_on_delivery)
    assert (denial.status, denial.payload, denial.manifest_ref) == ("rejected", None, None)
    assert len(reads) == 1 and len(checked) == len(set(checked)) == 2
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)
    prepared = assemble(evidence_db, (first,))
    assert prepared.status == "succeeded"
    assert json.loads(prepared.payload) == [
        {"source_type": "pdf", "location": {"page": 1}, "excerpt": PAGE_TEXT.decode()},
    ]
    assert connection.execute("""
        SELECT passage_ref, excerpt_revision, payload_digest
        FROM thalion.input_manifest_entry JOIN thalion.delivery_record USING (org_id, check_id)
        WHERE manifest_ref = %s
        """, (prepared.manifest_ref,)).fetchall() == [(first.passage_ref, 1, sha256(prepared.payload).digest())]


def test_uncited_inherited_pdf_page_revocation_blocks_wiki_but_keeps_allowed_originals(
    transport, evidence_transport, independent_authority, tmp_path,
):
    client, db, (owner, reviewer), credentials, _, markdown, _ = transport
    service, *_ = evidence_transport
    connection, tenant, *_ = db
    _, run, (first, unquoted) = pdf_pages(db)
    refs = [str(page.passage_ref) for page in (first, unquoted)]
    author_ref = credentials[owner].employee_ref
    rules = []
    for page in (first, unquoted, markdown):
        compile_page = replace(compile_rule(tenant.actor_id), passage_ref=page.passage_ref, fields=WORKSPACE_FIELDS)
        review_page = replace(compile_page, subject_id=tenant.other_actor_id, operation="review_wiki_revision", purpose="wiki_review")
        publish_page = replace(review_page, operation="publish_wiki_revision", purpose="wiki_publication")
        rules.extend((compile_page, review_page, publish_page, permit(tenant.actor_id, page.passage_ref)))
    set_rules(db, *rules, expected=2)
    writer, url, authority_ref = independent_authority
    source_revocations.enroll_space(writer, authority_ref, tenant.space_ref)
    source = source_revocations.SourceRevocationAuthority(lambda: open_database(url), authority_ref)
    tmp_path.chmod(0o700)
    private_json(tmp_path / "credentials.json", [])
    private_json(tmp_path / "source-grants.json", {
        str(credentials[token].employee_ref): [*refs, str(markdown.passage_ref)] for token in (owner, reviewer)
    })
    profile = LocalProfile(tmp_path, revocations=source)
    service.check_source = profile.check_source

    def author_check(probe):
        return profile.check_source(credentials[owner], probe)

    def reviewer_check(probe):
        return profile.check_source(credentials[reviewer], probe)

    parent = assemble(db, (first, unquoted), authority=author_check)
    assert parent.status == "succeeded"
    child = assemble(db, (first, markdown), (parent.manifest_ref,), authority=author_check)
    assert child.status == "succeeded"
    parent_excerpts = json.loads(parent.payload)
    assert json.loads(child.payload) == [parent_excerpts[0], "上海住宿限额。\n", parent_excerpts[1]]
    cite = (first.passage_ref, first.revision)
    statement = drafts.WikiStatement("Travel allowance is 600 CNY.", ((cite,),))
    draft = candidate((db, child, first, unquoted), statements=(statement,), authority=author_check)
    assert draft.status == "succeeded"
    assert preview(db, draft.ref, actor=tenant.actor_id, authority=author_check).payload is None
    material = preview(db, draft.ref, authority=reviewer_check)
    assert material.status == "succeeded"
    approval = submit(db, draft.ref, material, authority=reviewer_check)
    assert approval.status == "succeeded"
    published = authorize(db, draft.ref, approval.ref, authority=reviewer_check)
    assert published.status == "succeeded" and read_current(db, authority=author_check).ref == draft.ref

    query = SEARCH | {"include_wiki": True}
    response = client.post("/v1/search", headers=bearer(owner), json=query)
    before = response.json()
    assert response.status_code == 200
    assert before["wiki"][0]["claims"] == [{"text": statement.text, "passage_ids": [refs[0]]}]
    assert connection.execute("""
        SELECT dependency.passage_ref, dependency.excerpt_revision
        FROM thalion.delivery_record AS receipt JOIN thalion.delivery_dependency AS dependency USING (check_id)
        WHERE receipt.request_id = %s AND receipt.wiki_publication_ref = %s ORDER BY dependency.passage_ref
        """, (UUID(before["request_id"]), published.ref)).fetchall() == sorted([
        cite, (unquoted.passage_ref, 1), (markdown.passage_ref, markdown.revision),
    ])
    markdown_id, = connection.execute("""
        SELECT passage.version_id FROM thalion.object_identity AS identity
        JOIN thalion.passage ON (passage.org_id, passage.space_id, passage.passage_id) =
                                (identity.org_id, identity.space_id, identity.object_id)
        WHERE identity.object_type = 'passage' AND identity.public_id = %s
        """, (markdown.passage_ref,)).fetchone()
    assert select_wiki(connection, tenant.org_id, tenant.space_id, markdown_id, draft.ref) == published.ref

    source_revocations.revoke(writer, authority_ref, tenant.space_ref, author_ref, unquoted.passage_ref, "evidence", basis_ref=uuid4())
    assert read_current(db, authority=author_check).payload is None
    assert assemble(db, (first,), (child.manifest_ref,), authority=author_check).manifest_ref is None
    after = client.post("/v1/search", headers=bearer(owner), json=query).json()
    mcp = rpc(client, owner, "tools/call", name="search", arguments=query).json()["result"]["structuredContent"]
    assert after["wiki"] == mcp["wiki"] == []
    assert [part["passage_id"] for part in after["passages"]] == [refs[0]]
    assert after["passages"] == mcp["passages"]
    assert read_page(client, owner, first.passage_ref).status_code == 200
    assert read_page(client, owner, unquoted.passage_ref).status_code == 404
    assert connection.execute("SELECT count(*) FROM thalion.wiki_availability_event").fetchone() == (0,)
    review(db, run, decision="quarantined")
    with pytest.raises(DispositionConflict, match="not currently published"):
        select_wiki(connection, tenant.org_id, tenant.space_id, markdown_id, draft.ref)
    assert connection.execute("""
        SELECT reason FROM thalion.wiki_availability_event WHERE publication_ref = %s
        """, (published.ref,)).fetchall() == [("quarantined",)]
