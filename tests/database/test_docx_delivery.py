from dataclasses import replace
from hashlib import sha256
from uuid import UUID

import pytest

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence import processing
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from docx_fixture import docx_package
from test_docx_processing import docx_locators, register_docx
from test_effectivity import BEFORE, BEGIN, approve
from test_employee_portal import browser, load_credential, portal
from test_evidence import claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_pdf_delivery import assert_not_delivered, permit, read_page as read_reference
from test_persisted_access import authority_for, read, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import corpus, search
from test_wiki_inputs import assemble, compile_rule


EXCERPT = "不得报销\t除非书面批准\n按实际金额。"
PRIVATE = "仅限正式员工。"
ARGS = {"query": "书面批准 正式员工", "business_date": BEFORE.isoformat(), "include_wiki": True}


def publish_docx(db):
    connection, tenant, _, _, store = db
    version = register_docx(db, docx_package(), key="docx-policy", object_key="docx-policy", display_name="差旅 DOCX")
    run = processing.process_evidence_job(connection, claim(db), store)
    review(db, run)
    approve(connection, tenant, version, BEGIN)
    return version, run, docx_locators(db, version)


def search_docx(client, token):
    return client.post("/v1/search", json=ARGS, headers=bearer(token))


def test_docx_search_and_exact_reference_return_only_the_authorized_paragraph(transport):
    client, db, (owner, other), *_ = transport
    connection, tenant, *_ = db
    version, _, (target, adjacent) = publish_docx(db)
    set_rules(db, permit(tenant.actor_id), permit(tenant.actor_id, target.passage_ref),
              permit(tenant.other_actor_id, adjacent.passage_ref), expected=2)

    direct = read_reference(client, owner, target.passage_ref)
    found = search_docx(client, owner)
    assert direct.status_code == found.status_code == 200
    assert direct.headers["cache-control"] == found.headers["cache-control"] == "no-store"
    passage = direct.json()["passage"]
    assert found.json()["passages"] == [passage] and found.json()["wiki"] == []
    assert (passage["source_type"], passage["excerpt_revision"], passage["version_id"], passage["location"], passage["excerpt"]) == (
        "docx", 1, str(version.version_ref), {"heading_path": ["差旅", "住宿"], "paragraph": 1}, EXCERPT,
    )
    mcp_read = rpc(client, owner, "tools/call", name="read_passage", arguments={"id": str(target.passage_ref)})
    mcp_search = rpc(client, owner, "tools/call", name="search", arguments=ARGS)
    assert mcp_read.json()["result"]["structuredContent"]["passage"] == passage
    assert mcp_search.json()["result"]["structuredContent"]["passages"] == [passage]
    assert all(PRIVATE not in response.text and str(adjacent.passage_ref) not in response.text
               for response in (direct, found, mcp_read, mcp_search))
    assert_not_delivered(connection, read_reference(client, owner, adjacent.passage_ref), 404)
    assert_not_delivered(connection, read_reference(client, other, target.passage_ref), 404)
    assert [hit["excerpt"] for hit in search_docx(client, other).json()["passages"]] == [PRIVATE]
    for response in (direct, found):
        assert connection.execute("""
            SELECT dependency.passage_ref, dependency.excerpt_revision, delivery.payload_digest
            FROM thalion.delivery_record AS delivery
            JOIN thalion.delivery_dependency AS dependency USING (check_id)
            JOIN thalion.delivery_citation AS citation USING (check_id, position)
            WHERE delivery.request_id = %s
        """, (UUID(response.json()["request_id"]),)).fetchall() == [
            (target.passage_ref, target.revision, sha256(response.content).digest()),
        ]


@pytest.mark.parametrize("operation", ["read", "search"])
def test_docx_final_authority_check_discards_content_when_the_source_revokes(evidence_db, operation):
    connection, tenant, *_ = evidence_db
    _, _, (target, adjacent) = publish_docx(evidence_db)
    set_rules(evidence_db, permit(tenant.actor_id, target.passage_ref))
    live = authority_for({tenant.actor_id})
    checks = []

    def revoke(probe):
        checks.append(probe)
        full = live(probe)
        if len(checks) == 2:
            return replace(full, permitted_fields={scope: frozenset() for scope in probe.scopes})
        return full

    if operation == "read":
        decision = read(evidence_db, target, tenant.actor_id, revoke)
    else:
        decision = search(evidence_db, "书面批准", authority=revoke)
    assert (decision.status, decision.payload) == ("rejected", None)
    exact = {(target.passage_ref, target.revision)}
    preliminary = exact | {(adjacent.passage_ref, adjacent.revision)} if operation == "search" else exact
    assert [{(scope.object_id, scope.revision) for scope in probe.scopes} for probe in checks] == [
        preliminary, exact,
    ]
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_docx_denied_or_unavailable_authority_does_not_open_the_original(evidence_db, monkeypatch):
    _, tenant, _, _, store = evidence_db
    _, _, (target, _) = publish_docx(evidence_db)
    set_rules(evidence_db, permit(tenant.actor_id, target.passage_ref))

    def unexpected_read(*_):
        pytest.fail("The DOCX original must not be opened before a current grant.")

    def unavailable(_):
        raise AuthorizationUnavailable("Synthetic source outage")

    monkeypatch.setattr(store, "read", unexpected_read)
    assert read(evidence_db, target, tenant.actor_id, authority_for(set())).status == "rejected"
    assert read(evidence_db, target, tenant.actor_id, unavailable).status == "dependency_unavailable"
    assert search(evidence_db, "书面批准", authority=unavailable).status == "dependency_unavailable"


def test_docx_search_discards_the_candidate_if_quality_changes_before_sealing(evidence_db):
    connection, tenant, database_url, source, store = evidence_db
    _, run, (target, _) = publish_docx(evidence_db)
    set_rules(evidence_db, permit(tenant.actor_id, target.passage_ref))
    checks = []

    def invalidate(probe):
        checks.append(probe)
        if len(checks) == 2:
            with open_database(database_url) as concurrent:
                review((concurrent, tenant, database_url, source, store), run, decision="quarantined")
        return authority_for({tenant.actor_id})(probe)

    decision = search(evidence_db, "书面批准", authority=invalidate)
    assert len(checks) == 2 and (decision.status, decision.payload) == ("input_changed", None)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_docx_reprocessing_hides_old_revisions_until_the_new_batch_is_approved(evidence_db):
    connection, tenant, _, _, store = evidence_db
    version, _, (target, _) = publish_docx(evidence_db)
    set_rules(evidence_db, permit(tenant.actor_id, target.passage_ref))
    configured, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
               parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE profile = 'docx_literal_paragraphs_v1'
        RETURNING configuration_revision
    """).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, configured))
    pending = processing.process_evidence_job(connection, claim(evidence_db), store)
    authority = authority_for({tenant.actor_id})
    assert read(evidence_db, target, tenant.actor_id, authority).payload is None
    assert search(evidence_db, "书面批准").status == "no_evidence"
    review(evidence_db, pending)
    assert read(evidence_db, target, tenant.actor_id, authority).payload is None
    current = replace(target, revision=2)
    assert read(evidence_db, current, tenant.actor_id, authority).payload == EXCERPT.encode()


def test_docx_unavailable_original_is_not_an_empty_search(transport):
    client, db, (owner, _), *_ = transport
    connection, tenant, _, _, store = db
    version, _, (target, _) = publish_docx(db)
    set_rules(db, permit(tenant.actor_id, target.passage_ref), expected=2)
    key, = connection.execute("SELECT storage_key FROM thalion.asset WHERE content_digest = %s", (version.digest,)).fetchone()
    original = store.root / key
    original.rename(original.with_suffix(".unavailable"))
    assert_not_delivered(connection, read_reference(client, owner, target.passage_ref), 503)
    assert_not_delivered(connection, search_docx(client, owner), 503)


def test_docx_employee_and_compiler_grants_do_not_open_wiki_inputs(evidence_db):
    connection, tenant, *_ = evidence_db
    _, _, (target, _) = publish_docx(evidence_db)
    compile_grant = replace(compile_rule(tenant.actor_id), passage_ref=target.passage_ref,
                            fields=frozenset({"excerpt", "location"}))
    set_rules(evidence_db, permit(tenant.actor_id, target.passage_ref), compile_grant)
    assert search(evidence_db, "书面批准").status == "succeeded"
    result = assemble(evidence_db, (target,))
    assert (result.status, result.payload, result.manifest_ref) == ("rejected", None, None)
    assert connection.execute("SELECT count(*) FROM thalion.input_manifest").fetchone() == (0,)


def test_employee_portal_reopens_docx_heading_and_hides_it_after_revocation(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, _), _, live, *_ = portal
    _, tenant, *_ = db
    _, _, (target, _) = publish_docx(db)
    set_rules(db, permit(tenant.actor_id, target.passage_ref), expected=2)
    load_credential(page, owner)
    page.get_by_label("关键词或问题").fill("书面批准")
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    page.get_by_role("button", name="查找依据").click()
    open_original = page.get_by_role("button", name="核对原文：差旅 DOCX")
    expect(open_original).to_be_visible()
    open_original.click()
    detail = page.get_by_role("region", name="原文核对")
    expect(detail.get_by_text("差旅 / 住宿 / 第 1 段", exact=True)).to_be_visible()
    expect(detail.get_by_text("按实际金额。", exact=False)).to_be_visible()
    expect(detail.get_by_text(PRIVATE, exact=True)).to_be_hidden()
    live.remove(tenant.actor_id)
    open_original.click()
    expect(page.get_by_text("该引用不可用。请重新查找依据。", exact=True)).to_be_visible()
    expect(page.get_by_text("按实际金额。", exact=False)).to_be_hidden()
