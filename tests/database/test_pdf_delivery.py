from dataclasses import replace
from hashlib import sha256
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.access.policy import PASSAGE_FIELDS
from enterprise_kb.modules.operations import feedback
from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.transport.local import LocalProfile

from test_effectivity import BEGIN, BEFORE, approve
from test_employee_portal import browser, load_credential, portal, screenshot
from test_evidence import evidence_db, review
from test_evidence_transport import bearer, evidence_transport, private_json, rpc, transport
from test_feedback_work import admit, assign
from test_pdf_correction import TRANSCRIPT
from test_pdf_processing import PAGE_TEXT, text_page
from test_pdf_repair_approval import approve_batch, compare_batch, permit_review, stage_batch
from test_pdf_review import original_rule, pdf_review, stage_pdf
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_travel_search import corpus


PRIVATE = b"Travel refund excluded"
SEARCH = {"query": "Travel", "business_date": BEFORE.isoformat(), "include_wiki": False}


def excerpt_ref(connection, run, page):
    return connection.execute("""
        SELECT identity.public_id, excerpt.excerpt_revision
        FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (org_id, space_id, version_id, passage_id)
        JOIN thalion.object_identity AS identity ON identity.object_type = 'passage'
          AND (identity.org_id, identity.space_id, identity.object_id) = (passage.org_id, passage.space_id, passage.passage_id)
        WHERE (excerpt.run_ref, passage.pdf_page) = (%s, %s)
    """, (run.run_ref, page)).fetchone()


def publish_pdf(db):
    pytest.importorskip("pypdfium2")
    connection, tenant, *_ = db
    version, run = stage_pdf(db, text_page(PAGE_TEXT), text_page(PRIVATE))
    review(db, run)
    approve(connection, tenant, version, BEGIN)
    return version, excerpt_ref(connection, run, 1)[0], excerpt_ref(connection, run, 2)[0]


def index_pdf(db, version):
    connection, tenant, _, _, store = db
    run_ref, = connection.execute("""
        SELECT run.run_ref FROM thalion.processing_run AS run
        JOIN thalion.object_identity AS version ON version.object_type = 'document_version'
          AND (version.org_id, version.space_id, version.object_id) = (run.org_id, run.space_id, run.version_id)
        WHERE version.public_id = %s
        ORDER BY run.configuration_revision DESC LIMIT 1
        """, (version.version_ref,)).fetchone()
    return lexical.build_index(connection, store, tenant.space_ref, version.version_ref, run_ref)


def permit(principal, ref=None):
    return replace(binding(principal, passage_ref=ref), fields=PASSAGE_FIELDS)


def read_page(client, token, ref):
    return client.get(f"/v1/passages/{ref}", headers=bearer(token))


def search_pages(client, token):
    return client.post("/v1/search", headers=bearer(token), json=SEARCH)


def assert_not_delivered(connection, response, status):
    assert response.status_code == status, response.text
    body = response.json()
    assert "passage" not in body
    assert body.get("passages", []) == []
    assert connection.execute(
        "SELECT count(*) FROM thalion.delivery_record WHERE request_id = %s", (UUID(body["request_id"]),),
    ).fetchone() == (0,)


@pytest.mark.parametrize("indexed", [False, True], ids=["sealed-transcripts", "lexical-index"])
def test_employee_pdf_search_and_exact_read_share_http_mcp_and_revision_receipts(transport, monkeypatch, indexed):
    client, db, (owner, other), *_ = transport
    connection, tenant, *_ = db
    version, target, adjacent = publish_pdf(db)
    set_rules(db, permit(tenant.actor_id), permit(tenant.actor_id, target),
              permit(tenant.other_actor_id, adjacent), expected=2)

    scored = []
    if indexed:
        index = index_pdf(db, version)
        assert index_pdf(db, version) == index
        entries, = connection.execute(
            "SELECT entries FROM thalion.synthetic_lexical_index WHERE index_ref = %s", (index,),
        ).fetchone()
        assert entries == {
            str(target): [1, sha256(PAGE_TEXT).hexdigest(), "travel allowance 600 cny"],
            str(adjacent): [1, sha256(PRIVATE).hexdigest(), "travel refund excluded"],
        }
        score = lexical.score_indexed_passages

        def track(connection, org_id, space_id, passages, terms):
            result = score(connection, org_id, space_id, passages, terms)
            scored.append(result)
            return result

        monkeypatch.setattr(lexical, "score_indexed_passages", track)

    found = search_pages(client, owner)
    read = read_page(client, owner, target)
    assert found.status_code == read.status_code == 200
    assert read.headers["cache-control"] == found.headers["cache-control"] == "no-store"
    page = read.json()["passage"]
    assert found.json()["passages"] == [page]
    assert (page["source_type"], page["version_id"], page["excerpt_revision"], page["location"], page["excerpt"]) == (
        "pdf", str(version.version_ref), 1, {"page": 1}, PAGE_TEXT.decode(),
    )
    assert set(page) == {
        "passage_id", "excerpt_revision", "source_type", "title", "version_id",
        "version_label", "valid_from", "valid_until", "location", "excerpt",
    }
    mcp_search = rpc(client, owner, "tools/call", name="search", arguments=SEARCH)
    mcp_read = rpc(client, owner, "tools/call", name="read_passage", arguments={"id": str(target)})
    assert mcp_search.json()["result"]["structuredContent"]["passages"] == [page]
    assert mcp_read.json()["result"]["structuredContent"]["passage"] == page
    for delivered in (found, read, mcp_search, mcp_read):
        assert str(adjacent) not in delivered.text and PRIVATE.decode() not in delivered.text
    assert_not_delivered(connection, read_page(client, owner, adjacent), 404)
    assert_not_delivered(connection, read_page(client, other, target), 404)
    other_page, = search_pages(client, other).json()["passages"]
    assert (other_page["location"], other_page["excerpt"]) == ({"page": 2}, PRIVATE.decode())
    if indexed:
        assert scored == [{target: 1}, {target: 1}, {adjacent: 1}]
    for response in (found, read):
        assert connection.execute("""
            SELECT dependency.passage_ref, dependency.excerpt_revision, delivery.payload_digest
            FROM thalion.delivery_record AS delivery
            JOIN thalion.delivery_dependency AS dependency USING (check_id)
            JOIN thalion.delivery_citation AS citation USING (check_id, position)
            WHERE delivery.request_id = %s
        """, (UUID(response.json()["request_id"]),)).fetchall() == [(target, 1, sha256(response.content).digest())]


def test_pdf_original_preview_permission_does_not_grant_employee_evidence(pdf_review):
    db, profile, _, client, (reviewer, _), credentials = pdf_review
    connection, tenant, *_ = db
    version, target, _ = publish_pdf(db)
    set_rules(db, original_rule(tenant.actor_id), permit(tenant.actor_id, target))
    employee = str(credentials[reviewer].employee_ref)
    private_json(profile.root / "pdf-page-grants.json", {employee: [str(version.version_ref)]})
    credentials[reviewer] = replace(
        credentials[reviewer], operations=credentials[reviewer].operations | {"read_passage", "search"},
    )
    assert_not_delivered(connection, read_page(client, reviewer, target), 404)
    assert search_pages(client, reviewer).json()["status"] == "no_evidence"


@pytest.mark.parametrize("entry", ["read", "search"])
def test_employee_pdf_revocation_during_original_read_discards_the_payload(
    transport, evidence_transport, tmp_path_factory, monkeypatch, entry,
):
    client, db, (owner, _), credentials, *_ = transport
    connection, tenant, _, _, store = db
    version, target, _ = publish_pdf(db)
    set_rules(db, permit(tenant.actor_id, target), expected=2)
    root = tmp_path_factory.mktemp("pdf-employee-profile")
    root.chmod(0o700)
    private_json(root / "credentials.json", [])
    grants = root / "source-grants.json"
    private_json(grants, {str(credentials[owner].employee_ref): [str(target)]})
    evidence_transport[0].check_source = LocalProfile(root).check_source
    request = (lambda: read_page(client, owner, target)) if entry == "read" else (lambda: search_pages(client, owner))
    assert request().status_code == 200
    read = store.read
    observed = []

    def revoke(asset):
        payload = read(asset)
        if asset.digest == version.digest:
            observed.append(asset.digest)
            private_json(grants, {})
        return payload

    monkeypatch.setattr(store, "read", revoke)
    assert_not_delivered(connection, request(), 404 if entry == "read" else 403)
    assert observed == [version.digest]
    assert_not_delivered(connection, read_page(client, owner, target), 404)
    assert observed == [version.digest]


def test_employee_pdf_refuses_original_integrity_failure_even_with_a_sealed_transcript(transport):
    client, db, (owner, _), *_ = transport
    connection, tenant, _, _, store = db
    version, target, _ = publish_pdf(db)
    set_rules(db, permit(tenant.actor_id, target), expected=2)
    key, = connection.execute(
        "SELECT storage_key FROM thalion.asset WHERE content_digest = %s", (version.digest,),
    ).fetchone()
    original = store.root / key
    original.chmod(0o600)
    original.write_bytes(original.read_bytes().replace(PAGE_TEXT, b"X" * len(PAGE_TEXT)))
    assert_not_delivered(connection, read_page(client, owner, target), 503)
    assert_not_delivered(connection, search_pages(client, owner), 503)


def test_pdf_index_miss_does_not_hide_original_integrity_failure(transport):
    client, db, (owner, _), *_ = transport
    connection, tenant, _, _, store = db
    version, target, _ = publish_pdf(db)
    set_rules(db, permit(tenant.actor_id, target), expected=2)
    index_pdf(db, version)
    key, = connection.execute("SELECT storage_key FROM thalion.asset WHERE content_digest = %s", (version.digest,)).fetchone()
    original = store.root / key
    query = SEARCH | {"query": "not-present"}
    assert client.post("/v1/search", headers=bearer(owner), json=query).json()["status"] == "no_evidence"
    original.rename(original.with_suffix(".unavailable"))

    assert_not_delivered(connection, client.post("/v1/search", headers=bearer(owner), json=query), 503)


def test_employee_pdf_ocr_repair_needs_whole_batch_approval_and_current_quality(pdf_review):
    db, profile, _, client, _, credentials = pdf_review
    connection, version, _, repaired, _, reviewer, author = stage_batch(pdf_review)
    tenant = db[1]
    first, revision = excerpt_ref(connection, repaired, 1)
    target, added_revision = excerpt_ref(connection, repaired, 2)
    assert (revision, added_revision) == (2, 1)
    approve(connection, tenant, version, BEGIN)
    set_rules(db, original_rule(tenant.actor_id), original_rule(tenant.other_actor_id),
              permit(tenant.other_actor_id, first), permit(tenant.other_actor_id, target), expected=2)
    private_json(profile.root / "source-grants.json", {
        str(credentials[author].employee_ref): [str(first), str(target)],
    })
    credentials[author] = replace(credentials[author], operations=credentials[author].operations | {"read_passage", "search"})
    assert_not_delivered(connection, read_page(client, author, target), 404)
    assert search_pages(client, author).json()["status"] == "no_evidence"
    with pytest.raises(lexical.LexicalIndexUnavailable):
        lexical.build_index(connection, db[-1], tenant.space_ref, version.version_ref, repaired.run_ref)
    permit_review(pdf_review, reviewer)
    assert approve_batch(client, repaired, reviewer, compare_batch(client, repaired, reviewer)).status_code == 200
    index = lexical.build_index(connection, db[-1], tenant.space_ref, version.version_ref, repaired.run_ref)
    assert connection.execute("""
        SELECT run_ref, entries -> %s, entries -> %s FROM thalion.synthetic_lexical_index WHERE index_ref = %s
        """, (str(first), str(target), index)).fetchone() == (
        repaired.run_ref, [2, sha256(PAGE_TEXT).hexdigest(), PAGE_TEXT.decode().casefold()],
        [1, sha256(TRANSCRIPT.encode()).hexdigest(), TRANSCRIPT.casefold()],
    )
    assert read_page(client, author, target).json()["passage"]["excerpt"] == TRANSCRIPT
    assert read_page(client, author, first).json()["passage"]["excerpt_revision"] == 2
    review(db, repaired, decision="quarantined")
    with pytest.raises(lexical.LexicalIndexUnavailable):
        lexical.build_index(connection, db[-1], tenant.space_ref, version.version_ref, repaired.run_ref)
    assert_not_delivered(connection, read_page(client, author, target), 404)
    assert search_pages(client, author).json()["status"] == "no_evidence"


@pytest.mark.parametrize("width", [390, 1280])
def test_employee_portal_pdf_page_location_and_identity_switch(portal, width):
    from playwright.sync_api import expect

    page, _, db, (owner, other), *_ = portal
    _, tenant, *_ = db
    _, target, adjacent = publish_pdf(db)
    set_rules(db, permit(tenant.actor_id, target), permit(tenant.other_actor_id, adjacent), expected=2)
    page.set_viewport_size({"width": width, "height": 860})
    load_credential(page, owner)
    page.get_by_label("关键词或问题").fill(SEARCH["query"])
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    page.get_by_role("button", name="查找依据").click()
    page.get_by_role("button", name="核对原文：Synthetic travel rules").click()
    reference = page.get_by_role("region", name="原文核对")
    expect(reference.get_by_text("第 1 页（PDF 转录）", exact=True)).to_be_visible()
    expect(reference.get_by_text(PAGE_TEXT.decode(), exact=True)).to_be_visible()
    expect(page.get_by_text(PRIVATE.decode(), exact=True)).to_have_count(0)
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    page.evaluate("window.scrollTo(0, 0)")
    screenshot(page, f"employee-pdf-{width}.png")
    page.get_by_role("button", name="更换凭据").click()
    expect(page.get_by_text(PAGE_TEXT.decode(), exact=True)).to_have_count(0)
    load_credential(page, other)
    page.get_by_text("按引用编号打开", exact=True).click()
    page.get_by_label("引用编号", exact=True).fill(str(target))
    page.get_by_role("button", name="打开引用").click()
    expect(page.get_by_text("该引用不可用。请重新查找依据。", exact=True)).to_be_visible()


def test_pdf_feedback_assignee_needs_exact_page_permission(portal):
    from playwright.sync_api import expect

    page, base, db, (owner, assignee), credentials, *_ = portal
    connection, tenant, *_ = db
    _, target, adjacent = publish_pdf(db)
    set_rules(db, permit(tenant.actor_id, target), permit(tenant.other_actor_id, adjacent), expected=2)
    origin = page.request.get(f"{base}/v1/passages/{target}", headers=bearer(owner))
    assert origin.ok
    admit(credentials, owner, feedback.RECORD)
    reported = page.request.post(
        f"{base}/internal/feedback",
        headers=bearer(owner) | {"Idempotency-Key": str(uuid4())},
        data={"origin_request_id": origin.json()["request_id"], "category": "incorrect_evidence",
              "passage_id": str(target)},
    )
    assert reported.ok
    ref = reported.json()["feedback_id"]
    assign(connection, tenant, UUID(ref))
    admit(credentials, assignee, feedback.QUEUE, feedback.EVIDENCE)
    page.goto("/manage/feedback")
    page.get_by_label("办理测试凭据").fill(assignee)
    page.get_by_role("button", name="查看待办").click()
    expect(page.get_by_text(ref, exact=True)).to_be_visible()
    page.get_by_role("button", name="打开工单").click()
    read = page.get_by_role("button", name="以本人权限核对原文")
    with page.expect_response(f"**/internal/feedback/{ref}/evidence") as denied:
        read.click()
    assert denied.value.status == 404
    expect(page.get_by_text("无法查看这条原文，请确认工单分派和本人读权。", exact=True)).to_be_visible()
    evidence = page.locator("#work-evidence")
    expect(evidence).to_be_empty()

    set_rules(db, permit(tenant.other_actor_id, target), permit(tenant.other_actor_id, adjacent), expected=3)
    with page.expect_response(f"**/internal/feedback/{ref}/evidence") as allowed:
        read.click()
    assert allowed.value.status == 200
    expect(evidence.get_by_text(PAGE_TEXT.decode(), exact=True)).to_be_visible()
    expect(evidence.get_by_text("第 1 页（PDF 转录）", exact=True)).to_be_visible()
    expect(evidence.get_by_text(PRIVATE.decode(), exact=True)).to_have_count(0)
