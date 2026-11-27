from base64 import b64decode
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from struct import unpack
from uuid import uuid4

import psycopg
import pytest

from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity, source_revocations
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job
from enterprise_kb.transport import api, evidence, local

from test_evidence import claim, evidence_db
from test_evidence_transport import bearer, private_json
from test_effectivity import BEGIN, approve, record
from test_employee_portal import browser, loopback_page, screenshot
from test_markdown_repair import client_for, repair_rule
from test_pdf_processing import PAGE_TEXT, pdf_document, register_pdf, text_page
from test_persisted_access import set_rules
from test_runtime import open_database, runtime_db
from test_source_revocations import independent_authority


OPERATION = "preview_pdf_original_page"
FIELDS = frozenset({"original_page"})


class EmptyScan:
    def fingerprint(self):
        return sha256(b"synthetic empty OCR fixture").digest()

    def read(self, bitmap, remaining):
        return None, "empty"


def stage_pdf(db, *content):
    payload = pdf_document(*content)
    version = register_pdf(db, payload)
    run = processing.process_evidence_job(db[0], claim(db), db[-1], pdf_ocr=EmptyScan())
    return version, run


def original_rule(principal, *, until=None):
    return policy.LocalRule(
        principal, OPERATION, "allow", "evidence_quality_review", "local_workspace",
        FIELDS, datetime.now(UTC) - timedelta(days=1), until,
    )


@pytest.fixture
def pdf_review(evidence_db, tmp_path):
    pytest.importorskip("pypdfium2")
    connection, tenant, database_url, _, store = evidence_db
    profile_root = tmp_path / "profile"
    profile_root.mkdir(mode=0o700)
    private_json(profile_root / "credentials.json", [])
    private_json(profile_root / "source-grants.json", {})
    credentials = {}
    for principal in (tenant.actor_id, tenant.other_actor_id):
        ref, = connection.execute(
            "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
            (principal,),
        ).fetchone()
        credentials[token_urlsafe(32)] = evidence.SyntheticCredential(
            ref, tenant.space_ref, "synthetic-pdf-review", "shanghai", "employee",
            {OPERATION, "decide_hold"}, datetime.now(UTC) + timedelta(minutes=5),
        )
    profile = local.LocalProfile(profile_root)
    service = evidence.EvidenceService(
        lambda: open_database(database_url), credentials.get, profile.check_source, store,
    )
    with client_for(service) as client:
        yield evidence_db, profile, service, client, tuple(credentials), credentials


def grant(profile, credentials, token, version):
    private_json(
        profile.root / "pdf-page-grants.json",
        {str(credentials[token].employee_ref): [str(version.version_ref)]},
    )


def path(run, page):
    return f"{api.REPAIR_PATH}/{run.run_ref}/pdf-pages/{page}"


def test_preview_returns_only_the_exact_page_even_without_an_excerpt(pdf_review):
    db, profile, _, client, (reviewer, _), credentials = pdf_review
    connection, tenant, *_ = db
    version, run = stage_pdf(db, text_page(PAGE_TEXT), b"")
    assert run.passage_count == 1
    set_rules(db, original_rule(tenant.actor_id))
    grant(profile, credentials, reviewer, version)

    first = client.get(path(run, 1), headers=bearer(reviewer))
    empty = client.get(path(run, 2), headers=bearer(reviewer))
    for page, response in enumerate((first, empty), 1):
        assert response.status_code == 200, response.json()
        assert response.headers["cache-control"] == "no-store"
        data = response.json()
        assert set(data) == {"request_id", "version_id", "run_id", "page_number", "png_base64"}
        assert (data["version_id"], data["run_id"], data["page_number"]) == (
            str(version.version_ref), str(run.run_ref), page,
        )
        image = b64decode(data["png_base64"], validate=True)
        assert image[:16] == b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        assert unpack(">II", image[16:24]) == (840, 240)
        assert connection.execute("""
            SELECT preview.run_ref, preview.page_number, preview.payload_digest, request.outcome
            FROM thalion.pdf_page_preview AS preview JOIN thalion.request_record AS request USING (org_id, request_id)
            WHERE request.request_id = %s
        """, (data["request_id"],)).fetchone() == (run.run_ref, page, sha256(response.content).digest(), "succeeded")
    assert first.json()["png_base64"] != empty.json()["png_base64"]
    assert client.get(path(run, 3), headers=bearer(reviewer)).status_code == 409
    assert client.get(path(run, "01"), headers=bearer(reviewer)).status_code == 400
    assert client.get(path(run, 1) + "?other=1", headers=bearer(reviewer)).status_code == 400


def test_preview_requires_both_original_grants_and_designated_reviewer(pdf_review):
    db, profile, _, client, (reviewer, other), credentials = pdf_review
    connection, tenant, *_ = db
    version, run = stage_pdf(db, text_page(PAGE_TEXT))
    url = path(run, 1)
    assert client.get(url).status_code == 401
    grant(profile, credentials, reviewer, version)
    set_rules(db, repair_rule(tenant.actor_id))
    assert client.get(url, headers=bearer(reviewer)).status_code == 403
    set_rules(db, original_rule(tenant.actor_id), original_rule(tenant.other_actor_id), expected=2)
    grant(profile, credentials, other, version)
    assert client.get(url, headers=bearer(reviewer)).status_code == 403
    assert client.get(url, headers=bearer(other)).status_code == 403

    grant(profile, credentials, reviewer, version)
    set_rules(db, original_rule(tenant.actor_id, until=datetime.now(UTC) - timedelta(seconds=1)), expected=3)
    assert client.get(url, headers=bearer(reviewer)).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.pdf_page_preview").fetchone() == (0,)


def test_preview_does_not_approve_failed_run_or_reopen_old_batch(pdf_review, monkeypatch):
    db, profile, _, client, (reviewer, _), credentials = pdf_review
    connection, tenant, _, _, store = db
    version, run = stage_pdf(db, b"")
    assert (run.outcome, run.passage_count) == ("quarantined", 0)
    set_rules(db, original_rule(tenant.actor_id))
    grant(profile, credentials, reviewer, version)
    assert client.get(path(run, 1), headers=bearer(reviewer)).status_code == 200
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)

    newer, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
               parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE profile = 'pdf_pages_v1'
        RETURNING configuration_revision
    """).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, newer))
    replacement = processing.process_evidence_job(connection, claim(db), store, pdf_ocr=EmptyScan())
    stale = client.get(path(run, 1), headers=bearer(reviewer))
    assert stale.status_code == 409 and "png_base64" not in stale.text

    def late():
        return datetime.now(UTC) + timedelta(seconds=15)

    monkeypatch.setattr(api, "release_time", late)
    expired = client.get(path(replacement, 1), headers=bearer(reviewer))
    assert expired.status_code == 503 and "png_base64" not in expired.text


def test_source_revocation_blocks_original_preview_without_local_policy_change(pdf_review, independent_authority):
    db, profile, service, client, (reviewer, _), credentials = pdf_review
    _, tenant, *_ = db
    authority, url, authority_ref = independent_authority
    source_revocations.enroll_space(authority, authority_ref, tenant.space_ref)
    current = source_revocations.SourceRevocationAuthority(lambda: open_database(url), authority_ref)
    service.check_source = local.LocalProfile(profile.root, revocations=current).check_source
    version, run = stage_pdf(db, text_page(PAGE_TEXT))
    set_rules(db, original_rule(tenant.actor_id))
    grant(profile, credentials, reviewer, version)
    assert client.get(path(run, 1), headers=bearer(reviewer)).status_code == 200
    source_revocations.revoke(
        authority, authority_ref, tenant.space_ref, credentials[reviewer].employee_ref,
        version.version_ref, "evidence", basis_ref=uuid4(),
    )
    denied = client.get(path(run, 1), headers=bearer(reviewer))
    assert denied.status_code == 403 and "png_base64" not in denied.text

    def disconnected():
        raise psycopg.OperationalError("Synthetic source authority disconnected.")

    service.check_source = local.LocalProfile(profile.root, revocations=replace(current, connect=disconnected)).check_source
    unavailable = client.get(path(run, 1), headers=bearer(reviewer))
    assert unavailable.status_code == 503 and "png_base64" not in unavailable.text


@pytest.mark.parametrize("restriction", ["held", "withdrawn", "changed_digest"])
def test_preview_refuses_held_withdrawn_or_damaged_original(pdf_review, restriction):
    db, profile, _, client, (reviewer, custodian), credentials = pdf_review
    connection, tenant, _, _, store = db
    version, run = stage_pdf(db, text_page(PAGE_TEXT))
    set_rules(db, original_rule(tenant.actor_id))
    grant(profile, credentials, reviewer, version)
    assert client.get(path(run, 1), headers=bearer(reviewer)).status_code == 200
    if restriction == "held":
        held = client.post(
            api.HOLD_PATH, headers=bearer(custodian) | {"Idempotency-Key": uuid4().hex},
            json={"version_id": str(version.version_ref), "action": "establish",
                  "expected_generation": 0, "basis_id": str(uuid4())},
        )
        assert held.status_code == 200, held.json()
        expected = 403
    elif restriction == "withdrawn":
        approve(connection, tenant, version, BEGIN)
        command = record(connection, tenant, "stop_rule_use", "withdraw-pdf")
        effectivity.stop_synthetic_rule(
            connection, command, tenant.space_id, version.version_ref, "withdrawn", uuid4(),
        )
        expected = 403
    else:
        storage_key, = connection.execute("SELECT storage_key FROM thalion.asset").fetchone()
        original = store.root / storage_key
        original.chmod(0o600)
        content = original.read_bytes()
        original.write_bytes(content.replace(PAGE_TEXT, b"X" * len(PAGE_TEXT)))
        expected = 503
    refused = client.get(path(run, 1), headers=bearer(reviewer))
    assert refused.status_code == expected and "png_base64" not in refused.text
    assert connection.execute("SELECT count(*) FROM thalion.pdf_page_preview").fetchone() == (1,)


def open_pdf_controls(page, token, run):
    page.get_by_label("管理测试凭据").fill(token)
    page.get_by_role("button", name="载入审核凭据").click()
    page.get_by_role("radio", name="PDF 原页").check()
    page.get_by_label("校订批次编号").fill(str(run.run_ref))


def test_pdf_management_shows_exact_page_and_clears_on_navigation(browser, pdf_review):
    from playwright.sync_api import expect

    db, profile, service, _, (reviewer, _), credentials = pdf_review
    connection, tenant, *_ = db
    version, run = stage_pdf(db, text_page(PAGE_TEXT), b"")
    set_rules(db, original_rule(tenant.actor_id))
    grant(profile, credentials, reviewer, version)
    with loopback_page(browser, service, "/manage/repairs") as (page, base, shell):
        assert shell.headers["cache-control"] == "no-store"
        assert "img-src blob:" in shell.headers["content-security-policy"]
        assert reviewer not in shell.text()
        open_pdf_controls(page, reviewer, run)
        image = page.get_by_role("img", name="PDF 原页，第 1 页")
        show = page.get_by_role("button", name="查看原页")
        with page.expect_request(f"**{path(run, 1)}") as requested:
            show.click()
        assert requested.value.method == "GET"
        expect(image).to_be_visible()
        assert image.evaluate("(node) => node.complete && node.naturalWidth === 840")
        image_src = image.get_attribute("src")
        assert image_src.startswith("blob:")
        screenshot(page, "management-pdf-desktop.png")
        page.set_viewport_size({"width": 390, "height": 820})
        expect(image).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
        page.evaluate("window.scrollTo(0, 0)")
        screenshot(page, "management-pdf-mobile.png")
        page.get_by_role("checkbox", name="显示原尺寸").check()
        assert image.evaluate("(node) => node.getBoundingClientRect().width === node.naturalWidth")
        assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
        expect(page.get_by_role("button", name="批准校订")).to_be_hidden()
        page.get_by_label("物理页码").fill("2")
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
        assert not page.evaluate("""async (url) => {
            const probe = new Image();
            probe.src = url;
            return probe.decode().then(() => true, () => false);
        }""", image_src)
        show.click()
        expect(page.get_by_role("img", name="PDF 原页，第 2 页")).to_be_visible()
        page.get_by_role("radio", name="文本校订差异").check()
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
        page.get_by_role("radio", name="PDF 原页").check()
        show.click()
        expect(page.get_by_role("img")).to_have_count(1)
        private_json(profile.root / "pdf-page-grants.json", {})
        show.click()
        expect(page.get_by_text("此操作未获授权。", exact=True)).to_be_visible()
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
        grant(profile, credentials, reviewer, version)
        show.click()
        expect(page.get_by_role("img")).to_have_count(1)
        page.goto("/manage/wiki")
        page.go_back()
        assert page.url == f"{base}/manage/repairs"
        expect(page.get_by_role("heading", name="审核人验证")).to_be_visible()
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
        assert page.evaluate("[localStorage.length, sessionStorage.length, document.cookie, history.state]") == [0, 0, "", None]
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)


def test_late_pdf_image_cannot_repopulate_replaced_reviewer_session(browser, pdf_review):
    from playwright.sync_api import expect

    db, profile, service, _, (reviewer, other), credentials = pdf_review
    _, tenant, *_ = db
    version, run = stage_pdf(db, text_page(PAGE_TEXT))
    set_rules(db, original_rule(tenant.actor_id))
    grant(profile, credentials, reviewer, version)
    with loopback_page(browser, service, "/manage/repairs") as (page, _, _):
        page.evaluate("""() => {
            const fetchReal = window.fetch;
            let delayNext = true;
            window.fetch = async (url, options) => {
                if (!delayNext || !url.includes("/pdf-pages/")) return fetchReal(url, options);
                delayNext = false;
                const response = await fetchReal(url, {...options, signal: undefined});
                if (!response.ok) throw new Error("Expected a genuine authorized PDF response");
                await new Promise(resolve => {
                    window.releaseOldTestResponse = resolve;
                    document.body.dataset.oldResponseReady = "true";
                });
                return response;
            };
        }""")
        open_pdf_controls(page, reviewer, run)
        page.get_by_role("button", name="查看原页").click()
        expect(page.locator("body")).to_have_attribute("data-old-response-ready", "true")
        page.get_by_role("button", name="更换凭据").click()
        open_pdf_controls(page, other, run)
        page.get_by_role("button", name="查看原页").click()
        expect(page.get_by_text("此操作未获授权。", exact=True)).to_be_visible()
        page.evaluate("""async () => {
            window.releaseOldTestResponse();
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        }""")
        expect(page.locator("#repair-pdf-image img")).to_have_count(0)
        expect(page.get_by_text("此操作未获授权。", exact=True)).to_be_visible()
