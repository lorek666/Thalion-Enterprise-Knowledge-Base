from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from secrets import token_urlsafe
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from psycopg import errors

from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import processing, repair_review
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.runtime.events import pending_events
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job
from enterprise_kb.transport import api, evidence

from test_csv_wiki import withhold
from test_effectivity import BEGIN, approve, record
from test_employee_portal import browser, portal, screenshot
from test_evidence import approved, claim, evidence_db, register_markdown, review
from test_evidence_transport import bearer, evidence_transport, rpc
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import open_database, runtime_db
from test_sources import request_for
from test_travel_search import SEARCH_FIELDS, corpus, search
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble, compile_rule
from test_wiki_publication import authorize, read_current


PAYLOAD = b"# Travel\n\nHotel limit is 600 CNY.\n\nMeeting accommodation is exempt.\n"


def queue(db, version, revision):
    connection, tenant, *_ = db
    connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT %s, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
    """, (revision,))
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, revision))


def missing_exception(db, version, monkeypatch):
    queue(db, version, 10)
    parser = processing.parse_markdown

    def omit_clause(payload):
        parsed = parser(payload)
        return replace(parsed, passages=parsed.passages[:1])

    with monkeypatch.context() as patch:
        patch.setattr(processing, "parse_markdown", omit_clause)
        run = processing.process_markdown_job(db[0], claim(db), db[-1])
    assert run.passage_count == 1
    return run


def initial_run(db):
    version = register_markdown(db, payload=PAYLOAD)
    run = processing.process_markdown_job(db[0], claim(db), db[-1])
    review(db, run)
    approve(*db[:2], version, BEGIN)
    return version, run


def repair(db, lease, bad, basis, baseline=None):
    return processing.repair_markdown_job(
        db[0], lease, db[-1], replaces=bad.run_ref, basis_ref=basis,
        rollback_to=baseline.run_ref if baseline else None,
    )


def staged_repair(db, monkeypatch):
    version, _ = initial_run(db)
    bad = missing_exception(db, version, monkeypatch)
    review(db, bad, decision="quarantined")
    queue(db, version, 11)
    return version, bad, repair(db, claim(db), bad, uuid4())


def repair_rule(principal, *, fields=repair_review.FIELDS):
    return policy.LocalRule(
        principal, repair_review.PREVIEW, "allow", repair_review.PURPOSE, repair_review.DESTINATION,
        fields, datetime.now(UTC) - timedelta(days=1),
    )


def repair_service(db):
    connection, tenant, database_url, _, store = db
    credentials = {}
    for principal in (tenant.actor_id, tenant.other_actor_id):
        ref, = connection.execute(
            "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
            (principal,),
        ).fetchone()
        credentials[token_urlsafe(32)] = evidence.SyntheticCredential(
            ref, tenant.space_ref, "synthetic-review", "shanghai", "employee",
            {"search", "read_passage", *evidence.REPAIR_OPERATIONS}, datetime.now(UTC) + timedelta(minutes=5),
        )
    live = {tenant.actor_id, tenant.other_actor_id}
    service = evidence.EvidenceService(
        lambda: open_database(database_url), credentials.get,
        lambda _, probe: authority_for(live)(probe), store,
    )
    return service, tuple(credentials), live


def client_for(service):
    return TestClient(api.create_app(service), base_url="http://127.0.0.1")


def repair_path(run):
    return f"{api.REPAIR_PATH}/{run.run_ref}"


def get_preview(client, token, run):
    return client.get(f"{repair_path(run)}/preview", headers=bearer(token))


def submit_review(client, token, run, preview_id, outcome="approved", *, basis=None, key=None):
    return client.post(
        f"{repair_path(run)}/decision",
        headers=bearer(token) | {"Idempotency-Key": key or uuid4().hex},
        json={"preview_id": preview_id, "outcome": outcome, "basis_id": str(basis or uuid4())},
    )


def test_repaired_candidate_cannot_be_approved_without_reviewing_its_difference(evidence_db, monkeypatch):
    db = evidence_db
    connection, tenant, *_ = db
    version, _, replacement = staged_repair(db, monkeypatch)
    with pytest.raises(processing.QualityConflict, match="preview"):
        review(db, replacement)
    context = request_for(connection, tenant, tenant.actor_id, uuid4().hex, repair_review.DECIDE)
    with pytest.raises(errors.CheckViolation, match="sealed difference preview"):
        connection.execute(
            """
            INSERT INTO thalion.quality_decision (
                org_id, space_id, version_id, run_ref, reviewer_id, request_id, basis_ref, outcome
            )
            SELECT org_id, space_id, version_id, run_ref, %s, %s, %s, 'approved'
            FROM thalion.processing_run WHERE run_ref = %s
            """,
            (tenant.actor_id, context.request_id, uuid4(), replacement.run_ref),
        )
    assert approved(db, version) == ()


@pytest.mark.parametrize("rollback", [False, True], ids=["correction", "rollback"])
def test_repair_preserves_exact_old_revisions_and_needs_review(evidence_db, monkeypatch, rollback):
    db = evidence_db
    connection, tenant, *_ = db
    version, good = initial_run(db)
    old = approved(db, version)
    set_rules(
        db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS), compile_rule(tenant.actor_id),
        replace(compile_rule(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review"),
        replace(compile_rule(tenant.other_actor_id), operation="publish_wiki_revision", purpose="wiki_publication"),
        repair_rule(tenant.actor_id),
    )
    seal = assemble(db, old)
    assert seal.status == "succeeded"
    draft = candidate((db, seal, *old))
    checked = submit(db, draft.ref, preview(db, draft.ref))
    assert authorize(db, draft.ref, checked.ref).status == "succeeded"
    assert read_current(db).status == "succeeded"

    bad = missing_exception(db, version, monkeypatch)
    review(db, bad)
    assert search(db, "Meeting").status == "no_evidence"
    review(db, bad, decision="quarantined")
    queue(db, version, 11)
    basis = uuid4()
    replacement = repair(db, claim(db), bad, basis, good if rollback else None)
    assert replacement.outcome == "pending_review" and replacement.passage_count == 2
    assert approved(db, version) == ()
    assert connection.execute("""
        SELECT replaces_run_ref, rollback_run_ref, repair_basis_ref, manifest_digest
        FROM thalion.processing_run WHERE run_ref = %s
    """, (replacement.run_ref,)).fetchone() == (
        bad.run_ref, good.run_ref if rollback else None, basis, replacement.manifest_digest,
    )
    with pytest.raises(processing.ProcessingNotAdmitted):
        review(db, replacement, principal_id=tenant.other_actor_id)
    service, (reviewer, _), _ = repair_service(db)
    with client_for(service) as client:
        diff = get_preview(client, reviewer, replacement)
        assert diff.status_code == 200, diff.json()
        assert submit_review(client, reviewer, replacement, diff.json()["preview_id"]).status_code == 200
    current = approved(db, version)
    assert [(part.passage_ref, part.digest) for part in current] == [(part.passage_ref, part.digest) for part in old]
    assert [part.revision for part in current] == [3, 2]
    assert connection.execute("""
        SELECT passage.paragraph, excerpt.excerpt_revision FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (passage_id) ORDER BY passage.paragraph, excerpt.excerpt_revision
    """).fetchall() == [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2)]
    found = json.loads(search(db, "Meeting", include_wiki=True).payload)
    assert [part["passage_id"] for part in found["passages"]] == [str(old[1].passage_ref)]
    assert found["wiki"] == [] and read_current(db).payload is None
    assert search(db, "Meeting", authority=withhold(tenant.actor_id, current[1])).status == "no_evidence"
    assert connection.execute("""
        SELECT outcome FROM thalion.quality_decision WHERE run_ref = %s ORDER BY outcome
    """, (bad.run_ref,)).fetchall() == [("approved",), ("quarantined",)]
    assert connection.execute("""
        SELECT run_ref FROM thalion.current_export_transcript(%s, %s, (
            SELECT version_id FROM thalion.processing_run WHERE run_ref = %s
        ))
    """, (tenant.org_id, tenant.space_id, replacement.run_ref)).fetchall() == [(replacement.run_ref,)]


def test_repair_cannot_reopen_unquarantined_or_use_quarantined_baseline(evidence_db, monkeypatch):
    db = evidence_db
    connection, _, *_ = db
    version, good = initial_run(db)
    review(db, good, decision="quarantined")
    bad = missing_exception(db, version, monkeypatch)
    queue(db, version, 11)
    lease = claim(db)
    with pytest.raises(processing.QualityConflict, match="quarantine"):
        repair(db, lease, bad, uuid4())
    review(db, bad, decision="quarantined")
    with pytest.raises(processing.QualityConflict, match="baseline"):
        repair(db, lease, bad, uuid4(), good)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (2,)


@pytest.mark.parametrize("operation", ["no_change", "baseline_mismatch"])
def test_database_rejects_empty_change_or_inexact_rollback(evidence_db, monkeypatch, operation):
    db = evidence_db
    connection, tenant, *_ = db
    version, good = initial_run(db)
    bad = missing_exception(db, version, monkeypatch)
    review(db, bad, decision="quarantined")
    queue(db, version, 11)
    parser = processing.parse_markdown

    def wrong_result(payload):
        parsed = parser(payload)
        return replace(parsed, passages=parsed.passages[:1] if operation == "no_change" else parsed.passages[1:])

    monkeypatch.setattr(processing, "parse_markdown", wrong_result)
    events = pending_events(connection, tenant.org_id, "test")
    lease = claim(db)
    with pytest.raises(errors.CheckViolation, match="repair must change|rollback must match"):
        repair(db, lease, bad, uuid4(), good if operation == "baseline_mismatch" else None)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (2,)
    assert connection.execute("SELECT state FROM thalion.job WHERE job_id = %s", (lease.job_id,)).fetchone() == ("running",)
    assert pending_events(connection, tenant.org_id, "test") == events


@pytest.mark.parametrize("change", ["withdrawal", "newer_run"])
def test_repair_rechecks_safety_after_original_read(evidence_db, monkeypatch, change):
    db = evidence_db
    connection, tenant, database_url, source, store = db
    version, good = initial_run(db)
    bad = missing_exception(db, version, monkeypatch)
    review(db, bad, decision="quarantined")
    queue(db, version, 11)
    lease = claim(db)
    read = store.read

    def change_while_reading(asset):
        payload = read(asset)
        with open_database(database_url) as concurrent:
            other_db = (concurrent, tenant, database_url, source, store)
            if change == "withdrawal":
                effectivity.stop_synthetic_rule(
                    concurrent, record(concurrent, tenant, "stop_rule_use", "withdraw-during-repair"),
                    tenant.space_id, version.version_ref, "withdrawn", uuid4(),
                )
            else:
                queue(other_db, version, 12)
                with monkeypatch.context() as patch:
                    patch.setattr(store, "read", read)
                    processing.process_markdown_job(concurrent, claim(other_db), store)
        return payload

    monkeypatch.setattr(store, "read", change_while_reading)
    with pytest.raises((processing.ProcessingNotAdmitted, processing.QualityConflict)):
        repair(db, lease, bad, uuid4(), good)
    assert connection.execute(
        "SELECT 1 FROM thalion.processing_run WHERE configuration_revision = 11"
    ).fetchone() is None
    assert approved(db, version) == ()


def test_preview_seals_exact_difference_and_rejection(evidence_db, monkeypatch):
    db = evidence_db
    connection, tenant, *_ = db
    version, bad, replacement = staged_repair(db, monkeypatch)
    service, (reviewer, other), _ = repair_service(db)
    set_rules(db, repair_rule(tenant.actor_id), repair_rule(tenant.other_actor_id))
    with client_for(service) as client:
        assert client.get(f"{repair_path(replacement)}/preview").status_code == 401
        assert get_preview(client, other, replacement).status_code == 403
        response = get_preview(client, reviewer, replacement)
        assert response.status_code == 200, response.json()
        assert response.headers["cache-control"] == "no-store"
        preview = response.json()
        diff = preview["difference"]
        assert diff["replaces_run_id"] == str(bad.run_ref)
        assert diff["run_id"] == str(replacement.run_ref)
        assert diff["manifest_sha256"] == replacement.manifest_digest.hex()
        change, = diff["changes"]
        excerpt = change["after"]
        assert change["before"] is None and excerpt["revision"] == 2 and excerpt["paragraph"] == 2
        assert excerpt["excerpt"] == "Meeting accommodation is exempt.\n"
        assert PAYLOAD[excerpt["byte_start"]:excerpt["byte_end"]] == excerpt["excerpt"].encode()
        assert "Hotel limit" not in response.text
        assert rpc(client, reviewer, "tools/list").json()["result"]["tools"] == list(
            tool.model_dump(mode="json", by_alias=True, exclude_none=True) for tool in api.TOOLS
        )
        assert "Meeting accommodation" not in client.get(
            f"/v1/passages/{change['passage_id']}", headers=bearer(reviewer),
        ).text
        assert submit_review(client, other, replacement, preview["preview_id"]).status_code == 403
        assert submit_review(client, reviewer, replacement, str(uuid4())).status_code == 409
        key, basis = uuid4().hex, uuid4()
        rejected = submit_review(client, reviewer, replacement, preview["preview_id"], "quarantined", key=key, basis=basis)
        assert rejected.status_code == 200, rejected.json()
        replay = submit_review(client, reviewer, replacement, preview["preview_id"], "quarantined", key=key, basis=basis)
        assert replay.json()["decision_id"] == rejected.json()["decision_id"]
        assert submit_review(client, reviewer, replacement, preview["preview_id"]).status_code == 409
        assert get_preview(client, reviewer, replacement).status_code == 409
    assert approved(db, version) == ()
    assert connection.execute("""
        SELECT preview.difference_digest, request.outcome, decision.repair_preview_ref::text
        FROM thalion.repair_review_preview AS preview
        JOIN thalion.request_record AS request USING (org_id, request_id)
        JOIN thalion.quality_decision AS decision ON decision.repair_preview_ref = preview.preview_ref
    """).fetchall() == [(sha256(evidence.encode(diff)).digest(), "succeeded", preview["preview_id"])]


@pytest.mark.parametrize("change", ["source_revocation", "newer_run", "withdrawal", "expiry"])
def test_preview_does_not_authorize_a_later_decision(evidence_db, monkeypatch, change):
    db = evidence_db
    connection, tenant, *_, store = db
    version, _, replacement = staged_repair(db, monkeypatch)
    service, (reviewer, _), live = repair_service(db)
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    with client_for(service) as client:
        assert get_preview(client, reviewer, replacement).status_code == 403
        set_rules(db, repair_rule(tenant.actor_id), expected=2)
        if change == "expiry":
            monkeypatch.setattr(repair_review, "PREVIEW_WINDOW", timedelta(seconds=-1))
        response = get_preview(client, reviewer, replacement)
        assert response.status_code == 200, response.json()
        if change == "source_revocation":
            live.remove(tenant.actor_id)
        elif change == "newer_run":
            queue(db, version, 12)
            processing.process_markdown_job(connection, claim(db), store)
        elif change == "withdrawal":
            effectivity.stop_synthetic_rule(
                connection, record(connection, tenant, "stop_rule_use", "withdraw-after-preview"),
                tenant.space_id, version.version_ref, "withdrawn", uuid4(),
            )
        denied = submit_review(client, reviewer, replacement, response.json()["preview_id"])
        assert denied.status_code == (403 if change in {"source_revocation", "withdrawal"} else 409)
        assert '"difference"' not in denied.text
    assert approved(db, version) == ()
    assert connection.execute(
        "SELECT 1 FROM thalion.quality_decision WHERE run_ref = %s", (replacement.run_ref,),
    ).fetchone() is None


def test_source_revocation_during_preview_does_not_seal_or_deliver(evidence_db, monkeypatch):
    db = evidence_db
    connection, tenant, *_, store = db
    _, _, replacement = staged_repair(db, monkeypatch)
    service, (reviewer, _), live = repair_service(db)
    set_rules(db, repair_rule(tenant.actor_id))
    read = store.read

    def revoke(asset):
        payload = read(asset)
        live.remove(tenant.actor_id)
        return payload

    monkeypatch.setattr(store, "read", revoke)
    with client_for(service) as client:
        response = get_preview(client, reviewer, replacement)
        assert response.status_code == 403 and "Meeting accommodation" not in response.text
    assert connection.execute("SELECT count(*) FROM thalion.repair_review_preview").fetchone() == (0,)


def test_repair_page_submits_visible_difference_and_clears_on_account_change(portal, monkeypatch):
    from playwright.sync_api import expect

    page, _, db, (reviewer, other), credentials, _, _, _ = portal
    _, tenant, *_ = db
    _, _, replacement = staged_repair(db, monkeypatch)
    set_rules(db, repair_rule(tenant.actor_id), expected=2)
    credentials[reviewer] = replace(credentials[reviewer], operations=evidence.REPAIR_OPERATIONS)
    credentials[other] = replace(credentials[other], operations=evidence.REPAIR_OPERATIONS)
    page.set_viewport_size({"width": 390, "height": 820})
    shell = page.goto("/manage/repairs")
    assert shell.status == 200 and shell.headers["cache-control"] == "no-store"
    assert "Meeting accommodation" not in shell.text()

    def load(token):
        page.get_by_label("管理测试凭据").fill(token)
        page.get_by_role("button", name="载入审核凭据").click()
        page.get_by_label("校订批次编号").fill(str(replacement.run_ref))
        page.get_by_role("button", name="查看差异").click()

    text = page.get_by_text("Meeting accommodation is exempt.", exact=True)
    load(reviewer)
    expect(text).to_be_visible()
    expect(page.get_by_text("校订前", exact=True)).to_be_visible()
    expect(page.get_by_text("校订后", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-repair-mobile.png")
    page.get_by_role("button", name="更换凭据").click()
    expect(text).to_have_count(0)
    load(other)
    expect(page.get_by_text("此操作未获授权。", exact=True)).to_be_visible()
    expect(text).to_have_count(0)
    page.get_by_role("button", name="更换凭据").click()
    page.set_viewport_size({"width": 1280, "height": 860})
    load(reviewer)
    expect(text).to_be_visible()
    screenshot(page, "management-repair-desktop.png")
    page.get_by_label("审核依据编号").fill(str(uuid4()))
    page.get_by_role("button", name="批准校订").click()
    expect(page.get_by_text("校订已批准。", exact=True)).to_be_visible()
    expect(text).to_have_count(0)
    assert page.evaluate("[localStorage.length, sessionStorage.length, document.cookie]") == [0, 0, ""]
