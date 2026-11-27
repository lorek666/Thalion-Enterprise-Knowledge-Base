from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from psycopg import errors
import pytest

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import docx_evidence, processing, repair_review, rule_rollback
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.modules.sources.registry import SourceWrite
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job
from enterprise_kb.transport import api

from test_docx_repair import incomplete_run
from test_effectivity import BEGIN, approve, record
from test_employee_portal import browser, portal, screenshot
from test_evidence import approved, claim, evidence_db, register_markdown, review
from test_evidence_transport import bearer, evidence_transport, rpc
from test_markdown_repair import PAYLOAD, initial_run, missing_exception, queue, repair_rule
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import open_database, runtime_db
from test_sources import register, request_for
from test_travel_search import SEARCH_FIELDS, corpus, search
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble, compile_rule
from test_wiki_publication import authorize, read_current


RULES_PATH = "/internal/evidence/rules"
RULE_OPS = frozenset({
    "search", "read_passage",
    rule_rollback.READ_IMPACT, rule_rollback.PLAN_ROLLBACK,
    repair_review.PREVIEW, repair_review.DECIDE,
    "decide_hold",
})


def _headers(token: str, key: str | None = None) -> dict[str, str]:
    base = bearer(token)
    if key is not None:
        base["Idempotency-Key"] = key
    return base


def _withdraw(db, version):
    connection, tenant, *_ = db
    ctx = request_for(connection, tenant, tenant.other_actor_id, f"wd-{version.version_ref}", "stop_rule_use")
    effectivity.stop_synthetic_rule(connection, ctx, tenant.space_id, version.version_ref, "withdrawn", uuid4())

def _register_with_baseline(db, *, object_key: str, source_ref: UUID | None = None, reviewer_id: int | None = None,
                            payload: bytes = PAYLOAD, approve_baseline: bool = True):
    connection, tenant, _, default_source, store = db
    ver = register(
        connection, tenant, source_ref or default_source, store,
        key=str(uuid4()), object_key=object_key, display_name=f"Policy {object_key}",
        digest=sha256(payload).digest(), payload=payload,
    )
    run = processing.process_markdown_job(connection, claim(db), store)
    if approve_baseline:
        review(db, run, principal_id=reviewer_id)
    approve(connection, tenant, ver, BEGIN)
    return ver, run


def _run_faulty_10(db, version, monkeypatch):
    connection, tenant, *_ = db
    connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT 10, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
        ON CONFLICT (configuration_revision) DO NOTHING
    """)
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 10))
    parser = processing.parse_markdown

    def omit_clause(payload):
        parsed = parser(payload)
        return replace(parsed, passages=parsed.passages[:1])

    with monkeypatch.context() as patch:
        patch.setattr(processing, "parse_markdown", omit_clause)
        run = processing.process_markdown_job(connection, claim(db), db[-1])
    assert run.passage_count == 1
    return run


def test_rule_rollback_migration_and_db_guards(database_url, evidence_db, monkeypatch):
    assert upgrade(database_url) == ["0113_source_connector_cursor"]
    connection, tenant, _, source, _ = evidence_db
    source_id = connection.execute(
        "SELECT object_id FROM thalion.object_identity WHERE org_id = %s AND space_id = %s AND object_type = 'source' AND public_id = %s",
        (tenant.org_id, tenant.space_id, source),
    ).fetchone()[0]
    version, baseline = initial_run(evidence_db)
    version_id = connection.execute(
        "SELECT object_id FROM thalion.object_identity WHERE org_id = %s AND space_id = %s AND object_type = 'document_version' AND public_id = %s",
        (tenant.org_id, tenant.space_id, version.version_ref),
    ).fetchone()[0]
    bad = missing_exception(evidence_db, version, monkeypatch)
    q_dec = review(evidence_db, bad, decision="quarantined")
    _withdraw(evidence_db, version)

    # Insert a compatible target configuration revision and a fake parse job.
    connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT 20, parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE configuration_revision = 10
    """)
    job_id = enqueue_job(
        connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 20),
    )
    rb_ctx = request_for(connection, tenant, tenant.actor_id, "guard-rb-req", rule_rollback.PLAN_ROLLBACK)
    req_id = rb_ctx.request_id

    # Incompatible target profile/parser must be rejected by DB trigger.
    connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        VALUES (21, '9.9.9', 'pdf_pages_v1', 1)
    """)
    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute("""
                INSERT INTO thalion.processing_rule_rollback (
                    org_id, space_id, faulty_configuration_revision, target_configuration_revision,
                    actor_id, request_id, basis_ref, reason_code, quarantined_count, queued_count, skipped_count
                ) VALUES (%s, %s, 10, 21, %s, %s, %s, 'bad_compat', 0, 1, 0)
            """, (tenant.org_id, tenant.space_id, tenant.actor_id, req_id, uuid4()))

    # Queuing a stopped/withdrawn version directly in SQL must be rejected by DB trigger.
    with connection.transaction():
        rb_ref = connection.execute("""
            INSERT INTO thalion.processing_rule_rollback (
                org_id, space_id, faulty_configuration_revision, target_configuration_revision,
                actor_id, request_id, basis_ref, reason_code, quarantined_count, queued_count, skipped_count
            ) VALUES (%s, %s, 10, 20, %s, %s, %s, 'guard_check', 1, 1, 0)
            RETURNING rollback_ref
        """, (tenant.org_id, tenant.space_id, tenant.actor_id, req_id, uuid4())).fetchone()[0]
        with pytest.raises(errors.CheckViolation):
            with connection.transaction():
                connection.execute("""
                    INSERT INTO thalion.processing_rule_rollback_item (
                        rollback_ref, org_id, space_id, source_id, version_id,
                        faulty_run_ref, baseline_run_ref, action, skip_reason,
                        quarantine_decision_ref, queued_job_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued_rollback', NULL, %s, %s)
                """, (
                    rb_ref, tenant.org_id, tenant.space_id, source_id, version_id,
                    bad.run_ref, baseline.run_ref, q_dec, job_id,
                ))

    # Rollback audit header is immutable.
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        with connection.transaction():
            connection.execute(
                "UPDATE thalion.processing_rule_rollback SET reason_code = 'tampered' WHERE rollback_ref = %s",
                (rb_ref,),
            )


def test_cross_batch_rule_impact_and_rollback_closure(evidence_transport, monkeypatch):
    service, db, (owner, reviewer), credentials, live, _, _ = evidence_transport
    connection, tenant, _, source, store = db

    from enterprise_kb.modules.sources import registry

    src2_ctx = request_for(connection, tenant, tenant.actor_id, "create-second-rb-source", "register_source_contract")
    source2 = registry.register_synthetic_source(
        connection, src2_ctx, tenant.space_id,
        registry.SyntheticSource(
            "travel-extra", "travel-extra-archive", tenant.worker_id,
            approver_id=tenant.other_actor_id, processor_id=tenant.other_worker_id,
            quality_reviewer_id=tenant.other_actor_id,
        ),
    )

    # 1. Active version A with baseline + published Wiki referencing faulty run 10.
    ver_a, base_a = _register_with_baseline(db, object_key="rb-a")
    bad_a = _run_faulty_10(db, ver_a, monkeypatch)
    review(db, bad_a, decision="approved")
    bad_a_passages = approved(db, ver_a)
    # Publish a Wiki depending on faulty run 10 of ver_a.
    current_epoch = connection.execute(
        """
        SELECT s.safety_epoch FROM thalion.source AS s
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (s.org_id, s.space_id, 'source', s.source_id)
        WHERE oi.org_id = %s AND oi.space_id = %s AND oi.public_id = %s
        """,
        (tenant.org_id, tenant.space_id, source),
    ).fetchone()[0]
    set_rules(
        db,
        replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        binding(tenant.other_actor_id),
        compile_rule(tenant.actor_id),
        repair_rule(tenant.actor_id),
        *[policy.LocalRule(tenant.other_actor_id, op, "allow", purpose, dest, policy.WORKSPACE_EVIDENCE_FIELDS,
                           datetime.now(UTC) - timedelta(days=1))
          for op, purpose, dest in (policy.WIKI_REVIEW_ACCESS, policy.WIKI_PUBLISH_ACCESS)],
        expected=current_epoch,
    )
    p_item = bad_a_passages[0]
    manifest = assemble(db, [p_item], authority=authority_for(live))
    assert manifest.status == "succeeded"
    created = candidate(
        (db, manifest, p_item, None), topic="travel", authority=authority_for(live),
    )
    assert created.status == "succeeded" and created.ref is not None
    mat = preview(db, created.ref, authority=authority_for(live))
    assert mat.status == "succeeded"
    reviewed = submit(db, created.ref, mat, authority=authority_for(live))
    assert reviewed.status == "succeeded" and reviewed.ref is not None
    pub = authorize(db, created.ref, reviewed.ref, authority=authority_for(live))
    assert pub.status == "succeeded"
    assert read_current(db, authority=authority_for(live)).status == "succeeded"

    # 2. Active version B with baseline + faulty run 10 (pending_review).
    ver_b, base_b = _register_with_baseline(db, object_key="rb-b")
    bad_b = _run_faulty_10(db, ver_b, monkeypatch)

    # 3. Withdrawn version C with baseline + faulty run 10 (must stay stopped).
    ver_c, _ = _register_with_baseline(db, object_key="rb-c")
    bad_c = _run_faulty_10(db, ver_c, monkeypatch)
    _withdraw(db, ver_c)

    # 4. Held version D with baseline + faulty run 10 (must stay untouched).
    ver_d, _ = _register_with_baseline(db, object_key="rb-d")
    bad_d = _run_faulty_10(db, ver_d, monkeypatch)

    # 5. Version E processed only by faulty run 10 (no approved baseline -> quarantine stop-loss, skip auto-rollback).
    ver_e, _ = _register_with_baseline(
        db, object_key="rb-e", payload=b"# Only Faulty\n\nNo baseline here.\n", approve_baseline=False,
    )
    bad_e = _run_faulty_10(db, ver_e, monkeypatch)

    # 6. Version F in source2 (reviewed by other_actor_id, not owner) -> tests reviewer separation.
    ver_f, _ = _register_with_baseline(
        db, object_key="rb-f", source_ref=source2, reviewer_id=tenant.other_actor_id,
    )
    bad_f = _run_faulty_10(db, ver_f, monkeypatch)

    credentials[owner] = replace(credentials[owner], operations=RULE_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=RULE_OPS)
    no_op_token = "no-rule-access-token-1234567890abcdef"
    credentials[no_op_token] = replace(credentials[owner], operations=frozenset({"search", "read_passage"}))

    with TestClient(api.create_app(service), base_url="http://127.0.0.1:8765") as client:
        # Establish custody hold on version D via independent custodian (reviewer).
        hold_resp = client.post(
            "/internal/lifecycle/holds",
            headers=_headers(reviewer, f"hold-{ver_d.version_ref}"),
            json={
                "version_id": str(ver_d.version_ref), "action": "establish",
                "expected_generation": 0, "basis_id": str(uuid4()),
            },
        )
        assert hold_resp.status_code == 200

        # Unauthorized employee & MCP boundary checks.
        assert client.get(RULES_PATH, headers=bearer(no_op_token)).status_code == 403
        assert client.get(f"{RULES_PATH}/10/impact", headers=bearer(no_op_token)).status_code == 403
        tools_reply = rpc(client, owner, "tools/list")
        tool_names = {tool["name"] for tool in tools_reply.json()["result"]["tools"]}
        assert rule_rollback.READ_IMPACT not in tool_names
        assert rule_rollback.PLAN_ROLLBACK not in tool_names

        # Catalog & Impact inventory return metadata only (zero content/topic_key leak).
        # Owner (space owner + reviewer of source 1) sees all 6 runs across both sources.
        catalog = client.get(RULES_PATH, headers=bearer(owner))
        assert catalog.status_code == 200
        assert any(r["configuration_revision"] == 10 and r["run_count"] == 6 for r in catalog.json()["revisions"])

        # Reviewer (only reviewer of source 2, not space owner) sees ONLY source 2's 1 run.
        rev_impact = client.get(f"{RULES_PATH}/10/impact", headers=bearer(reviewer))
        assert rev_impact.status_code == 200
        assert rev_impact.json()["summary"]["total_runs"] == 1
        assert rev_impact.json()["items"][0]["run_id"] == str(bad_f.run_ref)

        impact_resp = client.get(f"{RULES_PATH}/10/impact", headers=bearer(owner))
        assert impact_resp.status_code == 200
        raw_text = impact_resp.text
        assert "Hotel limit" not in raw_text and "rollback-wiki" not in raw_text and "No baseline" not in raw_text
        impact = impact_resp.json()
        assert impact["summary"]["total_runs"] == 6
        assert impact["summary"]["rollback_eligible"] == 2
        assert impact["summary"]["stopped_or_deleted"] == 1
        assert impact["summary"]["held"] == 1
        assert len(impact["summary"]["affected_wikis"]) == 1

        by_run = {item["run_id"]: item for item in impact["items"]}
        assert by_run[str(bad_a.run_ref)]["rollback_eligible"] is True
        assert by_run[str(bad_a.run_ref)]["baseline_run_id"] == str(base_a.run_ref)
        assert len(by_run[str(bad_a.run_ref)]["affected_wiki_ids"]) == 1
        assert by_run[str(bad_b.run_ref)]["rollback_eligible"] is True
        assert "version_stopped" in by_run[str(bad_c.run_ref)]["ineligible_reasons"]
        assert "custody_hold" in by_run[str(bad_d.run_ref)]["ineligible_reasons"]
        assert "no_approved_baseline" in by_run[str(bad_e.run_ref)]["ineligible_reasons"]
        # Space owner is NOT quality_reviewer_id for source2 -> cannot bypass reviewer separation on bad_f.
        assert "requires_reviewer_quarantine" in by_run[str(bad_f.run_ref)]["ineligible_reasons"]

        # Owner triggers cross-batch rule rollback across space (idempotent + conflict check).
        basis = str(uuid4())
        rb_body = {"reason_code": "missing_exception_clause", "basis_id": basis}
        first_rb = client.post(f"{RULES_PATH}/10/rollback", headers=_headers(owner, "rb-10-k1"), json=rb_body)
        assert first_rb.status_code == 200
        rb_data = first_rb.json()
        assert rb_data["quarantined_count"] == 3  # bad_a, bad_b, bad_e (bad_c stopped, bad_d held, bad_f separate reviewer)
        assert rb_data["queued_count"] == 2  # bad_a, bad_b
        assert rb_data["skipped_count"] == 4  # bad_c, bad_d, bad_e, bad_f
        assert rb_data["target_configuration_revision"] > 10

        # Exact idempotent replay returns same receipt; mismatched payload conflicts 409.
        replay = client.post(f"{RULES_PATH}/10/rollback", headers=_headers(owner, "rb-10-k1"), json=rb_body)
        assert replay.status_code == 200 and replay.json()["rollback_id"] == rb_data["rollback_id"]
        conflict = client.post(
            f"{RULES_PATH}/10/rollback", headers=_headers(owner, "rb-10-k1"),
            json={"reason_code": "different_reason", "basis_id": basis},
        )
        assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "rule_rollback_conflict"

        # Published Wiki depending on bad_a was automatically suspended on quarantine!
        assert read_current(db, authority=authority_for(live)).status != "succeeded"

        # Execute queued rollback jobs -> produces pending_review candidate runs matching exact baselines.
        exec_items = rule_rollback.execute_rule_rollback(
            connection, tenant.org_id, tenant.space_id, UUID(rb_data["rollback_id"]), store,
        )
        assert len(exec_items) == 2
        assert all(item.status == "pending_review" and item.rollback_run_ref is not None for item in exec_items)

        # Approve both rolled-back runs via standard repair preview + decision flow.
        for item in exec_items:
            prev_resp = client.get(f"/internal/evidence/repairs/{item.rollback_run_ref}/preview", headers=bearer(owner))
            assert prev_resp.status_code == 200
            preview_id = prev_resp.json()["preview_id"]
            dec_resp = client.post(
                f"/internal/evidence/repairs/{item.rollback_run_ref}/decision",
                headers=_headers(owner, f"approve-{item.rollback_run_ref}"),
                json={"preview_id": preview_id, "outcome": "approved", "basis_id": str(uuid4())},
            )
            assert dec_resp.status_code == 200 and dec_resp.json()["outcome"] == "approved"

        # Re-running execute_rule_rollback is idempotent (already_completed).
        rerun = rule_rollback.execute_rule_rollback(
            connection, tenant.org_id, tenant.space_id, UUID(rb_data["rollback_id"]), store,
        )
        assert all(item.status == "already_completed" for item in rerun)

        # Restored exception clause is searchable again for ver_a / ver_b, while stopped ver_c stays blocked,
        # and suspended Wiki still requires clean rebuild + independent approval.
        delivered = search(db, "exempt", day=BEGIN, authority=authority_for(live))
        assert delivered.status == "succeeded"
        hits = json.loads(delivered.payload)["passages"]
        assert len(hits) >= 2
        hit_versions = {hit["version_id"] for hit in hits}
        assert str(ver_a.version_ref) in hit_versions and str(ver_b.version_ref) in hit_versions
        assert str(ver_c.version_ref) not in hit_versions
        assert read_current(db, authority=authority_for(live)).status != "succeeded"


def test_cross_batch_rule_rollback_supports_docx_and_tables(evidence_db, monkeypatch):
    connection, tenant, *_ = evidence_db
    store = evidence_db[-1]
    _, baseline, bad_run, _ = incomplete_run(evidence_db, monkeypatch)
    faulty_cfg = connection.execute(
        "SELECT configuration_revision FROM thalion.processing_run WHERE run_ref = %s",
        (bad_run.run_ref,),
    ).fetchone()[0]

    rb_ctx = request_for(connection, tenant, tenant.actor_id, f"docx-rb-{faulty_cfg}", rule_rollback.PLAN_ROLLBACK)
    receipt = rule_rollback.plan_rule_rollback(
        connection, rb_ctx, tenant.space_id, faulty_cfg, "docx_clause_dropped", uuid4(),
    )
    assert receipt["queued_count"] == 1 and receipt["skipped_count"] == 0
    exec_items = rule_rollback.execute_rule_rollback(
        connection, tenant.org_id, tenant.space_id, UUID(receipt["rollback_id"]), store,
    )
    assert len(exec_items) == 1 and exec_items[0].status == "pending_review"
    assert exec_items[0].rollback_run_ref is not None
    assert connection.execute(
        "SELECT thalion.docx_runs_match(%s, %s)", (baseline.run_ref, exec_items[0].rollback_run_ref),
    ).fetchone()[0]


def test_repair_management_page_rule_impact_and_rollback_ui(portal, monkeypatch):
    from playwright.sync_api import expect

    page, _, db, (owner, _), credentials, _, _, _ = portal
    ver, _ = initial_run(db)
    missing_exception(db, ver, monkeypatch)
    credentials[owner] = replace(credentials[owner], operations=RULE_OPS)

    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/manage/repairs")
    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="载入审核凭据").click()
    expect(page.get_by_role("heading", name="清洗规则影响清单与跨批次回退")).to_be_visible()

    page.get_by_role("button", name="载入规则目录").click()
    expect(page.locator("#repair-rule-catalog-status")).to_contain_text("已载入")
    page.get_by_role("button", name="查此规则影响").first.click()
    expect(page.locator("#repair-rule-status")).to_contain_text("规则 #10")
    expect(page.locator("#repair-rule-status")).to_contain_text("可自动回退 1")

    page.get_by_label("回退依据编号").fill(str(uuid4()))
    page.get_by_role("button", name="发起跨批次规则回退").click()
    expect(page.locator("#repair-rule-rollback-status")).to_contain_text("已登记规则回退")
    expect(page.locator("#repair-rule-rollback-status")).to_contain_text("已排入回退 1")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-rule-rollback-desktop.png")

    # Mobile viewport check (390px) and sign-out screen clearing.
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-rule-rollback-mobile.png")

    page.get_by_role("button", name="更换凭据").click()
    assert page.locator("#repair-rule-status").inner_text() == ""
    assert page.locator("#repair-rule-rollback-status").inner_text() == ""
