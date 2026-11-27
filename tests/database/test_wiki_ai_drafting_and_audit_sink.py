from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import httpx2
import pytest

from enterprise_kb.modules.access import policy
from enterprise_kb.ports.adapters import (
    HttpModelGatewayAdapter,
    HttpSecurityAuditLogAdapter,
    OpenAiCompatibleModelGatewayAdapter,
)
from enterprise_kb.runtime.audit_sink import FORBIDDEN_AUDIT_KEYS
from enterprise_kb.runtime.config import AuthenticatedEndpointConfig
from enterprise_kb.transport import api, evidence

from test_employee_portal import browser, loopback_page
from test_evidence import create_evidence_db
from test_evidence_transport import bearer, evidence_transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_travel_search import BEFORE, SEARCH_FIELDS, corpus


@pytest.fixture
def evidence_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    return create_evidence_db(connection, tenant, database_url, tmp_path, model_policy_approver_id=tenant.other_actor_id)


def _setup_wiki_and_model_policies(db, first, second, *, allow_model_egress: bool = True):
    connection, tenant, _, source_ref, _ = db
    now = datetime.now(UTC)
    compile_rule = policy.LocalRule(
        tenant.actor_id, policy.WIKI_INPUT_ACCESS[0], "allow",
        policy.WIKI_INPUT_ACCESS[1], policy.WIKI_INPUT_ACCESS[2],
        policy.WORKSPACE_EVIDENCE_FIELDS, now - timedelta(hours=1),
    )
    review_rule = policy.LocalRule(
        tenant.other_actor_id, policy.WIKI_REVIEW_ACCESS[0], "allow",
        policy.WIKI_REVIEW_ACCESS[1], policy.WIKI_REVIEW_ACCESS[2],
        policy.WORKSPACE_EVIDENCE_FIELDS, now - timedelta(hours=1),
    )
    publish_rule = replace(review_rule, operation=policy.WIKI_PUBLISH_ACCESS[0], purpose=policy.WIKI_PUBLISH_ACCESS[1])
    author_read = replace(binding(tenant.actor_id), fields=SEARCH_FIELDS)
    reviewer_read = replace(binding(tenant.other_actor_id), fields=SEARCH_FIELDS)
    set_rules(db, compile_rule, review_rule, publish_rule, author_read, reviewer_read, expected=2)
    if allow_model_egress:
        from test_sources import request_for

        egress_rules = (
            policy.LocalRule(
                tenant.actor_id,
                policy.MODEL_RULE_OPERATION,
                "allow",
                "wiki_compilation",
                policy.SYNTHETIC_MODEL_DESTINATION,
                frozenset({"excerpt"}),
                now - timedelta(hours=1),
                now + timedelta(hours=2),
                first.passage_ref,
            ),
            policy.LocalRule(
                tenant.actor_id,
                policy.MODEL_RULE_OPERATION,
                "allow",
                "wiki_compilation",
                policy.SYNTHETIC_MODEL_DESTINATION,
                frozenset({"excerpt"}),
                now - timedelta(hours=1),
                now + timedelta(hours=2),
                second.passage_ref,
            ),
        )
        ctx = request_for(connection, tenant, tenant.other_actor_id, str(uuid4()), policy.REPLACE_MODEL)
        policy.replace_synthetic_policy(
            connection, ctx, tenant.space_id, source_ref, 3, egress_rules, uuid4(), model_egress=True,
        )


def test_ai_wiki_drafting_enforces_egress_anti_hallucination_ledger_and_audit_sink(evidence_transport, corpus, monkeypatch):
    monkeypatch.setenv("THALION_GW_CRED", "gw-secret")
    monkeypatch.setenv("THALION_AUDIT_CRED", "audit-secret")
    service, db, (author, reviewer), credentials, _, first, second = evidence_transport
    connection, tenant, _, source_ref, _ = db
    admit(
        credentials, author,
        "read_wiki_status", "assemble_wiki_inputs", "create_wiki_candidate",
        "read_local_policy", "replace_local_policy",
    )
    admit(
        credentials, reviewer,
        "read_wiki_status", "read_wiki_candidate", "review_wiki_revision", "publish_wiki_revision",
    )
    _setup_wiki_and_model_policies(db, first, second, allow_model_egress=False)

    gateway_state = {"calls": 0, "mode": "valid"}
    audit_events: list[dict] = []
    audit_state = {"down": False, "gen": 0}
    log_ref = uuid4()

    def gateway_handler(request: httpx2.Request) -> httpx2.Response:
        gateway_state["calls"] += 1
        body = json.loads(request.content)
        assert body["purpose"] == "wiki_compilation"
        assert body["destination_id"] == policy.SYNTHETIC_MODEL_DESTINATION
        if gateway_state["mode"] == "timeout":
            raise httpx2.ReadTimeout("gateway timeout")
        if gateway_state["mode"] == "hallucinated":
            draft_obj = {
                "title": "AI 差旅指南",
                "markdown": "# 差旅\n上海住宿 600 元。",
                "citations": [[str(uuid4()), 1]],
            }
        else:
            draft_obj = {
                "title": "AI 差旅住宿指南",
                "markdown": "# 上海住宿\n依据原文，上海住宿限额见引文。",
                "citations": [[str(first.passage_ref), first.revision]],
                "statements": [
                    {
                        "text": "上海住宿限额以适用规则为准。",
                        "support_groups": [[[str(first.passage_ref), first.revision]]],
                    }
                ],
            }
        output_utf8 = json.dumps(draft_obj, ensure_ascii=False, separators=(",", ":"))
        digest_hex = sha256(output_utf8.encode("utf-8")).hexdigest()
        if gateway_state["mode"] == "tampered":
            digest_hex = "0" * 64
        return httpx2.Response(
            200,
            json={
                "provider_call_id": f"gw-call-{gateway_state['calls']}",
                "accepted": True,
                "input_tokens": 320,
                "output_tokens": 110,
                "billed_microunits": 4500,
                "output_digest": digest_hex,
                "output_utf8": output_utf8,
            },
        )

    def audit_handler(request: httpx2.Request) -> httpx2.Response:
        if audit_state["down"]:
            return httpx2.Response(503, text="audit sink down")
        payload = json.loads(request.content)
        assert not (FORBIDDEN_AUDIT_KEYS & set(payload))
        audit_events.append(payload)
        audit_state["gen"] += 1
        return httpx2.Response(
            200,
            json={
                "log_ref": str(log_ref),
                "stream_ref": str(uuid4()),
                "generation": audit_state["gen"],
                "recorded_at": datetime.now(UTC).isoformat(),
                "digest": sha256(request.content).hexdigest(),
            },
        )

    secrets = {"env:THALION_GW_CRED": "gw-secret", "env:THALION_AUDIT_CRED": "audit-secret"}
    gw = HttpModelGatewayAdapter(
        AuthenticatedEndpointConfig("https://gw.corp.example/v1", "env:THALION_GW_CRED"),
        destination_id=policy.SYNTHETIC_MODEL_DESTINATION,
        allowed_purposes=frozenset({"wiki_compilation"}),
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(gateway_handler),
    )
    audit_port = HttpSecurityAuditLogAdapter(
        AuthenticatedEndpointConfig("https://audit.corp.example/v1", "env:THALION_AUDIT_CRED"),
        log_ref=log_ref,
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(audit_handler),
    )

    wired = evidence.EvidenceService(
        service.connect,
        service.verify_token,
        service.check_source,
        service.store,
        retest_key=service.retest_key,
        backup_store=service.backup_store,
        model_gateway=gw,
        security_audit_log=audit_port,
        strict_audit_sink=True,
    )

    with TestClient(api.create_app(wired), base_url="http://127.0.0.1") as client:
        # 1. Seal manifest containing BOTH first (will be cited) and second (uncited input)
        sealed = client.post(
            "/internal/wiki/inputs",
            headers=bearer(author),
            json={
                "business_date": BEFORE.isoformat(),
                "direct": [[str(first.passage_ref), first.revision], [str(second.passage_ref), second.revision]],
            },
        )
        assert sealed.status_code == 200
        manifest_id = sealed.json()["manifest_id"]

        gen_body = {
            "business_date": BEFORE.isoformat(),
            "topic_key": "travel-ai-guide",
            "manifest_id": manifest_id,
            "reviewer_ref": str(credentials[reviewer].employee_ref),
            "basis_id": str(uuid4()),
            "title_hint": "差旅住宿指南",
            "instructions": "请提炼上海住宿上限并附带原文引文",
            "max_microunits": 50000,
        }

        # 2. Without model_egress policy -> 403 and ZERO outbound gateway calls
        no_egress = client.post(
            "/internal/wiki/revisions/generate",
            headers=command_headers(author),
            json=gen_body,
        )
        assert no_egress.status_code == 403
        assert gateway_state["calls"] == 0

        # 3. Grant model egress for both passages via independent approver
        now = datetime.now(UTC)
        from test_sources import request_for

        egress_rules = (
            policy.LocalRule(
                tenant.actor_id, policy.MODEL_RULE_OPERATION, "allow", "wiki_compilation",
                policy.SYNTHETIC_MODEL_DESTINATION, frozenset({"excerpt"}),
                now - timedelta(hours=1), now + timedelta(hours=2), first.passage_ref,
            ),
            policy.LocalRule(
                tenant.actor_id, policy.MODEL_RULE_OPERATION, "allow", "wiki_compilation",
                policy.SYNTHETIC_MODEL_DESTINATION, frozenset({"excerpt"}),
                now - timedelta(hours=1), now + timedelta(hours=2), second.passage_ref,
            ),
        )
        ctx = request_for(connection, tenant, tenant.other_actor_id, str(uuid4()), policy.REPLACE_MODEL)
        policy.replace_synthetic_policy(
            connection, ctx, tenant.space_id, source_ref, 3, egress_rules, uuid4(), model_egress=True,
        )

        # 4. Hallucinated citation outside manifest -> 403, no wiki_revision created
        gateway_state["mode"] = "hallucinated"
        hallucinated = client.post(
            "/internal/wiki/revisions/generate",
            headers=command_headers(author),
            json=gen_body,
        )
        assert hallucinated.status_code == 403
        assert connection.execute("SELECT count(*) FROM thalion.wiki_revision WHERE org_id = %s", (tenant.org_id,)).fetchone() == (0,)

        # 5. Gateway timeout -> 503 dependency_unavailable + outcome_unknown recorded in ledger
        gateway_state["mode"] = "timeout"
        timed_out = client.post(
            "/internal/wiki/revisions/generate",
            headers=command_headers(author),
            json=gen_body,
        )
        assert timed_out.status_code == 503
        assert connection.execute(
            "SELECT count(*) FROM thalion.external_call WHERE org_id = %s AND state = 'outcome_unknown'",
            (tenant.org_id,),
        ).fetchone()[0] >= 1

        # 6. Tampered digest -> 503 dependency_unavailable
        gateway_state["mode"] = "tampered"
        tampered = client.post(
            "/internal/wiki/revisions/generate",
            headers=command_headers(author),
            json=gen_body,
        )
        assert tampered.status_code == 503

        # 7. Self-review forbidden even before calling gateway
        gateway_state["mode"] = "valid"
        calls_before = gateway_state["calls"]
        self_review = client.post(
            "/internal/wiki/revisions/generate",
            headers=command_headers(author),
            json=gen_body | {"reviewer_ref": str(credentials[author].employee_ref)},
        )
        assert self_review.status_code == 403
        assert gateway_state["calls"] == calls_before

        # 8. Valid AI generation succeeds, logs ledger + external audit, stays awaiting independent review
        generated = client.post(
            "/internal/wiki/revisions/generate",
            headers=command_headers(author),
            json=gen_body,
        )
        assert generated.status_code == 200
        gen_payload = generated.json()
        revision_id = gen_payload["revision_id"]
        assert gen_payload["title"] == "AI 差旅住宿指南"
        assert gen_payload["billed_microunits"] == 4500
        assert gen_payload["input_tokens"] == 320
        assert gen_payload["output_tokens"] == 110
        assert gen_payload["citations"] == [[str(first.passage_ref), first.revision]]
        # Manifest retains BOTH passages (including uncited second)
        manifest_count = connection.execute(
            "SELECT count(*) FROM thalion.input_manifest_entry WHERE manifest_ref = %s",
            (UUID(manifest_id),),
        ).fetchone()[0]
        assert manifest_count == 2
        # Audit event emitted without leaking content
        assert any(ev["event_type"] == "security.wiki_ai_draft_generated" and ev["resource_ref"] == revision_id for ev in audit_events)
        assert all("上海住宿" not in json.dumps(ev, ensure_ascii=False) for ev in audit_events)

        # 9. Independent reviewer previews, approves, and publishes -> audit sink records publication
        preview = client.post(
            f"/internal/wiki/revisions/{revision_id}/preview",
            headers=bearer(reviewer),
            json={"business_date": BEFORE.isoformat()},
        )
        assert preview.status_code == 200
        prev_body = preview.json()
        reviewed = client.post(
            f"/internal/wiki/revisions/{revision_id}/review",
            headers=command_headers(reviewer),
            json={
                "business_date": BEFORE.isoformat(),
                "decision": "approved",
                "reason_code": "verified_ai_draft",
                "basis_id": str(uuid4()),
                "review_material_id": prev_body["review_material_id"],
                "content_digest": prev_body["content_digest"],
                "input_digest": prev_body["input_digest"],
            },
        )
        assert reviewed.status_code == 200
        review_id = reviewed.json()["review_id"]

        # 10. Strict audit sink failure blocks policy mutation atomically (rollback, HTTP 503)
        audit_state["down"] = True
        current_policy = client.get(f"/internal/sources/{source_ref}/access-policy", headers=bearer(author)).json()
        blocked_write = client.post(
            f"/internal/sources/{source_ref}/access-policy",
            headers=command_headers(author),
            json={
                "expected_epoch": current_policy["safety_epoch"],
                "basis_id": str(uuid4()),
                "rules": current_policy["rules"],
            },
        )
        assert blocked_write.status_code == 503
        after_blocked = client.get(f"/internal/sources/{source_ref}/access-policy", headers=bearer(author)).json()
        assert after_blocked["policy_revision"] == current_policy["policy_revision"]

        # 11. Restore audit sink and publish successfully
        audit_state["down"] = False
        published = client.post(
            f"/internal/wiki/revisions/{revision_id}/publish",
            headers=command_headers(reviewer),
            json={"business_date": BEFORE.isoformat(), "review_id": review_id},
        )
        assert published.status_code == 200
        pub_id = published.json()["publication_id"]
        assert any(ev["event_type"] == "security.wiki_published" and ev["resource_ref"] == pub_id for ev in audit_events)


def test_manage_wiki_browser_ai_generate_button(browser, evidence_transport, corpus, monkeypatch):
    monkeypatch.setenv("THALION_GW_CRED", "gw-secret")
    from playwright.sync_api import expect

    service, db, (author, reviewer), credentials, _, first, second = evidence_transport
    admit(credentials, author, "read_wiki_status", "assemble_wiki_inputs", "create_wiki_candidate")
    admit(credentials, reviewer, "read_wiki_status", "read_wiki_candidate", "review_wiki_revision", "publish_wiki_revision")
    _setup_wiki_and_model_policies(db, first, second, allow_model_egress=True)

    def gateway_handler(request: httpx2.Request) -> httpx2.Response:
        draft_obj = {
            "title": "浏览器 AI 生成草稿",
            "markdown": "# 上海出差\nAI 自动整理的差旅说明。",
            "citations": [[str(first.passage_ref), first.revision]],
        }
        output_utf8 = json.dumps(draft_obj, ensure_ascii=False, separators=(",", ":"))
        return httpx2.Response(
            200,
            json={
                "provider_call_id": "browser-gw-1",
                "accepted": True,
                "input_tokens": 120,
                "output_tokens": 60,
                "billed_microunits": 1200,
                "output_digest": sha256(output_utf8.encode("utf-8")).hexdigest(),
                "output_utf8": output_utf8,
            },
        )

    gw = HttpModelGatewayAdapter(
        AuthenticatedEndpointConfig("https://gw.corp.example/v1", "env:THALION_GW_CRED"),
        destination_id=policy.SYNTHETIC_MODEL_DESTINATION,
        allowed_purposes=frozenset({"wiki_compilation"}),
        secret_resolver={"env:THALION_GW_CRED": "gw-secret"}.__getitem__,
        transport=httpx2.MockTransport(gateway_handler),
    )
    wired = evidence.EvidenceService(
        service.connect, service.verify_token, service.check_source, service.store,
        retest_key=service.retest_key, backup_store=service.backup_store, model_gateway=gw,
    )
    with loopback_page(browser, wired, "/manage/wiki") as (page, _, _):
        page.fill("#wiki-token", author)
        page.get_by_role("button", name="查看发布台账").click()
        expect(page.locator("#wiki-workspace")).to_be_visible()
        page.fill("#wiki-business-date", BEFORE.isoformat())
        page.fill("#wiki-direct-inputs", f"{first.passage_ref}:{first.revision}")
        page.get_by_role("button", name="组装并封存输入清单").click()
        expect(page.locator("#wiki-inputs-status")).to_contain_text("已封存输入清单")
        page.fill("#wiki-topic-key", "browser-ai-topic")
        page.fill("#wiki-reviewer-ref", str(credentials[reviewer].employee_ref))
        page.fill("#wiki-ai-instructions", "简洁整理要点")
        page.get_by_role("button", name="AI 辅助生成待审草稿").click()
        expect(page.locator("#wiki-candidate-status")).to_contain_text("AI 已生成待审修订")
        expect(page.locator("#wiki-draft-title")).to_have_value("浏览器 AI 生成草稿")


def test_openai_compatible_gateway_generates_verified_wiki_draft_from_allowed_citations(evidence_transport, corpus, monkeypatch):
    monkeypatch.setenv("THALION_GW_CRED", "gw-secret")
    service, db, (author, reviewer), credentials, _, first, second = evidence_transport
    admit(credentials, author, "read_wiki_status", "assemble_wiki_inputs", "create_wiki_candidate")
    admit(credentials, reviewer, "read_wiki_status", "read_wiki_candidate", "review_wiki_revision")
    _setup_wiki_and_model_policies(db, first, second, allow_model_egress=True)

    captured: list[dict] = []

    def openai_handler(request: httpx2.Request) -> httpx2.Response:
        assert str(request.url) == "https://llm.corp.example/v1/chat/completions"
        req_body = json.loads(request.content.decode("utf-8"))
        captured.append(req_body)
        envelope = json.loads(req_body["messages"][1]["content"])
        allowed_citations = envelope["allowed_citations"]
        assert allowed_citations == [[str(first.passage_ref), first.revision]]
        draft_obj = {
            "title": "上海住宿大白话说明",
            "markdown": "# 上海住宿标准\n依据已授权摘录整理。",
            "citations": allowed_citations,
            "statements": [
                {
                    "text": "上海住宿标准以摘录为准。",
                    "support_groups": [allowed_citations],
                }
            ],
        }
        fenced = "```json\n" + json.dumps(draft_obj, ensure_ascii=False, separators=(",", ":")) + "\n```"
        return httpx2.Response(
            200,
            json={
                "id": "openai-draft-1",
                "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": fenced}}],
                "usage": {"prompt_tokens": 250, "completion_tokens": 80, "credit": 0.02},
            },
        )

    gw = OpenAiCompatibleModelGatewayAdapter(
        AuthenticatedEndpointConfig("https://llm.corp.example", "env:THALION_GW_CRED"),
        model="deepseek-v4.1-flash",
        destination_id=policy.SYNTHETIC_MODEL_DESTINATION,
        allowed_purposes=frozenset({"wiki_compilation"}),
        secret_resolver={"env:THALION_GW_CRED": "gw-secret"}.__getitem__,
        transport=httpx2.MockTransport(openai_handler),
    )
    wired = evidence.EvidenceService(
        service.connect,
        service.verify_token,
        service.check_source,
        service.store,
        retest_key=service.retest_key,
        backup_store=service.backup_store,
        model_gateway=gw,
    )

    with TestClient(api.create_app(wired), base_url="http://127.0.0.1") as client:
        sealed = client.post(
            "/internal/wiki/inputs",
            headers=bearer(author),
            json={"business_date": BEFORE.isoformat(), "direct": [[str(first.passage_ref), first.revision]]},
        )
        assert sealed.status_code == 200
        manifest_id = sealed.json()["manifest_id"]

        generated = client.post(
            "/internal/wiki/revisions/generate",
            headers=command_headers(author),
            json={
                "business_date": BEFORE.isoformat(),
                "topic_key": "openai-travel-guide",
                "manifest_id": manifest_id,
                "reviewer_ref": str(credentials[reviewer].employee_ref),
                "basis_id": str(uuid4()),
                "title_hint": "上海住宿标准",
                "instructions": "请用大白话整理",
                "max_microunits": 50000,
            },
        )
        assert generated.status_code == 200
        body = generated.json()
        assert UUID(body["revision_id"])
        assert body["input_tokens"] == 250
        assert body["output_tokens"] == 80
        assert body["billed_microunits"] == 20_000
        assert body["title"] == "上海住宿大白话说明"
        assert body["citations"] == [[str(first.passage_ref), first.revision]]
        assert len(captured) == 1
        assert captured[0]["model"] == "deepseek-v4.1-flash"
