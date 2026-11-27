from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from enterprise_kb.modules.access import delivery, policy
from enterprise_kb.modules.sources import effectivity

from test_effectivity import record
from test_employee_portal import browser, load_credential, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_persisted_access import binding, set_rules
from test_runtime import register_tenant, runtime_db
from test_travel_search import BEFORE, SEARCH_FIELDS, corpus
from test_wiki_inputs import compile_rule
from test_wiki_invalidation import version_ref
from test_wiki_publication import configure


WIKI_INPUTS_PATH = "/internal/wiki/inputs"
WIKI_REVISIONS_PATH = "/internal/wiki/revisions"
WIKI_STATUS_PATH = "/internal/wiki/status"

AUTHOR_OPS = frozenset({
    "read_wiki_status",
    policy.WIKI_INPUT_ACCESS[0],
    policy.WIKI_CANDIDATE_ACCESS[0],
    "search",
    "read_passage",
})
REVIEWER_OPS = frozenset({
    policy.WIKI_PREVIEW_ACCESS[0],
    policy.WIKI_REVIEW_ACCESS[0],
    policy.WIKI_PUBLISH_ACCESS[0],
    "read_passage",
})


def _principal_ref(connection, principal_id: int) -> str:
    return str(connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
        (principal_id,),
    ).fetchone()[0])


def _headers(token: str, key: str | None = None) -> dict[str, str]:
    headers = bearer(token)
    if key is not None:
        headers["Idempotency-Key"] = key
    return headers


def _setup_wiki_rules(db, expected: int = 2):
    _, tenant, *_ = db
    review_rule = replace(
        binding(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review",
        destination="local_workspace",
    )
    publish_rule = replace(review_rule, operation="publish_wiki_revision", purpose="wiki_publication")
    owner_read = replace(binding(tenant.actor_id), fields=SEARCH_FIELDS)
    reviewer_read = replace(binding(tenant.other_actor_id), fields=SEARCH_FIELDS)
    set_rules(db, compile_rule(tenant.actor_id), review_rule, publish_rule, owner_read, reviewer_read, expected=expected)


def test_wiki_workflow_endpoints_enforce_auth_roles_and_metadata_isolation(transport):
    client, db, (owner, reviewer), credentials, live, first, second = transport
    connection, tenant, *_ = db
    _setup_wiki_rules(db)
    reviewer_ref = _principal_ref(connection, tenant.other_actor_id)
    owner_ref = _principal_ref(connection, tenant.actor_id)

    # Unauthenticated and missing-operation rejections across all new endpoints.
    assert client.get(WIKI_REVISIONS_PATH).status_code == 401
    assert client.post(WIKI_INPUTS_PATH, json={}).status_code == 401
    assert client.post(WIKI_REVISIONS_PATH, json={}).status_code == 401
    assert client.get(WIKI_REVISIONS_PATH, headers=bearer(owner)).status_code == 403
    assert client.post(WIKI_INPUTS_PATH, headers=bearer(owner), json={
        "business_date": BEFORE.isoformat(), "direct": [[str(first.passage_ref), first.revision]],
    }).status_code == 403

    credentials[owner] = replace(credentials[owner], operations=AUTHOR_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=REVIEWER_OPS)

    # New internal wiki workflow operations must never be exposed via MCP.
    mcp_tools = {tool["name"] for tool in rpc(client, owner, "tools/list").json()["result"]["tools"]}
    assert mcp_tools == {"search", "read_passage"}
    assert rpc(client, reviewer, "tools/list").json()["result"]["tools"] == [
        tool for tool in rpc(client, reviewer, "tools/list").json()["result"]["tools"] if tool["name"] == "read_passage"
    ]

    # Author assembles inputs and creates a draft; self-review must be rejected.
    assembled = client.post(WIKI_INPUTS_PATH, headers=bearer(owner), json={
        "business_date": BEFORE.isoformat(),
        "direct": [[str(first.passage_ref), first.revision], [str(second.passage_ref), second.revision]],
    })
    assert assembled.status_code == 200 and assembled.headers["Cache-Control"] == "no-store"
    manifest_id = assembled.json()["manifest_id"]

    self_review = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, "wiki-self-review"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": "travel-ops",
        "title": "内部草稿标题不应泄漏",
        "markdown": "内部草稿正文内容",
        "manifest_id": manifest_id,
        "reviewer_ref": owner_ref,
        "basis_id": str(uuid4()),
        "citations": [[str(first.passage_ref), first.revision]],
    })
    assert self_review.status_code == 403

    created = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, "wiki-create-1"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": "travel-ops",
        "title": "内部草稿标题不应泄漏",
        "markdown": "内部草稿正文内容",
        "manifest_id": manifest_id,
        "reviewer_ref": reviewer_ref,
        "basis_id": str(uuid4()),
        "citations": [[str(first.passage_ref), first.revision]],
        "statements": [{
            "text": "上海住宿限额以原文为准。",
            "support_groups": [[[str(first.passage_ref), first.revision]]],
        }],
    })
    assert created.status_code == 200 and created.headers["Cache-Control"] == "no-store"
    revision_id = created.json()["revision_id"]

    # Exact idempotent replay returns same revision_id; different body with same key conflicts.
    replayed = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, "wiki-create-1"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": "travel-ops",
        "title": "内部草稿标题不应泄漏",
        "markdown": "内部草稿正文内容",
        "manifest_id": manifest_id,
        "reviewer_ref": reviewer_ref,
        "basis_id": created.request.content.decode("utf-8").split('"basis_id":"')[1].split('"')[0],
        "citations": [[str(first.passage_ref), first.revision]],
        "statements": [{
            "text": "上海住宿限额以原文为准。",
            "support_groups": [[[str(first.passage_ref), first.revision]]],
        }],
    })
    assert replayed.status_code == 200 and replayed.json()["revision_id"] == revision_id
    conflicted = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, "wiki-create-1"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": "travel-ops",
        "title": "不同草稿标题",
        "markdown": "不同正文",
        "manifest_id": manifest_id,
        "reviewer_ref": reviewer_ref,
        "basis_id": str(uuid4()),
        "citations": [[str(first.passage_ref), first.revision]],
    })
    assert conflicted.status_code == 409

    # Revision metadata listing must never leak title, markdown, topic_key, or passage text.
    reviewer_queue = client.get(WIKI_REVISIONS_PATH, headers=bearer(reviewer))
    assert reviewer_queue.status_code == 200 and reviewer_queue.headers["Cache-Control"] == "no-store"
    for secret in ("内部草稿标题不应泄漏", "内部草稿正文内容", "travel-ops", "上海住宿限额"):
        assert secret not in reviewer_queue.text
    assert reviewer_queue.json()["pending_rebuilds"] == []
    assert [item["revision_id"] for item in reviewer_queue.json()["revisions"]] == [revision_id]
    assert reviewer_queue.json()["revisions"][0]["stage"] == "awaiting_review"

    # Author cannot preview, review, or publish their own candidate even if granted review ops.
    credentials[owner] = replace(credentials[owner], operations=AUTHOR_OPS | REVIEWER_OPS)
    assert client.post(f"{WIKI_REVISIONS_PATH}/{revision_id}/preview", headers=bearer(owner), json={
        "business_date": BEFORE.isoformat(),
    }).status_code == 403


def test_wiki_workflow_full_publish_change_diagnosis_and_clean_rebuild(transport):
    client, db, (owner, reviewer), credentials, live, first, second = transport
    connection, tenant, *_ = db
    _setup_wiki_rules(db)
    reviewer_ref = _principal_ref(connection, tenant.other_actor_id)
    credentials[owner] = replace(credentials[owner], operations=AUTHOR_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=REVIEWER_OPS)

    # 1. Assemble inputs (including uncited `second`) and create candidate revision.
    assembled = client.post(WIKI_INPUTS_PATH, headers=bearer(owner), json={
        "business_date": BEFORE.isoformat(),
        "direct": [[str(first.passage_ref), first.revision], [str(second.passage_ref), second.revision]],
    })
    assert assembled.status_code == 200
    manifest_id = assembled.json()["manifest_id"]
    assert len(assembled.json()["excerpts"]) == 2

    created = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, "pub-create-1"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": "travel",
        "title": "本地差旅报销",
        "markdown": "上海住宿限额以原文为准。",
        "manifest_id": manifest_id,
        "reviewer_ref": reviewer_ref,
        "basis_id": str(uuid4()),
        "citations": [[str(first.passage_ref), first.revision]],
        "statements": [{
            "text": "上海住宿限额以原文为准。",
            "support_groups": [[[str(first.passage_ref), first.revision]]],
        }],
    })
    assert created.status_code == 200
    revision_id = created.json()["revision_id"]

    # Unreviewed draft is never visible in employee search.
    pre_search = client.post("/v1/search", headers=bearer(owner), json={
        "query": "限额", "business_date": BEFORE.isoformat(), "include_wiki": True,
    }).json()
    assert pre_search["wiki"] == []

    # 2. Reviewer previews candidate, sees all inputs (including uncited `second`), opens citation, approves, publishes.
    preview = client.post(f"{WIKI_REVISIONS_PATH}/{revision_id}/preview", headers=bearer(reviewer), json={
        "business_date": BEFORE.isoformat(),
    })
    assert preview.status_code == 200 and preview.headers["Cache-Control"] == "no-store"
    preview_body = preview.json()
    assert preview_body["expected_generation"] == 0
    assert preview_body["content"]["title"] == "本地差旅报销"
    inputs_by_id = {item["passage_id"]: item for item in preview_body["manifest_inputs"]}
    assert inputs_by_id[str(first.passage_ref)]["cited"] is True
    assert inputs_by_id[str(second.passage_ref)]["cited"] is False
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(reviewer)).status_code == 200

    approved = client.post(
        f"{WIKI_REVISIONS_PATH}/{revision_id}/review",
        headers=_headers(reviewer, "pub-review-1"),
        json={
            "business_date": BEFORE.isoformat(),
            "content_digest": preview_body["content_digest"],
            "input_digest": preview_body["input_digest"],
            "review_material_id": preview_body["review_material_id"],
            "decision": "approved",
            "reason_code": "verified_against_source",
            "basis_id": str(uuid4()),
        },
    )
    assert approved.status_code == 200 and approved.json()["decision"] == "approved"
    review_id = approved.json()["review_id"]

    published = client.post(
        f"{WIKI_REVISIONS_PATH}/{revision_id}/publish",
        headers=_headers(reviewer, "pub-release-1"),
        json={"business_date": BEFORE.isoformat(), "review_id": review_id},
    )
    assert published.status_code == 200 and published.json()["publication_id"]

    # Employee search now sees generation 1 Wiki.
    live_search = client.post("/v1/search", headers=bearer(owner), json={
        "query": "限额", "business_date": BEFORE.isoformat(), "include_wiki": True,
    }).json()
    assert len(live_search["wiki"]) == 1 and live_search["wiki"][0]["revision_id"] == revision_id

    # 3. Create candidate 2, preview & approve it; withdraw uncited `second` BEFORE publish -> publish must return 409 naming `second`.
    created_v2 = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, "pub-create-2"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": "travel",
        "title": "本地差旅报销修订",
        "markdown": "修订正文。",
        "manifest_id": manifest_id,
        "reviewer_ref": reviewer_ref,
        "basis_id": str(uuid4()),
        "citations": [[str(first.passage_ref), first.revision]],
        "statements": [{
            "text": "上海住宿限额修订版。",
            "support_groups": [[[str(first.passage_ref), first.revision]]],
        }],
    })
    assert created_v2.status_code == 200
    rev2_id = created_v2.json()["revision_id"]

    preview_v2 = client.post(f"{WIKI_REVISIONS_PATH}/{rev2_id}/preview", headers=bearer(reviewer), json={
        "business_date": BEFORE.isoformat(),
    }).json()
    assert preview_v2["expected_generation"] == 1
    assert preview_v2["comparison"]["previous_generation"] == 1

    review_v2 = client.post(
        f"{WIKI_REVISIONS_PATH}/{rev2_id}/review",
        headers=_headers(reviewer, "pub-review-2"),
        json={
            "business_date": BEFORE.isoformat(),
            "content_digest": preview_v2["content_digest"],
            "input_digest": preview_v2["input_digest"],
            "review_material_id": preview_v2["review_material_id"],
            "decision": "approved",
            "reason_code": "verified_revision",
            "basis_id": str(uuid4()),
        },
    ).json()["review_id"]

    # Source withdrawal on uncited `second` invalidates published gen-1 and blocks publishing rev2 with explicit item diagnosis.
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "stop-second-during-review"),
        tenant.space_id, version_ref(connection, second), "withdrawn", uuid4(),
    )
    blocked_pub = client.post(
        f"{WIKI_REVISIONS_PATH}/{rev2_id}/publish",
        headers=_headers(reviewer, "pub-release-2"),
        json={"business_date": BEFORE.isoformat(), "review_id": review_v2},
    )
    assert blocked_pub.status_code == 409
    blocked_body = blocked_pub.json()
    assert blocked_body["error"]["code"] == "wiki_input_changed"
    changed = {item["passage_id"]: item["reasons"] for item in blocked_body["changed_passages"]}
    assert str(second.passage_ref) in changed and "withdrawn" in changed[str(second.passage_ref)]
    assert "上海住宿限额" not in blocked_pub.text

    # While Wiki is stopped, unaffected passage `first` remains searchable for employees.
    after_stop = client.post("/v1/search", headers=bearer(owner), json={
        "query": "限额", "business_date": BEFORE.isoformat(), "include_wiki": True,
    }).json()
    assert len(after_stop["passages"]) == 1 and after_stop["wiki"] == []

    # 4. Clean rebuild from pending rebuild event: parents must be rejected; clean manifest publishes generation 2.
    owner_queue = client.get(WIKI_REVISIONS_PATH, headers=bearer(owner)).json()
    assert len(owner_queue["pending_rebuilds"]) == 1
    rebuild_event_id = owner_queue["pending_rebuilds"][0]["event_id"]

    dirty_rebuild = client.post(WIKI_INPUTS_PATH, headers=bearer(owner), json={
        "business_date": BEFORE.isoformat(),
        "direct": [[str(first.passage_ref), first.revision]],
        "parents": [manifest_id],
        "rebuild_event_id": rebuild_event_id,
    })
    assert dirty_rebuild.status_code == 400

    clean_manifest = client.post(WIKI_INPUTS_PATH, headers=bearer(owner), json={
        "business_date": BEFORE.isoformat(),
        "direct": [[str(first.passage_ref), first.revision]],
        "rebuild_event_id": rebuild_event_id,
    })
    assert clean_manifest.status_code == 200
    clean_manifest_id = clean_manifest.json()["manifest_id"]

    rebuilt = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, "pub-rebuild-1"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": "travel",
        "title": "本地差旅干净重编",
        "markdown": "仅依据未撤回原文重编。",
        "manifest_id": clean_manifest_id,
        "reviewer_ref": reviewer_ref,
        "basis_id": str(uuid4()),
        "citations": [[str(first.passage_ref), first.revision]],
        "statements": [{
            "text": "上海住宿限额干净重编版。",
            "support_groups": [[[str(first.passage_ref), first.revision]]],
        }],
    })
    assert rebuilt.status_code == 200
    rebuilt_id = rebuilt.json()["revision_id"]

    rebuilt_preview = client.post(f"{WIKI_REVISIONS_PATH}/{rebuilt_id}/preview", headers=bearer(reviewer), json={
        "business_date": BEFORE.isoformat(),
    }).json()
    assert rebuilt_preview["expected_generation"] == 1
    assert rebuilt_preview["comparison"]["previous_content_available"] is False

    rebuilt_review = client.post(
        f"{WIKI_REVISIONS_PATH}/{rebuilt_id}/review",
        headers=_headers(reviewer, "pub-rebuild-review"),
        json={
            "business_date": BEFORE.isoformat(),
            "content_digest": rebuilt_preview["content_digest"],
            "input_digest": rebuilt_preview["input_digest"],
            "review_material_id": rebuilt_preview["review_material_id"],
            "decision": "approved",
            "reason_code": "clean_rebuild_verified",
            "basis_id": str(uuid4()),
        },
    ).json()["review_id"]

    rebuilt_pub = client.post(
        f"{WIKI_REVISIONS_PATH}/{rebuilt_id}/publish",
        headers=_headers(reviewer, "pub-rebuild-release"),
        json={"business_date": BEFORE.isoformat(), "review_id": rebuilt_review},
    )
    assert rebuilt_pub.status_code == 200

    recovered = client.post("/v1/search", headers=bearer(owner), json={
        "query": "限额", "business_date": BEFORE.isoformat(), "include_wiki": True,
    }).json()
    assert len(recovered["wiki"]) == 1 and recovered["wiki"][0]["revision_id"] == rebuilt_id
    assert client.get(WIKI_REVISIONS_PATH, headers=bearer(owner)).json()["pending_rebuilds"] == []


def test_wiki_workflow_reports_generation_conflict_and_authority_failure(evidence_transport):
    service, db, (owner, reviewer), credentials, live, first, second = evidence_transport
    connection, tenant, *_ = db
    _setup_wiki_rules(db)
    reviewer_ref = _principal_ref(connection, tenant.other_actor_id)
    credentials[owner] = replace(credentials[owner], operations=AUTHOR_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=REVIEWER_OPS)
    from enterprise_kb.transport import api
    from fastapi.testclient import TestClient

    with TestClient(api.create_app(service), base_url="http://127.0.0.1:8765") as client:
        manifest_id = client.post(WIKI_INPUTS_PATH, headers=bearer(owner), json={
            "business_date": BEFORE.isoformat(),
            "direct": [[str(first.passage_ref), first.revision]],
        }).json()["manifest_id"]

        def create_and_approve(suffix: str):
            rev_id = client.post(WIKI_REVISIONS_PATH, headers=_headers(owner, f"race-c-{suffix}"), json={
                "business_date": BEFORE.isoformat(),
                "topic_key": "race-topic",
                "title": f"并发修订 {suffix}",
                "markdown": f"正文 {suffix}",
                "manifest_id": manifest_id,
                "reviewer_ref": reviewer_ref,
                "basis_id": str(uuid4()),
                "citations": [[str(first.passage_ref), first.revision]],
            }).json()["revision_id"]
            prev = client.post(f"{WIKI_REVISIONS_PATH}/{rev_id}/preview", headers=bearer(reviewer), json={
                "business_date": BEFORE.isoformat(),
            }).json()
            review_id = client.post(f"{WIKI_REVISIONS_PATH}/{rev_id}/review", headers=_headers(reviewer, f"race-r-{suffix}"), json={
                "business_date": BEFORE.isoformat(),
                "content_digest": prev["content_digest"],
                "input_digest": prev["input_digest"],
                "review_material_id": prev["review_material_id"],
                "decision": "approved",
                "reason_code": "ok",
                "basis_id": str(uuid4()),
            }).json()["review_id"]
            return rev_id, review_id

        rev_a, review_a = create_and_approve("a")
        rev_b, review_b = create_and_approve("b")
        assert client.post(f"{WIKI_REVISIONS_PATH}/{rev_a}/publish", headers=_headers(reviewer, "race-p-a"), json={
            "business_date": BEFORE.isoformat(), "review_id": review_a,
        }).status_code == 200
        loser = client.post(f"{WIKI_REVISIONS_PATH}/{rev_b}/publish", headers=_headers(reviewer, "race-p-b"), json={
            "business_date": BEFORE.isoformat(), "review_id": review_b,
        })
        assert loser.status_code == 409
        body = loser.json()
        assert body["error"]["code"] == "wiki_input_changed"
        assert body["topic_generation_changed"] is True
        assert body["expected_generation"] == 0 and body["current_generation"] == 1

        # Authority outage returns 503 dependency_unavailable.
        def outage(_credential, _probe):
            raise delivery.AuthorizationUnavailable("authority offline")

        service.check_source = outage
        assert client.post(WIKI_INPUTS_PATH, headers=bearer(owner), json={
            "business_date": BEFORE.isoformat(),
            "direct": [[str(first.passage_ref), first.revision]],
        }).status_code == 503


def test_wiki_management_page_end_to_end_draft_review_and_publish(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, reviewer), credentials, _, first, second = portal
    connection, tenant, *_ = db
    _setup_wiki_rules(db)
    reviewer_ref = _principal_ref(connection, tenant.other_actor_id)
    credentials[owner] = replace(credentials[owner], operations=AUTHOR_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=REVIEWER_OPS)

    # 1. Owner signs into /manage/wiki, assembles inputs, and submits a draft.
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/manage/wiki")
    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="查看发布台账").click()
    expect(page.get_by_role("heading", name="组装输入与提交草稿")).to_be_visible()

    page.get_by_label("办理业务日期").fill(BEFORE.isoformat())
    page.get_by_label("直接依据列表").fill(f"{first.passage_ref}:{first.revision}")
    page.get_by_role("button", name="组装并封存输入清单").click()
    expect(page.locator("#wiki-inputs-status")).to_contain_text("已封存输入清单")
    assert page.get_by_label("已封存输入清单标识").input_value() != ""

    page.get_by_label("主题键").fill("portal-travel")
    page.get_by_label("草稿标题").fill("页面端到端差旅主题")
    page.get_by_label("Markdown 正文").fill("上海住宿限额以原文核对为准。")
    page.get_by_label("独立审核人标识").fill(reviewer_ref)
    page.get_by_label("正文引用依据").fill(f"{first.passage_ref}:{first.revision}")
    page.get_by_label("可核对陈述").fill("上海住宿限额以原文核对为准。")
    page.get_by_role("button", name="提交候选草稿").click()
    expect(page.locator("#wiki-candidate-status")).to_contain_text("已提交候选修订")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-wiki-author.png")

    # Sign out clears draft form and credentials.
    page.get_by_role("button", name="退出管理").click()
    assert page.get_by_label("草稿标题").input_value() == ""

    # 2. Independent reviewer (without read_wiki_status) signs in on narrow mobile viewport, previews, approves, publishes.
    page.set_viewport_size({"width": 390, "height": 844})
    page.get_by_label("管理测试凭据").fill(reviewer)
    page.get_by_role("button", name="查看发布台账").click()
    expect(page.get_by_role("heading", name="修订审核与发布队列")).to_be_visible()
    page.get_by_role("button", name="载入预览").first.click()
    expect(page.get_by_text("页面端到端差旅主题", exact=True)).to_be_visible()
    expect(page.get_by_text(str(first.passage_ref))).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-wiki-reviewer-mobile.png")

    page.get_by_label("审核原因码").fill("verified_in_ui")
    page.get_by_role("button", name="批准该修订").click()
    expect(page.locator("#wiki-review-status")).to_contain_text("已记录审核决定：approved")

    page.get_by_role("button", name="发布已批修订").click()
    expect(page.locator("#wiki-review-status")).to_contain_text("已发布主题修订")

    # 3. Employee portal immediately sees the newly published Wiki revision.
    page.get_by_role("button", name="退出管理").click()
    page.get_by_role("link", name="员工取证").click()
    load_credential(page, owner)
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    page.get_by_label("关键词或问题").fill("限额")
    page.get_by_role("checkbox", name="附带已审核 Wiki 陈述").check()
    page.get_by_role("button", name="查找依据").click()
    expect(page.get_by_role("region", name="已审核 Wiki 陈述").get_by_role("heading", name="页面端到端差旅主题")).to_be_visible()
