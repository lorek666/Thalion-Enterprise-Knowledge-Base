from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from uuid import UUID, uuid4

from psycopg import errors
import pytest

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access import delivery, policy, travel
from enterprise_kb.modules.operations import evaluation, release
from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.modules.sources import effectivity, registry
from enterprise_kb.modules.wiki import publication, templates
from enterprise_kb.runtime.audit import RequestStart, start_request
from enterprise_kb.runtime.events import pending_events
from enterprise_kb.transport.evidence import SyntheticCredential

from test_effectivity import BEGIN, approve, record
from test_employee_portal import browser, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_persisted_access import binding, set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_source_restrictions import migrate_to_revision
from test_sources import request_for
from test_travel_search import BEFORE, SEARCH_FIELDS, corpus, publish
from test_wiki_inputs import compile_rule
from test_wiki_invalidation import version_ref
from test_wiki_publication import configure
from test_wiki_workflow_transport import AUTHOR_OPS, REVIEWER_OPS, _headers, _principal_ref, _setup_wiki_rules


RELEASE_SPACES_PATH = "/internal/release/spaces"
RELEASE_SWITCH_PATH = "/internal/release/spaces/switch"
RELEASE_OWNER_OPS = AUTHOR_OPS | {release.READ_SPACE_RELEASE, release.SWITCH_SPACE_RELEASE, release.ROLLBACK_WIKI_TOPIC}
RELEASE_REVIEWER_OPS = REVIEWER_OPS | {release.ROLLBACK_WIKI_TOPIC}


def _publish_wiki_via_http(
    client, connection, owner_tok: str, reviewer_tok: str, reviewer_ref: str,
    *, topic_key: str, title: str, markdown: str,
    direct_inputs: list[list], citations: list[list], statements: list[dict],
    tag: str,
) -> tuple[str, str, str]:
    assembled = client.post("/internal/wiki/inputs", headers=bearer(owner_tok), json={
        "business_date": BEFORE.isoformat(),
        "direct": direct_inputs,
    })
    assert assembled.status_code == 200, assembled.text
    manifest_id = assembled.json()["manifest_id"]

    draft = client.post("/internal/wiki/revisions", headers=_headers(owner_tok, f"draft-{tag}"), json={
        "business_date": BEFORE.isoformat(),
        "topic_key": topic_key,
        "title": title,
        "markdown": markdown,
        "manifest_id": manifest_id,
        "reviewer_ref": reviewer_ref,
        "basis_id": str(uuid4()),
        "citations": citations,
        "statements": statements,
    })
    assert draft.status_code == 200, draft.text
    rev_id = draft.json()["revision_id"]
    wiki_id = str(connection.execute(
        "SELECT w.wiki_ref FROM thalion.wiki_revision AS r JOIN thalion.wiki AS w USING (org_id, space_id, topic_key) WHERE r.revision_ref = %s",
        (UUID(rev_id),),
    ).fetchone()[0])

    preview = client.post(
        f"/internal/wiki/revisions/{rev_id}/preview",
        headers=bearer(reviewer_tok),
        json={"business_date": BEFORE.isoformat()},
    )
    assert preview.status_code == 200, preview.text
    preview_body = preview.json()

    reviewed = client.post(
        f"/internal/wiki/revisions/{rev_id}/review",
        headers=_headers(reviewer_tok, f"review-{tag}"),
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
    assert reviewed.status_code == 200, reviewed.text
    review_id = reviewed.json()["review_id"]

    published = client.post(
        f"/internal/wiki/revisions/{rev_id}/publish",
        headers=_headers(reviewer_tok, f"publish-{tag}"),
        json={"business_date": BEFORE.isoformat(), "review_id": review_id},
    )
    assert published.status_code == 200, published.text
    return wiki_id, rev_id, published.json()["publication_id"]


def _create_second_space(connection, org_id: int, owner_id: int, other_id: int, name: str) -> tuple[int, UUID]:
    with connection.transaction():
        space_id, = connection.execute(
            "INSERT INTO thalion.space (org_id, name, classification, owner_principal_id) "
            "VALUES (%s, %s, 'internal', %s) RETURNING space_id",
            (org_id, name, owner_id),
        ).fetchone()
        space_ref, = connection.execute(
            "INSERT INTO thalion.object_identity (object_type, object_id, org_id, space_id) "
            "VALUES ('space', %s, %s, %s) RETURNING public_id",
            (space_id, org_id, space_id),
        ).fetchone()
    return space_id, space_ref


def test_space_release_migration_and_db_guards(database_url):
    migrate_to_revision(database_url, "0104_governance_sharing_deleg")
    assert upgrade(database_url) == ["0113_source_connector_cursor"]

    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Synthetic Release Guard Org")
        # Non-owner cannot insert into space_release_config even via raw SQL.
        req_non_owner_id = uuid4()
        start_request(
            connection,
            RequestStart(
                tenant.org_id, req_non_owner_id, tenant.other_actor_id, None, "guard-test",
                release.SWITCH_SPACE_RELEASE, release.DESTINATION, BEFORE, 1,
                space_id=tenant.space_id, ingress="internal",
            ),
        )
        with pytest.raises(errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO thalion.space_release_config (
                        org_id, space_id, generation, action, wiki_delivery_enabled, lexical_index_mode,
                        rollback_trigger_summary, reason_code, basis_ref, actor_id, request_id
                    ) VALUES (%s, %s, 1, 'trial_switch', false, 'direct_scan', 'trigger', 'test_switch', %s, %s, %s)
                    """,
                    (tenant.org_id, tenant.space_id, uuid4(), tenant.other_actor_id, req_non_owner_id),
                )

        # Owner with open request inserts gen 1; generation skip and immutability are enforced.
        req_owner_id = uuid4()
        start_request(
            connection,
            RequestStart(
                tenant.org_id, req_owner_id, tenant.actor_id, None, "guard-test",
                release.SWITCH_SPACE_RELEASE, release.DESTINATION, BEFORE, 1,
                space_id=tenant.space_id, ingress="internal",
            ),
        )
        with connection.transaction():
            release_ref, = connection.execute(
                """
                INSERT INTO thalion.space_release_config (
                    org_id, space_id, generation, action, wiki_delivery_enabled, lexical_index_mode,
                    rollback_trigger_summary, reason_code, basis_ref, actor_id, request_id
                ) VALUES (%s, %s, 1, 'trial_switch', true, 'indexed', 'rollback on drop', 'initial_trial', %s, %s, %s)
                RETURNING release_ref
                """,
                (tenant.org_id, tenant.space_id, uuid4(), tenant.actor_id, req_owner_id),
            ).fetchone()

        with pytest.raises(errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO thalion.space_release_config (
                        org_id, space_id, generation, action, wiki_delivery_enabled, lexical_index_mode,
                        rollback_trigger_summary, reason_code, basis_ref, actor_id, request_id
                    ) VALUES (%s, %s, 3, 'trial_switch', false, 'direct_scan', 'skip gen', 'skip_gen', %s, %s, %s)
                    """,
                    (tenant.org_id, tenant.space_id, uuid4(), tenant.actor_id, req_owner_id),
                )

        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            with connection.transaction():
                connection.execute(
                    "UPDATE thalion.space_release_config SET wiki_delivery_enabled = false WHERE release_ref = %s",
                    (release_ref,),
                )
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            with connection.transaction():
                connection.execute("DELETE FROM thalion.space_release_config WHERE release_ref = %s", (release_ref,))
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            with connection.transaction():
                connection.execute("TRUNCATE thalion.space_release_config")

        # Unapproved template cannot be bound to space_release_config.
        tpl_req = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "register_template_revision")
        unapproved_rev = templates.register_template_revision(
            connection,
            templates.TemplateWrite(tenant.org_id, tenant.actor_id, tpl_req.request_id, tpl_req.idempotency_key),
            tenant.space_id,
            templates.TemplateSpec("travel-tpl", "Unapproved prompt", "synthetic-local", 4096, 512, tenant.other_actor_id),
        )
        with pytest.raises(errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO thalion.space_release_config (
                        org_id, space_id, generation, action, wiki_delivery_enabled, lexical_index_mode,
                        template_key, template_revision_ref,
                        rollback_trigger_summary, reason_code, basis_ref, actor_id, request_id
                    ) VALUES (%s, %s, 2, 'trial_switch', true, 'indexed', 'travel-tpl', %s, 'bad tpl', 'bad_tpl', %s, %s, %s)
                    """,
                    (tenant.org_id, tenant.space_id, unapproved_rev, uuid4(), tenant.actor_id, req_owner_id),
                )


def test_per_space_release_switch_lexical_fallback_and_template_rollback(transport):
    client, db, (owner, reviewer), credentials, live, first, second = transport
    connection, tenant, _, source, store = db
    _setup_wiki_rules(db)
    credentials[owner] = replace(credentials[owner], operations=RELEASE_OWNER_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=RELEASE_REVIEWER_OPS)
    reviewer_ref = _principal_ref(connection, tenant.other_actor_id)

    # Register & approve two template revisions in space A.
    tpl_revs = []
    for idx, prompt in enumerate(("Template v1 synthetic rules.", "Template v2 synthetic rules."), start=1):
        reg_req = request_for(connection, tenant, tenant.actor_id, f"tpl-reg-{idx}", "register_template_revision")
        rev = templates.register_template_revision(
            connection,
            templates.TemplateWrite(tenant.org_id, tenant.actor_id, reg_req.request_id, reg_req.idempotency_key),
            tenant.space_id,
            templates.TemplateSpec("travel-summary", prompt, "synthetic-local", 8192, 1024, tenant.other_actor_id),
        )
        rev_req = request_for(connection, tenant, tenant.other_actor_id, f"tpl-adm-{idx}", "decide_template_admission")
        templates.decide_template_admission(
            connection,
            templates.TemplateWrite(tenant.org_id, tenant.other_actor_id, rev_req.request_id, rev_req.idempotency_key),
            tenant.space_id, rev, "approved", uuid4(), "approved_synthetic_tpl",
        )
        tpl_revs.append(rev)

    # Publish Wiki in Space A and build lexical index for first passage's version.
    wiki_id, rev1_id, _ = _publish_wiki_via_http(
        client, connection, owner, reviewer, reviewer_ref,
        topic_key="travel-hotel",
        title="上海差旅住宿摘要",
        markdown="上海住宿上限 600 元/晚。",
        direct_inputs=[[str(first.passage_ref), first.revision]],
        citations=[[str(first.passage_ref), first.revision]],
        statements=[{"text": "上海普通住宿上限 600 元。", "support_groups": [[[str(first.passage_ref), first.revision]]]}],
        tag="space-a-v1",
    )
    ver_ref = version_ref(connection, first)
    run_ref, = connection.execute(
        """
        SELECT pe.run_ref FROM thalion.object_identity AS oi
        JOIN thalion.passage_excerpt AS pe
          ON (pe.org_id, pe.space_id, pe.passage_id, pe.excerpt_revision)
           = (oi.org_id, oi.space_id, oi.object_id, %s)
        WHERE oi.public_id = %s
        """,
        (first.revision, first.passage_ref),
    ).fetchone()
    index_ref = lexical.build_index(connection, store, tenant.space_ref, ver_ref, run_ref)

    # Create an independent Space B with its own published Wiki to verify per-space isolation.
    space_b_id, space_b_ref = _create_second_space(connection, tenant.org_id, tenant.actor_id, tenant.other_actor_id, "Space B")
    tenant_b = replace(tenant, space_id=space_b_id, space_ref=space_b_ref)
    src_b_req = request_for(connection, tenant_b, tenant.actor_id, "create-space-b-source", "register_source_contract")
    source_b_ref = registry.register_synthetic_source(
        connection, src_b_req, space_b_id,
        registry.SyntheticSource(
            "space-b-files", "space-b-archive", tenant.worker_id,
            approver_id=tenant.other_actor_id, processor_id=tenant.other_worker_id,
            quality_reviewer_id=tenant.actor_id,
        ),
    )
    db_b = (connection, tenant_b, db[2], source_b_ref, store)
    b_allowance, b_first, _ = publish(db_b, "b-allowance", "空间B住宿标准", "# 上海\n\n空间B上海住宿限额。\n".encode())
    approve(connection, tenant_b, b_allowance, BEGIN)
    _setup_wiki_rules(db_b, expected=1)
    owner_b_tok = "owner_space_b_" + "b" * 32
    reviewer_b_tok = "reviewer_space_b_" + "r" * 32
    now = datetime.now(UTC)
    credentials[owner_b_tok] = SyntheticCredential(
        credentials[owner].employee_ref, space_b_ref, "client-b-owner",
        credentials[owner].region, credentials[owner].traveler_class,
        RELEASE_OWNER_OPS, now + timedelta(minutes=10),
    )
    credentials[reviewer_b_tok] = SyntheticCredential(
        credentials[reviewer].employee_ref, space_b_ref, "client-b-rev",
        credentials[reviewer].region, credentials[reviewer].traveler_class,
        RELEASE_REVIEWER_OPS, now + timedelta(minutes=10),
    )
    _publish_wiki_via_http(
        client, connection, owner_b_tok, reviewer_b_tok, reviewer_ref,
        topic_key="travel-hotel-b",
        title="空间B住宿摘要",
        markdown="空间B上海住宿上限 600 元。",
        direct_inputs=[[str(b_first.passage_ref), b_first.revision]],
        citations=[[str(b_first.passage_ref), b_first.revision]],
        statements=[{"text": "空间B上海住宿上限 600 元。", "support_groups": [[[str(b_first.passage_ref), b_first.revision]]]}],
        tag="space-b-v1",
    )

    # MCP must never expose any /internal/release operations.
    mcp_tools = {tool["name"] for tool in rpc(client, owner, "tools/list").json()["result"]["tools"]}
    assert mcp_tools == {"search", "read_passage"}
    assert client.get(RELEASE_SPACES_PATH).status_code == 401
    assert client.get(RELEASE_SPACES_PATH, headers=bearer(reviewer)).status_code == 403

    # Step 1: Space A switches to gen 1 (wiki enabled, indexed, template v1).
    r1 = client.post(RELEASE_SWITCH_PATH, headers=_headers(owner, "rel-gen-1"), json={
        "action": "trial_switch",
        "wiki_delivery_enabled": True,
        "lexical_index_mode": "indexed",
        "template_key": "travel-summary",
        "template_revision_id": str(tpl_revs[0]),
        "observation_window_minutes": 60,
        "min_sample_requests": 50,
        "rollback_trigger_summary": "若命中率下降立即回退",
        "reason_code": "initial_space_trial",
        "basis_ref": str(uuid4()),
    })
    assert r1.status_code == 200, r1.text
    rel1_id = r1.json()["release_id"]
    assert r1.json()["generation"] == 1
    # Idempotent replay returns same release_id; mismatched payload returns 409.
    r1_replay = client.post(RELEASE_SWITCH_PATH, headers=_headers(owner, "rel-gen-1"), json={
        "action": "trial_switch",
        "wiki_delivery_enabled": True,
        "lexical_index_mode": "indexed",
        "template_key": "travel-summary",
        "template_revision_id": str(tpl_revs[0]),
        "observation_window_minutes": 60,
        "min_sample_requests": 50,
        "rollback_trigger_summary": "若命中率下降立即回退",
        "reason_code": "initial_space_trial",
        "basis_ref": r1.json()["basis_ref"],
    })
    assert r1_replay.status_code == 200 and r1_replay.json()["release_id"] == rel1_id
    r1_conflict = client.post(RELEASE_SWITCH_PATH, headers=_headers(owner, "rel-gen-1"), json={
        "action": "disable_wiki",
        "wiki_delivery_enabled": False,
        "lexical_index_mode": "indexed",
        "rollback_trigger_summary": "冲突测试",
        "reason_code": "conflict_case",
        "basis_ref": str(uuid4()),
    })
    assert r1_conflict.status_code == 409 and r1_conflict.json()["error"]["code"] == "release_conflict"

    # Both spaces deliver Wiki initially.
    search_a_on = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert search_a_on.status_code == 200 and len(search_a_on.json()["wiki"]) == 1
    search_b_on = client.post("/v1/search", headers=bearer(owner_b_tok), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert search_b_on.status_code == 200 and len(search_b_on.json()["wiki"]) == 1

    # Step 2: Disable Wiki ONLY in Space A and switch lexical mode to direct_scan + template v2.
    r2 = client.post(RELEASE_SWITCH_PATH, headers=_headers(owner, "rel-gen-2"), json={
        "action": "trial_switch",
        "wiki_delivery_enabled": False,
        "lexical_index_mode": "direct_scan",
        "template_key": "travel-summary",
        "template_revision_id": str(tpl_revs[1]),
        "rollback_trigger_summary": "退回纯 RAG 与直扫模式排查词项索引",
        "reason_code": "fallback_direct_scan_rag",
        "basis_ref": str(uuid4()),
    })
    assert r2.status_code == 200 and r2.json()["generation"] == 2

    # Space A search returns originals ONLY (no Wiki), while Space B still delivers its Wiki.
    search_a_off = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert search_a_off.status_code == 200
    assert search_a_off.json()["passages"] and search_a_off.json()["wiki"] == []
    search_b_still_on = client.post("/v1/search", headers=bearer(owner_b_tok), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert search_b_still_on.status_code == 200 and len(search_b_still_on.json()["wiki"]) == 1

    # Direct Wiki read in Space A is also blocked while wiki_delivery_enabled is false.
    read_req_id = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, read_req_id, tenant.actor_id, None, "direct-wiki-check",
        policy.WIKI_READ_ACCESS[0], policy.WIKI_READ_ACCESS[2], BEFORE, 1, space_id=tenant.space_id,
    ))
    direct_read = publication.read_current_revision(
        connection,
        delivery.DeliveryContext(
            read_req_id, tenant.org_id, tenant.actor_id, "direct-wiki-check",
            *policy.WIKI_READ_ACCESS, datetime.now(UTC) + timedelta(seconds=30),
        ),
        tenant.space_id, "travel-hotel", region="CN-SH", traveler_class="standard",
        check_authority=lambda check: delivery.AuthorityDecision(
            check.check_id, datetime.now(UTC), datetime.now(UTC) + timedelta(minutes=5),
            frozenset({tenant.actor_id}), {scope: scope.fields for scope in check.scopes}, "synthetic-proof",
        ),
    )
    assert direct_read.status == "rejected"

    # Verify direct_scan bypasses lexical index cleanly even if indexed entry text is stale/missing.
    assert connection.execute(
        "SELECT revision_ref, generation FROM thalion.active_compile_template WHERE (org_id, space_id, template_key) = (%s, %s, 'travel-summary')",
        (tenant.org_id, tenant.space_id),
    ).fetchone() == (tpl_revs[1], 2)
    assert index_ref is not None

    # Step 3: Roll back Space A to release gen 1 (restores wiki_delivery_enabled, indexed mode, and template v1).
    r3 = client.post(RELEASE_SWITCH_PATH, headers=_headers(owner, "rel-rollback-1"), json={
        "action": "rollback",
        "target_release_id": rel1_id,
        "rollback_trigger_summary": "回退至已验证的第 1 代空间发布配置",
        "reason_code": "restore_verified_release",
        "basis_ref": str(uuid4()),
    })
    assert r3.status_code == 200
    assert r3.json()["generation"] == 3
    assert r3.json()["wiki_delivery_enabled"] is True
    assert r3.json()["lexical_index_mode"] == "indexed"
    assert r3.json()["template_revision_id"] == str(tpl_revs[0])
    assert connection.execute(
        "SELECT revision_ref, generation FROM thalion.active_compile_template WHERE (org_id, space_id, template_key) = (%s, %s, 'travel-summary')",
        (tenant.org_id, tenant.space_id),
    ).fetchone() == (tpl_revs[0], 3)

    # Space A Wiki delivery is cleanly restored after rollback.
    search_a_restored = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert search_a_restored.status_code == 200
    assert search_a_restored.json()["wiki"][0]["revision_id"] == rev1_id
    overview = client.get(RELEASE_SPACES_PATH, headers=bearer(owner))
    assert overview.status_code == 200
    assert overview.json()["current"]["generation"] == 3
    assert len(overview.json()["releases"]) == 3
    assert overview.json()["wiki_topics"][0]["wiki_id"] == wiki_id
    assert any(ev.event_type == "release.space_switched" for ev in pending_events(connection, tenant.org_id, "rel-check"))


def test_wiki_topic_rollback_enforces_current_revocations_stops_and_deletions(transport):
    client, db, (owner, reviewer), credentials, live, first, second = transport
    connection, tenant, _, source, _ = db
    _setup_wiki_rules(db)
    credentials[owner] = replace(credentials[owner], operations=RELEASE_OWNER_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=RELEASE_REVIEWER_OPS)
    reviewer_ref = _principal_ref(connection, tenant.other_actor_id)

    # Gen 1 cites `first`, and ALSO carries `second` as an uncited input.
    wiki_id, rev1_id, pub1_id = _publish_wiki_via_http(
        client, connection, owner, reviewer, reviewer_ref,
        topic_key="travel-hotel",
        title="住宿规则第一版",
        markdown="上海住宿上限 600 元。",
        direct_inputs=[[str(first.passage_ref), first.revision], [str(second.passage_ref), second.revision]],
        citations=[[str(first.passage_ref), first.revision]],
        statements=[{"text": "第一版：上海住宿上限 600 元。", "support_groups": [[[str(first.passage_ref), first.revision]]]}],
        tag="rb-gen1",
    )
    # Gen 2 updates the same topic (cites `first` only).
    wiki_id_2, rev2_id, _ = _publish_wiki_via_http(
        client, connection, owner, reviewer, reviewer_ref,
        topic_key="travel-hotel",
        title="住宿规则第二版",
        markdown="上海住宿上限 600 元（第二版）。",
        direct_inputs=[[str(first.passage_ref), first.revision]],
        citations=[[str(first.passage_ref), first.revision]],
        statements=[{"text": "第二版：上海住宿上限 600 元。", "support_groups": [[[str(first.passage_ref), first.revision]]]}],
        tag="rb-gen2",
    )
    assert wiki_id_2 == wiki_id

    # Employee initially sees Gen 2.
    before_rb = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert before_rb.status_code == 200 and before_rb.json()["wiki"][0]["revision_id"] == rev2_id

    # Author of Gen 1 cannot self-rollback Gen 1.
    basis = str(uuid4())
    self_rb = client.post(
        f"/internal/release/wiki/{wiki_id}/rollback",
        headers=_headers(owner, "self-rb-1"),
        json={
            "target_revision_id": rev1_id,
            "business_date": BEFORE.isoformat(),
            "reason_code": "author_attempt",
            "basis_ref": basis,
        },
    )
    assert self_rb.status_code == 403

    # Independent publisher rolls back to Gen 1 with idempotency support.
    rb_ok = client.post(
        f"/internal/release/wiki/{wiki_id}/rollback",
        headers=_headers(reviewer, "pub-rb-1"),
        json={
            "target_revision_id": rev1_id,
            "business_date": BEFORE.isoformat(),
            "reason_code": "regression_in_v2",
            "basis_ref": basis,
        },
    )
    assert rb_ok.status_code == 200, rb_ok.text
    assert rb_ok.json()["target_publication_id"] == pub1_id
    rb_replay = client.post(
        f"/internal/release/wiki/{wiki_id}/rollback",
        headers=_headers(reviewer, "pub-rb-1"),
        json={
            "target_revision_id": rev1_id,
            "business_date": BEFORE.isoformat(),
            "reason_code": "regression_in_v2",
            "basis_ref": basis,
        },
    )
    assert rb_replay.status_code == 200 and rb_replay.json()["rollback_id"] == rb_ok.json()["rollback_id"]
    rb_conflict = client.post(
        f"/internal/release/wiki/{wiki_id}/rollback",
        headers=_headers(reviewer, "pub-rb-1"),
        json={
            "target_revision_id": rev1_id,
            "business_date": BEFORE.isoformat(),
            "reason_code": "different_reason",
            "basis_ref": basis,
        },
    )
    assert rb_conflict.status_code == 409

    # Search now serves Gen 1 with valid delivery audit receipt.
    after_rb = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert after_rb.status_code == 200 and after_rb.json()["wiki"][0]["revision_id"] == rev1_id

    # Live source authority revocation immediately blocks rolled-back Gen 1 delivery!
    live.discard(tenant.actor_id)
    revoked_search = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert revoked_search.status_code == 200
    assert revoked_search.json()["wiki"] == []
    assert revoked_search.json()["passages"] == []
    live.add(tenant.actor_id)

    # Now roll forward to Gen 2, then stop the version of Gen 1's uncited input (`second`):
    # rolling back to Gen 1 MUST be refused with 409 wiki_input_changed (never revives stopped/deleted input).
    rf = client.post(
        f"/internal/release/wiki/{wiki_id}/rollback",
        headers=_headers(reviewer, "pub-rf-2"),
        json={
            "target_revision_id": rev2_id,
            "business_date": BEFORE.isoformat(),
            "reason_code": "restore_v2_before_stop",
            "basis_ref": str(uuid4()),
        },
    )
    assert rf.status_code == 200

    second_ver = version_ref(connection, second)
    stop_req = request_for(connection, tenant, tenant.other_actor_id, "stop-second-ver", "stop_rule_use")
    effectivity.stop_synthetic_rule(
        connection, stop_req, tenant.space_id, second_ver, "withdrawn", uuid4(),
    )

    blocked_rb = client.post(
        f"/internal/release/wiki/{wiki_id}/rollback",
        headers=_headers(reviewer, "pub-rb-blocked"),
        json={
            "target_revision_id": rev1_id,
            "business_date": BEFORE.isoformat(),
            "reason_code": "try_revive_stopped",
            "basis_ref": str(uuid4()),
        },
    )
    assert blocked_rb.status_code == 409
    body = blocked_rb.json()
    assert body["error"]["code"] == "wiki_input_changed"
    assert "withdrawn" in body["stop_reasons"]
    assert body["disable_wiki_fallback_recommended"] is True

    # Space owner can fall back to pure RAG when no safe Wiki revision exists.
    disable = client.post(RELEASE_SWITCH_PATH, headers=_headers(owner, "disable-wiki-safe"), json={
        "action": "disable_wiki",
        "rollback_trigger_summary": "无安全旧版可回退，关闭本空间 Wiki 交付",
        "reason_code": "no_safe_wiki_revision",
        "basis_ref": str(uuid4()),
    })
    assert disable.status_code == 200 and disable.json()["wiki_delivery_enabled"] is False
    rag_only = client.post("/v1/search", headers=bearer(owner), json={
        "query": "上海", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert rag_only.status_code == 200 and rag_only.json()["wiki"] == []
    assert any(p["passage_id"] == str(first.passage_ref) for p in rag_only.json()["passages"])


def test_synthetic_comparative_evaluation_report_and_metric_separation(transport):
    client, db, (owner, reviewer), credentials, live, first, second = transport
    connection, tenant, _, _, store = db
    _setup_wiki_rules(db)
    credentials[owner] = replace(credentials[owner], operations=RELEASE_OWNER_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=RELEASE_REVIEWER_OPS)
    reviewer_ref = _principal_ref(connection, tenant.other_actor_id)

    # Publish a reviewed Wiki grounded in `first`.
    _publish_wiki_via_http(
        client, connection, owner, reviewer, reviewer_ref,
        topic_key="travel-hotel-eval",
        title="上海差旅住宿评测摘要",
        markdown="上海住宿上限 600 元/晚。",
        direct_inputs=[[str(first.passage_ref), first.revision]],
        citations=[[str(first.passage_ref), first.revision]],
        statements=[{"text": "上海住宿上限 600 元。", "support_groups": [[[str(first.passage_ref), first.revision]]]}],
        tag="eval-wiki",
    )

    v_first = version_ref(connection, first)
    v_second = version_ref(connection, second)
    t_first = evaluation.EvidenceTarget(v_first, first.passage_ref)
    t_second = evaluation.EvidenceTarget(v_second, second.passage_ref)

    cases = [
        # Cross-document case: first query hits only `first`; followup query hits `second`.
        evaluation.EvalCase(
            case_id="SYN-CROSS-1",
            family_id="fam-cross",
            kind="supported",
            cross_document=True,
            principal_id=tenant.actor_id,
            business_date=BEFORE,
            region=credentials[owner].region,
            traveler_class=credentials[owner].traveler_class,
            query="限额",
            followup_query="审批",
            required_evidence_groups=((t_first,), (t_second,)),
        ),
        # Single-document supported case (triggers Wiki in rag_plus_wiki arm).
        evaluation.EvalCase(
            case_id="SYN-SINGLE-1",
            family_id="fam-single",
            kind="supported",
            cross_document=False,
            principal_id=tenant.actor_id,
            business_date=BEFORE,
            region=credentials[owner].region,
            traveler_class=credentials[owner].traveler_class,
            query="上海",
            required_evidence_groups=((t_first,),),
        ),
        # Partial case: `second` is denied at source authority, only `first` should be delivered.
        evaluation.EvalCase(
            case_id="SYN-PARTIAL-1",
            family_id="fam-partial",
            kind="partial",
            principal_id=tenant.actor_id,
            business_date=BEFORE,
            region=credentials[owner].region,
            traveler_class=credentials[owner].traveler_class,
            query="上海",
            required_evidence_groups=((t_first,),),
            forbidden_passage_ids=frozenset({second.passage_ref}),
            forbidden_substrings=("审批",),
        ),
        # Unsupported case: must return no_evidence cleanly.
        evaluation.EvalCase(
            case_id="SYN-UNSUP-1",
            family_id="fam-unsup",
            kind="unsupported",
            principal_id=tenant.actor_id,
            business_date=BEFORE,
            region=credentials[owner].region,
            traveler_class=credentials[owner].traveler_class,
            query="不存在的南极洲火星差旅津贴",
        ),
        # Authority revoked case: `second` is revoked, must leak nothing.
        evaluation.EvalCase(
            case_id="SYN-REVOKED-1",
            family_id="fam-revoked",
            kind="authority_revoked",
            principal_id=tenant.actor_id,
            business_date=BEFORE,
            region=credentials[owner].region,
            traveler_class=credentials[owner].traveler_class,
            query="审批",
            forbidden_passage_ids=frozenset({second.passage_ref}),
            forbidden_substrings=("审批",),
        ),
        # Dependency fault drill: authority is unavailable, must report dependency_unavailable (not no_evidence).
        evaluation.EvalCase(
            case_id="SYN-FAULT-1",
            family_id="fam-fault",
            kind="dependency_fault",
            principal_id=tenant.actor_id,
            business_date=BEFORE,
            region=credentials[owner].region,
            traveler_class=credentials[owner].traveler_class,
            query="上海",
        ),
    ]

    def authority_for_case(case: evaluation.EvalCase, check: delivery.DeliveryCheck) -> delivery.AuthorityDecision:
        if case.kind == "dependency_fault":
            raise delivery.AuthorizationUnavailable("Synthetic authority outage drill.")
        now_ts = datetime.now(UTC)
        permitted = {}
        for scope in check.scopes:
            if case.case_id in {"SYN-PARTIAL-1", "SYN-REVOKED-1"} and scope.object_id == second.passage_ref:
                permitted[scope] = frozenset()
                continue
            permitted[scope] = scope.fields
        return delivery.AuthorityDecision(
            check.check_id, now_ts, now_ts + timedelta(minutes=5),
            frozenset({case.principal_id}), permitted, "synthetic-eval-proof",
        )

    report = evaluation.run_synthetic_comparison(
        connection, tenant.org_id, tenant.space_id, store, cases,
        check_authority=authority_for_case, run_label="fr15-synthetic-check",
    )
    assert report["dataset_kind"] == "synthetic_local"
    assert report["replaces_frozen_blind_eval"] is False
    assert report["qa_answer_latency_status"] == "unmeasured_no_approved_agent"
    assert "本机合成样本" in report["disclaimer"]
    assert report["paired_comparison"]["sample_insufficient"] is True

    rag_arm = report["arms"]["rag_only"]
    wiki_arm = report["arms"]["rag_plus_wiki"]
    for arm in (rag_arm, wiki_arm):
        assert arm["first_search_top5_hit_rate"]["rate"] == 1.0
        # Followup search MUST stay separated from first_search_cross_doc_complete_rate!
        assert arm["first_search_cross_doc_complete_rate"]["numerator"] == 0
        assert arm["first_search_cross_doc_complete_rate"]["denominator"] == 1
        assert arm["followup_cross_doc_complete_rate"]["numerator"] == 1
        assert arm["followup_cross_doc_complete_rate"]["denominator"] == 1
        assert arm["false_abstention_rate"]["rate"] == 0.0
        assert arm["partial_correct_rate"]["rate"] == 1.0
        assert arm["correct_abstention_rate"]["rate"] == 1.0
        assert arm["authority_revoked_zero_leak_rate"]["rate"] == 1.0
        assert arm["dependency_fault_accuracy"]["rate"] == 1.0
        assert arm["unauthorized_disclosures"] == 0
        # Dependency fault drill must NOT inflate normal request count (5 normal cases, not 6).
        assert arm["normal_requests"]["total"] == 5
        assert arm["normal_requests"]["complete_success"] == 5
        assert arm["normal_requests"]["conditional_total_p50_ms"] is not None

    assert rag_arm["wiki_delivery_count"] == 0
    assert wiki_arm["wiki_delivery_count"] >= 2
    assert wiki_arm["wiki_citation_support_rate"]["rate"] == 1.0
    assert wiki_arm["wiki_uncited_claims"] == 0
    assert wiki_arm["wiki_unsupported_citations"] == 0
    assert report["wiki_maintenance_burden"]["published_topics"] == 1
    assert report["wiki_maintenance_burden"]["available_topics"] == 1

    # Cross-doc case uses distinct request_ids for first search and followup search under one task_chain_id.
    cross_rec = next(r for r in report["case_results"]["rag_only"] if r["case_id"] == "SYN-CROSS-1")
    assert cross_rec["used_followup"] is True
    assert cross_rec["followup_request_id"] is not None
    assert cross_rec["first_request_id"] != cross_rec["followup_request_id"]

    # Sanitized report must not leak raw query text or passage excerpts.
    encoded_report = json.dumps(report, ensure_ascii=False)
    assert "不存在的南极洲火星差旅津贴" not in encoded_report
    assert "600 元" not in encoded_report

    # Zero-denominator metrics must report status="unmeasured" and rate=None (never 0% or 100%).
    small_report = evaluation.run_synthetic_comparison(
        connection, tenant.org_id, tenant.space_id, store, [cases[1]],
        check_authority=authority_for_case, run_label="fr15-zero-denom",
    )
    assert small_report["arms"]["rag_only"]["partial_correct_rate"] == {
        "numerator": 0, "denominator": 0, "rate": None, "status": "unmeasured",
    }
    assert small_report["arms"]["rag_only"]["first_search_cross_doc_complete_rate"]["status"] == "unmeasured"
    assert small_report["arms"]["rag_only"]["correct_abstention_rate"]["rate"] is None


def test_wiki_management_release_panel_desktop_and_mobile(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, reviewer), credentials, _, first, second = portal
    connection, tenant, *_ = db
    _setup_wiki_rules(db)
    credentials[owner] = replace(credentials[owner], operations=RELEASE_OWNER_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=RELEASE_REVIEWER_OPS)

    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/manage/wiki")
    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="查看发布台账").click()
    expect(page.locator("#wiki-release-section")).to_be_visible()
    expect(page.locator("#wiki-release-summary")).to_contain_text("Wiki 交付：启用")

    # Switch space release to direct_scan + pure RAG via UI.
    page.locator("#wiki-release-action").select_option("disable_wiki")
    page.locator("#wiki-release-lexical-mode").select_option("direct_scan")
    page.locator("#wiki-release-trigger").fill("观测期命中率下降即切回上一代")
    page.locator("#wiki-release-reason").fill("ui_disable_wiki")
    page.get_by_role("button", name="执行空间发布切换").click()
    expect(page.locator("#wiki-release-switch-status")).to_contain_text("已切换至发布代次 1")
    expect(page.locator("#wiki-release-summary")).to_contain_text("已关闭（纯 RAG）")
    expect(page.locator("#wiki-release-summary")).to_contain_text("direct_scan")

    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-wiki-release-desktop.png")

    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-wiki-release-mobile.png")

    page.get_by_role("button", name="退出管理").click()
    expect(page.locator("#wiki-release-section")).to_be_hidden()
    assert page.locator("#wiki-release-summary").inner_text() == ""
