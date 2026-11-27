from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from psycopg import errors
import pytest

from enterprise_kb.database import (
    local_connection_factory,
    production_connection_factory,
    rehearsal_marker,
    upgrade,
)
from enterprise_kb.modules.access import policy
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence import quality_restrictions
from enterprise_kb.modules.lifecycle import space_archive
from enterprise_kb.modules.operations import release
from enterprise_kb.modules.retrieval import lexical, vector
from enterprise_kb.modules.sources import (
    effectivity,
    registry,
    restriction_log,
    source_restrictions,
    source_revocations,
    sync,
)
from enterprise_kb.modules.wiki import drafts, inputs as wiki_inputs, publication
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.transport import api, evidence
from enterprise_kb.transport.api import SPACE_ARCHIVES_PATH

from conftest import temporary_database
from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import endpoint
from test_deletion_tombstone import (
    REGISTER as REGISTER_TOMBSTONE,
    approved as approve_disposition,
    register as register_tombstone,
    submitted as submit_disposition,
)
from test_disposition import configure as configure_retention
from test_effectivity import BEFORE, SWITCH, approve as approve_rule, record as record_rule
from test_evidence import evidence_db
from test_evidence_transport import bearer, rpc
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import open_database, runtime_db
from test_source_sync import sync_request
from test_travel_search import SEARCH_FIELDS, publish
from test_wiki_inputs import compile_rule


HIST_START = date(2026, 10, 1)
HIST_DAY = date(2026, 10, 15)
CURR_DAY = date(2026, 11, 15)

LODGING_A_MD = "# 上海差旅住宿标准\n\n上海差旅住宿限额为每晚 500 元，普通出差不含旺季上浮例外。\n".encode()
LODGING_B_MD = (
    "# 上海差旅住宿标准\n\n"
    "上海差旅住宿限额提高至每晚 600 元。例外脚注：国际会展旺季经总监预批可上浮 20%。\n"
).encode()
APPROVAL_MD = (
    "# 上海住宿超标审批流程\n\n"
    "上海差旅住宿超标申请必须提交总监级审批并附财务复核单。\n"
).encode()
LEGACY_DELETE_MD = (
    "# 历史餐补废止稿\n\n"
    "2024 年历史临时餐补 888 元已废止，进入销毁与删除墓碑流程。\n"
).encode()


def _principal_ref(connection, org_id: int, principal_id: int) -> UUID:
    return connection.execute(
        """
        SELECT public_id FROM thalion.object_identity
        WHERE (org_id, object_type, object_id) = (%s, 'principal', %s)
        """,
        (org_id, principal_id),
    ).fetchone()[0]


def _add_employee(connection, org_id: int, subject_key: str) -> tuple[int, UUID]:
    with connection.transaction():
        pid, = connection.execute(
            """
            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
            VALUES (%s, 'employee', 'https://synthetic.invalid', %s)
            RETURNING principal_id
            """,
            (org_id, subject_key),
        ).fetchone()
        pref, = connection.execute(
            """
            INSERT INTO thalion.object_identity (object_type, object_id, org_id)
            VALUES ('principal', %s, %s)
            RETURNING public_id
            """,
            (pid, org_id),
        ).fetchone()
    return pid, pref


def _index_version(connection, store, space_ref: UUID, version_ref: UUID, run_ref: UUID, embedder):
    lexical.build_index(connection, store, space_ref, version_ref, run_ref)
    vector.build_vector_index(connection, store, space_ref, version_ref, run_ref, embedder)


def test_travel_full_vertical_acceptance_end_to_end(
    postgres_server, evidence_db, empty_rehearsal, tmp_path_factory,
):
    """Goal §7.4 差旅完整纵向联合验收：
    A/B 生效切换 + 历史/现行适用日 + 双员工身份隔离 + 原文稳定引用 + HTTP/MCP 等价 +
    Wiki 编写/拦截自批/独立审核/发布/未引用输入权限传播 + 源端撤权未同步实时阻断与故障 fail-closed +
    文档撤回导致 Wiki 失效 + 保留/处置/删除墓碑 + 空间归档与隔离围栏空库重放不复活。
    """
    connection, tenant, database_url, source_ref, store = evidence_db
    embedder = vector.SyntheticLocalEmbeddingProvider()

    ver_a, passage_a, run_a = publish(
        evidence_db, "shanghai-lodging", "上海差旅住宿标准", LODGING_A_MD,
        source_version_key="rev-a", version_label="A",
    )
    ver_b, passage_b, run_b = publish(
        evidence_db, "shanghai-lodging", "上海差旅住宿标准", LODGING_B_MD,
        source_version_key="rev-b", version_label="B",
    )
    ver_app, passage_app, run_app = publish(
        evidence_db, "over-budget-approval", "上海住宿超标审批流程", APPROVAL_MD,
        source_version_key="rev-1", version_label="V1",
    )
    ver_legacy, passage_legacy, run_legacy = publish(
        evidence_db, "legacy-allowance-2024", "历史餐补废止稿", LEGACY_DELETE_MD,
        source_version_key="rev-old", version_label="OLD",
    )
    for ver, run in ((ver_a, run_a), (ver_b, run_b), (ver_app, run_app), (ver_legacy, run_legacy)):
        _index_version(connection, store, tenant.space_ref, ver.version_ref, run.run_ref, embedder)

    dec_a = approve_rule(connection, tenant, ver_a, HIST_START)
    approve_rule(connection, tenant, ver_b, SWITCH, replaces=dec_a)
    approve_rule(connection, tenant, ver_app, HIST_START)
    approve_rule(connection, tenant, ver_legacy, HIST_START)

    rel_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, rel_req, tenant.actor_id, None, "travel-e2e-setup",
            release.SWITCH_SPACE_RELEASE, release.DESTINATION, CURR_DAY, 1,
            space_id=tenant.space_id, ingress="internal",
        ),
    )
    release.switch_space_release(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, rel_req, f"rel-{uuid4()}"),
        tenant.space_id,
        action="trial_switch",
        wiki_delivery_enabled=True,
        lexical_index_mode="hybrid_vector",
        vector_model_id=embedder.model_id,
        rollback_trigger_summary="travel e2e hybrid vector verification",
        reason_code="travel_e2e_hybrid",
        basis_ref=uuid4(),
    )
    finish_request(connection, tenant.org_id, rel_req, "succeeded", 0)

    limited_id, limited_ref = _add_employee(connection, tenant.org_id, "travel-limited-employee")
    full_ref = _principal_ref(connection, tenant.org_id, tenant.actor_id)
    reviewer_ref = _principal_ref(connection, tenant.org_id, tenant.other_actor_id)

    compile_ws = replace(compile_rule(tenant.actor_id), fields=policy.WORKSPACE_EVIDENCE_FIELDS)
    review_ws = replace(
        binding(tenant.other_actor_id),
        operation="review_wiki_revision",
        purpose="wiki_review",
        destination="local_workspace",
        fields=policy.WORKSPACE_EVIDENCE_FIELDS,
    )
    publish_ws = replace(review_ws, operation="publish_wiki_revision", purpose="wiki_publication")

    set_rules(
        evidence_db,
        compile_ws,
        review_ws,
        publish_ws,
        replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        replace(binding(tenant.other_actor_id), fields=SEARCH_FIELDS),
        replace(binding(limited_id, passage_ref=passage_a.passage_ref), fields=SEARCH_FIELDS),
        replace(binding(limited_id, passage_ref=passage_b.passage_ref), fields=SEARCH_FIELDS),
        expected=1,
    )

    with temporary_database(postgres_server) as log_url, temporary_database(postgres_server) as src_auth_url:
        upgrade(log_url)
        upgrade(src_auth_url)
        with open_database(log_url) as log_conn, open_database(src_auth_url) as src_auth_writer:
            src_auth_ref = endpoint(src_auth_writer)
            source_revocations.enroll_space(src_auth_writer, src_auth_ref, tenant.space_ref)
            source_authority = source_revocations.SourceRevocationAuthority(
                lambda: open_database(src_auth_url), src_auth_ref,
            )

            auth_state = {
                "down": False,
                "revoked_pairs": set(),
            }
            live_principals = {tenant.actor_id, tenant.other_actor_id, limited_id}

            def check_source_authority(credential, probe):
                if auth_state["down"]:
                    raise AuthorizationUnavailable("simulated source authority outage")
                decision = authority_for(live_principals)(probe)
                if not auth_state["revoked_pairs"]:
                    return decision
                filtered = {
                    scope: (
                        frozenset()
                        if (probe.context.principal_id, scope.object_id) in auth_state["revoked_pairs"]
                        else fields
                    )
                    for scope, fields in decision.permitted_fields.items()
                }
                return replace(decision, permitted_fields=filtered)

            full_token = token_urlsafe(32)
            reviewer_token = token_urlsafe(32)
            limited_token = token_urlsafe(32)
            expires = datetime.now(UTC) + timedelta(minutes=10)
            credentials = {
                full_token: evidence.SyntheticCredential(
                    full_ref, tenant.space_ref, "travel-e2e-client", "shanghai", "employee",
                    frozenset({
                        "search", "read_passage",
                        space_archive.REQUEST, space_archive.EXPORT,
                        "register_retention_policy", "submit_disposition_case",
                    }),
                    expires,
                ),
                reviewer_token: evidence.SyntheticCredential(
                    reviewer_ref, tenant.space_ref, "travel-e2e-reviewer", "shanghai", "employee",
                    frozenset({
                        "search", "read_passage",
                        space_archive.APPROVE, REGISTER_TOMBSTONE,
                    }),
                    expires,
                ),
                limited_token: evidence.SyntheticCredential(
                    limited_ref, tenant.space_ref, "travel-e2e-client", "shanghai", "employee",
                    frozenset({"search", "read_passage"}),
                    expires,
                ),
            }

            service = evidence.EvidenceService(
                lambda: open_database(database_url),
                credentials.get,
                check_source_authority,
                store,
                embedding_provider=embedder,
            )

            with TestClient(api.create_app(service), base_url="http://127.0.0.1") as client:
                hist_query = {"query": "上海差旅住宿", "business_date": HIST_DAY.isoformat(), "include_wiki": False}
                hist_http = client.post("/v1/search", headers=bearer(full_token), json=hist_query)
                hist_mcp = rpc(client, full_token, "tools/call", name="search", arguments=hist_query)
                assert hist_http.status_code == 200 and hist_mcp.status_code == 200
                hist_http_body = hist_http.json()
                hist_mcp_body = hist_mcp.json()["result"]["structuredContent"]
                assert hist_mcp_body | {"request_id": hist_http_body["request_id"]} == hist_http_body
                hist_ids = {item["passage_id"] for item in hist_http_body["passages"]}
                assert hist_ids == {str(passage_a.passage_ref), str(passage_app.passage_ref)}
                assert str(passage_b.passage_ref) not in hist_ids
                hist_lodging = next(
                    item for item in hist_http_body["passages"] if item["passage_id"] == str(passage_a.passage_ref)
                )
                assert "500" in hist_lodging["excerpt"] and "600" not in hist_lodging["excerpt"]

                read_a_http = client.get(f"/v1/passages/{passage_a.passage_ref}", headers=bearer(full_token))
                read_a_mcp = rpc(
                    client, full_token, "tools/call", name="read_passage",
                    arguments={"id": str(passage_a.passage_ref)},
                )
                assert read_a_http.status_code == 200 and read_a_mcp.status_code == 200
                assert read_a_http.json()["passage"] == read_a_mcp.json()["result"]["structuredContent"]["passage"]
                assert "500" in read_a_http.json()["passage"]["excerpt"]

                curr_query = {"query": "上海差旅住宿", "business_date": CURR_DAY.isoformat(), "include_wiki": False}
                curr_http = client.post("/v1/search", headers=bearer(full_token), json=curr_query)
                assert curr_http.status_code == 200
                curr_passages = curr_http.json()["passages"]
                curr_ids = {item["passage_id"] for item in curr_passages}
                assert curr_ids == {str(passage_b.passage_ref), str(passage_app.passage_ref)}
                assert str(passage_a.passage_ref) not in curr_ids
                curr_lodging = next(
                    item for item in curr_passages if item["passage_id"] == str(passage_b.passage_ref)
                )
                assert "600" in curr_lodging["excerpt"] and "20%" in curr_lodging["excerpt"]

                limited_curr = client.post("/v1/search", headers=bearer(limited_token), json=curr_query)
                assert limited_curr.status_code == 200
                assert [item["passage_id"] for item in limited_curr.json()["passages"]] == [str(passage_b.passage_ref)]
                limited_denied_http = client.get(
                    f"/v1/passages/{passage_app.passage_ref}", headers=bearer(limited_token),
                )
                assert limited_denied_http.status_code == 404
                assert limited_denied_http.json()["error"]["code"] == "citation_unavailable"
                limited_denied_mcp = rpc(
                    client, limited_token, "tools/call", name="read_passage",
                    arguments={"id": str(passage_app.passage_ref)},
                )
                assert limited_denied_mcp.json()["result"]["isError"] is True
                assert limited_denied_mcp.json()["result"]["structuredContent"]["error"]["code"] == "citation_unavailable"

                wiki_auth = authority_for(live_principals)
                assembled = wiki_inputs.prepare_wiki_inputs(
                    connection,
                    ingress(
                        evidence_db, tenant.actor_id, CURR_DAY,
                        operation="assemble_wiki_inputs", purpose="wiki_compilation", destination="local_workspace",
                    ),
                    tenant.space_id,
                    ((passage_b.passage_ref, passage_b.revision), (passage_app.passage_ref, passage_app.revision)),
                    (), store,
                    region="shanghai", traveler_class="employee", check_authority=wiki_auth,
                )
                assert assembled.status == "succeeded", assembled

                self_candidate = drafts.create_manual_candidate(
                    connection,
                    ingress(
                        evidence_db, tenant.actor_id, CURR_DAY,
                        operation="create_wiki_candidate", purpose="wiki_compilation", destination="local_workspace",
                    ),
                    tenant.space_id,
                    drafts.ManualCandidate(
                        topic_key="travel-shanghai-lodging",
                        title="上海差旅住宿指南",
                        markdown=f"2026年11月起上海住宿标准为每晚 600 元 [p:{passage_b.passage_ref}]。",
                        manifest_ref=assembled.manifest_ref,
                        reviewer_id=tenant.actor_id,
                        basis_ref=uuid4(),
                        citations=((passage_b.passage_ref, passage_b.revision),),
                        statements=(
                            drafts.WikiStatement(
                                "2026年11月起上海住宿限额为每晚 600 元，旺季经预批可上浮 20%。",
                                (((passage_b.passage_ref, passage_b.revision),),),
                            ),
                        ),
                    ),
                    f"wiki-self-attempt-{uuid4()}",
                    region="shanghai", traveler_class="employee", check_authority=wiki_auth,
                )
                assert self_candidate.status == "rejected"

                created = drafts.create_manual_candidate(
                    connection,
                    ingress(
                        evidence_db, tenant.actor_id, CURR_DAY,
                        operation="create_wiki_candidate", purpose="wiki_compilation", destination="local_workspace",
                    ),
                    tenant.space_id,
                    drafts.ManualCandidate(
                        topic_key="travel-shanghai-lodging",
                        title="上海差旅住宿指南",
                        markdown=f"2026年11月起上海住宿标准为每晚 600 元 [p:{passage_b.passage_ref}]。",
                        manifest_ref=assembled.manifest_ref,
                        reviewer_id=tenant.other_actor_id,
                        basis_ref=uuid4(),
                        citations=((passage_b.passage_ref, passage_b.revision),),
                        statements=(
                            drafts.WikiStatement(
                                "2026年11月起上海住宿限额为每晚 600 元，旺季经预批可上浮 20%。",
                                (((passage_b.passage_ref, passage_b.revision),),),
                            ),
                        ),
                    ),
                    f"wiki-cand-{uuid4()}",
                    region="shanghai", traveler_class="employee", check_authority=wiki_auth,
                )
                assert created.status == "succeeded", created
                wiki_rev_ref = created.ref

                preview = drafts.read_candidate_for_review(
                    connection,
                    ingress(
                        evidence_db, tenant.other_actor_id, CURR_DAY,
                        operation="read_wiki_candidate", purpose="wiki_review", destination="local_workspace",
                    ),
                    tenant.space_id, wiki_rev_ref,
                    region="shanghai", traveler_class="employee", check_authority=wiki_auth,
                )
                assert preview.status == "succeeded", preview

                self_review = drafts.submit_review(
                    connection,
                    ingress(
                        evidence_db, tenant.actor_id, CURR_DAY,
                        operation="review_wiki_revision", purpose="wiki_review", destination="local_workspace",
                    ),
                    tenant.space_id, wiki_rev_ref, sha256(preview.payload).digest(), preview.input_digest,
                    "approved", "self_review_attempt", uuid4(), f"self-rev-{uuid4()}",
                    region="shanghai", traveler_class="employee", check_authority=wiki_auth,
                    review_material_ref=preview.review_material_ref,
                )
                assert self_review.status == "rejected"

                reviewed = drafts.submit_review(
                    connection,
                    ingress(
                        evidence_db, tenant.other_actor_id, CURR_DAY,
                        operation="review_wiki_revision", purpose="wiki_review", destination="local_workspace",
                    ),
                    tenant.space_id, wiki_rev_ref, sha256(preview.payload).digest(), preview.input_digest,
                    "approved", "independent_verified", uuid4(), f"ind-rev-{uuid4()}",
                    region="shanghai", traveler_class="employee", check_authority=wiki_auth,
                    review_material_ref=preview.review_material_ref,
                )
                assert reviewed.status == "succeeded", reviewed

                published = publication.publish_revision(
                    connection,
                    ingress(
                        evidence_db, tenant.other_actor_id, CURR_DAY,
                        operation="publish_wiki_revision", purpose="wiki_publication", destination="local_workspace",
                    ),
                    tenant.space_id, wiki_rev_ref, reviewed.ref, f"pub-{uuid4()}",
                    region="shanghai", traveler_class="employee", check_authority=wiki_auth,
                )
                assert published.status == "succeeded", published

                wiki_query = {"query": "上海住宿限额", "business_date": CURR_DAY.isoformat(), "top_k": 1, "include_wiki": True}
                wiki_http = client.post("/v1/search", headers=bearer(full_token), json=wiki_query)
                wiki_mcp = rpc(client, full_token, "tools/call", name="search", arguments=wiki_query)
                assert wiki_http.status_code == 200 and wiki_mcp.status_code == 200
                wiki_http_body = wiki_http.json()
                wiki_mcp_body = wiki_mcp.json()["result"]["structuredContent"]
                assert wiki_mcp_body | {"request_id": wiki_http_body["request_id"]} == wiki_http_body
                assert len(wiki_http_body["wiki"]) == 1
                assert wiki_http_body["wiki"][0]["revision_id"] == str(wiki_rev_ref)

                sealed_deps = connection.execute(
                    """
                    SELECT passage_ref FROM thalion.delivery_record
                    JOIN thalion.delivery_dependency USING (check_id, org_id)
                    WHERE request_id = %s
                    """,
                    (wiki_http_body["request_id"],),
                ).fetchall()
                assert {row[0] for row in sealed_deps} == {passage_b.passage_ref, passage_app.passage_ref}

                limited_wiki = client.post("/v1/search", headers=bearer(limited_token), json=wiki_query)
                assert limited_wiki.status_code == 200
                assert limited_wiki.json()["wiki"] == []
                assert [item["passage_id"] for item in limited_wiki.json()["passages"]] == [str(passage_b.passage_ref)]

                auth_state["revoked_pairs"].add((tenant.actor_id, passage_app.passage_ref))
                revoked_wiki_resp = client.post("/v1/search", headers=bearer(full_token), json=wiki_query)
                assert revoked_wiki_resp.status_code == 200
                assert revoked_wiki_resp.json()["wiki"] == []
                assert [item["passage_id"] for item in revoked_wiki_resp.json()["passages"]] == [str(passage_b.passage_ref)]
                revoked_read = client.get(f"/v1/passages/{passage_app.passage_ref}", headers=bearer(full_token))
                assert revoked_read.status_code == 404
                assert revoked_read.json()["error"]["code"] == "citation_unavailable"
                auth_state["revoked_pairs"].clear()

                auth_state["down"] = True
                outage_http = client.post("/v1/search", headers=bearer(full_token), json=wiki_query)
                outage_mcp = rpc(client, full_token, "tools/call", name="search", arguments=wiki_query)
                assert outage_http.status_code == 503
                assert outage_http.json()["error"]["code"] == "dependency_unavailable"
                assert outage_mcp.json()["result"]["isError"] is True
                assert outage_mcp.json()["result"]["structuredContent"]["error"]["code"] == "dependency_unavailable"
                auth_state["down"] = False

                archive_req = client.post(
                    SPACE_ARCHIVES_PATH,
                    headers=bearer(full_token) | {"Idempotency-Key": "e2e-space-arch-req"},
                    json={
                        "source_ids": [str(source_ref)],
                        "version_ids": [
                            str(ver_a.version_ref), str(ver_b.version_ref),
                            str(ver_app.version_ref), str(ver_legacy.version_ref),
                        ],
                        "wiki_revision_ids": [str(wiki_rev_ref)],
                    },
                )
                assert archive_req.status_code == 200, archive_req.text
                export_id = UUID(archive_req.json()["export_id"])

                exp_iso = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
                assert client.post(
                    f"{SPACE_ARCHIVES_PATH}/{export_id}/approve",
                    headers=bearer(full_token) | {"Idempotency-Key": "e2e-arch-self-app"},
                    json={"expires_at": exp_iso},
                ).status_code == 403
                assert client.post(
                    f"{SPACE_ARCHIVES_PATH}/{export_id}/approve",
                    headers=bearer(reviewer_token) | {"Idempotency-Key": "e2e-arch-ind-app"},
                    json={"expires_at": exp_iso},
                ).status_code == 200

                seal_req_id = uuid4()
                start_request(
                    connection,
                    RequestStart(
                        tenant.org_id, seal_req_id, tenant.actor_id, None, "e2e-seal",
                        space_archive.EXPORT, "internal_lifecycle", CURR_DAY, 1,
                        space_id=tenant.space_id, ingress="internal",
                    ),
                )
                seal_call = space_archive.OperationsCall(
                    tenant.org_id, tenant.space_id, tenant.actor_id, seal_req_id, "e2e-seal-cmd", 1,
                )
                seal_ctx = space_archive.delivery.DeliveryContext(
                    seal_req_id, tenant.org_id, tenant.actor_id, "e2e-seal",
                    space_archive.EXPORT, space_archive.PURPOSE, space_archive.ARCHIVE_DESTINATION,
                    datetime.now(UTC) + timedelta(minutes=2),
                )
                with connection.transaction():
                    space_archive.seal_space_archive(
                        connection, seal_call, export_id, store, seal_ctx,
                        authority_for({tenant.actor_id}),
                        rule_log=log_conn, source_authority=source_authority,
                    )
                finish_request(connection, tenant.org_id, seal_req_id, "succeeded", 0)
                pkg_bytes, pkg_digest = connection.execute(
                    "SELECT archive_bytes, archive_digest FROM thalion.space_archive_package WHERE export_ref = %s",
                    (export_id,),
                ).fetchone()

                withdraw_app_stop = effectivity.stop_synthetic_rule(
                    connection, record_rule(connection, tenant, "stop_rule_use", f"e2e-withdraw-app-{uuid4()}"),
                    tenant.space_id, ver_app.version_ref, "withdrawn", uuid4(),
                )
                after_withdraw = client.post("/v1/search", headers=bearer(full_token), json=wiki_query)
                assert after_withdraw.status_code == 200
                assert after_withdraw.json()["wiki"] == []
                assert [item["passage_id"] for item in after_withdraw.json()["passages"]] == [str(passage_b.passage_ref)]

                assert configure_retention(client, full_token, source_ref, action="destroy", expected=0).status_code == 200
                effectivity.stop_synthetic_rule(
                    connection, record_rule(connection, tenant, "stop_rule_use", f"e2e-stop-legacy-{uuid4()}"),
                    tenant.space_id, ver_legacy.version_ref, "withdrawn", uuid4(),
                )
                delete_event = uuid4()
                case_id = submit_disposition(
                    client, full_token, credentials, source_ref, SimpleNamespace(version_ref=ver_legacy.version_ref), expected=1,
                )
                disp_app_id = approve_disposition(client, reviewer_token, credentials, case_id, basis=delete_event)
                tomb_reply = register_tombstone(client, reviewer_token, case_id, disp_app_id)
                assert tomb_reply.status_code == 200, tomb_reply.text
                tombstone_id = UUID(tomb_reply.json()["tombstone_id"])
                source_restrictions.acknowledge_removal(
                    connection,
                    sync_request(connection, tenant, operation=source_restrictions.COMMIT),
                    sync.SyncSource(tenant.space_id, source_ref, 1),
                    source_restrictions.Removal(
                        delete_event, "legacy-allowance-2024", "first", "rev-old", "deleted", tombstone_id,
                    ),
                )

                source_revocations.revoke(
                    src_auth_writer, src_auth_ref, tenant.space_ref, limited_ref, passage_b.passage_ref,
                    "evidence", basis_ref=uuid4(),
                )
                delivered_rules = restriction_log.deliver_pending(connection, log_conn, tenant.org_id)
                assert withdraw_app_stop in delivered_rules.confirmed and tombstone_id in delivered_rules.confirmed
                assert quality_restrictions.deliver_pending(connection, log_conn, tenant.org_id).status == "ok"

                target, rehearsal_url = empty_rehearsal
                permit = space_archive.SpaceArchivePermit(
                    tenant.org_id, tenant.space_id, tenant.space_ref, export_id, bytes(pkg_digest), target.info.dbname,
                )
                scratch = tmp_path_factory.mktemp("travel-e2e-rebuild")
                checks = (
                    space_archive.OldReferenceCheck(
                        label="historical_vA_accessible_before_switch_after_rebuild",
                        kind="passage",
                        principal_ref=full_ref,
                        business_date=HIST_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=True,
                        passage_ref=passage_a.passage_ref,
                        version_ref=ver_a.version_ref,
                        query="500 元",
                    ),
                    space_archive.OldReferenceCheck(
                        label="current_vB_accessible_for_full_employee",
                        kind="passage",
                        principal_ref=full_ref,
                        business_date=CURR_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=True,
                        passage_ref=passage_b.passage_ref,
                        version_ref=ver_b.version_ref,
                        query="上海差旅住宿",
                    ),
                    space_archive.OldReferenceCheck(
                        label="replaced_vA_not_applicable_on_current_day_after_rebuild",
                        kind="passage",
                        principal_ref=full_ref,
                        business_date=CURR_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=False,
                        passage_ref=passage_a.passage_ref,
                        version_ref=ver_a.version_ref,
                        query="500 元",
                    ),
                    space_archive.OldReferenceCheck(
                        label="future_vB_not_applicable_on_historical_day_after_rebuild",
                        kind="passage",
                        principal_ref=full_ref,
                        business_date=HIST_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=False,
                        passage_ref=passage_b.passage_ref,
                        version_ref=ver_b.version_ref,
                        query="600 元",
                    ),
                    space_archive.OldReferenceCheck(
                        label="withdrawn_approval_blocked_no_resurrection",
                        kind="passage",
                        principal_ref=full_ref,
                        business_date=CURR_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=False,
                        passage_ref=passage_app.passage_ref,
                        version_ref=ver_app.version_ref,
                        query="超标审批",
                    ),
                    space_archive.OldReferenceCheck(
                        label="wiki_dependent_on_withdrawn_approval_blocked",
                        kind="wiki",
                        principal_ref=full_ref,
                        business_date=CURR_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=False,
                        topic_key="travel-shanghai-lodging",
                    ),
                    space_archive.OldReferenceCheck(
                        label="tombstoned_legacy_blocked_no_resurrection",
                        kind="passage",
                        principal_ref=full_ref,
                        business_date=HIST_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=False,
                        passage_ref=passage_legacy.passage_ref,
                        version_ref=ver_legacy.version_ref,
                        query="888 元",
                    ),
                    space_archive.OldReferenceCheck(
                        label="source_revoked_limited_employee_blocked_on_vB",
                        kind="passage",
                        principal_ref=limited_ref,
                        business_date=CURR_DAY,
                        region="shanghai",
                        traveler_class="employee",
                        expected_accessible=False,
                        passage_ref=passage_b.passage_ref,
                        version_ref=ver_b.version_ref,
                        query="600 元",
                    ),
                )

                report = space_archive.rebuild_space_archive_in_rehearsal(
                    target, permit, bytes(pkg_bytes), scratch,
                    authority=connection, log=log_conn,
                    authority_ref=endpoint(connection), log_ref=endpoint(log_conn),
                    source_authority=source_authority,
                    alternate_model_profile="travel-e2e-alt-v2",
                    lexical_index_mode="indexed",
                    reference_checks=checks,
                )
                report_dict = report.to_dict()
                assert report.rebuilt_sources == 1
                assert report.rebuilt_versions == 4
                assert report.rebuilt_wikis == 1
                assert report.replayed_stops >= 2
                assert report.replayed_deletions >= 1
                assert report.replayed_revocations == 1
                assert report_dict["verified_references"] == 2
                assert report_dict["blocked_references"] == 6
                assert set(report.indexed_versions) == {ver_a.version_ref, ver_b.version_ref}

                assert rehearsal_marker(target) == target.info.dbname
                with pytest.raises(errors.OperationalError, match="rehearsal"):
                    local_connection_factory(rehearsal_url)()
                with pytest.raises(errors.OperationalError, match="rehearsal"):
                    production_connection_factory(rehearsal_url)()
