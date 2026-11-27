from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import httpx2
import jwt
from psycopg import errors
import pytest

from enterprise_kb import worker
from enterprise_kb.database import upgrade
from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.lifecycle import backup_inventory
from enterprise_kb.modules.operations import release
from enterprise_kb.modules.retrieval import vector
from enterprise_kb.modules.sources import effectivity, originals, registry
from enterprise_kb.modules.wiki import templates
from enterprise_kb.ports.adapters import (
    HttpEmbeddingProviderAdapter,
    HttpModelGatewayAdapter,
    HttpObjectStorageAdapter,
    HttpSecurityAuditLogAdapter,
    HttpSourceAuthorityAdapter,
    HttpSourceConnectorAdapter,
    OidcJwksIdentityVerifier,
)
from enterprise_kb.ports.contracts import PortRegistry, ProductionIsolationError
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.runtime.audit_sink import FORBIDDEN_AUDIT_KEYS
from enterprise_kb.runtime.config import (
    AuthenticatedEndpointConfig,
    IdentityEndpointConfig,
    ObjectStorageEndpointConfig,
)
from enterprise_kb.transport import api, evidence

from test_effectivity import BEFORE, BEGIN
from test_evidence_transport import bearer, rpc
from test_runtime import Tenant, open_database, runtime_db
from test_sources import register, request_for


PROD_ISSUER = "https://idp.corp.example"
PROD_AUDIENCE = "thalion-kb-prod"
PROD_HOST = "kb.corp.example"
PROD_EMBED_MODEL = "corp-embed-prod-v1"
PROD_GATEWAY_DEST = "corp-llm-prod-v1"

DOC_ALLOWANCE = "# 上海差旅住宿标准\n\n员工赴上海出差住宿标准上限为每晚 650 元，凭合规增值税发票报销。\n".encode("utf-8")
DOC_RAIL = "# 高铁出行标准\n\n城际出差优先选乘高铁二等座，单程超过五小时可按流程申请一等座。\n".encode("utf-8")


def _generate_rsa_jwk(key_id: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = key_id
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return private_key, public_jwk


def _issue_prod_jwt(
    private_key,
    key_id: str,
    *,
    subject_ref: UUID,
    space_ref: UUID,
    operations: list[str],
    client_id: str = "corp-portal",
    region: str = "shanghai",
    traveler_class: str = "employee",
) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": PROD_ISSUER,
            "aud": PROD_AUDIENCE,
            "sub": str(subject_ref),
            "space_ref": str(space_ref),
            "client_id": client_id,
            "operations": operations,
            "region": region,
            "traveler_class": traveler_class,
            "iat": int(now.timestamp()) - 10,
            "nbf": int(now.timestamp()) - 10,
            "exp": int((now + timedelta(minutes=10)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": key_id},
    )


def _create_production_tenant(connection, name: str) -> tuple[Tenant, UUID, UUID]:
    with connection.transaction():
        org_id = connection.execute(
            "INSERT INTO thalion.organization (name, business_timezone) "
            "VALUES (%s, 'Asia/Shanghai') RETURNING org_id",
            (name,),
        ).fetchone()[0]
        principal_ids: list[int] = []
        principal_refs: list[UUID] = []
        for role in ("employee", "employee", "service", "service"):
            principal_id = connection.execute(
                "INSERT INTO thalion.principal "
                "(org_id, principal_type, authority_issuer, authority_subject_key) "
                "VALUES (%s, %s, %s, %s) RETURNING principal_id",
                (org_id, role, PROD_ISSUER, f"sub-{uuid4()}"),
            ).fetchone()[0]
            public_ref = connection.execute(
                "INSERT INTO thalion.object_identity (org_id, object_type, object_id) "
                "VALUES (%s, 'principal', %s) RETURNING public_id",
                (org_id, principal_id),
            ).fetchone()[0]
            principal_ids.append(principal_id)
            principal_refs.append(public_ref)
        space_id = connection.execute(
            "INSERT INTO thalion.space (org_id, name, classification, owner_principal_id) "
            "VALUES (%s, 'ProdTravelSpace', 'internal', %s) RETURNING space_id",
            (org_id, principal_ids[0]),
        ).fetchone()[0]
        space_ref = connection.execute(
            "INSERT INTO thalion.object_identity (org_id, object_type, object_id, space_id) "
            "VALUES (%s, 'space', %s, %s) RETURNING public_id",
            (org_id, space_id, space_id),
        ).fetchone()[0]
    tenant = Tenant(org_id, space_id, space_ref, *principal_ids)
    return tenant, principal_refs[0], principal_refs[1]


def _idempotent_headers(token: str) -> dict[str, str]:
    return bearer(token) | {"Idempotency-Key": f"prod-e2e-{uuid4()}"}


def test_production_mode_end_to_end_connector_worker_search_original_wiki_catalog_and_strict_audit(runtime_db):
    connection, _, database_url = runtime_db
    tenant, owner_ref, reviewer_ref = _create_production_tenant(connection, "ProdEnterpriseE2E")

    authority_ref = uuid4()
    security_log_ref = uuid4()
    private_key, public_jwk = _generate_rsa_jwk("prod-e2e-k1")
    local_encoder = vector.SyntheticLocalEmbeddingProvider()

    object_blobs: dict[str, bytes] = {}
    audit_records: list[dict] = []
    connector_state = {"synced": False, "extra_delta": False}
    audit_state = {"down": False}
    gateway_state = {"calls": 0, "passage_refs": ()}

    ctx = request_for(connection, tenant, tenant.actor_id, f"reg-prod-src-{uuid4()}", "register_source_contract")
    source_ref = registry.register_source(
        connection,
        ctx,
        tenant.space_id,
        registry.SyntheticSource(
            "corp-confluence-travel",
            "corp-confluence-archive",
            tenant.worker_id,
            approver_id=tenant.other_actor_id,
            processor_id=tenant.other_worker_id,
            quality_reviewer_id=tenant.actor_id,
            model_policy_approver_id=tenant.other_actor_id,
        ),
        admission=registry.PRODUCTION_ADMISSION,
    )

    def jwks_handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"keys": [public_jwk]})

    def authority_handler(request: httpx2.Request) -> httpx2.Response:
        payload = json.loads(request.content)
        now = datetime.now(UTC)
        grants = [
            {
                "object_id": scope["object_id"],
                "revision": scope["revision"],
                "fields": list(scope["fields"]),
            }
            for scope in payload["scopes"]
        ]
        return httpx2.Response(
            200,
            json={
                "check_id": payload["check_id"],
                "authority_ref": str(authority_ref),
                "checked_at": now.isoformat(),
                "valid_until": (now + timedelta(seconds=30)).isoformat(),
                "subject_ids": [payload["principal_id"]],
                "proof_ref": f"prod-auth-proof-{uuid4()}",
                "grants": grants,
            },
        )

    def storage_handler(request: httpx2.Request) -> httpx2.Response:
        storage_key = request.url.path.rsplit("/", 1)[-1]
        if request.method == "PUT":
            object_blobs[storage_key] = request.content
            return httpx2.Response(201, json={"sha256": sha256(request.content).hexdigest()})
        if storage_key not in object_blobs:
            return httpx2.Response(404, text="not found")
        return httpx2.Response(200, content=object_blobs[storage_key])

    def audit_handler(request: httpx2.Request) -> httpx2.Response:
        if audit_state["down"]:
            return httpx2.Response(503, text="audit sink unavailable")
        payload = json.loads(request.content)
        assert not (FORBIDDEN_AUDIT_KEYS & set(payload))
        audit_records.append(payload)
        return httpx2.Response(
            200,
            json={
                "log_ref": str(security_log_ref),
                "stream_ref": str(uuid4()),
                "generation": len(audit_records),
                "recorded_at": datetime.now(UTC).isoformat(),
                "digest": sha256(request.content).hexdigest(),
            },
        )

    def connector_handler(request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path.endswith("/deltas"):
            cursor = request.url.params.get("cursor")
            if not connector_state["synced"]:
                connector_state["synced"] = True
                items = [
                    {
                        "action": "upsert",
                        "object_key": "travel-allowance-sh",
                        "incarnation": "v1",
                        "source_version_key": "rev-1",
                        "version_label": "2026.1",
                        "display_name": "上海差旅住宿标准",
                        "media_type": "text/markdown",
                        "content_sha256": sha256(DOC_ALLOWANCE).hexdigest(),
                        "content_base64": None,
                        "download_key": "allowance",
                    },
                    {
                        "action": "upsert",
                        "object_key": "travel-rail-policy",
                        "incarnation": "v1",
                        "source_version_key": "rev-1",
                        "version_label": "2026.1",
                        "display_name": "高铁出行标准",
                        "media_type": "text/markdown",
                        "content_sha256": sha256(DOC_RAIL).hexdigest(),
                        "content_base64": None,
                        "download_key": "rail",
                    },
                ]
                for entry in items:
                    raw_bytes = DOC_ALLOWANCE if entry["download_key"] == "allowance" else DOC_RAIL
                    import base64

                    entry["content_base64"] = base64.b64encode(raw_bytes).decode("ascii")
                    entry.pop("download_key")
                return httpx2.Response(
                    200,
                    json={
                        "previous_cursor": cursor,
                        "through_cursor": "cursor-prod-1",
                        "has_more": False,
                        "items": items,
                    },
                )
            return httpx2.Response(
                200,
                json={
                    "previous_cursor": cursor,
                    "through_cursor": cursor or "cursor-prod-1",
                    "has_more": False,
                    "items": [],
                },
            )
        if path.endswith("/inventory"):
            return httpx2.Response(
                200,
                json={
                    "snapshot_ref": "inv-prod-1",
                    "observed_at": datetime.now(UTC).isoformat(),
                    "complete": True,
                    "stable_object_keys": ["travel-allowance-sh", "travel-rail-policy"],
                    "entries": [
                        {
                            "object_key": "travel-allowance-sh",
                            "incarnation": "v1",
                            "source_version_key": "rev-1",
                            "content_sha256": sha256(DOC_ALLOWANCE).hexdigest(),
                        },
                        {
                            "object_key": "travel-rail-policy",
                            "incarnation": "v1",
                            "source_version_key": "rev-1",
                            "content_sha256": sha256(DOC_RAIL).hexdigest(),
                        },
                    ],
                },
            )
        return httpx2.Response(404, text="unknown connector route")

    def embedding_handler(request: httpx2.Request) -> httpx2.Response:
        payload = json.loads(request.content)
        assert payload["model_id"] == PROD_EMBED_MODEL
        vectors = [list(local_encoder.embed_query(item)) for item in payload["inputs"]]
        return httpx2.Response(200, json={"model_id": PROD_EMBED_MODEL, "vectors": vectors})

    def gateway_handler(request: httpx2.Request) -> httpx2.Response:
        gateway_state["calls"] += 1
        payload = json.loads(request.content)
        assert payload["purpose"] == "wiki_compilation"
        assert payload["destination_id"] == PROD_GATEWAY_DEST
        first_ref, first_rev = gateway_state["passage_refs"][0]
        draft_body = {
            "title": "上海差旅住宿与高铁速查",
            "markdown": "# 差旅速查\n赴上海住宿上限每晚 650 元，详见原文引文。",
            "citations": [[str(first_ref), first_rev]],
            "statements": [
                {
                    "text": "上海差旅住宿上限为每晚 650 元。",
                    "support_groups": [[[str(first_ref), first_rev]]],
                }
            ],
        }
        encoded = json.dumps(draft_body, ensure_ascii=False, separators=(",", ":"))
        return httpx2.Response(
            200,
            json={
                "provider_call_id": f"prod-gw-{gateway_state['calls']}",
                "accepted": True,
                "input_tokens": 240,
                "output_tokens": 95,
                "billed_microunits": 3800,
                "output_digest": sha256(encoded.encode("utf-8")).hexdigest(),
                "output_utf8": encoded,
            },
        )

    secrets = {
        "vault:auth": "prod-auth-secret",
        "vault:obj": "prod-obj-secret",
        "vault:audit": "prod-audit-secret",
        "vault:conn": "prod-conn-secret",
        "vault:embed": "prod-embed-secret",
        "vault:gateway": "prod-gw-secret",
    }
    port_registry = PortRegistry(
        mode="production",
        identity=OidcJwksIdentityVerifier(
            IdentityEndpointConfig(PROD_ISSUER, PROD_AUDIENCE, "https://idp.corp.example/.well-known/jwks.json"),
            transport=httpx2.MockTransport(jwks_handler),
        ),
        source_authority=HttpSourceAuthorityAdapter(
            AuthenticatedEndpointConfig("https://auth.corp.example/v1/check", "vault:auth"),
            authority_ref=authority_ref,
            secret_resolver=secrets.__getitem__,
            transport=httpx2.MockTransport(authority_handler),
        ),
        object_storage=HttpObjectStorageAdapter(
            ObjectStorageEndpointConfig("https://obj.corp.example", "prod-originals", "vault:obj"),
            secret_resolver=secrets.__getitem__,
            transport=httpx2.MockTransport(storage_handler),
        ),
        security_audit_log=HttpSecurityAuditLogAdapter(
            AuthenticatedEndpointConfig("https://audit.corp.example/v1/events", "vault:audit"),
            log_ref=security_log_ref,
            secret_resolver=secrets.__getitem__,
            transport=httpx2.MockTransport(audit_handler),
        ),
        source_connector=HttpSourceConnectorAdapter(
            AuthenticatedEndpointConfig("https://connector.corp.example/v1", "vault:conn"),
            source_system="confluence-prod",
            secret_resolver=secrets.__getitem__,
            transport=httpx2.MockTransport(connector_handler),
        ),
        embedding_provider=HttpEmbeddingProviderAdapter(
            AuthenticatedEndpointConfig("https://embed.corp.example/v1", "vault:embed"),
            model_id=PROD_EMBED_MODEL,
            dimension=64,
            secret_resolver=secrets.__getitem__,
            transport=httpx2.MockTransport(embedding_handler),
        ),
        model_gateway=HttpModelGatewayAdapter(
            AuthenticatedEndpointConfig("https://gw.corp.example/v1", "vault:gateway"),
            destination_id=PROD_GATEWAY_DEST,
            allowed_purposes=frozenset({"wiki_compilation"}),
            secret_resolver=secrets.__getitem__,
            transport=httpx2.MockTransport(gateway_handler),
        ),
    )

    worker_config = worker.WorkerConfig.from_port_registry(
        lambda: open_database(database_url),
        port_registry,
        reconcile_on_sync=True,
    )
    first_cycle = worker.run_worker_cycle(worker_config)
    assert first_cycle.errors == ()
    assert len(first_cycle.synced_sources) == 1
    sync_summary = first_cycle.synced_sources[0]
    assert sync_summary["status"] == "succeeded"
    assert len(sync_summary["versions_registered"]) == 2
    assert sync_summary["reconciliation_status"] == "reconciled"
    assert sync_summary["reconciliation_matched"] == 2
    assert len(first_cycle.parsed_jobs) == 2
    assert all(job["outcome"] == "pending_review" for job in first_cycle.parsed_jobs)

    storage_kinds = connection.execute(
        "SELECT DISTINCT storage_kind FROM thalion.asset WHERE org_id = %s AND space_id = %s",
        (tenant.org_id, tenant.space_id),
    ).fetchall()
    assert storage_kinds == [("https_object_store",)]

    version_refs = [UUID(ver_str) for ver_str in sync_summary["versions_registered"]]
    approved_passages = []
    for parsed_job in first_cycle.parsed_jobs:
        run_ref = UUID(parsed_job["run_id"])
        ver_ref = UUID(parsed_job["version_id"])
        manifest_digest, = connection.execute(
            "SELECT manifest_digest FROM thalion.processing_run WHERE run_ref = %s",
            (run_ref,),
        ).fetchone()
        qual_ctx = request_for(connection, tenant, tenant.actor_id, f"qual-{uuid4()}", "decide_evidence_quality")
        processing.decide_quality(connection, qual_ctx, tenant.space_id, run_ref, manifest_digest, "approved", uuid4())
        eff_ctx = request_for(connection, tenant, tenant.other_actor_id, f"eff-{uuid4()}", "approve_effectivity")
        effectivity.approve_synthetic_rule(
            connection,
            eff_ctx,
            tenant.space_id,
            ver_ref,
            effectivity.Approval(BEGIN, None, None, None, uuid4()),
        )
        approved_passages.extend(
            processing.list_approved_passages(connection, tenant.org_id, tenant.space_id, ver_ref)
        )
    assert len(approved_passages) == 2
    gateway_state["passage_refs"] = tuple((item.passage_ref, item.revision) for item in approved_passages)

    second_cycle = worker.run_worker_cycle(worker_config)
    assert second_cycle.errors == ()
    assert len([row for row in second_cycle.lexical_indexed if row["status"] == "indexed"]) == 2
    assert len([row for row in second_cycle.vector_indexed if row["status"] == "indexed"]) == 2

    rel_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id,
            rel_req,
            tenant.actor_id,
            None,
            "prod-release",
            release.SWITCH_SPACE_RELEASE,
            "internal_release",
            BEFORE,
            1,
            space_id=tenant.space_id,
            ingress="internal",
        ),
    )
    release.switch_space_release(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, rel_req, f"rel-{uuid4()}"),
        tenant.space_id,
        action="trial_switch",
        wiki_delivery_enabled=True,
        lexical_index_mode="hybrid_vector",
        vector_model_id=PROD_EMBED_MODEL,
        rollback_trigger_summary="rollback to indexed if embedding latency spikes",
        reason_code="prod_e2e_release",
        basis_ref=uuid4(),
    )
    finish_request(connection, tenant.org_id, rel_req, "succeeded", 0)

    now = datetime.now(UTC)
    local_rules = (
        policy.LocalRule(
            owner_ref,
            "read_passage",
            "allow",
            "employee_evidence",
            "employee",
            policy.PASSAGE_FIELDS,
            now - timedelta(hours=1),
        ),
        policy.LocalRule(
            reviewer_ref,
            "read_passage",
            "allow",
            "employee_evidence",
            "employee",
            policy.PASSAGE_FIELDS,
            now - timedelta(hours=1),
        ),
        policy.LocalRule(
            owner_ref,
            policy.ORIGINAL_DOWNLOAD_ACCESS[0],
            "allow",
            policy.ORIGINAL_DOWNLOAD_ACCESS[1],
            policy.ORIGINAL_DOWNLOAD_ACCESS[2],
            policy.ORIGINAL_FIELDS,
            now - timedelta(hours=1),
            now + timedelta(days=7),
            version_ref=version_refs[0],
        ),
        policy.LocalRule(
            owner_ref,
            policy.WIKI_INPUT_ACCESS[0],
            "allow",
            policy.WIKI_INPUT_ACCESS[1],
            policy.WIKI_INPUT_ACCESS[2],
            policy.WORKSPACE_EVIDENCE_FIELDS,
            now - timedelta(hours=1),
        ),
        policy.LocalRule(
            reviewer_ref,
            policy.WIKI_REVIEW_ACCESS[0],
            "allow",
            policy.WIKI_REVIEW_ACCESS[1],
            policy.WIKI_REVIEW_ACCESS[2],
            policy.WORKSPACE_EVIDENCE_FIELDS,
            now - timedelta(hours=1),
        ),
        policy.LocalRule(
            reviewer_ref,
            policy.WIKI_PUBLISH_ACCESS[0],
            "allow",
            policy.WIKI_PUBLISH_ACCESS[1],
            policy.WIKI_PUBLISH_ACCESS[2],
            policy.WORKSPACE_EVIDENCE_FIELDS,
            now - timedelta(hours=1),
        ),
    )
    read_pol_ctx = request_for(connection, tenant, tenant.actor_id, f"rpol-{uuid4()}", policy.READ)
    current_epoch = policy.read_synthetic_policy(connection, read_pol_ctx, tenant.space_id, source_ref)["safety_epoch"]
    pol_ctx = request_for(connection, tenant, tenant.actor_id, f"pol-{uuid4()}", policy.REPLACE)
    policy.replace_synthetic_policy(connection, pol_ctx, tenant.space_id, source_ref, current_epoch, local_rules, uuid4())

    service = evidence.EvidenceService.from_port_registry(
        lambda: open_database(database_url),
        port_registry,
    )
    owner_ops = [
        "search",
        "read_passage",
        "download_original",
        "read_source_catalog",
        "trigger_connector_sync",
        "assemble_wiki_inputs",
        "create_wiki_candidate",
        "read_model_policy",
        "replace_model_policy",
    ]
    reviewer_ops = [
        "search",
        "read_passage",
        "read_model_policy",
        "replace_model_policy",
        "read_wiki_candidate",
        "review_wiki_revision",
        "publish_wiki_revision",
    ]
    owner_token = _issue_prod_jwt(
        private_key,
        "prod-e2e-k1",
        subject_ref=owner_ref,
        space_ref=tenant.space_ref,
        operations=owner_ops,
    )
    reviewer_token = _issue_prod_jwt(
        private_key,
        "prod-e2e-k1",
        subject_ref=reviewer_ref,
        space_ref=tenant.space_ref,
        operations=reviewer_ops,
    )

    with TestClient(
        api.create_app(service, allowed_hosts=(PROD_HOST,)),
        base_url=f"https://{PROD_HOST}",
    ) as client:
        current_model_pol = client.get(
            f"/internal/sources/{source_ref}/model-egress-policy",
            headers=bearer(reviewer_token),
        )
        assert current_model_pol.status_code == 200
        safety_epoch = current_model_pol.json()["safety_epoch"]

        synthetic_dest_attempt = client.post(
            f"/internal/sources/{source_ref}/model-egress-policy",
            headers=_idempotent_headers(reviewer_token),
            json={
                "expected_epoch": safety_epoch,
                "basis_id": str(uuid4()),
                "rules": [
                    {
                        "subject_id": str(owner_ref),
                        "operation": policy.MODEL_RULE_OPERATION,
                        "effect": "allow",
                        "purpose": "wiki_compilation",
                        "destination": policy.SYNTHETIC_MODEL_DESTINATION,
                        "fields": ["excerpt"],
                        "valid_from": (now - timedelta(hours=1)).isoformat(),
                        "valid_until": (now + timedelta(hours=2)).isoformat(),
                        "passage_id": str(approved_passages[0].passage_ref),
                    }
                ],
            },
        )
        assert synthetic_dest_attempt.status_code == 400
        assert synthetic_dest_attempt.json()["error"]["code"] == "invalid_arguments"

        prod_egress_rules = [
            {
                "subject_id": str(owner_ref),
                "operation": policy.MODEL_RULE_OPERATION,
                "effect": "allow",
                "purpose": "wiki_compilation",
                "destination": PROD_GATEWAY_DEST,
                "fields": ["excerpt"],
                "valid_from": (now - timedelta(hours=1)).isoformat(),
                "valid_until": (now + timedelta(hours=2)).isoformat(),
                "passage_id": str(passage.passage_ref),
            }
            for passage in approved_passages
        ]
        set_egress = client.post(
            f"/internal/sources/{source_ref}/model-egress-policy",
            headers=_idempotent_headers(reviewer_token),
            json={
                "expected_epoch": safety_epoch,
                "basis_id": str(uuid4()),
                "rules": prod_egress_rules,
            },
        )
        assert set_egress.status_code == 200, set_egress.text

        search_resp = client.post(
            "/v1/search",
            headers=bearer(owner_token),
            json={"query": "上海住宿 650", "business_date": BEFORE.isoformat()},
        )
        assert search_resp.status_code == 200
        search_body = search_resp.json()
        assert search_body["status"] == "hits"
        hit_id = search_body["passages"][0]["passage_id"]
        assert "650" in search_body["passages"][0]["excerpt"]

        mcp_resp = rpc(
            client,
            owner_token,
            "tools/call",
            name="search",
            arguments={"query": "高铁二等座", "business_date": BEFORE.isoformat()},
        )
        assert mcp_resp.status_code == 200
        assert mcp_resp.json()["result"]["structuredContent"]["status"] == "hits"

        passage_resp = client.get(f"/v1/passages/{hit_id}", headers=bearer(owner_token))
        assert passage_resp.status_code == 200
        assert "650" in passage_resp.json()["passage"]["excerpt"]

        orig_resp = client.get(f"/employee/originals/{version_refs[0]}", headers=bearer(owner_token))
        assert orig_resp.status_code == 200
        assert orig_resp.content == DOC_ALLOWANCE
        assert any(
            rec["event_type"] == "security.original_downloaded" and rec["resource_ref"] == str(version_refs[0])
            for rec in audit_records
        )

        sealed = client.post(
            "/internal/wiki/inputs",
            headers=bearer(owner_token),
            json={
                "business_date": BEFORE.isoformat(),
                "direct": [[str(item.passage_ref), item.revision] for item in approved_passages],
            },
        )
        assert sealed.status_code == 200
        manifest_id = sealed.json()["manifest_id"]

        generated = client.post(
            "/internal/wiki/revisions/generate",
            headers=_idempotent_headers(owner_token),
            json={
                "business_date": BEFORE.isoformat(),
                "topic_key": "prod-shanghai-travel",
                "manifest_id": manifest_id,
                "reviewer_ref": str(reviewer_ref),
                "basis_id": str(uuid4()),
                "title_hint": "上海差旅速查",
                "instructions": "总结上海住宿上限并保留原文引文",
                "max_microunits": 20000,
            },
        )
        assert generated.status_code == 200, generated.text
        revision_id = generated.json()["revision_id"]
        assert gateway_state["calls"] == 1
        assert any(
            rec["event_type"] == "security.wiki_ai_draft_generated" and rec["resource_ref"] == revision_id
            for rec in audit_records
        )

        preview = client.post(
            f"/internal/wiki/revisions/{revision_id}/preview",
            headers=bearer(reviewer_token),
            json={"business_date": BEFORE.isoformat()},
        )
        assert preview.status_code == 200
        prev_json = preview.json()
        reviewed = client.post(
            f"/internal/wiki/revisions/{revision_id}/review",
            headers=_idempotent_headers(reviewer_token),
            json={
                "business_date": BEFORE.isoformat(),
                "decision": "approved",
                "reason_code": "prod_review_ok",
                "basis_id": str(uuid4()),
                "review_material_id": prev_json["review_material_id"],
                "content_digest": prev_json["content_digest"],
                "input_digest": prev_json["input_digest"],
            },
        )
        assert reviewed.status_code == 200
        published = client.post(
            f"/internal/wiki/revisions/{revision_id}/publish",
            headers=_idempotent_headers(reviewer_token),
            json={"business_date": BEFORE.isoformat(), "review_id": reviewed.json()["review_id"]},
        )
        assert published.status_code == 200

        wiki_search = client.post(
            "/v1/search",
            headers=bearer(owner_token),
            json={"query": "上海差旅住宿", "business_date": BEFORE.isoformat(), "include_wiki": True},
        )
        assert wiki_search.status_code == 200
        assert len(wiki_search.json()["wiki"]) == 1
        assert wiki_search.json()["wiki"][0]["title"] == "上海差旅住宿与高铁速查"

        catalog = client.get("/internal/sources/catalog", headers=bearer(owner_token))
        assert catalog.status_code == 200
        cat_body = catalog.json()
        assert cat_body["connector_configured"] is True
        assert len(cat_body["sources"]) == 1
        assert cat_body["sources"][0]["source_id"] == str(source_ref)
        assert cat_body["sources"][0]["admission"] == "production_approved"
        assert cat_body["sources"][0]["document_count"] == 2

        audit_state["down"] = True
        audit_down_orig = client.get(f"/employee/originals/{version_refs[0]}", headers=bearer(owner_token))
        assert audit_down_orig.status_code == 503
        assert audit_down_orig.json()["error"]["code"] == "dependency_unavailable"

        audit_down_sync = client.post(
            f"/internal/sources/{source_ref}/connector-sync",
            headers=_idempotent_headers(owner_token),
            json={"reconcile": False, "max_pages": 2},
        )
        assert audit_down_sync.status_code == 503
        assert audit_down_sync.json()["error"]["code"] == "dependency_unavailable"


def test_bidirectional_isolation_service_worker_queries_and_database_triggers(runtime_db, tmp_path):
    connection, syn_tenant, database_url = runtime_db
    prod_tenant, prod_owner_ref, _ = _create_production_tenant(connection, "ProdIsolatedOrg")

    syn_dir = tmp_path / "syn_originals"
    syn_dir.mkdir(mode=0o700)
    bak_dir = tmp_path / "syn_backups"
    bak_dir.mkdir(mode=0o700)
    syn_store = originals.SyntheticOriginalStore(syn_dir)
    syn_backup = backup_inventory.SyntheticBackupStore(bak_dir, syn_store)

    prod_blobs: dict[str, bytes] = {}
    private_key, public_jwk = _generate_rsa_jwk("iso-k1")

    def storage_handler(request: httpx2.Request) -> httpx2.Response:
        key = request.url.path.rsplit("/", 1)[-1]
        if request.method == "PUT":
            prod_blobs[key] = request.content
            return httpx2.Response(201, json={"sha256": sha256(request.content).hexdigest()})
        return httpx2.Response(200, content=prod_blobs[key])

    secrets = {"vault:obj": "obj-sec", "vault:auth": "auth-sec", "vault:audit": "aud-sec"}
    prod_storage_port = HttpObjectStorageAdapter(
        ObjectStorageEndpointConfig("https://obj.corp.example", "iso-bucket", "vault:obj"),
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(storage_handler),
    )
    prod_store = originals.ObjectStorageOriginalStore(prod_storage_port)
    prod_identity = OidcJwksIdentityVerifier(
        IdentityEndpointConfig(PROD_ISSUER, PROD_AUDIENCE, "https://idp.corp.example/.well-known/jwks.json"),
        transport=httpx2.MockTransport(lambda _: httpx2.Response(200, json={"keys": [public_jwk]})),
    )
    prod_authority = HttpSourceAuthorityAdapter(
        AuthenticatedEndpointConfig("https://auth.corp.example/v1/check", "vault:auth"),
        authority_ref=uuid4(),
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(lambda _: httpx2.Response(503)),
    )
    prod_audit = HttpSecurityAuditLogAdapter(
        AuthenticatedEndpointConfig("https://audit.corp.example/v1/events", "vault:audit"),
        log_ref=uuid4(),
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(lambda _: httpx2.Response(503)),
    )
    prod_registry = PortRegistry(
        mode="production",
        identity=prod_identity,
        source_authority=prod_authority,
        object_storage=prod_storage_port,
        security_audit_log=prod_audit,
    )

    # 1. Constructor & PortRegistry bidirectional isolation checks
    with pytest.raises(ProductionIsolationError):
        evidence.EvidenceService(
            lambda: open_database(database_url),
            lambda _: None,
            lambda _, __: None,
            syn_store,
            authority_issuer=PROD_ISSUER,
        )
    with pytest.raises(ProductionIsolationError):
        evidence.EvidenceService(
            lambda: open_database(database_url),
            lambda _: None,
            lambda _, __: None,
            prod_store,
            authority_issuer=registry.SYNTHETIC_ISSUER,
        )
    with pytest.raises(ProductionIsolationError):
        evidence.EvidenceService(
            lambda: open_database(database_url),
            lambda _: None,
            lambda _, __: None,
            prod_store,
            backup_store=syn_backup,
            authority_issuer=PROD_ISSUER,
        )
    with pytest.raises(ProductionIsolationError):
        worker.WorkerConfig.from_port_registry(
            lambda: open_database(database_url),
            prod_registry,
            store=syn_store,
        )

    # 2. Cross-mode source contract registration rejections
    syn_bad_ctx = request_for(connection, syn_tenant, syn_tenant.actor_id, f"bad-syn-{uuid4()}", "register_source_contract")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_source(
            connection,
            syn_bad_ctx,
            syn_tenant.space_id,
            registry.SyntheticSource("bad-prod-on-syn", "bad-arch", syn_tenant.worker_id),
            admission=registry.PRODUCTION_ADMISSION,
        )

    prod_bad_ctx = request_for(connection, prod_tenant, prod_tenant.actor_id, f"bad-prod-{uuid4()}", "register_source_contract")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_source(
            connection,
            prod_bad_ctx,
            prod_tenant.space_id,
            registry.SyntheticSource("bad-syn-on-prod", "bad-arch", prod_tenant.worker_id),
            admission=registry.SYNTHETIC_ADMISSION,
        )

    # 3. Worker discovery isolation when synthetic & production jobs coexist in the same DB
    syn_src_ctx = request_for(connection, syn_tenant, syn_tenant.actor_id, f"syn-src-{uuid4()}", "register_source_contract")
    syn_src = registry.register_source(
        connection,
        syn_src_ctx,
        syn_tenant.space_id,
        registry.SyntheticSource(
            "syn-coexist",
            "syn-arch",
            syn_tenant.worker_id,
            processor_id=syn_tenant.other_worker_id,
            quality_reviewer_id=syn_tenant.actor_id,
        ),
        admission=registry.SYNTHETIC_ADMISSION,
    )
    prod_src_ctx = request_for(connection, prod_tenant, prod_tenant.actor_id, f"prod-src-{uuid4()}", "register_source_contract")
    prod_src = registry.register_source(
        connection,
        prod_src_ctx,
        prod_tenant.space_id,
        registry.SyntheticSource(
            "prod-coexist",
            "prod-arch",
            prod_tenant.worker_id,
            processor_id=prod_tenant.other_worker_id,
            quality_reviewer_id=prod_tenant.actor_id,
        ),
        admission=registry.PRODUCTION_ADMISSION,
    )

    syn_ver = register(
        connection,
        syn_tenant,
        syn_src,
        syn_store,
        key=f"syn-ver-{uuid4()}",
        payload=DOC_ALLOWANCE,
        digest=sha256(DOC_ALLOWANCE).digest(),
    )
    prod_ver = register(
        connection,
        prod_tenant,
        prod_src,
        prod_store,
        key=f"prod-ver-{uuid4()}",
        payload=DOC_RAIL,
        digest=sha256(DOC_RAIL).digest(),
    )

    # Cross-mode store usage during version registration is rejected
    cross_store_ctx = request_for(connection, prod_tenant, prod_tenant.worker_id, f"cross-{uuid4()}", "register_version")
    with pytest.raises(registry.SourceNotAdmitted):
        registry.register_version(
            connection,
            cross_store_ctx,
            registry.SourceVersion(
                prod_tenant.space_id,
                prod_src,
                1,
                "cross-doc",
                "v1",
                "rev-x",
                "Cross Doc",
                "1.0",
                sha256(DOC_ALLOWANCE).digest(),
            ),
            DOC_ALLOWANCE,
            syn_store,
        )

    # Synthetic worker only parses synthetic_ver, leaves prod_ver untouched in queue
    syn_worker = worker.WorkerConfig(
        connect=lambda: open_database(database_url),
        store=syn_store,
        enable_sync=False,
        enable_alerts=False,
    )
    syn_report = worker.run_worker_cycle(syn_worker)
    assert [item["version_id"] for item in syn_report.parsed_jobs] == [str(syn_ver.version_ref)]

    # Production worker only parses prod_ver
    prod_worker = worker.WorkerConfig.from_port_registry(
        lambda: open_database(database_url),
        prod_registry,
        enable_sync=False,
        enable_alerts=False,
    )
    prod_report = worker.run_worker_cycle(prod_worker)
    assert [item["version_id"] for item in prod_report.parsed_jobs] == [str(prod_ver.version_ref)]

    # 4. PostgreSQL trigger enforcement against direct SQL cross-mode writes
    syn_source_id, syn_doc_id = connection.execute(
        "SELECT source_id, document_id FROM thalion.document WHERE org_id = %s AND space_id = %s",
        (syn_tenant.org_id, syn_tenant.space_id),
    ).fetchone()
    prod_source_id, prod_doc_id = connection.execute(
        "SELECT source_id, document_id FROM thalion.document WHERE org_id = %s AND space_id = %s",
        (prod_tenant.org_id, prod_tenant.space_id),
    ).fetchone()

    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.source_contract_revision (
                    org_id, space_id, source_id, revision, admission, collector_id,
                    object_namespace, processor_id, quality_reviewer_id
                ) VALUES (%s, %s, %s, 2, 'production_approved', %s, 'syn-arch', %s, %s)
                """,
                (
                    syn_tenant.org_id,
                    syn_tenant.space_id,
                    syn_source_id,
                    syn_tenant.worker_id,
                    syn_tenant.other_worker_id,
                    syn_tenant.actor_id,
                ),
            )

    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.asset (
                    org_id, space_id, source_id, document_id, storage_kind, storage_key,
                    media_type, byte_length, content_digest
                ) VALUES (%s, %s, %s, %s, 'https_object_store', %s, 'text/markdown', %s, %s)
                """,
                (
                    syn_tenant.org_id,
                    syn_tenant.space_id,
                    syn_source_id,
                    syn_doc_id,
                    sha256(b"bad-syn-https-key").hexdigest(),
                    len(DOC_ALLOWANCE),
                    sha256(DOC_ALLOWANCE).digest(),
                ),
            )

    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.asset (
                    org_id, space_id, source_id, document_id, storage_kind, storage_key,
                    media_type, byte_length, content_digest
                ) VALUES (%s, %s, %s, %s, 'synthetic_file', %s, 'text/markdown', %s, %s)
                """,
                (
                    prod_tenant.org_id,
                    prod_tenant.space_id,
                    prod_source_id,
                    prod_doc_id,
                    sha256(b"bad-prod-file-key").hexdigest(),
                    len(DOC_RAIL),
                    sha256(DOC_RAIL).digest(),
                ),
            )

    # 5. Compile template & model egress bidirectional isolation
    bad_prod_tpl_req = request_for(
        connection, prod_tenant, prod_tenant.actor_id, f"bad-prod-tpl-{uuid4()}", "register_template_revision"
    )
    with pytest.raises(templates.TemplateNotAdmitted):
        templates.register_template_revision(
            connection,
            templates.TemplateWrite(
                bad_prod_tpl_req.org_id,
                bad_prod_tpl_req.principal_id,
                bad_prod_tpl_req.request_id,
                bad_prod_tpl_req.idempotency_key,
            ),
            prod_tenant.space_id,
            templates.TemplateSpec(
                "prod-tpl", "Summarize travel rules.", "synthetic-local", 4096, 512, prod_tenant.other_actor_id
            ),
        )

    bad_syn_tpl_req = request_for(
        connection, syn_tenant, syn_tenant.actor_id, f"bad-syn-tpl-{uuid4()}", "register_template_revision"
    )
    with pytest.raises(templates.TemplateNotAdmitted):
        templates.register_template_revision(
            connection,
            templates.TemplateWrite(
                bad_syn_tpl_req.org_id,
                bad_syn_tpl_req.principal_id,
                bad_syn_tpl_req.request_id,
                bad_syn_tpl_req.idempotency_key,
            ),
            syn_tenant.space_id,
            templates.TemplateSpec(
                "syn-tpl", "Summarize synthetic rules.", PROD_GATEWAY_DEST, 4096, 512, syn_tenant.other_actor_id
            ),
        )

    prod_tpl_req = request_for(
        connection, prod_tenant, prod_tenant.actor_id, f"ok-prod-tpl-{uuid4()}", "register_template_revision"
    )
    prod_tpl_rev = templates.register_template_revision(
        connection,
        templates.TemplateWrite(
            prod_tpl_req.org_id,
            prod_tpl_req.principal_id,
            prod_tpl_req.request_id,
            prod_tpl_req.idempotency_key,
        ),
        prod_tenant.space_id,
        templates.TemplateSpec(
            "prod-tpl", "Summarize approved travel rules.", PROD_GATEWAY_DEST, 4096, 512, prod_tenant.other_actor_id
        ),
    )
    prod_tpl_adm_req = request_for(
        connection, prod_tenant, prod_tenant.other_actor_id, f"adm-prod-tpl-{uuid4()}", "decide_template_admission"
    )
    templates.decide_template_admission(
        connection,
        templates.TemplateWrite(
            prod_tpl_adm_req.org_id,
            prod_tpl_adm_req.principal_id,
            prod_tpl_adm_req.request_id,
            prod_tpl_adm_req.idempotency_key,
        ),
        prod_tenant.space_id,
        prod_tpl_rev,
        "approved",
        uuid4(),
        "approved_prod_template",
    )
    prod_tpl_act_req = request_for(
        connection, prod_tenant, prod_tenant.actor_id, f"act-prod-tpl-{uuid4()}", "activate_template_revision"
    )
    assert (
        templates.activate_template_revision(
            connection,
            templates.TemplateWrite(
                prod_tpl_act_req.org_id,
                prod_tpl_act_req.principal_id,
                prod_tpl_act_req.request_id,
                prod_tpl_act_req.idempotency_key,
            ),
            prod_tenant.space_id,
            prod_tpl_rev,
            0,
        )
        == 1
    )

    # Direct SQL bypass attempt for cross-mode compile_template_revision is blocked by trigger
    sql_tpl_req = request_for(
        connection, prod_tenant, prod_tenant.actor_id, f"sql-tpl-{uuid4()}", "register_template_revision"
    )
    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.compile_template_revision (
                    org_id, space_id, template_key, prompt, model_profile,
                    max_input_bytes, max_output_tokens, author_id, reviewer_id, request_id
                ) VALUES (%s, %s, 'prod-tpl', 'Bypass prompt', 'synthetic-local', 4096, 512, %s, %s, %s)
                """,
                (
                    prod_tenant.org_id,
                    prod_tenant.space_id,
                    prod_tenant.actor_id,
                    prod_tenant.other_actor_id,
                    sql_tpl_req.request_id,
                ),
            )

    # Direct SQL bypass attempt for synthetic-gateway on production source is blocked by trigger
    prod_passage_ref, = connection.execute(
        """
        SELECT identity.public_id
        FROM thalion.passage AS passage
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
        WHERE (passage.org_id, passage.space_id) = (%s, %s)
        LIMIT 1
        """,
        (prod_tenant.org_id, prod_tenant.space_id),
    ).fetchone()
    sql_pol_req = request_for(
        connection, prod_tenant, prod_tenant.actor_id, f"sql-pol-{uuid4()}", policy.REPLACE_MODEL
    )
    prod_epoch, = connection.execute(
        "SELECT safety_epoch FROM thalion.source WHERE (org_id, space_id, source_id) = (%s, %s, %s)",
        (prod_tenant.org_id, prod_tenant.space_id, prod_source_id),
    ).fetchone()
    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.policy_revision (
                    org_id, space_id, source_id, revision, actor_id, request_id, basis_ref, binding_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
                """,
                (
                    prod_tenant.org_id,
                    prod_tenant.space_id,
                    prod_source_id,
                    prod_epoch + 1,
                    prod_tenant.actor_id,
                    sql_pol_req.request_id,
                    uuid4(),
                ),
            )
            connection.execute(
                """
                INSERT INTO thalion.permission_binding (
                    org_id, space_id, source_id, revision, subject_id, passage_ref,
                    operation, effect, purpose, destination, fields, valid_from, valid_until
                ) VALUES (
                    %s, %s, %s, %s, %s, %s,
                    'send_model_evidence', 'allow', 'model_answer', 'synthetic-gateway',
                    ARRAY['excerpt'], now(), now() + interval '1 hour'
                )
                """,
                (
                    prod_tenant.org_id,
                    prod_tenant.space_id,
                    prod_source_id,
                    prod_epoch + 1,
                    prod_tenant.actor_id,
                    prod_passage_ref,
                ),
            )


def test_thalion_worker_production_cli_check_config_and_flag_isolation(
    database_url, monkeypatch, capsys, tmp_path
):
    upgrade(database_url)
    prod_env = {
        "THALION_MODE": "production",
        "THALION_BUSINESS_TIMEZONE": "Asia/Shanghai",
        "THALION_DATABASE_URL_REF": "env:THALION_WORKER_PROD_DB",
        "THALION_WORKER_PROD_DB": database_url,
        "THALION_ALLOWED_HOSTS": PROD_HOST,
        "THALION_OIDC_ISSUER": PROD_ISSUER,
        "THALION_OIDC_AUDIENCE": PROD_AUDIENCE,
        "THALION_OIDC_JWKS_URL": "https://idp.corp.example/.well-known/jwks.json",
        "THALION_SOURCE_AUTHORITY_ENDPOINT": "https://auth.corp.example/v1/check",
        "THALION_SOURCE_AUTHORITY_CREDENTIAL_REF": "env:THALION_WORKER_AUTH_CRED",
        "THALION_WORKER_AUTH_CRED": "worker-auth-secret-token",
        "THALION_SOURCE_AUTHORITY_REF": str(uuid4()),
        "THALION_OBJECT_STORAGE_ENDPOINT": "https://obj.corp.example",
        "THALION_OBJECT_STORAGE_BUCKET": "thalion-prod-bucket",
        "THALION_OBJECT_STORAGE_CREDENTIAL_REF": "env:THALION_WORKER_OBJ_CRED",
        "THALION_WORKER_OBJ_CRED": "worker-obj-secret-token",
        "THALION_SECURITY_AUDIT_ENDPOINT": "https://audit.corp.example/v1/events",
        "THALION_SECURITY_AUDIT_CREDENTIAL_REF": "env:THALION_WORKER_AUDIT_CRED",
        "THALION_WORKER_AUDIT_CRED": "worker-audit-secret-token",
        "THALION_SECURITY_AUDIT_LOG_REF": str(uuid4()),
        "THALION_SOURCE_CONNECTOR_ENDPOINT": "https://connector.corp.example/v1",
        "THALION_SOURCE_CONNECTOR_CREDENTIAL_REF": "env:THALION_WORKER_CONN_CRED",
        "THALION_WORKER_CONN_CRED": "worker-conn-secret-token",
        "THALION_SOURCE_CONNECTOR_SYSTEM": "confluence-prod",
        "THALION_EMBEDDING_ENDPOINT": "https://embed.corp.example/v1",
        "THALION_EMBEDDING_CREDENTIAL_REF": "env:THALION_WORKER_EMBED_CRED",
        "THALION_WORKER_EMBED_CRED": "worker-embed-secret-token",
        "THALION_EMBEDDING_MODEL_ID": PROD_EMBED_MODEL,
        "THALION_EMBEDDING_DIMENSION": "64",
    }
    for env_key, env_value in prod_env.items():
        monkeypatch.setenv(env_key, env_value)

    exit_code = worker.main(["--mode", "production", "--check-config"])
    assert exit_code == 0
    summary_raw = capsys.readouterr().out
    summary = json.loads(summary_raw)
    assert summary == {
        "status": "ok",
        "mode": "production",
        "admission": "production_approved",
        "connector_configured": True,
        "embedding_configured": True,
        "strict_audit_sink": True,
        "alert_webhook_configured": False,
    }
    assert database_url not in summary_raw
    assert "worker-auth-secret-token" not in summary_raw
    assert "worker-obj-secret-token" not in summary_raw

    with pytest.raises(SystemExit):
        worker.main(["--mode", "production", "--originals", str(tmp_path)])
    capsys.readouterr()

    with pytest.raises(SystemExit):
        worker.main(["--mode", "production", "--embedding-synthetic-model", vector.DEFAULT_MODEL_ID])
    capsys.readouterr()
