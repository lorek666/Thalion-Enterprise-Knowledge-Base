from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx2
import jwt
import pytest

from enterprise_kb.modules.access.delivery import (
    DeliveryCandidate,
    DeliveryCheck,
    DeliveryContext,
    EvidenceScope,
    LocalAuthorization,
    SafetyEpochs,
    authorize_delivery,
)
from enterprise_kb.modules.access.rules import PermissionBinding
from enterprise_kb.ports.contracts import (
    AuthorityPortUnavailable,
    ConnectorPortUnavailable,
    EmbeddingPortUnavailable,
    IdentityPortUnavailable,
    ModelGatewayUnavailable,
    ModelGenerationRequest,
    ModelOutcomeUnknown,
    ObjectStorageUnavailable,
    PortRegistry,
    PortUnavailable,
    SecurityLogUnavailable,
)
from enterprise_kb.runtime.config import (
    AuthenticatedEndpointConfig,
    IdentityEndpointConfig,
    ObjectStorageEndpointConfig,
    validate_deployment_config,
)


def _rsa_jwk(kid: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = kid
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return private_key, public_jwk


def test_secret_ref_resolution_enforces_private_files_and_rejects_unconfigured_vault(tmp_path, monkeypatch):
    from enterprise_kb.ports.adapters import resolve_secret_ref

    monkeypatch.setenv("THALION_UNIT_TEST_SECRET", "resolved-token-value")
    assert resolve_secret_ref("env:THALION_UNIT_TEST_SECRET") == "resolved-token-value"

    with pytest.raises(PortUnavailable):
        resolve_secret_ref("env:THALION_MISSING_SECRET_XYZ")

    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-token-value\n", encoding="utf-8")
    secret_file.chmod(0o644)
    with pytest.raises(PortUnavailable):
        resolve_secret_ref(f"file:{secret_file}")

    secret_file.chmod(0o600)
    assert resolve_secret_ref(f"file:{secret_file}") == "file-token-value"

    with pytest.raises(PortUnavailable):
        resolve_secret_ref("vault:thalion/prod/token")
    assert resolve_secret_ref("vault:thalion/prod/token", external_resolver=lambda ref: f"ext:{ref}") == (
        "ext:vault:thalion/prod/token"
    )


def test_oidc_jwks_verifier_validates_rs256_rotation_and_rejects_attacks():
    from enterprise_kb.ports.adapters import OidcJwksIdentityVerifier

    key_v1, jwk_v1 = _rsa_jwk("key-v1")
    key_v2, jwk_v2 = _rsa_jwk("key-v2")
    active_jwks = {"keys": [jwk_v1]}
    jwks_fetches = {"count": 0}

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert str(request.url) == "https://idp.corp.example/.well-known/jwks.json"
        jwks_fetches["count"] += 1
        return httpx2.Response(200, json=active_jwks)

    verifier = OidcJwksIdentityVerifier(
        IdentityEndpointConfig(
            issuer="https://idp.corp.example",
            audience="thalion-kb",
            jwks_url="https://idp.corp.example/.well-known/jwks.json",
        ),
        transport=httpx2.MockTransport(handler),
    )
    assert verifier.admission == "production_approved"

    now = datetime.now(UTC)
    sub_ref = uuid4()
    space_ref = uuid4()
    delegated_ref = uuid4()
    claims = {
        "iss": "https://idp.corp.example",
        "aud": "thalion-kb",
        "sub": str(sub_ref),
        "space_ref": str(space_ref),
        "client_id": "corp-agent",
        "operations": ["search", "read_passage"],
        "act": {"sub": str(delegated_ref)},
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    token_v1 = jwt.encode(claims, key_v1, algorithm="RS256", headers={"kid": "key-v1"})
    verified = verifier.verify_bearer_token(token_v1)
    assert verified is not None
    assert verified.subject_ref == sub_ref
    assert verified.space_ref == space_ref
    assert verified.delegated_subject_ref == delegated_ref
    assert verified.operations == frozenset({"search", "read_passage"})
    assert jwks_fetches["count"] == 1

    # 密钥轮换：未知 kid 触发重新拉取 JWKS 并验证通过
    active_jwks["keys"] = [jwk_v2]
    token_v2 = jwt.encode(claims, key_v2, algorithm="RS256", headers={"kid": "key-v2"})
    verified_v2 = verifier.verify_bearer_token(token_v2)
    assert verified_v2 is not None and verified_v2.subject_ref == sub_ref
    assert jwks_fetches["count"] == 2

    # 拒绝 alg=none、HS256 降级、错受众、过期令牌
    unsigned = jwt.encode(claims, "", algorithm="none")
    assert verifier.verify_bearer_token(unsigned) is None
    hs256 = jwt.encode(claims, "shared-secret-at-least-32-bytes-long!!", algorithm="HS256")
    assert verifier.verify_bearer_token(hs256) is None
    wrong_aud = jwt.encode(claims | {"aud": "other-service"}, key_v2, algorithm="RS256", headers={"kid": "key-v2"})
    assert verifier.verify_bearer_token(wrong_aud) is None
    expired = jwt.encode(
        claims | {"exp": int((now - timedelta(seconds=10)).timestamp())},
        key_v2,
        algorithm="RS256",
        headers={"kid": "key-v2"},
    )
    assert verifier.verify_bearer_token(expired) is None

    # JWKS 上游故障必须 fail-closed 抛 IdentityPortUnavailable
    broken = OidcJwksIdentityVerifier(
        IdentityEndpointConfig(
            issuer="https://idp.corp.example",
            audience="thalion-kb",
            jwks_url="https://idp.corp.example/.well-known/jwks.json",
        ),
        transport=httpx2.MockTransport(lambda _req: httpx2.Response(503)),
    )
    with pytest.raises(IdentityPortUnavailable):
        broken.verify_bearer_token(token_v2)


def test_source_authority_adapter_rejects_overgrant_and_fails_closed(monkeypatch):
    from enterprise_kb.ports.adapters import HttpSourceAuthorityAdapter

    monkeypatch.setenv("THALION_AUTH_TOKEN", "auth-secret")
    authority_ref = uuid4()
    object_id = uuid4()
    scope = EvidenceScope(1, 2, object_id, frozenset({"excerpt", "citation"}), 1)
    context = DeliveryContext(
        uuid4(), 1, 10, "corp-agent", "search", "employee_evidence", "employee",
        datetime.now(UTC) + timedelta(seconds=30),
    )
    probe = DeliveryCheck(uuid4(), context, "a" * 64, frozenset({scope}))

    mode = {"behavior": "ok"}

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["Authorization"] == "Bearer auth-secret"
        if request.url.path.endswith("/checkpoints/" + str(object_id)):
            return httpx2.Response(200, json={"authority_ref": str(authority_ref), "generation": 7})
        body = json.loads(request.content.decode("utf-8"))
        if mode["behavior"] == "ok":
            granted_fields = ["excerpt"]
        elif mode["behavior"] == "full":
            granted_fields = ["excerpt", "citation"]
        else:
            granted_fields = ["excerpt", "original"]
        return httpx2.Response(
            200,
            json={
                "check_id": body["check_id"],
                "authority_ref": str(authority_ref),
                "checked_at": datetime.now(UTC).isoformat(),
                "valid_until": (datetime.now(UTC) + timedelta(seconds=8)).isoformat(),
                "proof_ref": "proof-001",
                "subject_ids": [10],
                "grants": [{"object_id": str(object_id), "revision": 1, "fields": granted_fields}],
            },
        )

    adapter = HttpSourceAuthorityAdapter(
        AuthenticatedEndpointConfig("https://auth.corp.example/v1", "env:THALION_AUTH_TOKEN"),
        authority_ref=authority_ref,
        transport=httpx2.MockTransport(handler),
    )
    decision = adapter.authorize_scopes({"subject": "emp-1"}, probe)
    assert decision.permitted_fields[scope] == frozenset({"excerpt"})
    assert decision.subject_ids == frozenset({10})
    assert decision.proof_ref == "proof-001"
    assert adapter.checkpoint(object_id) == 7

    # 与统一最终交付边界 authorize_delivery 端到端协作验证
    mode["behavior"] = "full"
    epochs = SafetyEpochs(1, 1, 1)
    candidate = DeliveryCandidate(payload=b"verified-evidence", dependencies={scope: epochs})
    local_auth = LocalAuthorization(
        epochs={scope: epochs},
        bindings=(
            PermissionBinding(
                org_id=1,
                space_id=1,
                source_id=2,
                object_id=object_id,
                subject_id=10,
                operation="search",
                effect="allow",
                purposes=frozenset({"employee_evidence"}),
                destinations=frozenset({"employee"}),
                fields=frozenset({"excerpt", "citation"}),
                valid_from=datetime.now(UTC) - timedelta(minutes=1),
                valid_until=datetime.now(UTC) + timedelta(minutes=10),
            ),
        ),
    )
    delivery = authorize_delivery(
        context,
        candidate,
        check_authority=lambda check: adapter.authorize_scopes({"subject": "emp-1"}, check),
        load_local=lambda _check: local_auth,
    )
    assert delivery.status == "succeeded"
    assert delivery.authority_proof_ref == "proof-001"

    # 上游返回未请求的字段（越权扩权）必须被适配器拒绝
    mode["behavior"] = "overgrant"
    with pytest.raises(AuthorityPortUnavailable):
        adapter.authorize_scopes({"subject": "emp-1"}, probe)

    # 网络超时 fail-closed
    def timeout_handler(_request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ReadTimeout("timeout")

    failing = HttpSourceAuthorityAdapter(
        AuthenticatedEndpointConfig("https://auth.corp.example/v1", "env:THALION_AUTH_TOKEN"),
        authority_ref=authority_ref,
        transport=httpx2.MockTransport(timeout_handler),
    )
    with pytest.raises(AuthorityPortUnavailable):
        failing.authorize_scopes({"subject": "emp-1"}, probe)
    failed_delivery = authorize_delivery(
        context,
        candidate,
        check_authority=lambda check: failing.authorize_scopes({"subject": "emp-1"}, check),
        load_local=lambda _check: local_auth,
    )
    assert failed_delivery.status == "dependency_unavailable"


def test_object_storage_security_log_model_gateway_and_embedding_adapters(monkeypatch):
    from enterprise_kb.ports.adapters import (
        HttpEmbeddingProviderAdapter,
        HttpModelGatewayAdapter,
        HttpObjectStorageAdapter,
        HttpSecurityAuditLogAdapter,
        HttpSourceConnectorAdapter,
        build_production_port_registry,
    )

    monkeypatch.setenv("THALION_OBJ_CRED", "obj-cred")
    monkeypatch.setenv("THALION_AUDIT_CRED", "audit-cred")
    monkeypatch.setenv("THALION_CONN_CRED", "conn-cred")
    monkeypatch.setenv("THALION_GW_CRED", "gw-cred")
    monkeypatch.setenv("THALION_EMB_CRED", "emb-cred")
    monkeypatch.setenv("THALION_AUTH_CRED", "auth-cred")

    # 1. Object storage verifies exact digest and rejects path traversal / corruption
    stored_bytes = b"immutable original policy bytes"
    stored_digest = sha256(stored_bytes).digest()
    objects: dict[str, bytes] = {}

    def obj_handler(request: httpx2.Request) -> httpx2.Response:
        key = request.url.path.split("/objects/", 1)[1]
        if request.method == "PUT":
            assert request.headers.get("If-None-Match") == "*"
            if key in objects:
                return httpx2.Response(412)
            objects[key] = request.content
            return httpx2.Response(201, json={"sha256": sha256(request.content).hexdigest()})
        if key not in objects:
            return httpx2.Response(404)
        return httpx2.Response(200, content=objects[key])

    obj_adapter = HttpObjectStorageAdapter(
        ObjectStorageEndpointConfig("https://obj.corp.example", "thalion-prod", "env:THALION_OBJ_CRED"),
        transport=httpx2.MockTransport(obj_handler),
    )
    assert obj_adapter.write_immutable("docs/v1.md", stored_bytes) == stored_digest
    assert obj_adapter.read_verified("docs/v1.md", stored_digest, len(stored_bytes)) == stored_bytes
    with pytest.raises(ObjectStorageUnavailable):
        obj_adapter.write_immutable("docs/v1.md", stored_bytes)
    with pytest.raises(ObjectStorageUnavailable):
        obj_adapter.read_verified("docs/v1.md", bytes(32), len(stored_bytes))
    with pytest.raises(ObjectStorageUnavailable):
        obj_adapter.read_verified("../escape.md", stored_digest, len(stored_bytes))

    # 2. Security audit log adapter
    log_ref = uuid4()
    stream_ref = uuid4()

    def audit_handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST":
            return httpx2.Response(
                201,
                json={
                    "log_ref": str(log_ref),
                    "stream_ref": str(stream_ref),
                    "generation": 4,
                    "recorded_at": datetime.now(UTC).isoformat(),
                    "digest": "b" * 64,
                },
            )
        return httpx2.Response(200, json={"log_ref": str(log_ref), "generation": 4})

    audit_adapter = HttpSecurityAuditLogAdapter(
        AuthenticatedEndpointConfig("https://audit.corp.example/v1", "env:THALION_AUDIT_CRED"),
        log_ref=log_ref,
        transport=httpx2.MockTransport(audit_handler),
    )
    receipt = audit_adapter.append_restriction_receipt(uuid4(), {"event": "withdrawn"})
    assert receipt.log_ref == log_ref and receipt.generation == 4
    assert audit_adapter.verify_checkpoint(uuid4(), 4) is True
    assert audit_adapter.verify_checkpoint(uuid4(), 5) is False

    bad_audit = HttpSecurityAuditLogAdapter(
        AuthenticatedEndpointConfig("https://audit.corp.example/v1", "env:THALION_AUDIT_CRED"),
        log_ref=log_ref,
        transport=httpx2.MockTransport(lambda _r: httpx2.Response(500)),
    )
    with pytest.raises(SecurityLogUnavailable):
        bad_audit.append_restriction_receipt(uuid4(), {"event": "withdrawn"})

    # 3. Model gateway distinguishes refused purpose, unknown outcome (ReadTimeout), and valid receipt
    gw_mode = {"state": "ok"}

    def gw_handler(_request: httpx2.Request) -> httpx2.Response:
        if gw_mode["state"] == "timeout":
            raise httpx2.ReadTimeout("gateway read timed out after dispatch")
        return httpx2.Response(
            200,
            json={
                "provider_call_id": "call-999",
                "accepted": True,
                "input_tokens": 120,
                "output_tokens": 45,
                "billed_microunits": 3500,
                "output_digest": "c" * 64,
            },
        )

    gw_adapter = HttpModelGatewayAdapter(
        AuthenticatedEndpointConfig("https://gw.corp.example/v1", "env:THALION_GW_CRED"),
        destination_id="corp-llm-gw",
        allowed_purposes=frozenset({"wiki_draft"}),
        transport=httpx2.MockTransport(gw_handler),
    )
    req = ModelGenerationRequest(uuid4(), "wiki_draft", "corp-llm-gw", bytes(32), b"payload", 10_000)
    gw_receipt = gw_adapter.invoke_generation(req)
    assert gw_receipt.provider_call_id == "call-999" and gw_receipt.billed_microunits == 3500
    with pytest.raises(ModelGatewayUnavailable):
        gw_adapter.invoke_generation(
            ModelGenerationRequest(uuid4(), "unapproved_purpose", "corp-llm-gw", bytes(32), b"payload", 10_000)
        )
    gw_mode["state"] = "timeout"
    with pytest.raises(ModelOutcomeUnknown):
        gw_adapter.invoke_generation(req)

    # 4. Embedding provider validates dimension, finiteness, and batch count
    emb_mode = {"state": "ok"}

    def emb_handler(request: httpx2.Request) -> httpx2.Response:
        payload = json.loads(request.content.decode("utf-8"))
        if emb_mode["state"] == "bad_dim":
            return httpx2.Response(200, json={"model_id": "corp-bge-v1", "vectors": [[1.0, 0.0]]})
        if emb_mode["state"] == "nan":
            return httpx2.Response(200, content=b'{"model_id":"corp-bge-v1","vectors":[[NaN,0.0,0.0,0.0]]}')
        vectors = [[3.0, 4.0, 0.0, 0.0] for _ in payload["inputs"]]
        return httpx2.Response(200, json={"model_id": "corp-bge-v1", "vectors": vectors})

    emb_adapter = HttpEmbeddingProviderAdapter(
        AuthenticatedEndpointConfig("https://emb.corp.example/v1", "env:THALION_EMB_CRED"),
        model_id="corp-bge-v1",
        dimension=4,
        transport=httpx2.MockTransport(emb_handler),
    )
    vec = emb_adapter.embed_query("上海住宿标准")
    assert len(vec) == 4 and pytest.approx(vec[0], abs=1e-5) == 0.6 and pytest.approx(vec[1], abs=1e-5) == 0.8
    emb_mode["state"] = "bad_dim"
    with pytest.raises(EmbeddingPortUnavailable):
        emb_adapter.embed_query("上海住宿标准")
    emb_mode["state"] = "nan"
    with pytest.raises(EmbeddingPortUnavailable):
        emb_adapter.embed_query("上海住宿标准")

    # 5. Source connector handles delta paging, rejects stalled cursor loops, and validates inventory
    conn_mode = {"state": "ok"}
    source_ref = uuid4()

    def conn_handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/deltas"):
            if conn_mode["state"] == "stalled":
                return httpx2.Response(
                    200,
                    json={"through_cursor": "cur-1", "has_more": True, "items": []},
                )
            if conn_mode["state"] == "error":
                return httpx2.Response(503)
            return httpx2.Response(
                200,
                json={
                    "through_cursor": "cur-2",
                    "has_more": False,
                    "items": [{"stable_object_key": "policy/travel-v1", "event": "upsert"}],
                },
            )
        if conn_mode["state"] == "dup_inventory":
            return httpx2.Response(
                200,
                json={
                    "snapshot_ref": "inv-2",
                    "observed_at": datetime.now(UTC).isoformat(),
                    "complete": True,
                    "stable_object_keys": ["policy/a", "policy/a"],
                },
            )
        return httpx2.Response(
            200,
            json={
                "snapshot_ref": "inv-1",
                "observed_at": datetime.now(UTC).isoformat(),
                "complete": True,
                "stable_object_keys": ["policy/travel-v1", "policy/travel-v2"],
            },
        )

    conn_adapter = HttpSourceConnectorAdapter(
        AuthenticatedEndpointConfig("https://conn.corp.example/v1", "env:THALION_CONN_CRED"),
        source_system="corp-wiki",
        transport=httpx2.MockTransport(conn_handler),
    )
    page = conn_adapter.fetch_delta_page(source_ref, "cur-1")
    assert page.previous_cursor == "cur-1" and page.through_cursor == "cur-2" and len(page.items) == 1
    inventory = conn_adapter.fetch_full_inventory(source_ref)
    assert inventory.complete is True and inventory.stable_object_keys == frozenset(
        {"policy/travel-v1", "policy/travel-v2"}
    )
    conn_mode["state"] = "stalled"
    with pytest.raises(ConnectorPortUnavailable):
        conn_adapter.fetch_delta_page(source_ref, "cur-1")
    conn_mode["state"] = "error"
    with pytest.raises(ConnectorPortUnavailable):
        conn_adapter.fetch_delta_page(source_ref, None)
    conn_mode["state"] = "dup_inventory"
    with pytest.raises(ConnectorPortUnavailable):
        conn_adapter.fetch_full_inventory(source_ref)

    # 6. build_production_port_registry assembles and validates a production PortRegistry
    prod_cfg = validate_deployment_config(
        {
            "mode": "production",
            "business_timezone": "Asia/Shanghai",
            "database_url_ref": "env:THALION_DB_URL",
            "allowed_hosts": ["kb.corp.example"],
            "identity": {
                "issuer": "https://idp.corp.example",
                "audience": "thalion-kb",
                "jwks_url": "https://idp.corp.example/.well-known/jwks.json",
            },
            "source_authority": {
                "endpoint": "https://auth.corp.example/v1",
                "credential_ref": "env:THALION_AUTH_CRED",
            },
            "object_storage": {
                "endpoint": "https://obj.corp.example",
                "bucket": "thalion-prod",
                "credential_ref": "env:THALION_OBJ_CRED",
            },
            "security_audit_log": {
                "endpoint": "https://audit.corp.example/v1",
                "credential_ref": "env:THALION_AUDIT_CRED",
            },
            "source_connector": {
                "endpoint": "https://conn.corp.example/v1",
                "credential_ref": "env:THALION_CONN_CRED",
            },
            "model_gateway": {
                "endpoint": "https://gw.corp.example/v1",
                "credential_ref": "env:THALION_GW_CRED",
            },
            "embedding_provider": {
                "endpoint": "https://emb.corp.example/v1",
                "credential_ref": "env:THALION_EMB_CRED",
            },
        }
    )
    registry = build_production_port_registry(
        prod_cfg,
        source_authority_ref=uuid4(),
        security_log_ref=log_ref,
        source_connector_system="corp-wiki",
        model_destination_id="corp-llm-gw",
        model_allowed_purposes=frozenset({"wiki_draft"}),
        embedding_model_id="corp-bge-v1",
        embedding_dimension=4,
    )
    assert isinstance(registry, PortRegistry)
    assert registry.mode == "production"
    assert registry.source_connector is not None
    registry.validate()


def test_openai_compatible_model_gateway_adapter_and_registry(monkeypatch):
    from enterprise_kb.ports.adapters import (
        OpenAiCompatibleModelGatewayAdapter,
        build_production_port_registry,
        model_gateway_options_from_env,
    )

    monkeypatch.setenv("THALION_GW_CRED", "openai-test-secret")
    monkeypatch.setenv("THALION_AUTH_CRED", "auth-cred")
    monkeypatch.setenv("THALION_OBJ_CRED", "obj-cred")
    monkeypatch.setenv("THALION_AUDIT_CRED", "audit-cred")

    seen: list[dict] = []
    mode = {"state": "ok"}

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["Authorization"] == "Bearer openai-test-secret"
        assert request.headers["Idempotency-Key"]
        seen.append({"url": str(request.url), "body": json.loads(request.content.decode("utf-8"))})
        if mode["state"] == "timeout":
            raise httpx2.ReadTimeout("timed out after dispatch")
        if mode["state"] == "http_error":
            return httpx2.Response(502, text="bad gateway")
        if mode["state"] == "empty":
            return httpx2.Response(200, json={"id": "chat-empty", "choices": [{"message": {"content": "   "}}]})
        if mode["state"] == "bad_usage":
            return httpx2.Response(
                200,
                json={
                    "id": "chat-bad-usage",
                    "choices": [{"finish_reason": "stop", "message": {"content": '{"title":"ok"}'}}],
                    "usage": {"prompt_tokens": -1, "completion_tokens": 5},
                },
            )
        if mode["state"] == "truncated":
            return httpx2.Response(
                200,
                json={
                    "id": "chat-trunc",
                    "choices": [{"finish_reason": "length", "message": {"content": '{"title":"partial"'}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 4096},
                },
            )
        if mode["state"] == "fenced":
            return httpx2.Response(
                200,
                json={
                    "id": "chat-fenced",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": '```json\n{"title":"差旅标准","markdown":"限额650元"}\n```',
                                "reasoning_content": "thinking...",
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 210, "completion_tokens": 95, "credit": 0.05},
                },
            )
        return httpx2.Response(
            200,
            json={
                "id": "chat-1",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": '{"title":"差旅标准","markdown":"限额650元"}'},
                    }
                ],
                "usage": {"prompt_tokens": 120, "completion_tokens": 45, "credit": 0.01},
            },
        )

    adapter = OpenAiCompatibleModelGatewayAdapter(
        AuthenticatedEndpointConfig("https://gw.corp.example", "env:THALION_GW_CRED"),
        model="deepseek-v4.1-flash",
        destination_id="corp-openai-gw",
        allowed_purposes=frozenset({"wiki_compilation", "model_answer"}),
        transport=httpx2.MockTransport(handler),
    )
    assert adapter.chat_completions_url == "https://gw.corp.example/v1/chat/completions"

    adapter_v1 = OpenAiCompatibleModelGatewayAdapter(
        AuthenticatedEndpointConfig("https://gw.corp.example/v1/", "env:THALION_GW_CRED"),
        model="deepseek-v4.1-flash",
        destination_id="corp-openai-gw",
        allowed_purposes=frozenset({"wiki_compilation"}),
    )
    assert adapter_v1.chat_completions_url == "https://gw.corp.example/v1/chat/completions"

    adapter_full = OpenAiCompatibleModelGatewayAdapter(
        AuthenticatedEndpointConfig("https://gw.corp.example/v1/chat/completions", "env:THALION_GW_CRED"),
        model="deepseek-v4.1-flash",
        destination_id="corp-openai-gw",
        allowed_purposes=frozenset({"wiki_compilation"}),
    )
    assert adapter_full.chat_completions_url == "https://gw.corp.example/v1/chat/completions"

    req = ModelGenerationRequest(uuid4(), "wiki_compilation", "corp-openai-gw", bytes(32), b'{"excerpts":["a"]}', 100_000)
    receipt = adapter.invoke_generation(req)
    assert receipt.provider_call_id == "chat-1"
    assert receipt.accepted is True
    assert receipt.input_tokens == 120
    assert receipt.output_tokens == 45
    assert receipt.billed_microunits == 10_000
    assert receipt.output_utf8 == '{"title":"差旅标准","markdown":"限额650元"}'
    assert receipt.output_digest == sha256(receipt.output_utf8.encode("utf-8")).digest()
    assert seen[-1]["url"] == "https://gw.corp.example/v1/chat/completions"
    assert seen[-1]["body"]["model"] == "deepseek-v4.1-flash"
    assert seen[-1]["body"]["response_format"] == {"type": "json_object"}

    mode["state"] = "fenced"
    fenced_receipt = adapter.invoke_generation(req)
    assert fenced_receipt.provider_call_id == "chat-fenced"
    assert fenced_receipt.output_utf8 == '{"title":"差旅标准","markdown":"限额650元"}'
    assert fenced_receipt.billed_microunits == 50_000

    mode["state"] = "truncated"
    trunc_receipt = adapter.invoke_generation(req)
    assert trunc_receipt.accepted is False
    assert trunc_receipt.output_tokens == 4096

    with pytest.raises(ModelGatewayUnavailable):
        adapter.invoke_generation(
            ModelGenerationRequest(uuid4(), "unapproved", "corp-openai-gw", bytes(32), b"{}", 10_000)
        )

    mode["state"] = "http_error"
    with pytest.raises(ModelGatewayUnavailable):
        adapter.invoke_generation(req)

    mode["state"] = "timeout"
    with pytest.raises(ModelOutcomeUnknown):
        adapter.invoke_generation(req)

    mode["state"] = "empty"
    with pytest.raises(ModelOutcomeUnknown):
        adapter.invoke_generation(req)

    mode["state"] = "bad_usage"
    with pytest.raises(ModelOutcomeUnknown):
        adapter.invoke_generation(req)

    env_options = model_gateway_options_from_env(
        {
            "THALION_MODEL_GATEWAY_DESTINATION": "corp-openai-gw",
            "THALION_MODEL_GATEWAY_PURPOSES": "wiki_compilation, model_answer",
            "THALION_MODEL_GATEWAY_PROTOCOL": "openai_compatible",
            "THALION_MODEL_GATEWAY_MODEL": "deepseek-v4.1-flash",
            "THALION_MODEL_GATEWAY_TIMEOUT_SECONDS": "45",
            "THALION_MODEL_GATEWAY_MAX_TOKENS": "2048",
        }
    )
    assert env_options == {
        "model_destination_id": "corp-openai-gw",
        "model_allowed_purposes": frozenset({"wiki_compilation", "model_answer"}),
        "model_gateway_protocol": "openai_compatible",
        "model_gateway_model": "deepseek-v4.1-flash",
        "model_gateway_timeout_seconds": 45.0,
        "model_gateway_max_tokens": 2048,
    }

    prod_cfg = validate_deployment_config(
        {
            "mode": "production",
            "business_timezone": "Asia/Shanghai",
            "database_url_ref": "env:THALION_DB_URL",
            "allowed_hosts": ["kb.corp.example"],
            "identity": {
                "issuer": "https://idp.corp.example",
                "audience": "thalion-kb",
                "jwks_url": "https://idp.corp.example/.well-known/jwks.json",
            },
            "source_authority": {
                "endpoint": "https://auth.corp.example/v1",
                "credential_ref": "env:THALION_AUTH_CRED",
            },
            "object_storage": {
                "endpoint": "https://obj.corp.example",
                "bucket": "thalion-prod",
                "credential_ref": "env:THALION_OBJ_CRED",
            },
            "security_audit_log": {
                "endpoint": "https://audit.corp.example/v1",
                "credential_ref": "env:THALION_AUDIT_CRED",
            },
            "model_gateway": {
                "endpoint": "https://gw.corp.example/v1",
                "credential_ref": "env:THALION_GW_CRED",
            },
        }
    )
    reg = build_production_port_registry(
        prod_cfg,
        source_authority_ref=uuid4(),
        security_log_ref=uuid4(),
        **env_options,
    )
    assert isinstance(reg.model_gateway, OpenAiCompatibleModelGatewayAdapter)
    assert reg.model_gateway.model == "deepseek-v4.1-flash"
    assert reg.model_gateway.max_tokens == 2048

    with pytest.raises(ValueError, match="model_gateway_model"):
        build_production_port_registry(
            prod_cfg,
            source_authority_ref=uuid4(),
            security_log_ref=uuid4(),
            model_destination_id="corp-openai-gw",
            model_allowed_purposes=frozenset({"wiki_compilation"}),
            model_gateway_protocol="openai_compatible",
        )

    with pytest.raises(ValueError, match="Unsupported model_gateway_protocol"):
        build_production_port_registry(
            prod_cfg,
            source_authority_ref=uuid4(),
            security_log_ref=uuid4(),
            model_destination_id="corp-openai-gw",
            model_allowed_purposes=frozenset({"wiki_compilation"}),
            model_gateway_protocol="unknown_proto",
        )


def test_openai_compatible_embedding_adapter_and_registry(monkeypatch):
    from enterprise_kb.ports.adapters import (
        OpenAiCompatibleEmbeddingProviderAdapter,
        build_production_port_registry,
        embedding_options_from_env,
    )

    monkeypatch.setenv("THALION_EMB_CRED", "embed-openai-secret")
    monkeypatch.setenv("THALION_AUTH_CRED", "auth-cred")
    monkeypatch.setenv("THALION_OBJ_CRED", "obj-cred")
    monkeypatch.setenv("THALION_AUDIT_CRED", "audit-cred")

    seen: list[dict] = []
    mode = {"state": "ok"}

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["Authorization"] == "Bearer embed-openai-secret"
        body = json.loads(request.content.decode("utf-8"))
        seen.append({"url": str(request.url), "body": body})
        if mode["state"] == "http_error":
            return httpx2.Response(502, text="bad gateway")
        if mode["state"] == "dup_index":
            return httpx2.Response(
                200,
                json={
                    "model": "nvidia/nemotron-3.5-embed-8b",
                    "data": [
                        {"index": 0, "embedding": [1.0, 0.0, 0.0, 0.0]},
                        {"index": 0, "embedding": [0.0, 1.0, 0.0, 0.0]},
                    ],
                },
            )
        if mode["state"] == "wrong_dim":
            return httpx2.Response(
                200,
                json={
                    "model": "nvidia/nemotron-3.5-embed-8b",
                    "data": [{"index": 0, "embedding": [1.0, 2.0]}],
                },
            )
        if mode["state"] == "zero_vec":
            return httpx2.Response(
                200,
                json={
                    "model": "nvidia/nemotron-3.5-embed-8b",
                    "data": [{"index": 0, "embedding": [0.0, 0.0, 0.0, 0.0]}],
                },
            )
        if mode["state"] == "nan_vec":
            return httpx2.Response(
                200,
                content=b'{"model":"nvidia/nemotron-3.5-embed-8b","data":[{"index":0,"embedding":[1.0,NaN,0.0,0.0]}]}',
                headers={"Content-Type": "application/json"},
            )
        if len(body["input"]) == 2:
            # Deliberately return indices out of order to verify index-based reassembly.
            return httpx2.Response(
                200,
                json={
                    "model": "nvidia/nemotron-3.5-embed-8b",
                    "data": [
                        {"index": 1, "embedding": [0.0, 3.0, 4.0, 0.0]},
                        {"index": 0, "embedding": [3.0, 4.0, 0.0, 0.0]},
                    ],
                },
            )
        return httpx2.Response(
            200,
            json={
                "model": "nvidia/nemotron-3.5-embed-8b",
                "data": [{"index": 0, "embedding": [0.0, 0.0, 5.0, 0.0]}],
            },
        )

    adapter = OpenAiCompatibleEmbeddingProviderAdapter(
        AuthenticatedEndpointConfig("https://emb.corp.example", "env:THALION_EMB_CRED"),
        model_id="nvidia/nemotron-3.5-embed-8b",
        dimension=4,
        request_dimensions=True,
        passage_input_type="passage",
        query_input_type="query",
        transport=httpx2.MockTransport(handler),
    )
    assert adapter.admission == "production_approved"
    assert adapter.embeddings_url == "https://emb.corp.example/v1/embeddings"

    vectors = adapter.embed_passages(["上海住宿标准", "高铁二等座规定"])
    assert vectors == ((0.6, 0.8, 0.0, 0.0), (0.0, 0.6, 0.8, 0.0))
    assert seen[-1]["url"] == "https://emb.corp.example/v1/embeddings"
    assert seen[-1]["body"] == {
        "model": "nvidia/nemotron-3.5-embed-8b",
        "input": ["上海住宿标准", "高铁二等座规定"],
        "dimensions": 4,
        "input_type": "passage",
    }

    query_vec = adapter.embed_query("上海酒店多少钱")
    assert query_vec == (0.0, 0.0, 1.0, 0.0)
    assert seen[-1]["body"] == {
        "model": "nvidia/nemotron-3.5-embed-8b",
        "input": ["上海酒店多少钱"],
        "dimensions": 4,
        "input_type": "query",
    }

    no_dim_adapter = OpenAiCompatibleEmbeddingProviderAdapter(
        AuthenticatedEndpointConfig("https://emb.corp.example/v1", "env:THALION_EMB_CRED"),
        model_id="nvidia/nemotron-3.5-embed-8b",
        dimension=4,
        request_dimensions=False,
        transport=httpx2.MockTransport(handler),
    )
    assert no_dim_adapter.embeddings_url == "https://emb.corp.example/v1/embeddings"
    no_dim_adapter.embed_query("不含维度参数")
    assert "dimensions" not in seen[-1]["body"]
    assert "input_type" not in seen[-1]["body"]

    mode["state"] = "dup_index"
    with pytest.raises(EmbeddingPortUnavailable, match="index"):
        adapter.embed_passages(["a", "b"])

    mode["state"] = "wrong_dim"
    with pytest.raises(EmbeddingPortUnavailable, match="dimension"):
        adapter.embed_query("a")

    mode["state"] = "zero_vec"
    with pytest.raises(EmbeddingPortUnavailable, match="zero norm"):
        adapter.embed_query("a")

    mode["state"] = "nan_vec"
    with pytest.raises(EmbeddingPortUnavailable):
        adapter.embed_query("a")

    mode["state"] = "http_error"
    with pytest.raises(EmbeddingPortUnavailable, match="HTTP 502"):
        adapter.embed_query("a")

    with pytest.raises(ValueError, match="model_id"):
        OpenAiCompatibleEmbeddingProviderAdapter(
            AuthenticatedEndpointConfig("https://emb.corp.example/v1", "env:THALION_EMB_CRED"),
            model_id="bad/../model",
            dimension=4,
        )

    env_options = embedding_options_from_env(
        {
            "THALION_EMBEDDING_PROTOCOL": "openai_compatible",
            "THALION_EMBEDDING_MODEL_ID": "nvidia/nemotron-3.5-embed-8b",
            "THALION_EMBEDDING_DIMENSION": "1024",
            "THALION_EMBEDDING_REQUEST_DIMENSIONS": "true",
            "THALION_EMBEDDING_PASSAGE_INPUT_TYPE": "passage",
            "THALION_EMBEDDING_QUERY_INPUT_TYPE": "query",
            "THALION_EMBEDDING_TIMEOUT_SECONDS": "45",
        }
    )
    assert env_options == {
        "embedding_protocol": "openai_compatible",
        "embedding_model_id": "nvidia/nemotron-3.5-embed-8b",
        "embedding_dimension": 1024,
        "embedding_request_dimensions": True,
        "embedding_passage_input_type": "passage",
        "embedding_query_input_type": "query",
        "embedding_timeout_seconds": 45.0,
    }

    with pytest.raises(ValueError, match="boolean"):
        embedding_options_from_env({"THALION_EMBEDDING_REQUEST_DIMENSIONS": "maybe"})

    prod_cfg = validate_deployment_config(
        {
            "mode": "production",
            "business_timezone": "Asia/Shanghai",
            "database_url_ref": "env:THALION_DB_URL",
            "allowed_hosts": ["kb.corp.example"],
            "identity": {
                "issuer": "https://idp.corp.example",
                "audience": "thalion-kb",
                "jwks_url": "https://idp.corp.example/.well-known/jwks.json",
            },
            "source_authority": {
                "endpoint": "https://auth.corp.example/v1",
                "credential_ref": "env:THALION_AUTH_CRED",
            },
            "object_storage": {
                "endpoint": "https://obj.corp.example",
                "bucket": "thalion-prod",
                "credential_ref": "env:THALION_OBJ_CRED",
            },
            "security_audit_log": {
                "endpoint": "https://audit.corp.example/v1",
                "credential_ref": "env:THALION_AUDIT_CRED",
            },
            "embedding_provider": {
                "endpoint": "https://emb.corp.example/v1",
                "credential_ref": "env:THALION_EMB_CRED",
            },
        }
    )
    reg = build_production_port_registry(
        prod_cfg,
        source_authority_ref=uuid4(),
        security_log_ref=uuid4(),
        **env_options,
    )
    assert isinstance(reg.embedding_provider, OpenAiCompatibleEmbeddingProviderAdapter)
    assert reg.embedding_provider.model_id == "nvidia/nemotron-3.5-embed-8b"
    assert reg.embedding_provider.dimension == 1024
    assert reg.embedding_provider.request_dimensions is True
    assert reg.embedding_provider.passage_input_type == "passage"
    assert reg.embedding_provider.query_input_type == "query"

    with pytest.raises(ValueError, match="Unsupported embedding_protocol"):
        build_production_port_registry(
            prod_cfg,
            source_authority_ref=uuid4(),
            security_log_ref=uuid4(),
            embedding_protocol="unknown_embed_proto",
            embedding_model_id="nvidia/nemotron-3.5-embed-8b",
            embedding_dimension=1024,
        )
