from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import httpx2
import jwt
import pytest

from enterprise_kb.modules.access import delivery, governance, original_download, policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.operations import release
from enterprise_kb.modules.retrieval import lexical, vector
from enterprise_kb.modules.sources import originals, registry
from enterprise_kb.ports.adapters import (
    HttpEmbeddingProviderAdapter,
    HttpObjectStorageAdapter,
    HttpSecurityAuditLogAdapter,
    HttpSourceAuthorityAdapter,
    OidcJwksIdentityVerifier,
)
from enterprise_kb.ports.contracts import (
    PortRegistry,
    ProductionIsolationError,
)
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.runtime.config import (
    AuthenticatedEndpointConfig,
    ConfigValidationError,
    IdentityEndpointConfig,
    ObjectStorageEndpointConfig,
    ProductionDeploymentConfig,
)
from enterprise_kb.transport import api, evidence, local

from test_effectivity import BEFORE, BEGIN, approve
from test_evidence import approved, claim, review
from test_evidence_transport import bearer, rpc
from test_identity import migrate_to_revision
from test_persisted_access import binding, set_rules
from test_runtime import Tenant, open_database, runtime_db
from test_sources import register, request_for
from test_travel_search import SEARCH_FIELDS


def _rsa_jwk(kid: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = kid
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return private_key, public_jwk


def _sign_token(
    private_key,
    kid: str,
    *,
    issuer: str,
    audience: str,
    subject_ref: UUID,
    space_ref: UUID,
    client_id: str,
    operations: list[str],
    region: str = "shanghai",
    traveler_class: str = "employee",
    ttl_seconds: int = 300,
) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "sub": str(subject_ref),
            "space_ref": str(space_ref),
            "client_id": client_id,
            "operations": operations,
            "region": region,
            "traveler_class": traveler_class,
            "iat": int(now.timestamp()) - 10,
            "nbf": int(now.timestamp()) - 10,
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _register_production_tenant(connection, label: str, issuer: str, *, employee_subject: str | None = None) -> Tenant:
    with connection.transaction():
        org_id = connection.execute(
            "INSERT INTO thalion.organization (name, business_timezone) "
            "VALUES (%s, 'Asia/Shanghai') RETURNING org_id",
            (label,),
        ).fetchone()[0]
        actors = []
        for role in ("employee", "employee", "service", "service"):
            subject = employee_subject if not actors and employee_subject is not None else str(uuid4())
            actor_id = connection.execute(
                "INSERT INTO thalion.principal "
                "(org_id, principal_type, authority_issuer, authority_subject_key) "
                "VALUES (%s, %s, %s, %s) RETURNING principal_id",
                (org_id, role, issuer, subject),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO thalion.object_identity (org_id, object_type, object_id) "
                "VALUES (%s, 'principal', %s)",
                (org_id, actor_id),
            )
            actors.append(actor_id)
        space_id = connection.execute(
            "INSERT INTO thalion.space (org_id, name, classification, owner_principal_id) "
            "VALUES (%s, 'ProdTravel', 'internal', %s) RETURNING space_id",
            (org_id, actors[0]),
        ).fetchone()[0]
        space_ref = connection.execute(
            "INSERT INTO thalion.object_identity (org_id, object_type, object_id, space_id) "
            "VALUES (%s, 'space', %s, %s) RETURNING public_id",
            (org_id, space_id, space_id),
        ).fetchone()[0]
    return Tenant(org_id, space_id, space_ref, *actors)


def _setup_production_corpus(connection, database_url: str, issuer: str, storage_port: HttpObjectStorageAdapter):
    tenant = _register_production_tenant(connection, f"ProdOrg-{uuid4().hex[:8]}", issuer)
    store = originals.ObjectStorageOriginalStore(storage_port)
    ctx = request_for(connection, tenant, tenant.actor_id, f"prod-src-{uuid4()}", "register_source_contract")
    source_ref = registry.register_source(
        connection,
        ctx,
        tenant.space_id,
        registry.SyntheticSource(
            "travel-prod",
            "travel-prod-archive",
            tenant.worker_id,
            approver_id=tenant.other_actor_id,
            processor_id=tenant.other_worker_id,
            quality_reviewer_id=tenant.actor_id,
        ),
        admission=registry.PRODUCTION_ADMISSION,
    )
    db = (connection, tenant, database_url, source_ref, store)

    def _publish(object_key: str, title: str, payload: bytes):
        ver = register(
            connection,
            tenant,
            source_ref,
            store,
            key=str(uuid4()),
            object_key=object_key,
            display_name=title,
            digest=sha256(payload).digest(),
            payload=payload,
        )
        lease = claim(db)
        assert lease is not None
        assert lease.spec.target_ref == ver.version_ref
        run = processing.process_markdown_job(connection, lease, store)
        review(db, run)
        return ver, approved(db, ver)[0], run

    allowance, first, _ = _publish("allowance", "住宿标准", "# 上海\n\n上海住宿限额。\n".encode())
    approval, second, run = _publish("approval", "受限审批说明", "# 差旅\n\n上海住宿超标需审批。\n".encode())
    approve(connection, tenant, allowance, BEGIN)
    approve(connection, tenant, approval, BEGIN)
    return db, allowance, first, second, run


def test_load_production_config_from_env_parses_valid_env_and_rejects_invalid():
    from enterprise_kb.runtime.config import load_production_config_from_env

    valid_env = {
        "THALION_MODE": "production",
        "THALION_BUSINESS_TIMEZONE": "Asia/Shanghai",
        "THALION_DATABASE_URL_REF": "env:THALION_PROD_DB_URL",
        "THALION_ALLOWED_HOSTS": "kb.corp.example, kb-alt.corp.example",
        "THALION_OIDC_ISSUER": "https://idp.corp.example",
        "THALION_OIDC_AUDIENCE": "thalion-kb",
        "THALION_OIDC_JWKS_URL": "https://idp.corp.example/.well-known/jwks.json",
        "THALION_SOURCE_AUTHORITY_ENDPOINT": "https://source-auth.corp.example/v1/check",
        "THALION_SOURCE_AUTHORITY_CREDENTIAL_REF": "env:THALION_AUTH_SECRET",
        "THALION_OBJECT_STORAGE_ENDPOINT": "https://object.corp.example",
        "THALION_OBJECT_STORAGE_BUCKET": "thalion-originals-prod",
        "THALION_OBJECT_STORAGE_CREDENTIAL_REF": "env:THALION_OBJ_SECRET",
        "THALION_SECURITY_AUDIT_ENDPOINT": "https://audit-sink.corp.example/v1/events",
        "THALION_SECURITY_AUDIT_CREDENTIAL_REF": "env:THALION_AUDIT_SECRET",
        "THALION_EMBEDDING_ENDPOINT": "https://embedding.corp.example/v1",
        "THALION_EMBEDDING_CREDENTIAL_REF": "env:THALION_EMBED_SECRET",
    }
    parsed = load_production_config_from_env(valid_env)
    assert isinstance(parsed, ProductionDeploymentConfig)
    assert parsed.allowed_hosts == ("kb.corp.example", "kb-alt.corp.example")
    assert parsed.embedding_provider is not None
    assert parsed.model_gateway is None

    with pytest.raises(ConfigValidationError, match="HTTPS"):
        load_production_config_from_env(
            dict(valid_env, THALION_OIDC_JWKS_URL="http://idp.corp.example/.well-known/jwks.json")
        )

    with pytest.raises(ConfigValidationError, match="secret reference"):
        load_production_config_from_env(
            dict(valid_env, THALION_DATABASE_URL_REF="postgresql://user:raw@db.corp.example/kb")
        )

    with pytest.raises(ConfigValidationError, match="pair|both|credential_ref|endpoint"):
        partial_embed = dict(valid_env)
        partial_embed.pop("THALION_EMBEDDING_CREDENTIAL_REF")
        load_production_config_from_env(partial_embed)


def test_production_port_registry_wiring_drives_http_mcp_and_fails_closed(runtime_db):
    connection, _, database_url = runtime_db
    prod_issuer = "https://idp.corp.example"
    prod_audience = "thalion-kb-prod"
    authority_ref = uuid4()
    security_log_ref = uuid4()
    syn_encoder = vector.SyntheticLocalEmbeddingProvider()

    objects: dict[str, bytes] = {}
    private_key, public_jwk = _rsa_jwk("prod-k1")
    jwks_state = {"fail": False}
    authority_state = {"revoked": False, "overgrant": False, "down": False, "calls": 0}
    storage_state = {"tamper": False, "calls": 0}
    embedding_state = {"down": False, "calls": 0}

    def jwks_handler(request: httpx2.Request) -> httpx2.Response:
        if jwks_state["fail"]:
            return httpx2.Response(503, text="jwks down")
        return httpx2.Response(200, json={"keys": [public_jwk]})

    def authority_handler(request: httpx2.Request) -> httpx2.Response:
        authority_state["calls"] += 1
        if authority_state["down"]:
            return httpx2.Response(503, text="authority down")
        payload = json.loads(request.content)
        assert request.headers["authorization"] == "Bearer auth-secret-1"
        now = datetime.now(UTC)
        decisions = []
        for scope in payload["scopes"]:
            if authority_state["revoked"]:
                granted = []
            elif authority_state["overgrant"]:
                granted = list(scope["fields"]) + ["unauthorized_extra_field"]
            else:
                granted = list(scope["fields"])
            decisions.append(
                {
                    "object_id": scope["object_id"],
                    "revision": scope["revision"],
                    "fields": granted,
                }
            )
        return httpx2.Response(
            200,
            json={
                "check_id": payload["check_id"],
                "authority_ref": str(authority_ref),
                "checked_at": now.isoformat(),
                "valid_until": (now + timedelta(seconds=15)).isoformat(),
                "subject_ids": [payload["principal_id"]],
                "proof_ref": f"prod-proof-{authority_state['calls']}",
                "grants": decisions,
            },
        )

    def storage_handler(request: httpx2.Request) -> httpx2.Response:
        storage_state["calls"] += 1
        assert request.headers["authorization"] == "Bearer obj-secret-1"
        storage_key = request.url.path.rsplit("/", 1)[-1]
        if request.method == "PUT":
            raw = request.content
            objects[storage_key] = raw
            return httpx2.Response(201, json={"sha256": sha256(raw).hexdigest()})
        raw = objects[storage_key]
        if storage_state["tamper"]:
            raw = raw[:-1] + (b"X" if raw[-1:] != b"X" else b"Y")
        return httpx2.Response(200, content=raw)

    def audit_handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            json={
                "log_ref": str(security_log_ref),
                "stream_ref": str(uuid4()),
                "generation": 1,
                "recorded_at": datetime.now(UTC).isoformat(),
                "digest": sha256(request.content).hexdigest(),
            },
        )

    def embedding_handler(request: httpx2.Request) -> httpx2.Response:
        embedding_state["calls"] += 1
        if embedding_state["down"]:
            return httpx2.Response(503, text="embedding down")
        payload = json.loads(request.content)
        vectors = [list(syn_encoder.embed_query(text)) for text in payload["inputs"]]
        return httpx2.Response(
            200,
            json={"model_id": payload["model_id"], "vectors": vectors},
        )

    secrets = {
        "vault:auth": "auth-secret-1",
        "vault:obj": "obj-secret-1",
        "vault:audit": "audit-secret-1",
        "vault:embed": "embed-secret-1",
    }
    identity_port = OidcJwksIdentityVerifier(
        IdentityEndpointConfig(prod_issuer, prod_audience, "https://idp.corp.example/.well-known/jwks.json"),
        transport=httpx2.MockTransport(jwks_handler),
    )
    authority_port = HttpSourceAuthorityAdapter(
        AuthenticatedEndpointConfig("https://auth.corp.example/v1/check", "vault:auth"),
        authority_ref=authority_ref,
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(authority_handler),
    )
    storage_port = HttpObjectStorageAdapter(
        ObjectStorageEndpointConfig("https://obj.corp.example", "prod-originals", "vault:obj"),
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(storage_handler),
    )
    audit_port = HttpSecurityAuditLogAdapter(
        AuthenticatedEndpointConfig("https://audit.corp.example/v1/events", "vault:audit"),
        log_ref=security_log_ref,
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(audit_handler),
    )
    embedding_port = HttpEmbeddingProviderAdapter(
        AuthenticatedEndpointConfig("https://embed.corp.example/v1", "vault:embed"),
        model_id="corp-embed-v1",
        dimension=64,
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(embedding_handler),
    )

    db, version, first, second, _ = _setup_production_corpus(connection, database_url, prod_issuer, storage_port)
    _, tenant, _, _, store = db
    set_rules(
        db,
        replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        replace(binding(tenant.other_actor_id, passage_ref=first.passage_ref), fields=SEARCH_FIELDS),
    )

    actor_ref = connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
        (tenant.actor_id,),
    ).fetchone()[0]
    other_actor_ref = connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
        (tenant.other_actor_id,),
    ).fetchone()[0]
    run_ref, = connection.execute(
        """
        SELECT processing.run_ref FROM thalion.processing_run AS processing
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (processing.org_id, processing.space_id, 'document_version', processing.version_id)
        WHERE identity.public_id = %s
        """,
        (version.version_ref,),
    ).fetchone()

    vector.build_vector_index(
        connection, store, tenant.space_ref, version.version_ref, run_ref, embedding_port,
    )
    lexical.build_index(connection, store, tenant.space_ref, version.version_ref, run_ref)
    req_id = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, req_id, tenant.actor_id, None, "prod-release-setup",
            release.SWITCH_SPACE_RELEASE, "internal_release", BEFORE, 1,
            space_id=tenant.space_id, ingress="internal",
        ),
    )
    release.switch_space_release(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, req_id, str(uuid4())),
        tenant.space_id,
        action="trial_switch",
        wiki_delivery_enabled=False,
        lexical_index_mode="hybrid_vector",
        vector_model_id="corp-embed-v1",
        rollback_trigger_summary="production port wiring hybrid check",
        reason_code="prod_port_wiring",
        basis_ref=uuid4(),
    )

    port_registry = PortRegistry(
        mode="production",
        identity=identity_port,
        source_authority=authority_port,
        object_storage=storage_port,
        security_audit_log=audit_port,
        embedding_provider=embedding_port,
    )
    service = evidence.EvidenceService.from_port_registry(
        lambda: open_database(database_url),
        port_registry,
    )

    class BadSyntheticIdentity:
        admission = "synthetic_local"
        issuer = prod_issuer
        audience = prod_audience

        def verify_bearer_token(self, token: str):
            return None

    with pytest.raises(ProductionIsolationError):
        evidence.EvidenceService.from_port_registry(
            lambda: open_database(database_url),
            PortRegistry(
                mode="production",
                identity=BadSyntheticIdentity(),
                source_authority=authority_port,
                object_storage=storage_port,
                security_audit_log=audit_port,
            ),
        )

    token = _sign_token(
        private_key,
        "prod-k1",
        issuer=prod_issuer,
        audience=prod_audience,
        subject_ref=actor_ref,
        space_ref=tenant.space_ref,
        client_id="corp-agent",
        operations=["search", "read_passage"],
    )
    other_token = _sign_token(
        private_key,
        "prod-k1",
        issuer=prod_issuer,
        audience=prod_audience,
        subject_ref=other_actor_ref,
        space_ref=tenant.space_ref,
        client_id="corp-agent",
        operations=["search", "read_passage"],
    )

    with TestClient(
        api.create_app(service, allowed_hosts=("kb.corp.example",)),
        base_url="https://kb.corp.example",
    ) as client:
        wrong_host = client.post(
            "/v1/search",
            headers=bearer(token) | {"Host": "evil.invalid"},
            json={"query": "酒店能报多少", "business_date": BEFORE.isoformat()},
        )
        assert wrong_host.status_code == 403
        loopback_host = client.post(
            "/v1/search",
            headers=bearer(token) | {"Host": "127.0.0.1"},
            json={"query": "酒店能报多少", "business_date": BEFORE.isoformat()},
        )
        assert loopback_host.status_code == 403

        search_body = {"query": "上海住宿", "business_date": BEFORE.isoformat()}
        http_search = client.post("/v1/search", headers=bearer(token), json=search_body)
        assert http_search.status_code == 200
        http_payload = http_search.json()
        assert http_payload["status"] == "hits"
        assert len(http_payload["passages"]) >= 1
        first_hit = next(item for item in http_payload["passages"] if item["passage_id"] == str(first.passage_ref))
        citation_id = first_hit["passage_id"]
        assert "上海住宿限额" in first_hit["excerpt"]
        assert authority_state["calls"] >= 1
        assert storage_state["calls"] >= 1
        assert embedding_state["calls"] >= 1

        mcp_search = rpc(client, token, "tools/call", name="search", arguments=search_body)
        assert mcp_search.status_code == 200
        mcp_result = mcp_search.json()["result"]["structuredContent"]
        assert any(item["passage_id"] == citation_id for item in mcp_result["passages"])

        http_read = client.get(f"/v1/passages/{citation_id}", headers=bearer(token))
        assert http_read.status_code == 200
        assert "上海住宿限额" in http_read.json()["passage"]["excerpt"]

        mcp_read = rpc(client, token, "tools/call", name="read_passage", arguments={"id": citation_id})
        assert mcp_read.status_code == 200
        assert mcp_read.json()["result"]["structuredContent"]["passage"]["passage_id"] == citation_id

        restricted_search = client.post("/v1/search", headers=bearer(other_token), json=search_body)
        assert restricted_search.status_code == 200
        restricted_ids = [item["passage_id"] for item in restricted_search.json()["passages"]]
        assert restricted_ids == [str(first.passage_ref)]
        restricted_denied = client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(other_token))
        assert restricted_denied.status_code == 404
        assert restricted_denied.json()["error"]["code"] == "citation_unavailable"

        authority_state["revoked"] = True
        revoked_search = client.post("/v1/search", headers=bearer(token), json=search_body)
        assert revoked_search.status_code == 200
        assert revoked_search.json()["status"] == "no_evidence"
        assert revoked_search.json()["passages"] == []
        revoked_read = client.get(f"/v1/passages/{citation_id}", headers=bearer(token))
        assert revoked_read.status_code == 404
        assert revoked_read.json()["error"]["code"] == "citation_unavailable"
        authority_state["revoked"] = False

        authority_state["overgrant"] = True
        overgrant_resp = client.post("/v1/search", headers=bearer(token), json=search_body)
        assert overgrant_resp.status_code == 503
        assert overgrant_resp.json()["error"]["code"] == "dependency_unavailable"
        authority_state["overgrant"] = False

        authority_state["down"] = True
        down_resp = client.post("/v1/search", headers=bearer(token), json=search_body)
        assert down_resp.status_code == 503
        assert down_resp.json()["error"]["code"] == "dependency_unavailable"
        authority_state["down"] = False

        storage_state["tamper"] = True
        tamper_resp = client.get(f"/v1/passages/{citation_id}", headers=bearer(token))
        assert tamper_resp.status_code == 503
        assert tamper_resp.json()["error"]["code"] == "dependency_unavailable"
        storage_state["tamper"] = False

        embedding_state["down"] = True
        embed_down = client.post("/v1/search", headers=bearer(token), json=search_body)
        assert embed_down.status_code == 503
        assert embed_down.json()["error"]["code"] == "dependency_unavailable"
        embedding_state["down"] = False

        jwks_state["fail"] = True
        unknown_kid_token = _sign_token(
            private_key,
            "prod-k-unseen",
            issuer=prod_issuer,
            audience=prod_audience,
            subject_ref=actor_ref,
            space_ref=tenant.space_ref,
            client_id="corp-agent",
            operations=["search", "read_passage"],
        )
        jwks_down = client.post("/v1/search", headers=bearer(unknown_kid_token), json=search_body)
        assert jwks_down.status_code == 503
        assert jwks_down.json()["error"]["code"] == "dependency_unavailable"

    jwks_state["fail"] = False
    mismatched_embedding = HttpEmbeddingProviderAdapter(
        AuthenticatedEndpointConfig("https://embed.corp.example/v1", "vault:embed"),
        model_id="corp-embed-v2",
        dimension=64,
        secret_resolver=secrets.__getitem__,
        transport=httpx2.MockTransport(embedding_handler),
    )
    mismatch_service = evidence.EvidenceService.from_port_registry(
        lambda: open_database(database_url),
        PortRegistry(
            mode="production",
            identity=identity_port,
            source_authority=authority_port,
            object_storage=storage_port,
            security_audit_log=audit_port,
            embedding_provider=mismatched_embedding,
        ),
    )
    with TestClient(
        api.create_app(mismatch_service, allowed_hosts=("kb.corp.example",)),
        base_url="https://kb.corp.example",
    ) as mismatch_client:
        mismatch_resp = mismatch_client.post("/v1/search", headers=bearer(token), json=search_body)
        assert mismatch_resp.status_code == 503
        assert mismatch_resp.json()["error"]["code"] == "dependency_unavailable"


def test_production_browser_sso_maps_standard_claims_to_registered_employee(runtime_db, tmp_path):
    connection, _, database_url = runtime_db
    issuer = "https://idp.corp.example"
    subject = "opaque-oidc-employee-key"
    employee = _register_production_tenant(connection, "SSO org", issuer, employee_subject=subject)
    other = _register_production_tenant(connection, "Another org", issuer)
    policy_file = tmp_path / "access.json"
    policy_file.write_text(json.dumps({
        "issuer": issuer, "client_id": "kb-web", "group_claim": "realm_access.roles",
        "groups": {
            "kb-readers": {"space_ref": str(employee.space_ref), "operations": ["search"]},
            "unrelated-admins": {"space_ref": str(other.space_ref), "operations": ["read_passage"]},
        },
    }))
    policy_file.chmod(0o600)
    config = IdentityEndpointConfig(issuer, "api-audience", f"{issuer}/jwks")
    signing_key, jwk = _rsa_jwk("standard-oidc")
    issued_token = None

    def idp(request):
        if request.url.path == "/jwks":
            return httpx2.Response(200, json={"keys": [jwk]})
        assert request.url.path == "/token"
        assert parse_qs(request.content.decode())["code_verifier"]
        return httpx2.Response(200, json={"id_token": issued_token, "access_token": "ignored-provider-access-token"})

    transport = httpx2.MockTransport(idp)
    network_identity = OidcJwksIdentityVerifier(config, transport=transport)
    connect = local.production_connection_factory(database_url)
    deployment = type("Deployment", (), {"identity": config})()
    sso, identity = local._build_production_oidc_sso(deployment, {
        "THALION_OIDC_AUTHORIZATION_ENDPOINT": f"{issuer}/authorize", "THALION_OIDC_TOKEN_ENDPOINT": f"{issuer}/token",
        "THALION_OIDC_CLIENT_ID": "web-idp-client", "THALION_OIDC_REDIRECT_URI": "https://kb.corp.example/auth/oidc/callback",
        "THALION_OIDC_ACCESS_MAP_FILE": str(policy_file),
    }, connect, network_identity)
    sso._transport = transport
    registry = PortRegistry(
        mode="production", identity=identity,
        source_authority=HttpSourceAuthorityAdapter(
            AuthenticatedEndpointConfig("https://auth.corp.example", "env:AUTH_TOKEN"), authority_ref=uuid4(),
        ),
        object_storage=HttpObjectStorageAdapter(ObjectStorageEndpointConfig(
            "https://objects.corp.example", "originals", "env:OBJECT_TOKEN",
        )),
        security_audit_log=HttpSecurityAuditLogAdapter(
            AuthenticatedEndpointConfig("https://audit.corp.example/events", "env:AUDIT_TOKEN"), log_ref=uuid4(),
        ),
    )
    service = evidence.EvidenceService.from_port_registry(connect, registry)
    with TestClient(api.create_app(service, allowed_hosts=("kb.corp.example",), oidc_sso=sso),
                    base_url="https://kb.corp.example") as client:
        def login(groups, *, audience="web-idp-client", external_subject=subject, authorized_party=None):
            nonlocal issued_token
            start = client.get("/auth/oidc/login", follow_redirects=False)
            parameters = parse_qs(urlsplit(start.headers["location"]).query)
            now = int(datetime.now(UTC).timestamp())
            claims = {
                "iss": issuer, "aud": audience, "sub": external_subject, "iat": now, "exp": now + 900,
                "nonce": parameters["nonce"][0], "realm_access": {"roles": groups},
                "space_ref": str(other.space_ref), "operations": ["read_passage"],
            }
            if authorized_party is not None:
                claims["azp"] = authorized_party
            issued_token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "standard-oidc"})
            return client.get("/auth/oidc/callback", params={"code": "accepted", "state": parameters["state"][0]},
                              follow_redirects=False)

        assert login(["kb-readers"], audience="api-audience").status_code == 401
        assert login(["kb-readers"], audience=["web-idp-client", "api-audience"], authorized_party="another-app").status_code == 401
        assert login(["kb-readers"], external_subject="unregistered-user").status_code == 403
        assert login(["unknown-group"]).status_code == 403
        assert login(["unrelated-admins"]).status_code == 403
        assert login("kb-readers").status_code == 403
        callback = login(["kb-readers", "unrelated-admins"])
        assert callback.status_code == 302
        ticket = urlsplit(callback.headers["location"]).fragment.removeprefix("oidc_ticket=")
        exchange = client.post("/auth/oidc/exchange", json={"ticket": ticket}).json()
        browser_token = exchange["access_token"]
        assert browser_token != issued_token
        assert datetime.fromisoformat(exchange["expires_at"]) <= datetime.now(UTC) + timedelta(minutes=5)
        caller = service.identify(browser_token)
        assert (caller.org_id, caller.space_id) == (employee.org_id, employee.space_id)
        assert caller.credential.operations == {"search"}
        assert caller.credential.client_id == "kb-web"
        assert client.get(f"/v1/passages/{uuid4()}", headers=bearer(browser_token)).status_code == 403
        assert client.get(f"/v1/passages/{uuid4()}", headers=bearer(issued_token)).status_code == 401
        connection.execute("UPDATE thalion.principal SET disabled = true WHERE principal_id = %s", (employee.actor_id,))
        assert client.get(f"/v1/passages/{uuid4()}", headers=bearer(browser_token)).status_code == 401
        assert login(["kb-readers"]).status_code == 403


def test_production_browser_sso_requires_explicit_access_mapping(runtime_db):
    from enterprise_kb.transport.local import _build_production_oidc_sso

    _, _, database_url = runtime_db
    config = IdentityEndpointConfig(
        "https://idp.corp.example", "api-audience", "https://idp.corp.example/jwks"
    )
    identity = OidcJwksIdentityVerifier(config, transport=httpx2.MockTransport(lambda _: httpx2.Response(200)))
    deployment = type("Deployment", (), {"identity": config})()
    with pytest.raises(ConfigValidationError, match="ACCESS_MAP_FILE"):
        _build_production_oidc_sso(
            deployment,
            {
                "THALION_OIDC_AUTHORIZATION_ENDPOINT": "https://idp.corp.example/authorize",
                "THALION_OIDC_TOKEN_ENDPOINT": "https://idp.corp.example/token",
                "THALION_OIDC_CLIENT_ID": "web-idp-client",
                "THALION_OIDC_REDIRECT_URI": "https://kb.corp.example/auth/oidc/callback",
            },
            local.production_connection_factory(database_url),
            identity,
        )


def test_thalion_serve_production_check_config_verifies_env_ports_and_head(
    database_url, monkeypatch, capsys
):
    from enterprise_kb.database import expected_head_revisions, upgrade

    prod_env = {
        "THALION_MODE": "production",
        "THALION_BUSINESS_TIMEZONE": "Asia/Shanghai",
        "THALION_DATABASE_URL_REF": "env:THALION_TEST_PROD_DB",
        "THALION_TEST_PROD_DB": database_url,
        "THALION_ALLOWED_HOSTS": "kb.corp.example",
        "THALION_OIDC_ISSUER": "https://idp.corp.example",
        "THALION_OIDC_AUDIENCE": "thalion-kb",
        "THALION_OIDC_JWKS_URL": "https://idp.corp.example/.well-known/jwks.json",
        "THALION_SOURCE_AUTHORITY_ENDPOINT": "https://source-auth.corp.example/v1/check",
        "THALION_SOURCE_AUTHORITY_CREDENTIAL_REF": "env:THALION_TEST_AUTH_CRED",
        "THALION_TEST_AUTH_CRED": "auth-token",
        "THALION_SOURCE_AUTHORITY_REF": str(uuid4()),
        "THALION_OBJECT_STORAGE_ENDPOINT": "https://object.corp.example",
        "THALION_OBJECT_STORAGE_BUCKET": "thalion-originals-prod",
        "THALION_OBJECT_STORAGE_CREDENTIAL_REF": "env:THALION_TEST_OBJ_CRED",
        "THALION_TEST_OBJ_CRED": "obj-token",
        "THALION_SECURITY_AUDIT_ENDPOINT": "https://audit.corp.example/v1/events",
        "THALION_SECURITY_AUDIT_CREDENTIAL_REF": "env:THALION_TEST_AUDIT_CRED",
        "THALION_TEST_AUDIT_CRED": "audit-token",
        "THALION_SECURITY_AUDIT_LOG_REF": str(uuid4()),
    }
    for key, val in prod_env.items():
        monkeypatch.setenv(key, val)

    migrate_to_revision(database_url, "0107_vector_index_generation")
    monkeypatch.setattr("sys.argv", ["thalion-serve", "--mode", "production", "--check-config"])
    assert local.main() == 1
    assert capsys.readouterr().err

    upgrade(database_url)
    assert local.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["mode"] == "production"
    assert tuple(payload["schema_revisions"]) == expected_head_revisions()
    assert payload["ports"]["identity"] == "production_approved"
    assert payload["ports"]["source_authority"] == "production_approved"
    assert payload["ports"]["object_storage"] == "production_approved"
    assert payload["ports"]["security_audit_log"] == "production_approved"
    serialized = json.dumps(payload)
    assert database_url not in serialized
    assert "auth-token" not in serialized
    assert "obj-token" not in serialized

    monkeypatch.setenv("THALION_EMBEDDING_ENDPOINT", "https://emb.corp.example/v1")
    monkeypatch.setenv("THALION_EMBEDDING_CREDENTIAL_REF", "env:THALION_TEST_EMB_CRED")
    monkeypatch.setenv("THALION_TEST_EMB_CRED", "embed-secret-token")
    monkeypatch.setenv("THALION_EMBEDDING_PROTOCOL", "openai_compatible")
    monkeypatch.setenv("THALION_EMBEDDING_MODEL_ID", "nvidia/nemotron-3.5-embed-8b")
    monkeypatch.setenv("THALION_EMBEDDING_DIMENSION", "1024")
    monkeypatch.setenv("THALION_EMBEDDING_REQUEST_DIMENSIONS", "true")
    monkeypatch.setenv("THALION_EMBEDDING_PASSAGE_INPUT_TYPE", "passage")
    monkeypatch.setenv("THALION_EMBEDDING_QUERY_INPUT_TYPE", "query")
    assert local.main() == 0
    emb_payload = json.loads(capsys.readouterr().out)
    assert emb_payload["ports"]["embedding_provider"] == "production_approved"
    assert emb_payload["embedding_protocol"] == "openai_compatible"
    assert emb_payload["embedding_model_id"] == "nvidia/nemotron-3.5-embed-8b"
    assert emb_payload["embedding_dimension"] == 1024
    assert "embed-secret-token" not in json.dumps(emb_payload)

    monkeypatch.setenv("THALION_OIDC_JWKS_URL", "http://idp.corp.example/jwks.json")
    assert local.main() == 1
    assert capsys.readouterr().err


def test_original_download_propagates_authority_issuer_to_shared_groups(runtime_db):
    connection, _, database_url = runtime_db
    prod_issuer = "https://idp.corp.example"
    objects: dict[str, bytes] = {}

    def storage_handler(request: httpx2.Request) -> httpx2.Response:
        storage_key = request.url.path.rsplit("/", 1)[-1]
        if request.method == "PUT":
            objects[storage_key] = request.content
            return httpx2.Response(201, json={"sha256": sha256(request.content).hexdigest()})
        return httpx2.Response(200, content=objects[storage_key])

    storage_port = HttpObjectStorageAdapter(
        ObjectStorageEndpointConfig("https://obj.corp.example", "prod-originals", "vault:obj"),
        secret_resolver={"vault:obj": "obj-secret-1"}.__getitem__,
        transport=httpx2.MockTransport(storage_handler),
    )

    db, version, *_ = _setup_production_corpus(connection, database_url, prod_issuer, storage_port)
    _, tenant, _, source_ref, store = db
    now = datetime.now(UTC)
    other_actor_ref = connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE org_id = %s AND object_type = 'principal' AND object_id = %s",
        (tenant.org_id, tenant.other_actor_id),
    ).fetchone()[0]

    grp_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, grp_req, tenant.actor_id, None, "prod-orig-grp",
            governance.MANAGE_SHARED_GROUP, governance.DESTINATION, BEFORE, 1,
            space_id=tenant.space_id, ingress="internal",
        ),
    )
    grp = governance.create_shared_group(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, grp_req, f"grp-{uuid4()}"),
        tenant.space_id,
        target_source_ref=source_ref,
        name="Prod Original Readers",
        purpose="original_verification",
        scope_summary="Scoped original download for non-synthetic issuer",
        starts_at=now - timedelta(hours=1),
        review_at=now + timedelta(days=2),
        expires_at=now + timedelta(days=7),
        basis_ref=uuid4(),
    )
    finish_request(connection, tenant.org_id, grp_req, "succeeded", 0)

    mem_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, mem_req, tenant.actor_id, None, "prod-orig-grp",
            governance.MANAGE_SHARED_GROUP, governance.DESTINATION, BEFORE, 1,
            space_id=tenant.space_id, ingress="internal",
        ),
    )
    governance.add_shared_group_member(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, mem_req, f"mem-{uuid4()}"),
        tenant.space_id,
        UUID(grp["group_id"]),
        member_ref=other_actor_ref,
        starts_at=now - timedelta(minutes=30),
        expires_at=now + timedelta(days=7),
        basis_ref=uuid4(),
    )
    finish_request(connection, tenant.org_id, mem_req, "succeeded", 0)

    group_pid = connection.execute(
        "SELECT object_id FROM thalion.object_identity WHERE org_id = %s AND object_type = 'principal' AND public_id = %s",
        (tenant.org_id, UUID(grp["group_principal_id"])),
    ).fetchone()[0]
    group_issuer, = connection.execute(
        "SELECT authority_issuer FROM thalion.principal WHERE org_id = %s AND principal_id = %s",
        (tenant.org_id, group_pid),
    ).fetchone()
    assert group_issuer == prod_issuer

    group_download_rule = policy.LocalRule(
        group_pid,
        policy.ORIGINAL_DOWNLOAD_ACCESS[0],
        "allow",
        policy.ORIGINAL_DOWNLOAD_ACCESS[1],
        policy.ORIGINAL_DOWNLOAD_ACCESS[2],
        policy.ORIGINAL_FIELDS,
        now - timedelta(hours=1),
        now + timedelta(days=7),
        version_ref=version.version_ref,
    )
    set_rules(db, group_download_rule, expected=1)

    def allow_all(check: delivery.DeliveryCheck) -> delivery.AuthorityDecision:
        checked_at = datetime.now(UTC)
        return delivery.AuthorityDecision(
            check.check_id,
            checked_at,
            checked_at + timedelta(seconds=60),
            frozenset({tenant.other_actor_id}),
            {scope: scope.fields for scope in check.scopes},
            f"prod-orig-proof:{uuid4()}",
        )

    req_id = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, req_id, tenant.other_actor_id, None, "prod-orig-client",
            policy.ORIGINAL_DOWNLOAD_ACCESS[0], policy.ORIGINAL_DOWNLOAD_ACCESS[2], BEFORE, 1,
            space_id=tenant.space_id, ingress="http",
        ),
    )
    context = delivery.DeliveryContext(
        req_id,
        tenant.org_id,
        tenant.other_actor_id,
        "prod-orig-client",
        policy.ORIGINAL_DOWNLOAD_ACCESS[0],
        policy.ORIGINAL_DOWNLOAD_ACCESS[1],
        policy.ORIGINAL_DOWNLOAD_ACCESS[2],
        datetime.now(UTC) + timedelta(seconds=60),
        authority_issuer=prod_issuer,
    )
    decision, filename = original_download.download_original(
        connection,
        context,
        tenant.space_id,
        version.version_ref,
        store,
        region="shanghai",
        traveler_class="employee",
        check_authority=allow_all,
        check_final_authority=allow_all,
    )
    assert decision.status == "succeeded"
    assert filename == "original.md"
    receipt = connection.execute(
        "SELECT request_id FROM thalion.original_download_receipt WHERE org_id = %s AND request_id = %s",
        (tenant.org_id, req_id),
    ).fetchone()
    assert receipt == (req_id,)

    wrong_issuer_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, wrong_issuer_req, tenant.other_actor_id, None, "prod-orig-client",
            policy.ORIGINAL_DOWNLOAD_ACCESS[0], policy.ORIGINAL_DOWNLOAD_ACCESS[2], BEFORE, 1,
            space_id=tenant.space_id, ingress="http",
        ),
    )
    wrong_context = replace(context, request_id=wrong_issuer_req, authority_issuer="https://other-idp.invalid")
    denied, denied_name = original_download.download_original(
        connection,
        wrong_context,
        tenant.space_id,
        version.version_ref,
        store,
        region="shanghai",
        traveler_class="employee",
        check_authority=allow_all,
        check_final_authority=allow_all,
    )
    assert denied.status == "rejected"
    assert denied_name is None
