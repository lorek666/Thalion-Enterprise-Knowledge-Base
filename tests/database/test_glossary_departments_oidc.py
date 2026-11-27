from base64 import urlsafe_b64encode
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
import json
import os
from secrets import token_urlsafe
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import httpx2
import jwt
from psycopg import errors
import pytest
import uvicorn

from enterprise_kb.modules import glossary
from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.modules.sources import departments, effectivity, registry
from enterprise_kb.runtime.jobs import claim_job
from enterprise_kb.transport import api, evidence
from enterprise_kb.transport.oidc_sso import OidcSsoConfig, OidcSsoManager

from test_employee_portal import browser, loopback_page
from test_evidence import create_evidence_db
from test_evidence_transport import bearer
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import LEASE_FOR, open_database, runtime_db
from test_sources import request_for
from test_travel_search import SEARCH_FIELDS


BUSINESS_DAY = date(2026, 11, 20)


def _publish_markdown(db, *, key: str, title: str, content: str):
    connection, tenant, _, source_ref, store = db
    raw = content.encode("utf-8")
    reg_ctx = request_for(connection, tenant, tenant.worker_id, str(uuid4()), "register_version")
    version = registry.register_synthetic_version(
        connection,
        reg_ctx,
        registry.SourceVersion(
            tenant.space_id,
            source_ref,
            1,
            key,
            "v1",
            "rev-1",
            title,
            "1.0",
            sha256(raw).digest(),
        ),
        raw,
        store,
    )
    lease = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert lease is not None
    run = processing.process_evidence_job(connection, lease, store)
    assert run.outcome == "pending_review"
    q_ctx = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "decide_evidence_quality")
    processing.decide_quality(connection, q_ctx, tenant.space_id, run.run_ref, run.manifest_digest, "approved", uuid4())
    eff_ctx = request_for(connection, tenant, tenant.other_actor_id, str(uuid4()), effectivity.APPROVE)
    effectivity.approve_synthetic_rule(
        connection,
        eff_ctx,
        tenant.space_id,
        version.version_ref,
        effectivity.Approval(BUSINESS_DAY - timedelta(days=10), None, "shanghai", "employee", uuid4()),
    )
    lexical.build_index(connection, store, tenant.space_ref, version.version_ref, run.run_ref)
    passages = processing.list_approved_passages(connection, tenant.org_id, tenant.space_id, version.version_ref)
    return version, passages[0]


def _make_rsa_jwk():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk_dict["kid"] = "thalion-test-key-1"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return private_key, {"keys": [jwk_dict]}


@pytest.fixture
def stage4_env(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    db = create_evidence_db(connection, tenant, database_url, tmp_path)
    connection, tenant, database_url, source_ref, store = db

    # Create 4 documents:
    # 1) finance doc 1 (lodging)
    # 2) finance doc 2 (meal allowance)
    # 3) hr doc 1 (annual leave)
    # 4) unassigned doc whose title says "财务部草稿" (must NEVER be inferred into finance!)
    fin1_ver, fin1_p = _publish_markdown(db, key="fin-1", title="上海住宿标准", content="# 上海住宿\n\n上海住宿限额每晚 680 元。\n")
    fin2_ver, fin2_p = _publish_markdown(db, key="fin-2", title="出差餐饮补贴", content="# 餐饮\n\n出差餐饮补贴每日 120 元。\n")
    hr1_ver, hr1_p = _publish_markdown(db, key="hr-1", title="员工年假规定", content="# 年假\n\n员工每年享有 10 天带薪年假。\n")
    unassigned_ver, unassigned_p = _publish_markdown(
        db, key="unassigned-1", title="财务部草稿通知", content="# 财务部草稿\n\n住宿标准讨论草稿。\n"
    )

    # Actor A (owner): full search access to all 4 docs + glossary & department management
    # Actor B (restricted employee): ONLY allowed fin1_p! (NOT fin2_p, NOT hr1_p, NOT unassigned_p)
    set_rules(
        db,
        replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        replace(binding(tenant.other_actor_id, passage_ref=fin1_p.passage_ref), fields=SEARCH_FIELDS),
    )

    refs = {}
    for pid in (tenant.actor_id, tenant.other_actor_id):
        refs[pid] = connection.execute(
            "SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s",
            (pid,),
        ).fetchone()[0]

    owner_token = token_urlsafe(32)
    restricted_token = token_urlsafe(32)
    now = datetime.now(UTC)
    credentials = {
        owner_token: evidence.SyntheticCredential(
            refs[tenant.actor_id],
            tenant.space_ref,
            "synthetic-ui",
            "shanghai",
            "employee",
            frozenset({"search", "read_passage"} | glossary.OPERATIONS | departments.OPERATIONS),
            now + timedelta(minutes=15),
        ),
        restricted_token: evidence.SyntheticCredential(
            refs[tenant.other_actor_id],
            tenant.space_ref,
            "synthetic-ui",
            "shanghai",
            "employee",
            frozenset({"search", "read_passage"}),
            now + timedelta(minutes=15),
        ),
    }
    live = {tenant.actor_id, tenant.other_actor_id}
    service = evidence.EvidenceService(
        lambda: open_database(database_url),
        credentials.get,
        lambda _cred, probe: authority_for(live)(probe),
        store,
    )
    return {
        "db": db,
        "service": service,
        "owner_token": owner_token,
        "restricted_token": restricted_token,
        "owner_ref": refs[tenant.actor_id],
        "restricted_ref": refs[tenant.other_actor_id],
        "docs": {
            "fin1": (fin1_ver, fin1_p),
            "fin2": (fin2_ver, fin2_p),
            "hr1": (hr1_ver, hr1_p),
            "unassigned": (unassigned_ver, unassigned_p),
        },
    }


def test_glossary_expansion_and_explicit_department_permission_counts(stage4_env):
    service = stage4_env["service"]
    connection, tenant, *_ = stage4_env["db"]
    owner = stage4_env["owner_token"]
    restricted = stage4_env["restricted_token"]
    docs = stage4_env["docs"]

    with TestClient(api.create_app(service), base_url="http://127.0.0.1") as client:
        # 1. Assign explicit departments for fin1, fin2, hr1; leave unassigned_ver without department
        for key_name, dept_code, dept_name in (
            ("fin1", "finance", "财务部"),
            ("fin2", "finance", "财务部"),
            ("hr1", "hr", "人力资源部"),
        ):
            doc_ref = docs[key_name][0].document_ref
            r = client.post(
                f"/internal/sources/documents/{doc_ref}/department",
                headers=bearer(owner) | {"Idempotency-Key": f"dept-{key_name}"},
                json={"department_code": dept_code, "department_name": dept_name},
            )
            assert r.status_code == 200
            assert r.json()["department_code"] == dept_code
            assert r.json()["department_name"] == dept_name

        # Non-owner cannot modify document department
        denied_dept = client.post(
            f"/internal/sources/documents/{docs['fin1'][0].document_ref}/department",
            headers=bearer(restricted) | {"Idempotency-Key": "dept-denied"},
            json={"department_code": "hr", "department_name": "人力资源部"},
        )
        assert denied_dept.status_code == 403

        # Immutable audit table rejects modification
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            with connection.transaction():
                connection.execute("DELETE FROM thalion.document_department_event")

        # 2. Permission-scoped department options:
        # Owner sees finance=2, hr=1 (NOT 3 for finance even though unassigned doc title contains "财务部"!)
        owner_depts = client.get(f"/employee/department-options?business_date={BUSINESS_DAY}", headers=bearer(owner))
        assert owner_depts.status_code == 200
        assert owner_depts.json()["departments"] == [
            {"department_code": "finance", "department_name": "财务部", "document_count": 2},
            {"department_code": "hr", "department_name": "人力资源部", "document_count": 1},
        ]

        # Restricted employee only has access to fin1 -> sees ONLY finance=1, hr completely invisible!
        restr_depts = client.get(f"/employee/department-options?business_date={BUSINESS_DAY}", headers=bearer(restricted))
        assert restr_depts.status_code == 200
        assert restr_depts.json()["departments"] == [
            {"department_code": "finance", "department_name": "财务部", "document_count": 1},
        ]

        # 3. Department filter in /v1/search + permission-scoped department_facets
        # Search "住宿" filtered to finance -> only fin1 (unassigned "财务部草稿" is NOT returned!)
        r_fin = client.post(
            "/v1/search",
            headers=bearer(owner),
            json={
                "query": "住宿",
                "business_date": BUSINESS_DAY.isoformat(),
                "departments": ["finance"],
                "include_department_facets": True,
            },
        )
        assert r_fin.status_code == 200
        body_fin = r_fin.json()
        assert [p["passage_id"] for p in body_fin["passages"]] == [str(docs["fin1"][1].passage_ref)]
        assert body_fin["department_facets"] == [
            {"department_code": "finance", "department_name": "财务部", "document_count": 1},
        ]

        # Restricted employee searching "住宿" with finance filter gets fin1; with hr filter gets no_evidence
        r_hr_restr = client.post(
            "/v1/search",
            headers=bearer(restricted),
            json={
                "query": "年假",
                "business_date": BUSINESS_DAY.isoformat(),
                "departments": ["hr"],
                "include_department_facets": True,
            },
        )
        assert r_hr_restr.status_code == 200
        assert r_hr_restr.json()["status"] == "no_evidence"
        assert r_hr_restr.json()["department_facets"] == []

        # 4. Business Glossary CRUD + Query Synonym Expansion + Audit Immutability
        # Before adding glossary, searching "差补" matches nothing
        before_syn = client.post(
            "/v1/search",
            headers=bearer(owner),
            json={"query": "差补", "business_date": BUSINESS_DAY.isoformat()},
        )
        assert before_syn.status_code == 200 and before_syn.json()["passages"] == []

        # Create glossary entry linking "住宿限额" <-> ["差补", "房补"]
        g_create = client.post(
            "/internal/glossary",
            headers=bearer(owner) | {"Idempotency-Key": "gloss-1"},
            json={
                "term": "住宿限额",
                "synonyms": ["差补", "房补"],
                "definition": "员工因公出差每晚报销住宿费用上限。",
            },
        )
        assert g_create.status_code == 200
        entry_id = g_create.json()["entry"]["entry_id"]

        # Duplicate normalized term returns 409 conflict
        g_dup = client.post(
            "/internal/glossary",
            headers=bearer(owner) | {"Idempotency-Key": "gloss-dup"},
            json={"term": "住宿限额", "synonyms": [], "definition": "重复词条"},
        )
        assert g_dup.status_code == 409

        # Now searching "差补" automatically expands to "住宿限额" and hits fin1!
        after_syn = client.post(
            "/v1/search",
            headers=bearer(owner),
            json={"query": "差补", "business_date": BUSINESS_DAY.isoformat(), "include_department_facets": True},
        )
        assert after_syn.status_code == 200
        assert any(p["passage_id"] == str(docs["fin1"][1].passage_ref) for p in after_syn.json()["passages"])

        # Add HR synonym "PTO" -> "年假" and verify restricted employee STILL cannot see HR doc!
        g_hr = client.post(
            "/internal/glossary",
            headers=bearer(owner) | {"Idempotency-Key": "gloss-2"},
            json={"term": "年假", "synonyms": ["PTO"], "definition": "员工带薪年休假"},
        )
        assert g_hr.status_code == 200
        owner_pto = client.post(
            "/v1/search",
            headers=bearer(owner),
            json={"query": "PTO", "business_date": BUSINESS_DAY.isoformat()},
        )
        assert owner_pto.status_code == 200
        assert any(p["passage_id"] == str(docs["hr1"][1].passage_ref) for p in owner_pto.json()["passages"])
        restr_pto = client.post(
            "/v1/search",
            headers=bearer(restricted),
            json={"query": "PTO", "business_date": BUSINESS_DAY.isoformat()},
        )
        assert restr_pto.status_code == 200 and restr_pto.json()["passages"] == []

        # Deactivate glossary entry -> synonym expansion stops immediately!
        g_off = client.post(
            f"/internal/glossary/{entry_id}/status",
            headers=bearer(owner) | {"Idempotency-Key": "gloss-off"},
            json={"status": "inactive"},
        )
        assert g_off.status_code == 200 and g_off.json()["entry"]["status"] == "inactive"
        after_off = client.post(
            "/v1/search",
            headers=bearer(owner),
            json={"query": "差补", "business_date": BUSINESS_DAY.isoformat()},
        )
        assert after_off.status_code == 200 and after_off.json()["passages"] == []

        # Glossary audit table is strictly immutable
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            with connection.transaction():
                connection.execute("UPDATE thalion.glossary_audit_event SET term = 'tampered'")


def test_oidc_pkce_sso_security_and_chrome_e2e(stage4_env):
    service = stage4_env["service"]
    owner_token = stage4_env["owner_token"]
    owner_ref = stage4_env["owner_ref"]
    docs = stage4_env["docs"]

    private_key, jwks_payload = _make_rsa_jwk()
    issuer = "https://idp.example.test"
    client_id = "thalion-web"
    issued_codes: dict[str, dict] = {}

    def mock_idp_handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/jwks":
            return httpx2.Response(200, json=jwks_payload)
        if request.url.path == "/token":
            form = parse_qs(request.content.decode("utf-8"))
            code = form.get("code", [""])[0]
            verifier = form.get("code_verifier", [""])[0]
            record = issued_codes.pop(code, None)
            if record is None:
                return httpx2.Response(400, json={"error": "invalid_grant"})
            computed_challenge = urlsafe_b64encode(sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
            if computed_challenge != record["code_challenge"]:
                return httpx2.Response(400, json={"error": "invalid_pkce"})
            now_ts = int(datetime.now(UTC).timestamp())
            id_token = jwt.encode(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "sub": str(owner_ref),
                    "nonce": record["nonce"],
                    "iat": now_ts,
                    "exp": now_ts + 300,
                },
                private_key,
                algorithm="RS256",
                headers={"kid": "thalion-test-key-1"},
            )
            return httpx2.Response(200, json={"access_token": owner_token, "id_token": id_token, "token_type": "Bearer"})
        return httpx2.Response(404)

    sso_config = OidcSsoConfig(
        issuer=issuer,
        authorization_endpoint=f"{issuer}/authorize",
        token_endpoint=f"{issuer}/token",
        jwks_url=f"{issuer}/jwks",
        client_id=client_id,
        redirect_uri="http://127.0.0.1/auth/oidc/callback",
        allow_http_loopback=True,
    )
    sso_manager = OidcSsoManager(sso_config, transport=httpx2.MockTransport(mock_idp_handler))

    with TestClient(api.create_app(service, oidc_sso=sso_manager), base_url="http://127.0.0.1") as client:
        # Prepare department & glossary data
        client.post(
            f"/internal/sources/documents/{docs['fin1'][0].document_ref}/department",
            headers=bearer(owner_token) | {"Idempotency-Key": "sso-dept-1"},
            json={"department_code": "finance", "department_name": "财务部"},
        )
        client.post(
            "/internal/glossary",
            headers=bearer(owner_token) | {"Idempotency-Key": "sso-gloss-1"},
            json={"term": "住宿限额", "synonyms": ["差补"], "definition": "住宿费用上限"},
        )

        # 1. Status endpoint reports enabled
        st = client.get("/auth/oidc/status")
        assert st.status_code == 200 and st.json()["enabled"] is True

        # 2. Login initiates PKCE S256 & sanitizes malicious open-redirect return_to
        login = client.get("/auth/oidc/login?return_to=https://evil.example/steal", follow_redirects=False)
        assert login.status_code == 302
        auth_loc = urlparse(login.headers["location"])
        qs = parse_qs(auth_loc.query)
        assert qs["code_challenge_method"] == ["S256"]
        assert qs["client_id"] == [client_id]
        state = qs["state"][0]
        nonce = qs["nonce"][0]
        code_challenge = qs["code_challenge"][0]

        # 3. Missing CSRF cookie fails closed (400) using a separate clean client without tx cookie
        with TestClient(api.create_app(service, oidc_sso=sso_manager), base_url="http://127.0.0.1") as clean_client:
            no_cookie = clean_client.get(f"/auth/oidc/callback?code=abc&state={state}", follow_redirects=False)
            assert no_cookie.status_code == 400

        # 4. Tampered nonce in IdP token fails closed (401)
        bad_code = "code-bad-nonce"
        issued_codes[bad_code] = {"nonce": "wrong-nonce", "code_challenge": code_challenge}
        bad_cb = client.get(f"/auth/oidc/callback?code={bad_code}&state={state}", follow_redirects=False)
        assert bad_cb.status_code == 401
        assert bad_cb.json()["error"]["code"] == "oidc_nonce_mismatch"

        # 5. Replaying already-consumed state fails closed (401)
        replay = client.get(f"/auth/oidc/callback?code=anything&state={state}", follow_redirects=False)
        assert replay.status_code in {400, 401}

        # 6. Full valid login -> callback -> single-use ticket exchange -> sanitized return_to="/"
        login2 = client.get("/auth/oidc/login?return_to=https://evil.example/steal", follow_redirects=False)
        qs2 = parse_qs(urlparse(login2.headers["location"]).query)
        good_code = "code-valid-1"
        issued_codes[good_code] = {"nonce": qs2["nonce"][0], "code_challenge": qs2["code_challenge"][0]}
        cb2 = client.get(f"/auth/oidc/callback?code={good_code}&state={qs2['state'][0]}", follow_redirects=False)
        assert cb2.status_code == 302
        loc2 = cb2.headers["location"]
        assert loc2.startswith("/#oidc_ticket=")
        ticket = loc2.split("#oidc_ticket=", 1)[1]

        ex = client.post("/auth/oidc/exchange", json={"ticket": ticket})
        assert ex.status_code == 200
        assert ex.json()["access_token"] == owner_token
        assert ex.json()["subject"] == str(owner_ref)

        # Ticket is strictly single-use
        ex_replay = client.post("/auth/oidc/exchange", json={"ticket": ticket})
        assert ex_replay.status_code == 401

    # 7. Real Chrome Browser E2E: full OIDC SSO redirect + department filter + synonym search!
    if os.environ.get("THALION_BROWSER_E2E") != "1":
        return

    from fastapi import FastAPI, Request, Response
    import socket

    with socket.socket() as sock1, socket.socket() as sock2:
        sock1.bind(("127.0.0.1", 0))
        port = sock1.getsockname()[1]
        sock2.bind(("127.0.0.1", 0))
        idp_port = sock2.getsockname()[1]

    base = f"http://127.0.0.1:{port}"
    idp_base = f"http://127.0.0.1:{idp_port}"
    sso_e2e_cfg = OidcSsoConfig(
        issuer=issuer,
        authorization_endpoint=f"{idp_base}/authorize",
        token_endpoint=f"{issuer}/token",
        jwks_url=f"{issuer}/jwks",
        client_id=client_id,
        redirect_uri=f"{base}/auth/oidc/callback",
        allow_http_loopback=True,
    )
    sso_e2e = OidcSsoManager(sso_e2e_cfg, transport=httpx2.MockTransport(mock_idp_handler))
    app = api.create_app(service, oidc_sso=sso_e2e)

    idp_app = FastAPI()

    @idp_app.get("/authorize")
    async def mock_idp_authorize(request: Request):
        code = f"e2e-{token_urlsafe(8)}"
        issued_codes[code] = {
            "nonce": request.query_params["nonce"],
            "code_challenge": request.query_params["code_challenge"],
        }
        cb_url = f"{request.query_params['redirect_uri']}?{urlencode({'code': code, 'state': request.query_params['state']})}"
        return Response(status_code=302, headers={"Location": cb_url})

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    idp_server = uvicorn.Server(uvicorn.Config(idp_app, host="127.0.0.1", port=idp_port, log_level="error"))
    thread = Thread(target=server.run, daemon=True)
    idp_thread = Thread(target=idp_server.run, daemon=True)
    thread.start()
    idp_thread.start()
    while not (server.started and idp_server.started):
        pass
    try:
        from playwright.sync_api import sync_playwright

        channel = os.environ.get("THALION_BROWSER_CHANNEL", "chrome")
        with sync_playwright() as p:
            br = p.chromium.launch(channel=channel, headless=True)
            context = br.new_context()
            page = context.new_page()
            page.goto(f"{base}/")
            page.wait_for_selector("#oidc-login-button:not([hidden])", timeout=5000)
            page.click("#oidc-login-button")
            # Auto redirects through mock IdP -> /auth/oidc/callback -> /#oidc_ticket=... -> unlocks workspace!
            page.wait_for_selector("#workspace:not([hidden])", timeout=8000)
            assert "oidc_ticket" not in page.url

            # Load permission-scoped department options
            page.fill("#business-day", BUSINESS_DAY.isoformat())
            page.click("#load-department-options")
            page.wait_for_selector("#department-options-panel:not([hidden])", timeout=5000)
            option_texts = page.locator("#department-options option").all_text_contents()
            assert any("财务部（1 份）" in t for t in option_texts)
            page.select_option("#department-options", "finance")

            # Search using business synonym "差补" under finance department!
            page.fill("#query", "差补")
            page.click('#search-form button[type="submit"]')
            page.wait_for_selector("#results li.passage", timeout=5000)
            result_text = page.locator("#results").inner_text()
            assert "上海住宿标准" in result_text
            facet_text = page.locator("#department-facet-list").inner_text()
            assert "财务部" in facet_text and "1 份" in facet_text
            br.close()
    finally:
        server.should_exit = True
        idp_server.should_exit = True
        thread.join(timeout=5)
        idp_thread.join(timeout=5)
