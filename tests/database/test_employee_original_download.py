from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access import policy
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.transport import api, evidence, local

from test_access_policy_transport import policy_path, replace_policy
from test_csv_delivery import publish_csv
from test_csv_processing import CSV, csv_cells, register_csv
from test_effectivity import BEGIN, approve
from test_employee_portal import browser, find_travel, load_credential, loopback_page
from test_evidence_transport import bearer, evidence_transport, private_json, rpc, transport
from test_evidence import claim, create_evidence_db, evidence_db, review
from test_holds import CAPABILITY as HOLD_CAPABILITY, decide as decide_hold
from test_identity import migrate_to_revision, space
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_sources import request_for
from test_travel_search import SEARCH_FIELDS, corpus


OPERATION = "download_original"
ORIGINAL = "# 上海\n\n上海住宿限额。\n".encode()


def download_path(version):
    return f"/employee/originals/{version.version_ref}"


def test_employee_original_requires_credentials(transport, corpus):
    client, *_ = transport
    _, version, *_ = corpus
    response = client.get(download_path(version))
    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert "Content-Disposition" not in response.headers


@pytest.fixture
def downloads(evidence_transport, corpus):
    service, db, (employee, other), credentials, live, first, _ = evidence_transport
    _, version, *_ = corpus
    connection, tenant, *_ = db
    credentials[employee] = replace(credentials[employee], operations=credentials[employee].operations | {OPERATION})
    grants = {version.version_ref, first.passage_ref}

    def check_source(credential, probe):
        decision = authority_for(live)(probe)
        if probe.context.operation != OPERATION:
            return decision
        return replace(decision, permitted_fields={
            scope: fields if scope.object_id in grants else frozenset()
            for scope, fields in decision.permitted_fields.items()
        })

    service.check_source = check_source
    with TestClient(api.create_app(service), base_url="http://127.0.0.1") as client:
        yield client, connection, tenant, service, employee, other, version, first, db, grants


def grant_original(db, version, *extra):
    _, tenant, *_ = db
    allow = policy.LocalRule(
        tenant.actor_id, OPERATION, "allow", "employee_evidence", "employee", frozenset({"original"}),
        datetime.now(UTC) - timedelta(days=1), version_ref=version.version_ref,
    )
    return set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS), allow, *extra, expected=2)


def test_passage_and_other_employee_credentials_do_not_allow_original(downloads, monkeypatch):
    client, _, _, service, employee, other, version, first, *_ = downloads
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(employee)).status_code == 200

    def must_not_read(_asset):
        pytest.fail("The original store was opened without full permission.")

    monkeypatch.setattr(service.store, "read", must_not_read)
    assert client.get(download_path(version), headers=bearer(other)).status_code == 403
    denied = client.get(download_path(version), headers=bearer(employee))
    unknown = client.get(f"/employee/originals/{uuid4()}", headers=bearer(employee))
    assert denied.status_code == unknown.status_code == 404
    assert denied.json()["error"] == unknown.json()["error"]


def test_exact_original_and_audit_are_bound_to_the_delivered_bytes(downloads):
    client, connection, _, _, employee, _, version, _, db, _ = downloads
    grant_original(db, version)
    response = client.get(download_path(version), headers=bearer(employee))
    assert response.status_code == 200
    assert response.content == ORIGINAL
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert response.headers["Content-Disposition"] == 'attachment; filename="original.md"'
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert connection.execute("""
        SELECT receipt.payload_digest, request.outcome
        FROM thalion.original_download_receipt AS receipt
        JOIN thalion.request_record AS request USING (org_id, request_id)
        WHERE request.operation = 'download_original'
    """).fetchall() == [(sha256(ORIGINAL).digest(), "succeeded")]
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_owner_can_author_exact_download_rule_and_round_trip_policy(downloads, evidence_transport):
    client, _, _, _, employee, _, version, first, db, _ = downloads
    credentials = evidence_transport[3]
    credentials[employee] = replace(
        credentials[employee], operations=credentials[employee].operations | {"read_local_policy", "replace_local_policy"},
    )
    source = db[3]
    snapshot = client.get(policy_path(source), headers=bearer(employee)).json()
    rule = {
        "subject_id": str(credentials[employee].employee_ref), "operation": OPERATION, "effect": "allow",
        "purpose": "employee_evidence", "destination": "employee", "fields": ["original"],
        "valid_from": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
    }
    command = {"expected_epoch": snapshot["safety_epoch"], "basis_id": str(uuid4())}
    assert replace_policy(client, employee, source, command | {
        "rules": [rule | {"version_id": str(first.passage_ref)}],
    }).status_code == 403
    exact = rule | {"version_id": str(version.version_ref)}
    assert replace_policy(client, employee, source, command | {"rules": [*snapshot["rules"], exact]}).status_code == 200
    current = client.get(policy_path(source), headers=bearer(employee)).json()
    assert current["rules"] == [*snapshot["rules"], exact]
    assert client.get(download_path(version), headers=bearer(employee)).content == ORIGINAL


def test_csv_entire_download_is_blocked_by_denied_cell_even_without_a_search_unit(downloads):
    client, connection, tenant, _, employee, _, _, _, db, grants = downloads
    version, _, cells = publish_csv(db)
    grants.update({version.version_ref, *(cell.passage_ref for cell in cells)})
    deny = binding(tenant.actor_id, effect="deny", passage_ref=cells[-1].passage_ref)
    revision = grant_original(db, version, deny)
    assert client.get(download_path(version), headers=bearer(employee)).status_code == 404
    rule = policy.LocalRule(
        tenant.actor_id, OPERATION, "allow", "employee_evidence", "employee", frozenset({"original"}),
        datetime.now(UTC) - timedelta(days=1), version_ref=version.version_ref,
    )
    set_rules(db, rule, expected=revision)
    available = client.get(download_path(version), headers=bearer(employee))
    assert available.content == CSV and available.headers["Content-Disposition"] == 'attachment; filename="original.csv"'
    assert connection.execute("SELECT count(*) FROM thalion.original_download_receipt").fetchone() == (1,)


@pytest.mark.parametrize("restriction", ["local_excerpt", "source_excerpt", "source_original"])
def test_version_grant_cannot_bypass_granular_restrictions(downloads, restriction, monkeypatch):
    client, connection, tenant, service, employee, _, version, first, db, grants = downloads
    rules = ()
    if restriction == "local_excerpt":
        rules = (binding(tenant.actor_id, effect="deny", passage_ref=first.passage_ref),)
    else:
        grants.remove(first.passage_ref if restriction == "source_excerpt" else version.version_ref)
    grant_original(db, version, *rules)

    def must_not_read(_asset):
        pytest.fail("A restricted file was opened before authorization.")

    monkeypatch.setattr(service.store, "read", must_not_read)
    response = client.get(download_path(version), headers=bearer(employee))
    assert response.status_code == 404
    assert "Content-Disposition" not in response.headers
    assert connection.execute("SELECT count(*) FROM thalion.original_download_receipt").fetchone() == (0,)


@pytest.mark.parametrize("dependency_down", [False, True])
def test_original_rechecked_after_read_and_denial_is_not_a_successful_receipt(downloads, dependency_down, monkeypatch):
    client, connection, _, service, employee, _, version, _, db, grants = downloads
    grant_original(db, version)
    read = service.store.read
    check_source = service.check_source
    hashes = []

    def check(credential, probe):
        hashes.append(probe.payload_sha256)
        if dependency_down and len(hashes) == 2:
            raise AuthorizationUnavailable("private detail")
        return check_source(credential, probe)

    def revoke_while_reading(asset):
        body = read(asset)
        grants.remove(version.version_ref)
        return body

    monkeypatch.setattr(service, "check_source", check)
    monkeypatch.setattr(service.store, "read", revoke_while_reading)
    response = client.get(download_path(version), headers=bearer(employee))
    assert response.status_code == (503 if dependency_down else 404)
    assert hashes == [sha256(b"").hexdigest(), sha256(ORIGINAL).hexdigest()]
    assert "Content-Disposition" not in response.headers
    assert "private detail" not in response.text
    assert connection.execute("SELECT count(*) FROM thalion.original_download_receipt").fetchone() == (0,)


def test_current_source_policy_ignores_archive_grant_and_enforces_unsynced_revocation(
    downloads, revocation_authority, evidence_transport,
):
    client, connection, tenant, service, employee, _, version, first, db, _ = downloads
    authority, source, profile = revocation_authority
    grant_original(db, version)
    employee_ref = evidence_transport[3][employee].employee_ref
    grant = {str(employee_ref): [str(version.version_ref)]}
    private_json(profile.root / "archive-grants.json", grant)
    private_json(profile.root / "pdf-page-grants.json", grant)
    service.check_source = profile.check_source
    assert client.get(download_path(version), headers=bearer(employee)).status_code == 404
    private_json(profile.root / "original-download-grants.json", grant)
    assert client.get(download_path(version), headers=bearer(employee)).content == ORIGINAL
    source_revocations.revoke(
        authority, source.authority_ref, tenant.space_ref, employee_ref, first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    assert client.get(download_path(version), headers=bearer(employee)).status_code == 404
    assert connection.execute("SELECT count(*) FROM thalion.original_download_receipt").fetchone() == (1,)
    tools = rpc(client, employee, "tools/list").json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == {"search", "read_passage"}


def test_independent_revocation_cannot_commit_between_final_check_and_dispatch(
    downloads, revocation_authority, evidence_transport, monkeypatch,
):
    client, _, tenant, service, employee, _, version, first, db, _ = downloads
    authority, source, profile = revocation_authority
    grant_original(db, version)
    employee_ref = evidence_transport[3][employee].employee_ref
    private_json(profile.root / "original-download-grants.json", {str(employee_ref): [str(version.version_ref)]})
    service.check_source = profile.check_source
    service.pin_original_source = profile.check_pinned_original
    generation = []

    def revoke_at_send():
        if not generation:
            generation.append(0)
            authority.execute("SET lock_timeout = '100ms'")
            with pytest.raises(errors.LockNotAvailable):
                source_revocations.revoke(
                    authority, source.authority_ref, tenant.space_ref, employee_ref, first.passage_ref,
                    "evidence", basis_ref=uuid4(),
                )
        return datetime.now(UTC)

    monkeypatch.setattr(api, "release_time", revoke_at_send)
    assert client.get(download_path(version), headers=bearer(employee)).content == ORIGINAL
    assert generation == [0]
    assert source_revocations.revoke(
        authority, source.authority_ref, tenant.space_ref, employee_ref, first.passage_ref,
        "evidence", basis_ref=uuid4(),
    ).generation == 1
    assert client.get(download_path(version), headers=bearer(employee)).status_code == 404


def test_source_grant_capacity_covers_more_than_512_cells(downloads, evidence_transport, tmp_path_factory):
    client, connection, tenant, service, employee, _, _, _, db, _ = downloads
    payload = ("编号,限额（元/人·晚）,例外\r\n" + "".join(f"{row},600,无\r\n" for row in range(171))).encode()
    version = register_csv(db, payload=payload, key="large-csv", object_key="large-csv")
    run = processing.process_evidence_job(connection, claim(db), service.store)
    review(db, run)
    approve(connection, tenant, version, BEGIN)
    cells = [str(cell.passage_ref) for cell in csv_cells(db, version)]
    assert len(cells) == 513
    grant_original(db, version)
    profile_root = tmp_path_factory.mktemp("original-large-csv")
    profile_root.chmod(0o700)
    employee_ref = str(evidence_transport[3][employee].employee_ref)
    private_json(profile_root / "credentials.json", [])
    private_json(profile_root / "source-grants.json", {employee_ref: cells})
    private_json(profile_root / "original-download-grants.json", {employee_ref: [str(version.version_ref)]})
    profile = local.LocalProfile(profile_root)
    service.check_source = profile.check_source
    assert client.get(download_path(version), headers=bearer(employee)).content == payload
    private_json(profile_root / "source-grants.json", {employee_ref: cells[:-1]})
    assert client.get(download_path(version), headers=bearer(employee)).status_code == 404


def test_original_cannot_cross_space(downloads, evidence_transport):
    client, connection, tenant, _, employee, _, version, _, db, _ = downloads
    grant_original(db, version)
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id, name="Other test space")
    credentials = evidence_transport[3]
    credentials[employee] = replace(credentials[employee], space_ref=other_space)
    response = client.get(download_path(version), headers=bearer(employee))
    assert response.status_code == 404
    assert "Content-Disposition" not in response.headers


def test_version_hold_during_read_blocks_original_without_receipt(downloads, evidence_transport, monkeypatch):
    client, connection, _, service, employee, custodian, version, _, db, _ = downloads
    grant_original(db, version)
    credentials = evidence_transport[3]
    credentials[custodian] = replace(credentials[custodian], operations=credentials[custodian].operations | {HOLD_CAPABILITY})
    read = service.store.read

    def hold_while_reading(asset):
        body = read(asset)
        with TestClient(api.create_app(service), base_url="http://127.0.0.1") as custodian_client:
            assert decide_hold(custodian_client, custodian, version.version_ref).json()["state"] == "held"
        return body

    monkeypatch.setattr(service.store, "read", hold_while_reading)
    assert client.get(download_path(version), headers=bearer(employee)).status_code == 404
    assert connection.execute("SELECT count(*) FROM thalion.original_download_receipt").fetchone() == (0,)


def test_upgrade_preserves_existing_passage_binding_without_granting_original(database_url, tmp_path):
    migrate_to_revision(database_url, "0089_docx_wiki_rebuild")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Legacy readers")
        create_evidence_db(connection, tenant, database_url, tmp_path)
        old = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "replace_local_policy")
        params = (tenant.org_id, tenant.space_id, tenant.actor_id, old.request_id, uuid4())
        with connection.transaction():
            source, = connection.execute("SELECT source_id FROM thalion.source").fetchone()
            connection.execute("""
                INSERT INTO thalion.policy_revision (org_id, space_id, source_id, revision, actor_id, request_id, basis_ref, binding_count)
                VALUES (%s, %s, %s, 2, %s, %s, %s, 1)
            """, (*params[:2], source, *params[2:]))
            connection.execute("""
                INSERT INTO thalion.permission_binding (
                    org_id, space_id, source_id, revision, subject_id, operation, effect, purpose, destination, fields, valid_from
                ) VALUES (%s, %s, %s, 2, %s, 'read_passage', 'allow', 'employee_evidence', 'employee', ARRAY['excerpt'], now())
            """, (*params[:2], source, params[2]))
            connection.execute("UPDATE thalion.source SET local_policy_revision = 2 WHERE source_id = %s", (source,))
        assert upgrade(database_url) == ["0113_source_connector_cursor"]
        assert connection.execute("""
            SELECT operation, effect, fields, version_ref FROM thalion.permission_binding
        """).fetchall() == [("read_passage", "allow", ["excerpt"], None)]


def test_service_refuses_start_before_original_download_migration(database_url, tmp_path, monkeypatch, capsys):
    migrate_to_revision(database_url, "0089_docx_wiki_rebuild")
    tmp_path.chmod(0o700)
    (tmp_path / "originals").mkdir(mode=0o700)
    private_json(tmp_path / "credentials.json", [])
    private_json(tmp_path / "source-grants.json", {})
    monkeypatch.setenv("THALION_DATABASE_URL", database_url)
    monkeypatch.delenv("THALION_SOURCE_AUTHORITY_URL", raising=False)
    monkeypatch.delenv("THALION_SOURCE_AUTHORITY_REF", raising=False)
    monkeypatch.setattr("sys.argv", ["thalion-serve", "--profile", str(tmp_path)])
    starts = []
    monkeypatch.setattr(local.uvicorn, "run", lambda app, **_: starts.append(app))
    assert local.main() == 1
    assert "共享迁移" in capsys.readouterr().err
    assert starts == []
    upgrade(database_url)
    assert local.main() == 0 and len(starts) == 1


def test_browser_downloads_exact_original_only_on_click(browser, downloads):
    _, _, _, service, employee, _, version, _, db, _ = downloads
    grant_original(db, version)
    with loopback_page(browser, service) as (page, _, _):
        requests = []
        page.on("request", lambda request: requests.append(request.url) if "/employee/originals/" in request.url else None)
        page.set_viewport_size({"width": 390, "height": 844})
        load_credential(page, employee)
        find_travel(page)
        page.get_by_role("button", name="核对原文：住宿标准").click()
        button = page.get_by_role("button", name="下载完整原件")
        assert requests == []
        with page.expect_download() as result:
            button.click(timeout=3000)
        download = result.value
        assert download.suggested_filename == "original.md"
        assert download.path().read_bytes() == ORIGINAL
        assert len(requests) == 1
        assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")


@pytest.mark.parametrize("event", ["switch_employee", "pagehide"])
def test_browser_does_not_save_late_attachment(browser, downloads, event):
    from playwright.sync_api import expect

    _, _, _, service, employee, other, version, _, db, _ = downloads
    grant_original(db, version)
    with loopback_page(browser, service) as (page, _, _):
        page.evaluate("""() => {
            const fetchReal = window.fetch;
            window.fetch = async (url, options) => {
                if (!url.startsWith('/employee/originals/')) return fetchReal(url, options);
                const response = await fetchReal(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestAttachment = resolve;
                    document.body.dataset.downloadReady = 'true';
                });
                return response;
            };
            const create = URL.createObjectURL;
            URL.createObjectURL = blob => {
                document.body.dataset.attachmentCreated = 'true';
                return create(blob);
            };
        }""")
        load_credential(page, employee)
        find_travel(page)
        page.get_by_role("button", name="核对原文：住宿标准").click()
        page.get_by_role("button", name="下载完整原件").click(timeout=3000)
        expect(page.locator("body")).to_have_attribute("data-download-ready", "true")
        if event == "switch_employee":
            page.get_by_role("button", name="更换凭据").click()
            load_credential(page, other)
        else:
            page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'))")
        page.evaluate("""async () => {
            window.releaseTestAttachment();
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        }""")
        assert page.locator("body").get_attribute("data-attachment-created") is None
