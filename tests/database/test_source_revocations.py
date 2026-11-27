from dataclasses import replace
from shutil import copytree
from uuid import uuid4

import psycopg
import pytest

from enterprise_kb.database import local_connection_factory, upgrade
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.transport import local

from test_archive_rule_checkpoint import endpoint
from test_disposition_cases import candidate
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, private_json, rpc, transport
from test_original_export import approve, archive_fixture, command, request
from test_persisted_access import read
from test_rule_replay import rehearsal_clone
from test_runtime import open_database, runtime_db
from test_travel_search import corpus


@pytest.fixture
def independent_authority(independent_database_url):
    upgrade(independent_database_url)
    with open_database(independent_database_url) as authority:
        yield authority, independent_database_url, endpoint(authority)


@pytest.fixture
def revocation_authority(independent_authority, evidence_transport, tmp_path):
    authority, url, authority_ref = independent_authority
    service, db, tokens, credentials, _, first, second = evidence_transport
    _, tenant, *_ = db
    source_revocations.enroll_space(authority, authority_ref, tenant.space_ref)
    source = source_revocations.SourceRevocationAuthority(lambda: open_database(url), authority_ref)
    tmp_path.chmod(0o700)
    private_json(tmp_path / "credentials.json", [])
    private_json(tmp_path / "source-grants.json", {
        str(credentials[token].employee_ref): [str(first.passage_ref), str(second.passage_ref)]
        for token in tokens
    })
    profile = local.LocalProfile(tmp_path, revocations=source)
    service.check_source = profile.check_source
    return authority, source, profile


def test_external_revocation_denies_http_and_mcp_with_unchanged_local_policy_and_grants(transport, revocation_authority):
    client, db, (employee, colleague), credentials, _, first, second = transport
    connection, tenant, *_ = db
    authority, source, profile = revocation_authority
    ref = credentials[employee].employee_ref
    citation = f"/v1/passages/{first.passage_ref}"
    assert client.get(citation, headers=bearer(employee)).status_code == 200
    assert client.get(citation, headers=bearer(colleague)).status_code == 200
    policy = connection.execute("SELECT local_policy_revision FROM thalion.source").fetchall()
    grants = (profile.root / "source-grants.json").read_bytes()

    decision = source_revocations.revoke(
        authority, source.authority_ref, tenant.space_ref, ref, first.passage_ref, "evidence", basis_ref=uuid4(),
    )

    assert client.get(citation, headers=bearer(employee)).status_code == 404
    mcp = rpc(client, employee, "tools/call", name="read_passage", arguments={"id": str(first.passage_ref)})
    assert mcp.json()["result"]["structuredContent"]["error"]["code"] == "citation_unavailable"
    search = client.post("/v1/search", headers=bearer(employee), json={"query": "上海住宿"})
    assert search.status_code == 200
    assert [part["passage_id"] for part in search.json()["passages"]] == [str(second.passage_ref)]
    assert client.get(citation, headers=bearer(colleague)).status_code == 200
    assert connection.execute("SELECT local_policy_revision FROM thalion.source").fetchall() == policy
    assert (profile.root / "source-grants.json").read_bytes() == grants
    assert authority.execute("""
        SELECT generation, decision_ref FROM thalion.source_revocation_event WHERE space_ref = %s
        """, (tenant.space_ref,)).fetchall() == [(1, decision.decision_ref)]


def test_configured_authority_fails_closed_on_outage_or_unenrolled_space(transport, evidence_transport, revocation_authority):
    client, _, (employee, _), _, _, first, _ = transport
    service, *_ = evidence_transport
    _, source, profile = revocation_authority
    citation = f"/v1/passages/{first.passage_ref}"
    assert client.get(citation, headers=bearer(employee)).status_code == 200
    with pytest.raises(AuthorizationUnavailable):
        source.snapshot(uuid4())

    def unavailable():
        raise psycopg.OperationalError("Simulated refusal.")

    broken = local.LocalProfile(profile.root, revocations=replace(source, connect=unavailable))
    service.check_source = broken.check_source
    assert client.get(citation, headers=bearer(employee)).status_code == 503
    response = client.post("/v1/search", headers=bearer(employee), json={"query": "上海住宿"})
    assert response.status_code == 503 and first.passage_ref.hex not in response.text


@pytest.mark.parametrize(("access_use", "evidence_status", "archive_status"), [
    ("evidence", 404, 200), ("archive", 200, 403),
])
def test_revocation_for_one_use_does_not_change_the_other_use_for_the_same_passage(
    archive_fixture, revocation_authority, evidence_transport, corpus, access_use, evidence_status, archive_status,
):
    client, db, owner, reviewer, service, _, _ = archive_fixture
    authority, source, profile = revocation_authority
    _, tenant, *_ = db
    _, _, _, credentials, _, first, _ = evidence_transport
    _, version, *_ = corpus
    employee_ref = credentials[owner].employee_ref
    service.check_archive_source = profile.check_archive_source
    private_json(profile.root / "archive-grants.json", {str(employee_ref): [str(version.version_ref)]})
    grant_path = profile.root / "transcript-archive-grants.json"
    private_json(grant_path, {str(employee_ref): {str(first.passage_ref): first.revision}})
    grants = grant_path.read_bytes()

    export_id = request(client, owner, version, scope="original_and_transcript").json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    key = str(uuid4())
    citation = f"/v1/passages/{first.passage_ref}"
    assert client.get(citation, headers=bearer(owner)).status_code == 200
    sealed = command(client, owner, uri, key=key)
    assert sealed.status_code == 200
    source_revocations.revoke(
        authority, source.authority_ref, tenant.space_ref, employee_ref, first.passage_ref, access_use, basis_ref=uuid4(),
    )

    assert client.get(citation, headers=bearer(owner)).status_code == evidence_status
    retried = command(client, owner, uri, key=key)
    assert retried.status_code == archive_status
    if archive_status == 200:
        assert retried.json()["package_id"] == sealed.json()["package_id"]
    assert grant_path.read_bytes() == grants


def test_startup_rejects_wrong_authority_endpoint(independent_authority, database_url, monkeypatch):
    _, url, authority_ref = independent_authority
    monkeypatch.setenv("THALION_SOURCE_AUTHORITY_REF", str(authority_ref))
    with pytest.raises(ValueError):
        local._configured_source_revocations()
    monkeypatch.setenv("THALION_SOURCE_AUTHORITY_URL", url)
    assert local._configured_source_revocations().authority_ref == authority_ref
    upgrade(database_url)
    monkeypatch.setenv("THALION_SOURCE_AUTHORITY_URL", database_url)
    with pytest.raises(AuthorizationUnavailable):
        local._configured_source_revocations()


def test_revocation_history_rejects_rewrites_and_bulk_removal(revocation_authority, evidence_transport):
    authority, source, _ = revocation_authority
    _, db, (employee, _), credentials, _, first, _ = evidence_transport
    _, tenant, *_ = db
    ref = credentials[employee].employee_ref
    decision = source_revocations.revoke(
        authority, source.authority_ref, tenant.space_ref, ref, first.passage_ref, "evidence", basis_ref=uuid4(),
    )
    retry = source_revocations.revoke(
        authority, source.authority_ref, tenant.space_ref, ref, first.passage_ref, "evidence", basis_ref=decision.basis_ref,
    )
    assert retry == decision
    for statement in (
        "UPDATE thalion.source_revocation_event SET basis_ref = gen_random_uuid()",
        "DELETE FROM thalion.source_revocation_event",
        "TRUNCATE thalion.source_revocation_event",
        "TRUNCATE thalion.source_revocation_stream, thalion.source_revocation_event",
    ):
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            authority.execute(statement)
    assert source.snapshot(tenant.space_ref).decisions == (decision,)


def test_old_snapshot_with_an_independent_live_authority_never_uses_its_stale_grant(
    revocation_authority, evidence_transport, postgres_server, tmp_path_factory,
):
    authority, source, profile = revocation_authority
    _, db, (employee, _), credentials, _, first, second = evidence_transport
    primary, tenant, primary_url, source_ref, store = db
    scratch = tmp_path_factory.mktemp("source-revocation-rehearsal")
    staged_store = SyntheticOriginalStore(copytree(store.root, scratch / "originals"))
    credential = credentials[employee]
    with rehearsal_clone(primary, primary_url, postgres_server) as (_, target, target_url):
        staged_db = (target, tenant, target_url, source_ref, staged_store)
        live_authority = lambda probe: profile.check_source(credential, probe)
        assert read(staged_db, first, tenant.actor_id, live_authority).payload is not None
        decision = source_revocations.revoke(
            authority, source.authority_ref, tenant.space_ref,
            credential.employee_ref, first.passage_ref, "evidence", basis_ref=uuid4(),
        )
        assert read(staged_db, first, tenant.actor_id, live_authority).payload is None
        assert read(staged_db, second, tenant.actor_id, live_authority).payload is not None
        assert target.execute("SELECT count(*) FROM thalion.source_revocation_event").fetchone() == (0,)
        assert source.snapshot(tenant.space_ref).generation == decision.generation
        with pytest.raises(psycopg.OperationalError):
            local_connection_factory(target_url)()
