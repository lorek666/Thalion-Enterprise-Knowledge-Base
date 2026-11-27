from hashlib import sha256
from io import BytesIO
import json
from uuid import uuid4
from zipfile import ZipFile

import pytest

from enterprise_kb.modules.evidence.processing import process_markdown_job
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job
from enterprise_kb.transport.local import LocalProfile

from test_disposition_cases import candidate
from test_disposition_verification import original
from test_evidence import approved, claim, evidence_db, review
from test_evidence_transport import evidence_transport, private_json, transport
from test_original_export import approve, archive_fixture, command, request
from test_persisted_access import authority_for
from test_runtime import runtime_db
from test_travel_search import corpus, publish

SCOPE = "original_and_transcript"


@pytest.fixture
def transcript(archive_fixture):
    _, db, *_ = archive_fixture
    payload = b"# Travel\r\n\r\nSynthetic allowance.\r\n\r\nAn uncited exception.\r\n"
    version, _, run = publish(db, "archive-transcript", "合成转录档案", payload)
    passages = approved(db, version)
    assert len(passages) == 2
    return archive_fixture, version, run, passages


def test_transcript_archive_requires_every_separate_grant_and_preserves_exact_locations(transcript, tmp_path_factory):
    (client, db, owner, reviewer, service, _, _), version, run, passages = transcript
    connection, *_ = db
    root = tmp_path_factory.mktemp("transcript-archive-profile")
    root.chmod(0o700)
    employee = str(service.verify_token(owner).employee_ref)
    private_json(root / "credentials.json", [])
    private_json(root / "source-grants.json", {employee: [str(part.passage_ref) for part in passages]})
    private_json(root / "archive-grants.json", {employee: [str(version.version_ref)]})
    profile = LocalProfile(root)
    service.check_archive_source = profile.check_archive_source
    requested = request(client, owner, version, scope=SCOPE)
    assert requested.status_code == 200, requested.text
    export_id = requested.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    key = str(uuid4())
    assert command(client, owner, uri, key=key).status_code == 403
    grants = root / "transcript-archive-grants.json"
    private_json(grants, {employee: {str(passages[0].passage_ref): passages[0].revision}})
    assert command(client, owner, uri, key=key).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(grants, {employee: {str(part.passage_ref): part.revision + 1 for part in passages}})
    assert command(client, owner, uri, key=key).status_code == 403
    private_json(grants, {employee: {str(part.passage_ref): part.revision for part in passages}})
    sealed = command(client, owner, uri, key=key)
    assert sealed.status_code == 200 and sealed.json()["scope"] == SCOPE and sealed.json()["restorable"] is False
    assert "uncited exception" not in sealed.text
    archive_bytes, = connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    with ZipFile(BytesIO(archive_bytes)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        transcription = json.loads(archive.read("transcription.json"))
        original_bytes = original(db, version).read_bytes()
        assert archive.read("original.md") == original_bytes
        assert manifest["scope"] == SCOPE
        assert manifest["transcription_sha256"] == sha256(archive.read("transcription.json")).hexdigest()
        assert transcription["run_id"] == str(run.run_ref)
        assert transcription["manifest_sha256"] == run.manifest_digest.hex()
        assert len(transcription["passages"]) == len(passages)
        for entry, part in zip(transcription["passages"], passages, strict=True):
            assert (entry["passage_id"], entry["excerpt_revision"]) == (str(part.passage_ref), part.revision)
            assert (entry["byte_start"], entry["byte_end"]) == (part.byte_start, part.byte_end)
            excerpt = original_bytes[part.byte_start:part.byte_end]
            assert archive.read(entry["member"]) == excerpt
            assert entry["sha256"] == sha256(excerpt).hexdigest() == part.digest.hex()
    private_json(grants, {employee: {str(passages[0].passage_ref): passages[0].revision}})
    assert command(client, owner, uri, key=key).status_code == 403


def test_quarantine_at_final_authorization_invalidates_approved_transcript_scope(transcript):
    (client, db, owner, reviewer, service, _, _), version, run, _ = transcript
    connection, *_ = db
    export_id = request(client, owner, version, scope=SCOPE).json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    changes = []

    def check(credential, probe):
        changes.append(review(db, run, decision="quarantined"))
        return authority_for({db[1].actor_id})(probe)

    service.check_archive_source = check
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert len(changes) == 1
    assert request(client, owner, version, scope=SCOPE).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_transcript_without_conditional_source_permission_cannot_be_downgraded(transcript):
    (client, db, owner, reviewer, service, _, _), version, _, _ = transcript
    export_id = request(client, owner, version, scope=SCOPE).json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    assert command(client, owner, f"/{export_id}/seal", scope="original_only").status_code == 400
    assert command(client, owner, f"/{uuid4()}/seal").status_code == 403


def test_new_processing_run_never_inherits_an_older_transcript_approval(transcript):
    (client, db, owner, reviewer, _, _, _), version, _, _ = transcript
    connection, tenant, _, _, store = db
    export_id = request(client, owner, version, scope=SCOPE).json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision WHERE configuration_revision = 1
    """)
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 2))
    replacement = process_markdown_job(connection, claim(db), store)
    uri = f"/{export_id}/seal"
    assert request(client, owner, version, scope=SCOPE).status_code == 409
    assert command(client, owner, uri).status_code == 409
    review(db, replacement)
    assert command(client, owner, uri).status_code == 409
    fresh = request(client, owner, version, scope=SCOPE).json()["export_id"]
    assert approve(client, reviewer, fresh).status_code == 200
    assert command(client, owner, f"/{fresh}/seal").status_code == 200
    content, = connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    with ZipFile(BytesIO(content)) as archive:
        assert {part["excerpt_revision"] for part in json.loads(archive.read("transcription.json"))["passages"]} == {2}
