from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID
from zipfile import ZipFile

import psycopg
from psycopg import sql
import pytest

from enterprise_kb.database import local_connection_factory, rehearsal_marker, upgrade
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.transport.local import LocalProfile

from test_disposition_cases import candidate
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, private_json, transport
from test_original_export import approve, archive_fixture, command, request
from test_runtime import open_database, runtime_db
from test_transcript_export import transcript
from test_travel_search import corpus


SCOPE = "original_and_rebuild"


@pytest.fixture
def rebuild_bundle(transcript):
    (client, db, owner, reviewer, *_), version, run, passages = transcript
    connection, tenant, _, source_ref, _ = db
    opened = request(client, owner, version, scope=SCOPE)
    assert opened.status_code == 200, opened.text
    export_ref = opened.json()["export_id"]
    assert approve(client, reviewer, export_ref).status_code == 200
    sealed = command(client, owner, f"/{export_ref}/seal")
    assert sealed.status_code == 200, sealed.text
    summary = sealed.json()
    assert summary["scope"] == SCOPE and summary["restorable"] is False
    payload, digest = connection.execute(
        "SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package",
    ).fetchone()
    assert sha256(payload).hexdigest() == digest.hex() == summary["archive_sha256"]
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-version-rebuild.v1"
        assert manifest["restorable"] is False
    original_bytes = original(db, version).read_bytes()
    origin = (tenant.org_id, tenant.space_id, UUID(export_ref), version.version_ref)
    return origin, digest, payload, source_ref, version, run, passages, original_bytes


@pytest.fixture
def empty_rehearsal(independent_database_url):
    upgrade(independent_database_url)
    with open_database(independent_database_url) as connection:
        name = connection.info.dbname
        connection.execute(sql.SQL("ALTER DATABASE {} SET thalion.restore_rehearsal = {}").format(
            sql.Identifier(name), sql.Literal(name),
        ))
        assert connection.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
        yield connection, independent_database_url


def test_rebuild_preserves_exact_citations_without_reviving_access(rebuild_bundle, empty_rehearsal, tmp_path_factory):
    origin, digest, payload, source_ref, version, run, passages, original_bytes = rebuild_bundle
    connection, url = empty_rehearsal
    permit = archive_rehearsal.RebuildPermit(*origin, digest, connection.info.dbname)
    scratch = tmp_path_factory.mktemp("rebuild-empty")

    restored = archive_rehearsal.rebuild_version(connection, permit, payload, scratch)

    assert restored.store.read(restored.asset) == original_bytes
    assert restored.store.root == scratch.resolve()
    assert dict(connection.execute("""
        SELECT object_type, public_id FROM thalion.object_identity
        WHERE object_type IN ('source', 'document', 'document_version')
        """).fetchall()) == {
        "source": source_ref, "document": version.document_ref, "document_version": version.version_ref,
    }
    assert connection.execute("""
        SELECT identity.public_id, excerpt.excerpt_revision, passage.byte_start, passage.byte_end, excerpt.content_digest
        FROM thalion.passage AS passage
        JOIN thalion.passage_excerpt AS excerpt USING (org_id, space_id, version_id, passage_id)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
        ORDER BY passage.byte_start
        """).fetchall() == [
        (part.passage_ref, part.revision, part.byte_start, part.byte_end, part.digest) for part in passages
    ]
    assert connection.execute("""
        SELECT job.state, attempt.outcome, candidate.manifest_digest
        FROM thalion.processing_run AS candidate
        JOIN thalion.job AS job USING (org_id, job_id, generation)
        JOIN thalion.job_attempt AS attempt USING (org_id, job_id, generation)
        WHERE job.result_ref = candidate.run_ref
        """).fetchone() == ("succeeded", "succeeded", run.manifest_digest)
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.rule_effectivity").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_approval").fetchone() == (0,)
    assert connection.execute("SELECT lifecycle FROM thalion.space").fetchone() == ("archived",)
    assert rehearsal_marker(connection) == connection.info.dbname
    with pytest.raises(psycopg.OperationalError, match="rehearsal"):
        local_connection_factory(url)()


def test_rebuild_refuses_unmatched_permit_and_nonempty_target(rebuild_bundle, empty_rehearsal, tmp_path_factory):
    origin, digest, payload, *_ = rebuild_bundle
    connection, _ = empty_rehearsal
    permit = archive_rehearsal.RebuildPermit(*origin, digest, connection.info.dbname)
    scratch = tmp_path_factory.mktemp("rebuild-refused")
    for wrong in (
        replace(permit, database="another_database"), replace(permit, digest=bytes(32)),
        replace(permit, space_id=permit.space_id + 1),
    ):
        with pytest.raises(archive_rehearsal.ArchiveRejected):
            archive_rehearsal.rebuild_version(connection, wrong, payload, scratch)
    assert list(scratch.iterdir()) == []
    assert connection.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    archive_rehearsal.rebuild_version(connection, permit, payload, scratch)
    empty_store = tmp_path_factory.mktemp("rebuild-second")
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(connection, permit, payload, empty_store)
    assert list(empty_store.iterdir()) == []


def test_rebuild_rejects_mismatched_transcript_bytes_even_with_a_matching_digest(
    rebuild_bundle, empty_rehearsal, tmp_path_factory,
):
    origin, _, payload, *_ = rebuild_bundle
    connection, _ = empty_rehearsal
    altered = BytesIO()
    with ZipFile(BytesIO(payload)) as original_archive, ZipFile(altered, "w") as altered_archive:
        changed = next(name for name in original_archive.namelist() if name.startswith("transcript/"))
        for name in original_archive.namelist():
            member = original_archive.read(name)
            altered_archive.writestr(name, bytes(len(member)) if name == changed else member)
    payload = altered.getvalue()
    permit = archive_rehearsal.RebuildPermit(*origin, sha256(payload).digest(), connection.info.dbname)
    scratch = tmp_path_factory.mktemp("rebuild-inconsistent")
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(connection, permit, payload, scratch)
    assert connection.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert list(scratch.iterdir()) == []


def test_rebuild_rolls_back_when_the_reconstruction_event_cannot_commit(
    rebuild_bundle, empty_rehearsal, tmp_path_factory,
):
    origin, digest, payload, *_ = rebuild_bundle
    connection, _ = empty_rehearsal
    permit = archive_rehearsal.RebuildPermit(*origin, digest, connection.info.dbname)
    scratch = tmp_path_factory.mktemp("rebuild-rollback")
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CHECK (event_type <> 'lifecycle.synthetic_archive.rebuilt')
        """)
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(connection, permit, payload, scratch)
    assert connection.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert list(scratch.iterdir()) == []


def test_legacy_transcript_archive_is_not_a_rebuild_bundle(transcript, empty_rehearsal, tmp_path_factory):
    (client, db, owner, reviewer, *_), version, *_ = transcript
    opened = request(client, owner, version, scope="original_and_transcript")
    export_ref = opened.json()["export_id"]
    assert approve(client, reviewer, export_ref).status_code == 200
    assert command(client, owner, f"/{export_ref}/seal").status_code == 200
    payload, digest = db[0].execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    connection, _ = empty_rehearsal
    permit = archive_rehearsal.RebuildPermit(
        db[1].org_id, db[1].space_id, UUID(export_ref), version.version_ref, digest, connection.info.dbname,
    )
    scratch = tmp_path_factory.mktemp("rebuild-legacy")
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(connection, permit, payload, scratch)
    assert connection.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert list(scratch.iterdir()) == []


def test_rebuild_archive_requires_separate_metadata_and_exact_transcript_grants(transcript, tmp_path_factory):
    (client, db, owner, reviewer, service, *_), version, _, passages = transcript
    profile_dir = tmp_path_factory.mktemp("rebuild-profile")
    profile_dir.chmod(0o700)
    employee = str(service.verify_token(owner).employee_ref)
    private_json(profile_dir / "credentials.json", [])
    private_json(profile_dir / "source-grants.json", {})
    profile = LocalProfile(profile_dir)
    service.check_archive_source = profile.check_archive_source
    private_json(profile_dir / "archive-grants.json", {employee: [str(version.version_ref)]})
    transcript_grants = profile_dir / "transcript-archive-grants.json"
    private_json(transcript_grants, {employee: {str(part.passage_ref): part.revision for part in passages}})
    opened = request(client, owner, version, scope=SCOPE)
    assert opened.status_code == 200
    export_ref = opened.json()["export_id"]
    assert approve(client, reviewer, export_ref).status_code == 200
    uri = f"/{export_ref}/seal"
    assert command(client, owner, uri).status_code == 403
    private_json(profile_dir / "rebuild-archive-grants.json", {employee: [str(version.version_ref)]})
    private_json(transcript_grants, {employee: {str(passages[0].passage_ref): passages[0].revision}})
    assert command(client, owner, uri).status_code == 403
    assert db[0].execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(transcript_grants, {employee: {str(part.passage_ref): part.revision for part in passages}})
    assert command(client, owner, uri).status_code == 200


def test_approved_rebuild_scope_does_not_pick_up_changed_document_metadata(transcript):
    (client, db, owner, reviewer, *_), version, *_ = transcript
    opened = request(client, owner, version, scope=SCOPE)
    assert opened.status_code == 200
    export_ref = opened.json()["export_id"]
    assert approve(client, reviewer, export_ref).status_code == 200
    db[0].execute("""
        UPDATE thalion.document SET display_name = 'Changed after approval'
        WHERE document_id = (SELECT object_id FROM thalion.object_identity WHERE public_id = %s)
        """, (version.document_ref,))
    assert command(client, owner, f"/{export_ref}/seal").status_code == 409
    assert db[0].execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
