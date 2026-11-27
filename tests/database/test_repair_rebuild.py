from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import psycopg
import pytest

from enterprise_kb.database import local_connection_factory
from enterprise_kb.modules.evidence import quality_restrictions
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.sources import restriction_log, source_revocations

from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import archive_subject, rebuild, rule_log
from test_archive_rule_checkpoint import restore_source_authority
from test_disposition_cases import candidate
from test_evidence import evidence_db, review
from test_evidence_transport import evidence_transport, transport
from test_original_export import approve, archive_fixture, command, request
from test_repair_archive import repaired_archive
from test_rule_restriction_log import stop
from test_runtime import runtime_db
from test_sources import register
from test_travel_search import corpus


@pytest.fixture
def repair_bundle(repaired_archive, empty_rehearsal, rule_log, restore_source_authority, tmp_path_factory):
    client, db, owner, reviewer, _, version, *_ = repaired_archive
    authority, tenant, _, source, store = db
    unrelated = register(authority, tenant, source, store, key="repair-rebuild-control", object_key="another-rule")
    decision = stop(authority, tenant, unrelated.version_ref)
    assert restriction_log.deliver_pending(authority, rule_log, tenant.org_id).confirmed == (decision,)
    assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).status == "ok"
    response = request(client, owner, version, scope="original_and_rebuild")
    assert response.status_code == 200, response.json()
    export = response.json()["export_id"]
    assert approve(client, reviewer, export).status_code == 200
    sealed = command(client, owner, f"/{export}/seal")
    assert sealed.status_code == 200, sealed.json()
    assert sealed.json()["restorable"] is False
    payload, = authority.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    target, url = empty_rehearsal
    permit = archive_rehearsal.RebuildPermit(
        tenant.org_id, tenant.space_id, UUID(export), version.version_ref, sha256(payload).digest(), target.info.dbname,
    )
    scratch = tmp_path_factory.mktemp("repair-rebuild")
    return target, url, permit, payload, scratch, restore_source_authority[1], rule_log


def test_repair_rebuild_preserves_exact_archive_without_live_approvals(repair_bundle, repaired_archive):
    target, url, permit, payload, scratch, *_ = repair_bundle
    _, db, _, _, _, version, current, *_ = repaired_archive
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        history = json.loads(archive.read("repair-history.json"))
        expected_bytes = archive.read("original.md")
    assert manifest["format"] == "thalion.synthetic-version-rebuild.v2"

    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(target, permit, payload, scratch)
    rebuilt = rebuild(repair_bundle, db[0])

    assert rebuilt.store.read(rebuilt.asset) == expected_bytes
    assert target.execute("""
        SELECT version_ref, run_ref, history FROM thalion.archive_repair_rebuild
        """).fetchone() == (version.version_ref, current.run_ref, history)
    assert target.execute("""
        SELECT version_ref, archive_digest FROM thalion.archive_rebuild_rule_check
        """).fetchone() == (version.version_ref, permit.digest)
    assert target.execute("SELECT lifecycle FROM thalion.space").fetchone() == ("archived",)
    assert target.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
    assert target.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        target.execute("UPDATE thalion.archive_repair_rebuild SET history = '{}'::jsonb")
    with pytest.raises(psycopg.OperationalError, match="rehearsal"):
        local_connection_factory(url)()


@pytest.mark.parametrize("restriction", ["current_quarantine", "lagging_quality", "historic_only_revocation", "withdrawal"])
def test_repair_rebuild_refuses_new_restrictions(
    repair_bundle, repaired_archive, restore_source_authority, restriction,
):
    target, _, _, payload, scratch, source, log = repair_bundle
    _, db, _, _, _, version, current, failed, *_ = repaired_archive
    authority, tenant, *_ = db
    if restriction in {"current_quarantine", "lagging_quality"}:
        if restriction == "lagging_quality":
            log.execute("ALTER TABLE thalion.rule_log_entry DISABLE TRIGGER rule_log_entry_immutable")
            log.execute("DELETE FROM thalion.rule_log_entry WHERE payload ->> 'kind' = 'quality_quarantine'")
        else:
            review(db, current, decision="quarantined")
            assert quality_restrictions.deliver_pending(authority, log, tenant.org_id).status == "ok"
    elif restriction == "historic_only_revocation":
        with ZipFile(BytesIO(payload)) as archive:
            history = json.loads(archive.read("repair-history.json"))
        historic = next(run for run in history["runs"] if run["run_id"] == str(failed.run_ref))
        revoked = UUID(historic["passages"][0]["passage_id"])
        assert revoked not in {UUID(part["passage_id"]) for part in history["runs"][-1]["passages"]}
        source_revocations.revoke(
            restore_source_authority[0], source.authority_ref, tenant.space_ref, archive_subject(db),
            revoked, "archive", basis_ref=uuid4(),
        )
    else:
        decision = stop(authority, tenant, version.version_ref, "withdrawn")
        assert restriction_log.deliver_pending(authority, log, tenant.org_id).confirmed == (decision,)

    with pytest.raises(archive_rehearsal.ArchiveRejected):
        rebuild(repair_bundle, authority)
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert list(scratch.iterdir()) == []
