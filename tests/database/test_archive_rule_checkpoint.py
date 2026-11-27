from dataclasses import replace
from hashlib import sha256
from io import BytesIO
from uuid import uuid4
from zipfile import ZipFile

import psycopg
import pytest

from enterprise_kb.database import local_connection_factory, rehearsal_marker, upgrade
from enterprise_kb.modules.evidence import quality_restrictions
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.sources import restriction_log, source_revocations
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore

from conftest import temporary_database
from test_archive_rebuild import empty_rehearsal, rebuild_bundle
from test_disposition_cases import candidate
from test_evidence import create_evidence_db, evidence_db, register_markdown, review
from test_evidence_transport import evidence_transport, transport
from test_identity import migrate_to_revision
from test_original_export import archive_fixture
from test_rule_restriction_log import stop
from test_runtime import open_database, register_tenant, runtime_db
from test_transcript_export import transcript
from test_travel_search import corpus


@pytest.fixture
def rule_log(postgres_server):
    with temporary_database(postgres_server) as url:
        upgrade(url)
        with open_database(url) as log:
            yield log


def endpoint(connection):
    return connection.execute("SELECT log_ref FROM thalion.rule_log_endpoint").fetchone()[0]


@pytest.fixture
def restore_source_authority(postgres_server, corpus):
    _, tenant, *_ = corpus[0]
    with temporary_database(postgres_server) as url:
        upgrade(url)
        with open_database(url) as connection:
            authority_ref = endpoint(connection)
            source_revocations.enroll_space(connection, authority_ref, tenant.space_ref)
            yield connection, source_revocations.SourceRevocationAuthority(lambda: open_database(url), authority_ref), url


def archive_subject(db):
    connection, tenant, *_ = db
    return connection.execute("""
        SELECT public_id FROM thalion.object_identity
        WHERE (org_id, object_type, object_id) = (%s, 'principal', %s)
        """, (tenant.org_id, tenant.actor_id)).fetchone()[0]


@pytest.fixture
def checked_bundle(rebuild_bundle, empty_rehearsal, rule_log, restore_source_authority, tmp_path_factory):
    origin, digest, payload, *_ = rebuild_bundle
    target, url = empty_rehearsal
    permit = archive_rehearsal.RebuildPermit(*origin, digest, target.info.dbname)
    scratch = tmp_path_factory.mktemp("rule-checked-archive")
    return target, url, permit, payload, scratch, restore_source_authority[1], rule_log


def rebuild(bundle, authority, **overrides):
    target, _, permit, payload, scratch, source_authority, log = bundle
    return archive_rehearsal.rebuild_with_rule_checkpoint(
        target, permit, payload, scratch, **({
            "authority": authority, "authority_ref": endpoint(authority),
            "log": log, "log_ref": endpoint(log),
            "source_authority": source_authority,
        } | overrides),
    )


def assert_empty(bundle):
    target, _, _, _, scratch, *_ = bundle
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert target.execute("SELECT count(*) FROM thalion.archive_rebuild_rule_check").fetchone() == (0,)
    assert list(scratch.iterdir()) == []


def confirm_unrelated_stop(db, log, *, version_ref=None):
    authority, tenant, *_ = db
    if version_ref is None:
        version_ref = register_markdown(db).version_ref
    decision = stop(authority, tenant, version_ref)
    assert restriction_log.deliver_pending(authority, log, tenant.org_id).confirmed == (decision,)
    assert quality_restrictions.deliver_pending(authority, log, tenant.org_id).status == "ok"
    return authority.execute("""
        SELECT stream_ref FROM thalion.rule_restriction_stream WHERE org_id = %s
        """, (tenant.org_id,)).fetchone()[0]


def test_current_independent_history_allows_fenced_rebuild_and_records_its_exact_watermark(
    checked_bundle, transcript, restore_source_authority,
):
    (_, db, *_), _, _, passages = transcript
    authority, tenant, *_ = db
    target, url, permit, _, _, source_authority, log = checked_bundle
    source_writer, _, _ = restore_source_authority
    stream = confirm_unrelated_stop(db, log)
    subject = archive_subject(db)
    source_revocations.revoke(
        source_writer, source_authority.authority_ref, tenant.space_ref, subject, passages[0].passage_ref,
        "evidence", basis_ref=uuid4(),
    )
    source_revocations.revoke(
        source_writer, source_authority.authority_ref, tenant.space_ref, uuid4(), passages[0].passage_ref,
        "archive", basis_ref=uuid4(),
    )
    source_snapshot = source_authority.snapshot(tenant.space_ref)

    restored = rebuild(checked_bundle, authority)

    assert restored.store.read(restored.asset) == b"# Travel\r\n\r\nSynthetic allowance.\r\n\r\nAn uncited exception.\r\n"
    assert target.execute("""
        SELECT version_ref, archive_digest, origin_org_id, origin_space_id, export_ref,
               authority_ref, log_ref, stream_ref, generation, quality_stream_ref, quality_generation,
               source_authority_ref, source_space_ref, source_stream_ref, source_generation, source_requester_ref
        FROM thalion.archive_rebuild_rule_check
        """).fetchone() == (
        permit.version_ref, permit.digest, permit.org_id, permit.space_id, permit.export_ref,
        endpoint(authority), endpoint(log), stream, 1,
        *authority.execute("""
            SELECT stream_ref, generation FROM thalion.quality_restriction_stream WHERE org_id = %s
            """, (permit.org_id,)).fetchone(),
        source_authority.authority_ref, tenant.space_ref, source_snapshot.stream_ref, 2, subject,
    )
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        target.execute("UPDATE thalion.archive_rebuild_rule_check SET generation = 2")
    with pytest.raises(psycopg.errors.FeatureNotSupported):
        target.execute("TRUNCATE thalion.archive_rebuild_rule_check")
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        target.execute("TRUNCATE thalion.archive_rebuild_rule_check CASCADE")
    assert rehearsal_marker(target) == target.info.dbname
    with pytest.raises(psycopg.OperationalError, match="rehearsal"):
        local_connection_factory(url)()


def test_rule_receipt_is_not_enough_without_an_independent_quality_baseline(checked_bundle, transcript):
    (_, db, *_), _, _, _ = transcript
    authority, tenant, *_ = db
    *_, log = checked_bundle
    unrelated = register_markdown(db)
    decision = stop(authority, tenant, unrelated.version_ref)
    assert restriction_log.deliver_pending(authority, log, tenant.org_id).confirmed == (decision,)

    with pytest.raises(archive_rehearsal.ArchiveRejected, match="independent quality history"):
        rebuild(checked_bundle, authority)
    assert_empty(checked_bundle)


def test_quality_baseline_rejects_divergent_independent_payload(checked_bundle, transcript):
    (_, db, *_), _, _, _ = transcript
    authority, tenant, *_ = db
    *_, log = checked_bundle
    confirm_unrelated_stop(db, log)
    log.execute("ALTER TABLE thalion.rule_log_entry DISABLE TRIGGER rule_log_entry_immutable")
    log.execute("""
        UPDATE thalion.rule_log_entry SET payload = jsonb_set(payload, '{authority_ref}', to_jsonb(%s::text))
        WHERE payload ->> 'kind' = 'quality_baseline'
        """, (str(uuid4()),))
    assert quality_restrictions.deliver_pending(authority, log, tenant.org_id).status == "conflict"
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="independent quality history"):
        rebuild(checked_bundle, authority)
    assert_empty(checked_bundle)


def test_unverified_or_wrong_rule_source_never_materializes_archive(checked_bundle, transcript):
    (_, db, *_), _, _, _ = transcript
    authority, *_ = db
    *_, log = checked_bundle
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        rebuild(checked_bundle, authority)
    confirm_unrelated_stop(db, log)
    for overrides in (
        {"authority_ref": uuid4()}, {"log_ref": uuid4()},
        {"log": authority, "log_ref": endpoint(authority)},
    ):
        with pytest.raises(archive_rehearsal.ArchiveRejected):
            rebuild(checked_bundle, authority, **overrides)
        assert_empty(checked_bundle)


@pytest.mark.parametrize("kind", ["suspended", "withdrawn"])
def test_rebuild_blocks_a_post_archive_stop_before_and_after_log_confirmation(checked_bundle, transcript, kind):
    (_, db, *_), version, _, _ = transcript
    authority, tenant, *_ = db
    *_, log = checked_bundle
    confirm_unrelated_stop(db, log)
    decision = stop(authority, tenant, version.version_ref, kind)

    with pytest.raises(archive_rehearsal.ArchiveRejected):
        rebuild(checked_bundle, authority)
    assert_empty(checked_bundle)
    assert restriction_log.deliver_pending(authority, log, tenant.org_id).confirmed == (decision,)
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        rebuild(checked_bundle, authority)
    assert_empty(checked_bundle)


def test_verified_rules_cannot_attest_a_digest_not_registered_for_the_original_request(checked_bundle, transcript):
    (_, db, *_), _, _, _ = transcript
    authority, *_ = db
    target, url, permit, payload, scratch, source_authority, log = checked_bundle
    confirm_unrelated_stop(db, log)
    repacked = BytesIO(payload)
    with ZipFile(repacked, "a") as archive:
        archive.comment = b"Different archive bytes with identical checked members"
    altered = repacked.getvalue()
    revised = replace(permit, digest=sha256(altered).digest())
    bundle = target, url, revised, altered, scratch, source_authority, log
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="exact sealed archive"):
        rebuild(bundle, authority)
    assert_empty(checked_bundle)


def test_safety_heads_remain_locked_while_the_restored_original_is_staged(
    checked_bundle, transcript, monkeypatch, restore_source_authority,
):
    (_, db, *_), version, run, _ = transcript
    authority, tenant, source_url, *_ = db
    *_, log = checked_bundle
    confirm_unrelated_stop(db, log)
    stage = SyntheticOriginalStore.stage
    _, source_authority, revocation_url = restore_source_authority
    subject = archive_subject(db)

    with open_database(source_url) as writer, open_database(revocation_url) as source_writer:
        writer.execute("SET lock_timeout = '200ms'")
        source_writer.execute("SET lock_timeout = '200ms'")

        def revoke_archive():
            return source_revocations.revoke(
                source_writer, source_authority.authority_ref, tenant.space_ref, subject, version.version_ref,
                "archive", basis_ref=uuid4(),
            )

        def check_lock(store, key, digest, payload):
            with pytest.raises(psycopg.errors.LockNotAvailable):
                stop(writer, tenant, version.version_ref)
            with pytest.raises(psycopg.errors.LockNotAvailable):
                review((writer, *db[1:]), run, decision="quarantined")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                revoke_archive()
            return stage(store, key, digest, payload)

        with monkeypatch.context() as patch:
            patch.setattr(SyntheticOriginalStore, "stage", check_lock)
            rebuild(checked_bundle, authority)
        assert review((writer, *db[1:]), run, decision="quarantined") is not None
        assert stop(writer, tenant, version.version_ref) is not None
        assert revoke_archive().generation == 1


def test_failed_checkpoint_write_leaves_no_rebuilt_data(checked_bundle, transcript):
    (_, db, *_), _, _, _ = transcript
    authority, *_ = db
    target, *_, log = checked_bundle
    confirm_unrelated_stop(db, log)
    target.execute("ALTER TABLE thalion.archive_rebuild_rule_check ADD CHECK (generation > 1)")
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        rebuild(checked_bundle, authority)
    assert_empty(checked_bundle)


@pytest.mark.parametrize("target_kind", ["version", "uncited_passage"])
def test_current_archive_revocation_rejects_old_seal_before_materializing_data(
    checked_bundle, transcript, restore_source_authority, target_kind,
):
    (_, db, *_), version, _, passages = transcript
    authority, tenant, *_ = db
    writer, source_authority, _ = restore_source_authority
    confirm_unrelated_stop(db, checked_bundle[-1])
    object_ref = version.version_ref if target_kind == "version" else passages[-1].passage_ref
    source_revocations.revoke(
        writer, source_authority.authority_ref, tenant.space_ref, archive_subject(db), object_ref,
        "archive", basis_ref=uuid4(),
    )

    with pytest.raises(archive_rehearsal.ArchiveRejected, match="source revocation blocks"):
        rebuild(checked_bundle, authority)
    assert_empty(checked_bundle)


def test_unverified_source_revocations_do_not_fall_back_to_an_offline_rebuild(
    checked_bundle, transcript, restore_source_authority, postgres_server,
):
    (_, db, *_), _, _, _ = transcript
    authority, *_ = db
    _, source_authority, _ = restore_source_authority
    confirm_unrelated_stop(db, checked_bundle[-1])

    def unavailable():
        raise psycopg.OperationalError("Synthetic source authority unavailable.")

    with temporary_database(postgres_server) as url:
        upgrade(url)
        with open_database(url) as unenrolled:
            missing_space = source_revocations.SourceRevocationAuthority(lambda: open_database(url), endpoint(unenrolled))
            for candidate in (
                None, replace(source_authority, authority_ref=uuid4()),
                replace(source_authority, connect=unavailable), missing_space,
                replace(source_authority, authority_ref=endpoint(checked_bundle[-1])),
            ):
                with pytest.raises(archive_rehearsal.ArchiveRejected, match="independent source revocations"):
                    rebuild(checked_bundle, authority, source_authority=candidate)
                assert_empty(checked_bundle)


def test_upgrade_keeps_legacy_checkpoints_but_requires_source_evidence_for_new_ones(database_url, tmp_path):
    migrate_to_revision(database_url, "0039_source_revocations")
    record = """
        INSERT INTO thalion.archive_rebuild_rule_check (
            version_ref, archive_digest, origin_org_id, origin_space_id, export_ref,
            authority_ref, log_ref, stream_ref, generation, quality_stream_ref, quality_generation
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, 1)
    """
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Legacy archive rehearsal")
        db = create_evidence_db(connection, tenant, database_url, tmp_path)
        previous = register_markdown(db).version_ref
        values = bytes(32), tenant.org_id, tenant.space_id, uuid4(), uuid4(), uuid4(), uuid4(), uuid4()
        connection.execute(record, (previous, *values))

        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert connection.execute("""
            SELECT version_ref, source_authority_ref, source_generation FROM thalion.archive_rebuild_rule_check
            """).fetchall() == [(previous, None, None)]
        with pytest.raises(psycopg.errors.CheckViolation, match="archive_rebuild_source_checkpoint_required"):
            connection.execute(record, (uuid4(), *values))
