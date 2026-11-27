from datetime import UTC

import pytest
from psycopg import errors
from psycopg.types.json import Jsonb

from enterprise_kb.database import upgrade
from enterprise_kb.modules.evidence import processing, quality_restrictions

from test_archive_rule_checkpoint import endpoint, rule_log
from test_evidence import approved, claim, create_evidence_db, evidence_db, register_markdown, review
from test_identity import migrate_to_revision
from test_pdf_review import pdf_review, stage_pdf
from test_rule_replay import rehearsal_clone
from test_runtime import open_database, register_tenant, runtime_db
from test_sources import register


def test_previous_quarantine_backfills_and_exact_log_can_resume_a_partial_delivery(database_url, tmp_path, rule_log):
    migrate_to_revision(database_url, "0036_wiki_rebuild_rehearsal")
    with open_database(database_url) as authority:
        tenant = register_tenant(authority, "Quality history migration")
        database = create_evidence_db(authority, tenant, database_url, tmp_path)
        version = register_markdown(database)
        run = processing.process_markdown_job(authority, claim(database), database[4])
        review(database, run)
        decision = review(database, run, decision="quarantined")
        assert upgrade(database_url) == ["0113_source_connector_cursor"]
        stream_ref, generation = authority.execute("""
            SELECT stream_ref, generation FROM thalion.quality_restriction_stream WHERE org_id = %s
            """, (tenant.org_id,)).fetchone()
        assert generation == 2
        assert authority.execute("""
            SELECT generation, decision_ref FROM thalion.quality_restriction_item
            """).fetchall() == [(2, decision)]
        assert quality_restrictions.deliver_pending(authority, authority, tenant.org_id).status == "not_independent"
        assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id, limit=1).confirmed == ()
        with authority.transaction():
            assert quality_restrictions.check_pinned_history(authority, rule_log, tenant.org_id, endpoint(authority)) is None
        assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id, limit=1).confirmed == (decision,)
        assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).confirmed == ()
        with authority.transaction():
            checked = quality_restrictions.check_pinned_history(authority, rule_log, tenant.org_id, endpoint(authority))
            assert (checked.stream_ref, checked.generation, checked.blocked_versions) == (
                stream_ref, generation, {version.version_ref},
            )
        assert rule_log.execute("""
            SELECT generation, decision_ref, payload ->> 'kind', payload ->> 'run_ref', payload ->> 'manifest_sha256'
            FROM thalion.rule_log_entry WHERE stream_ref = %s ORDER BY generation
            """, (stream_ref,)).fetchall() == [
            (1, stream_ref, "quality_baseline", None, None),
            (2, decision, "quality_quarantine", str(run.run_ref), run.manifest_digest.hex()),
        ]


def test_quality_outbox_failure_rolls_back_quarantine_and_leaves_no_sequence_gap(evidence_db, rule_log):
    authority, tenant, _, _, store = evidence_db
    version = register_markdown(evidence_db)
    run = processing.process_markdown_job(authority, claim(evidence_db), store)
    review(evidence_db, run)
    assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).status == "ok"
    authority.execute("ALTER TABLE thalion.quality_restriction_item ADD CHECK (generation > 2)")

    with pytest.raises(errors.CheckViolation):
        review(evidence_db, run, decision="quarantined")
    assert len(approved(evidence_db, version)) == 1
    assert authority.execute("SELECT generation FROM thalion.quality_restriction_stream").fetchone() == (1,)
    assert authority.execute("SELECT outcome FROM thalion.quality_decision").fetchall() == [("approved",)]
    assert rule_log.execute("SELECT count(*) FROM thalion.rule_log_entry").fetchone() == (1,)


def test_automatic_pdf_quarantine_is_attested_without_a_fabricated_reviewer(pdf_review, rule_log, postgres_server):
    database = pdf_review[0]
    authority, tenant, url, *_ = database
    authority_ref, log_ref = endpoint(authority), endpoint(rule_log)
    assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).confirmed == ()
    with rehearsal_clone(authority, url, postgres_server) as (authority, older, _):
        version, run = stage_pdf((authority, *database[1:]), b"", b"")
        assert run.outcome == "quarantined"
        assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).confirmed == (run.run_ref,)
        with authority.transaction():
            current = quality_restrictions.check_pinned_history(authority, rule_log, tenant.org_id, authority_ref)
        assert current.generation == 2 and current.blocked_versions == {version.version_ref}
        payload, = rule_log.execute(
            "SELECT payload FROM thalion.rule_log_entry WHERE decision_ref = %s", (run.run_ref,),
        ).fetchone()
        assert payload["kind"] == "pdf_processing_quarantine"
        assert (payload["manifest_sha256"], payload["reason"], payload["page_count"]) == (
            run.manifest_digest.hex(), run.reason, 2,
        )
        assert "reviewer_ref" not in payload and "basis_ref" not in payload
        replay = quality_restrictions.rehearse_replay(
            authority, rule_log, older, tenant.org_id, authority_ref=authority_ref, log_ref=log_ref,
        )
        assert replay.status == "closed"
        assert older.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
        assert older.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    with open_database(url) as source:
        with rehearsal_clone(source, url, postgres_server) as (authority, current_clone, _):
            replay = quality_restrictions.rehearse_replay(
                authority, rule_log, current_clone, tenant.org_id, authority_ref=authority_ref, log_ref=log_ref,
            )
            assert (replay.status, replay.applied, replay.generation) == ("replayed", (), 2)
            assert current_clone.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)


def test_automatic_pdf_quality_outbox_failure_rolls_back_processing(pdf_review):
    database = pdf_review[0]
    authority = database[0]
    authority.execute("ALTER TABLE thalion.quality_restriction_item ADD CHECK (generation > 2)")
    with pytest.raises(errors.CheckViolation):
        stage_pdf(database, b"")
    assert authority.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert authority.execute("SELECT count(*) FROM thalion.pdf_page_observation").fetchone() == (0,)
    assert authority.execute("SELECT generation FROM thalion.quality_restriction_stream").fetchone() == (1,)


def test_pdf_quality_migration_appends_historical_machine_quarantine_after_manual_history(database_url, tmp_path, rule_log):
    pytest.importorskip("pypdfium2")
    migrate_to_revision(database_url, "0070_pdf_repair_rebuild")
    with open_database(database_url) as authority:
        tenant = register_tenant(authority, "PDF quality history migration")
        database = create_evidence_db(authority, tenant, database_url, tmp_path)
        register(authority, tenant, database[3], database[4], object_key="manual-evidence")
        markdown = processing.process_markdown_job(authority, claim(database), database[-1])
        decision = review(database, markdown, decision="quarantined")
        version, pdf = stage_pdf(database, b"")
        stream_ref, = authority.execute("SELECT stream_ref FROM thalion.quality_restriction_stream").fetchone()
        assert authority.execute("SELECT count(*) FROM thalion.quality_restriction_item").fetchone() == (1,)
        space_ref, version_ref, reviewer_ref, configuration, basis_ref, recorded_at = authority.execute("""
            SELECT space_ref, version_ref, reviewer_ref, configuration_revision, basis_ref, recorded_at
            FROM thalion.quality_restriction_material WHERE decision_ref = %s
            """, (decision,)).fetchone()
        legacy_rows = [
            (1, stream_ref, {"schema_revision": 1, "kind": "quality_baseline", "authority_ref": str(endpoint(authority))}),
            (2, decision, {
                "schema_revision": 1, "kind": "quality_quarantine", "space_ref": str(space_ref),
                "version_ref": str(version_ref), "reviewer_ref": str(reviewer_ref), "run_ref": str(markdown.run_ref),
                "configuration_revision": configuration, "manifest_sha256": markdown.manifest_digest.hex(),
                "basis_ref": str(basis_ref), "recorded_at": recorded_at.astimezone(UTC).isoformat(),
            }),
        ]
        with rule_log.cursor() as cursor:
            cursor.executemany("""
                INSERT INTO thalion.rule_log_entry (stream_ref, generation, decision_ref, payload) VALUES (%s, %s, %s, %s)
                """, [(stream_ref, generation, ref, Jsonb(payload)) for generation, ref, payload in legacy_rows])

        assert upgrade(database_url) == ["0113_source_connector_cursor"]

        assert authority.execute("SELECT stream_ref, generation FROM thalion.quality_restriction_stream").fetchone() == (
            stream_ref, 3,
        )
        assert authority.execute("""
            SELECT generation, decision_ref FROM thalion.quality_restriction_item ORDER BY generation
            """).fetchall() == [(2, decision), (3, pdf.run_ref)]
        assert authority.execute("SELECT decision_ref FROM thalion.quality_decision").fetchall() == [(decision,)]
        assert rule_log.execute("""
            SELECT generation, decision_ref, payload FROM thalion.rule_log_entry ORDER BY generation
            """).fetchall() == legacy_rows
        with authority.transaction():
            assert quality_restrictions.check_pinned_history(authority, rule_log, tenant.org_id, endpoint(authority)) is None
        assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).confirmed == (pdf.run_ref,)
        with authority.transaction():
            checked = quality_restrictions.check_pinned_history(authority, rule_log, tenant.org_id, endpoint(authority))
            assert checked.blocked_versions == {version_ref, version.version_ref}
