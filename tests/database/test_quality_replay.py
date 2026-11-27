import json
from shutil import copytree
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest

from enterprise_kb.database import local_connection_factory, rehearsal_marker
from enterprise_kb.modules.evidence import quality_restrictions
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore

from test_archive_rule_checkpoint import endpoint, rule_log
from test_evidence import evidence_db, review
from test_persisted_access import authority_for, read
from test_rule_replay import rehearsal_clone
from test_runtime import open_database, runtime_db
from test_travel_search import corpus, publish, search
from test_wiki_drafts import workspace
from test_wiki_publication import authorize, configure, read_current
from test_wiki_search import reviewed


def replay(primary, log, target, org_id, **pins):
    return quality_restrictions.rehearse_replay(
        primary, log, target, org_id,
        **({"authority_ref": endpoint(primary), "log_ref": endpoint(log)} | pins),
    )


def test_replay_blocks_a_quarantined_reference_and_its_uncited_wiki_dependency(
    workspace, corpus, rule_log, postgres_server, tmp_path_factory,
):
    db, _, retained, affected = workspace
    source, tenant, source_url, source_ref, store = db
    _, _, _, _, affected_run, _ = corpus
    configure(db, 2)
    publication = authorize(db, *reviewed(workspace))
    assert publication.status == "succeeded"
    scratch = tmp_path_factory.mktemp("quality-replay")
    staged_store = SyntheticOriginalStore(copytree(store.root, scratch / "originals"))
    authority = authority_for({tenant.actor_id})

    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, staged_url):
        staged_db = staged, tenant, staged_url, source_ref, staged_store
        assert read(staged_db, affected, tenant.actor_id, authority).payload is not None
        assert read_current(staged_db).payload is not None
        original_requests = staged.execute("""
            SELECT count(*) FROM thalion.request_record WHERE operation = 'decide_evidence_quality'
            """).fetchone()
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).status == "ok"
        decision = review((primary, *db[1:]), affected_run, decision="quarantined")

        assert replay(primary, rule_log, staged, tenant.org_id).status == "closed"
        assert staged.execute("SELECT count(*) FROM thalion.quality_restriction_item").fetchone() == (0,)
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (decision,)
        result = replay(primary, rule_log, staged, tenant.org_id)
        assert (result.status, result.applied, result.generation) == ("replayed", (decision,), 2)
        assert staged.execute("""
            SELECT decision.run_ref, decision.reviewer_id, decision.basis_ref, decision.recorded_at,
                   decision.request_id, decision.replay_log_ref
            FROM thalion.quality_decision AS decision WHERE decision_ref = %s
            """, (decision,)).fetchone() == (
                *primary.execute("""
                    SELECT run_ref, reviewer_id, basis_ref, recorded_at
                    FROM thalion.quality_decision WHERE decision_ref = %s
                    """, (decision,)).fetchone(), None, endpoint(rule_log),
            )
        assert staged.execute("""
            SELECT count(*) FROM thalion.request_record WHERE operation = 'decide_evidence_quality'
            """).fetchone() == original_requests
        assert staged.execute("""
            SELECT reason, cause_ref FROM thalion.wiki_availability_event WHERE publication_ref = %s
            """, (publication.ref,)).fetchall() == [("quarantined", decision)]
        assert read(staged_db, affected, tenant.actor_id, authority).payload is None
        assert read_current(staged_db).payload is None
        visible = json.loads(search(staged_db, "上海住宿", include_wiki=True).payload)
        assert not visible["wiki"]
        assert [part["passage_id"] for part in visible["passages"]] == [str(retained.passage_ref)]
        assert rehearsal_marker(staged) == staged.info.dbname
        with pytest.raises(psycopg.OperationalError, match="rehearsal"):
            local_connection_factory(staged_url)()
        repeated = replay(primary, rule_log, staged, tenant.org_id)
        assert (repeated.status, repeated.applied, repeated.generation) == ("replayed", (), 2)


def test_missing_run_in_later_decision_rolls_back_the_entire_replay(evidence_db, rule_log, postgres_server):
    source, tenant, source_url, *_ = evidence_db
    _, _, before = publish(evidence_db, "quality-from-backup", "Synthetic allowance", b"# Travel\n\nBefore backup.\n")
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        primary_db = (primary, *evidence_db[1:])
        first = review(primary_db, before, decision="quarantined")
        _, _, after = publish(primary_db, "quality-after-backup", "New synthetic version", b"# Travel\n\nAfter backup.\n")
        latest = review(primary_db, after, decision="quarantined")
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (first, latest)
        result = replay(primary, rule_log, staged, tenant.org_id)
        assert (result.status, result.applied, result.generation) == ("closed", (), None)
        assert staged.execute("SELECT generation FROM thalion.quality_restriction_stream").fetchone() == (1,)
        assert staged.execute("SELECT outcome FROM thalion.quality_decision").fetchall() == [("approved",)]
        assert staged.execute("SELECT count(*) FROM thalion.quality_restriction_item").fetchone() == (0,)


def test_quality_replay_refuses_a_divergent_local_history(evidence_db, rule_log, postgres_server):
    source, tenant, source_url, *_ = evidence_db
    _, _, first = publish(evidence_db, "quality-branch-a", "Synthetic A", b"# Travel\n\nVersion A.\n")
    _, _, second = publish(evidence_db, "quality-branch-b", "Synthetic B", b"# Travel\n\nVersion B.\n")
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        current = review((primary, *evidence_db[1:]), first, decision="quarantined")
        divergent = review((staged, *evidence_db[1:]), second, decision="quarantined")
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (current,)
        assert replay(primary, rule_log, staged, tenant.org_id).status == "closed"
        assert staged.execute("SELECT decision_ref FROM thalion.quality_restriction_item").fetchall() == [(divergent,)]
        assert quality_restrictions.deliver_pending(staged, rule_log, tenant.org_id).status == "unavailable"


def test_replay_requires_exact_endpoints_and_database_level_isolation(evidence_db, rule_log, postgres_server):
    source, tenant, source_url, *_ = evidence_db
    _, _, run = publish(evidence_db, "quality-provenance", "Synthetic basis", b"# Travel\n\nSynthetic evidence.\n")
    replay_insert = """
        INSERT INTO thalion.quality_decision (
            org_id, space_id, version_id, run_ref, reviewer_id, basis_ref, outcome, replay_log_ref
        )
        SELECT org_id, space_id, version_id, run_ref, reviewer_id, basis_ref, %s, %s
        FROM thalion.quality_decision WHERE run_ref = %s AND outcome = 'approved'
        """
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        log_ref = endpoint(rule_log)
        with pytest.raises(psycopg.errors.CheckViolation, match="fenced database"):
            primary.execute(replay_insert, ("quarantined", log_ref, run.run_ref))
        with pytest.raises(psycopg.errors.CheckViolation, match="quality_decision_provenance"):
            staged.execute(replay_insert, ("approved", log_ref, run.run_ref))
        with pytest.raises(psycopg.errors.CheckViolation, match="distinct log"):
            staged.execute(replay_insert, ("quarantined", endpoint(primary), run.run_ref))
        decision = review((primary, *evidence_db[1:]), run, decision="quarantined")
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (decision,)
        assert replay(primary, rule_log, primary, tenant.org_id).status == "closed"
        assert replay(primary, rule_log, staged, tenant.org_id, authority_ref=uuid4()).status == "closed"
        assert replay(primary, rule_log, staged, tenant.org_id, log_ref=uuid4()).status == "closed"
        assert replay(primary, rule_log, staged, tenant.org_id + 1).status == "closed"
        database = staged.info.dbname
        staged.execute(sql.SQL("ALTER DATABASE {} RESET thalion.restore_rehearsal").format(sql.Identifier(database)))
        staged.execute("SELECT set_config('thalion.restore_rehearsal', %s, false)", (database,))
        assert replay(primary, rule_log, staged, tenant.org_id).status == "closed"
        assert staged.execute("SELECT count(*) FROM thalion.quality_restriction_item").fetchone() == (0,)


def test_replay_pins_current_quality_generation_until_target_commits(
    evidence_db, rule_log, postgres_server, monkeypatch,
):
    source, tenant, source_url, *_ = evidence_db
    _, _, first = publish(evidence_db, "quality-control-lock", "Synthetic A", b"# Travel\n\nFirst run.\n")
    _, _, second = publish(evidence_db, "quality-control-followup", "Synthetic B", b"# Travel\n\nSecond run.\n")
    apply = quality_restrictions._apply_quarantine
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        first_decision = review((primary, *evidence_db[1:]), first, decision="quarantined")
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (first_decision,)
        with open_database(source_url) as writer:
            writer.execute("SET lock_timeout = '200ms'")

            def assert_pinned(target, org_id, entry, log_ref):
                with pytest.raises(psycopg.errors.LockNotAvailable):
                    review((writer, *evidence_db[1:]), second, decision="quarantined")
                apply(target, org_id, entry, log_ref)

            with monkeypatch.context() as patch:
                patch.setattr(quality_restrictions, "_apply_quarantine", assert_pinned)
                assert replay(primary, rule_log, staged, tenant.org_id).applied == (first_decision,)
            latest = review((writer, *evidence_db[1:]), second, decision="quarantined")
        assert replay(primary, rule_log, staged, tenant.org_id).status == "closed"
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (latest,)
        assert replay(primary, rule_log, staged, tenant.org_id).applied == (latest,)
