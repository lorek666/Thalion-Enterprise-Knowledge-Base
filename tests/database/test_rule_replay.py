from contextlib import contextmanager
import json
from shutil import copytree
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest

from enterprise_kb.database import local_connection_factory, rehearsal_marker
from enterprise_kb.modules.sources import originals, restriction_log

from conftest import temporary_database
from test_effectivity import policy_db
from test_evidence import evidence_db
from test_persisted_access import authority_for, read
from test_rule_restriction_log import independent_log, stop
from test_runtime import open_database, runtime_db
from test_travel_search import corpus, search
from test_wiki_drafts import workspace
from test_wiki_invalidation import version_ref
from test_wiki_publication import authorize, configure, read_current
from test_wiki_search import reviewed


@contextmanager
def rehearsal_clone(source, source_url, postgres_server):
    template = source.info.dbname
    source.close()
    with temporary_database(postgres_server, template=template) as url:
        with psycopg.connect(url, autocommit=True) as setup:
            database = setup.info.dbname
            setup.execute(sql.SQL("ALTER DATABASE {} SET thalion.restore_rehearsal = {}").format(
                sql.Identifier(database), sql.Literal(database),
            ))
        with open_database(source_url) as primary, open_database(url) as staged:
            yield primary, staged, url


def test_replay_keeps_withdrawn_citation_and_dependent_wiki_closed_but_retained_source_reads(
    workspace, independent_log, postgres_server, tmp_path_factory,
):
    db, _, retained, affected = workspace
    source, tenant, source_url, source_ref, store = db
    configure(db, 2)
    published = authorize(db, *reviewed(workspace))
    assert published.status == "succeeded"
    affected_version = version_ref(source, affected)
    scratch = tmp_path_factory.mktemp("restore")
    staged_store = originals.SyntheticOriginalStore(copytree(store.root, scratch / "originals"))
    current_authority = authority_for({tenant.actor_id})

    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, staged_url):
        staged_db = (staged, tenant, staged_url, source_ref, staged_store)
        assert read(staged_db, affected, tenant.actor_id, current_authority).payload is not None
        assert read_current(staged_db).payload is not None
        latest = stop(primary, tenant, affected_version)
        with pytest.raises(psycopg.OperationalError, match="rehearsal"):
            local_connection_factory(staged_url)()
        assert restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id).status == "closed"
        assert staged.execute("SELECT count(*) FROM thalion.rule_use_stop").fetchone() == (0,)

        assert restriction_log.deliver_pending(primary, independent_log, tenant.org_id).confirmed == (latest,)
        result = restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id)
        assert (result.status, result.applied, result.generation) == ("replayed", (latest,), 1)
        with pytest.raises(psycopg.OperationalError, match="rehearsal"):
            local_connection_factory(staged_url)()
        assert read(staged_db, affected, tenant.actor_id, current_authority).payload is None
        assert read_current(staged_db).payload is None
        assert read(staged_db, retained, tenant.actor_id, current_authority).payload is not None
        visible = json.loads(search(staged_db, "上海住宿", include_wiki=True).payload)
        assert not visible["wiki"]
        assert [part["passage_id"] for part in visible["passages"]] == [str(retained.passage_ref)]
        assert staged.execute(
            "SELECT reason, cause_ref FROM thalion.wiki_availability_event WHERE publication_ref = %s",
            (published.ref,),
        ).fetchall() == [("withdrawn", latest)]
        repeated = restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id)
        assert (repeated.status, repeated.applied, repeated.generation) == ("replayed", (), 1)


def test_replay_refuses_unmarked_or_wrong_database_and_rolls_back_a_partial_batch(
    policy_db, independent_log, postgres_server,
):
    source, tenant, source_url, previous, replacement = policy_db
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        first = stop(primary, tenant, previous.version_ref, "suspended")
        second = stop(primary, tenant, replacement.version_ref)
        assert restriction_log.deliver_pending(primary, independent_log, tenant.org_id).confirmed == (first, second)
        assert restriction_log.rehearse_replay(primary, independent_log, primary, tenant.org_id).status == "closed"
        assert restriction_log.rehearse_replay(primary, independent_log, independent_log, tenant.org_id).status == "closed"
        assert restriction_log.rehearse_replay(staged, independent_log, primary, tenant.org_id).status == "closed"
        database = sql.Identifier(staged.info.dbname)
        staged.execute(sql.SQL("ALTER DATABASE {} RESET thalion.restore_rehearsal").format(database))
        assert restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id).status == "closed"
        staged.execute(sql.SQL("ALTER DATABASE {} SET thalion.restore_rehearsal = {}").format(
            database, sql.Literal(staged.info.dbname),
        ))
        staged.execute("ALTER TABLE thalion.rule_use_stop ADD CONSTRAINT test_withdrawal CHECK (kind = 'suspended')")
        failed = restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id)
        assert (failed.status, failed.applied, failed.generation) == ("closed", (), None)
        assert staged.execute("SELECT count(*) FROM thalion.rule_use_stop").fetchone() == (0,)
        assert staged.execute("SELECT count(*) FROM thalion.rule_restriction_stream").fetchone() == (0,)
        staged.execute("ALTER TABLE thalion.rule_use_stop DROP CONSTRAINT test_withdrawal")
        assert restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id).applied == (first, second)
        assert staged.execute("SELECT count(*) FROM thalion.rule_log_confirmation").fetchone() == (0,)


def test_replay_accepts_only_an_exact_prefix_from_same_history(policy_db, independent_log, postgres_server):
    source, tenant, source_url, previous, replacement = policy_db
    prefix = stop(source, tenant, previous.version_ref, "suspended")
    assert restriction_log.deliver_pending(source, independent_log, tenant.org_id).confirmed == (prefix,)
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        next_stop = stop(primary, tenant, previous.version_ref)
        assert restriction_log.deliver_pending(primary, independent_log, tenant.org_id).confirmed == (next_stop,)
        result = restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id)
        assert (result.status, result.applied, result.generation) == ("replayed", (next_stop,), 2)

        divergent = stop(staged, tenant, replacement.version_ref, "suspended")
        final_stop = stop(primary, tenant, replacement.version_ref)
        assert restriction_log.deliver_pending(primary, independent_log, tenant.org_id).confirmed == (final_stop,)
        assert restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id).status == "closed"
        assert restriction_log.deliver_pending(staged, independent_log, tenant.org_id).status == "unavailable"
        assert staged.execute(
            "SELECT decision_ref FROM thalion.rule_restriction_item ORDER BY generation"
        ).fetchall() == [(prefix,), (next_stop,), (divergent,)]


def test_database_fence_is_visible_without_superuser_and_does_not_trust_session_settings(
    policy_db, postgres_server,
):
    source, _, source_url, *_ = policy_db
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        role = sql.Identifier(f"rehearsal_reader_{uuid4().hex}")
        staged.execute(sql.SQL("CREATE ROLE {}").format(role))
        try:
            for connection, expected in ((primary, None), (staged, staged.info.dbname)):
                with connection.transaction():
                    connection.execute(sql.SQL("SET LOCAL ROLE {}").format(role))
                    connection.execute("SELECT set_config('thalion.restore_rehearsal', '', true)")
                    assert rehearsal_marker(connection) == expected
        finally:
            staged.execute(sql.SQL("DROP ROLE {}").format(role))


def test_replay_holds_live_restriction_generation_until_staging_commit(
    policy_db, independent_log, postgres_server, monkeypatch,
):
    source, tenant, source_url, previous, replacement = policy_db
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, _):
        first = stop(primary, tenant, previous.version_ref)
        assert restriction_log.deliver_pending(primary, independent_log, tenant.org_id).confirmed == (first,)
        apply = restriction_log._apply_restriction
        with open_database(source_url) as writer:
            writer.execute("SET lock_timeout = '200ms'")

            def try_newer_stop(target, org_id, entry, log_ref):
                with pytest.raises(psycopg.errors.LockNotAvailable):
                    stop(writer, tenant, replacement.version_ref)
                apply(target, org_id, entry, log_ref)

            with monkeypatch.context() as patch:
                patch.setattr(restriction_log, "_apply_restriction", try_newer_stop)
                result = restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id)
            assert (result.status, result.applied) == ("replayed", (first,))
            newer = stop(writer, tenant, replacement.version_ref)
        assert restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id).status == "closed"
        assert restriction_log.deliver_pending(primary, independent_log, tenant.org_id).confirmed == (newer,)
        assert restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id).applied == (newer,)
