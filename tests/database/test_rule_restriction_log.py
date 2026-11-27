from datetime import UTC
import json
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.sources import effectivity, restriction_log

from test_effectivity import policy_db, record
from test_evidence import create_evidence_db, evidence_db, register_markdown
from test_identity import migrate_to_revision
from test_runtime import open_database, register_tenant, runtime_db
from test_travel_search import corpus, search
from test_wiki_drafts import workspace
from test_wiki_invalidation import version_ref
from test_wiki_publication import authorize, configure, read_current
from test_wiki_search import reviewed


@pytest.fixture
def independent_log(independent_database_url):
    upgrade(independent_database_url)
    with open_database(independent_database_url) as connection:
        yield connection


def stop(connection, tenant, version, kind="withdrawn", *, basis=None):
    context = record(connection, tenant, "stop_rule_use", str(uuid4()))
    return effectivity.stop_synthetic_rule(
        connection, context, tenant.space_id, version, kind, basis or uuid4(),
    )


def test_offline_independent_log_does_not_keep_source_or_wiki_visible(workspace):
    db, _, first, second = workspace
    connection, tenant, *_ = db
    configure(db, 2)
    assert authorize(db, *reviewed(workspace)).status == "succeeded"
    assert read_current(db).payload is not None
    before = json.loads(search(db, "上海住宿", include_wiki=True).payload)
    assert {part["passage_id"] for part in before["passages"]} == {str(first.passage_ref), str(second.passage_ref)}

    target = version_ref(connection, second)
    decision = stop(connection, tenant, target)
    assert restriction_log.deliver_pending(connection, None, tenant.org_id).status == "unavailable"
    assert connection.execute("SELECT decision_ref FROM thalion.rule_restriction_item").fetchall() == [(decision,)]
    assert connection.execute("SELECT count(*) FROM thalion.rule_log_confirmation").fetchone() == (0,)
    assert read_current(db).payload is None
    visible = json.loads(search(db, "上海住宿", include_wiki=True).payload)
    assert visible["wiki"] == []
    assert [part["passage_id"] for part in visible["passages"]] == [str(first.passage_ref)]


def test_delivery_retries_same_exact_decision_after_local_confirmation_fails(policy_db, independent_log):
    connection, tenant, _, previous, _ = policy_db
    basis = uuid4()
    decision = stop(connection, tenant, previous.version_ref, basis=basis)
    assert stop(connection, tenant, previous.version_ref, basis=basis) == decision
    connection.execute("ALTER TABLE thalion.rule_log_confirmation ADD CONSTRAINT pending_receipt CHECK (false)")

    with pytest.raises(errors.CheckViolation):
        restriction_log.deliver_pending(connection, independent_log, tenant.org_id)
    assert connection.execute("SELECT count(*) FROM thalion.rule_log_confirmation").fetchone() == (0,)
    generation, logged_ref, body = independent_log.execute(
        "SELECT generation, decision_ref, payload FROM thalion.rule_log_entry",
    ).fetchone()
    assert (generation, logged_ref) == (1, decision)
    assert body["space_ref"] == str(tenant.space_ref)
    assert body["version_ref"] == str(previous.version_ref)
    assert body["kind"] == "withdrawn" and body["basis_ref"] == str(basis)
    actor_ref, recorded_at = connection.execute(
        """
        SELECT actor.public_id, stop.recorded_at FROM thalion.rule_use_stop AS stop
        JOIN thalion.object_identity AS actor
          ON (actor.org_id, actor.object_type, actor.object_id) = (stop.org_id, 'principal', stop.decided_by)
        WHERE stop.decision_ref = %s
        """, (decision,),
    ).fetchone()
    assert body["approver_ref"] == str(actor_ref)
    assert body["recorded_at"] == recorded_at.astimezone(UTC).isoformat()
    assert restriction_log.verify_replay_input(connection, independent_log, tenant.org_id).status == "verified"

    connection.execute("ALTER TABLE thalion.rule_log_confirmation DROP CONSTRAINT pending_receipt")
    retried = restriction_log.deliver_pending(connection, independent_log, tenant.org_id)
    assert (retried.status, retried.confirmed) == ("ok", (decision,))
    assert restriction_log.deliver_pending(connection, independent_log, tenant.org_id).confirmed == ()
    assert independent_log.execute("SELECT count(*) FROM thalion.rule_log_entry").fetchone() == (1,)


def test_recovery_rejects_same_database_and_older_log_but_accepts_complete_records(policy_db, independent_log):
    connection, tenant, database_url, previous, replacement = policy_db
    assert restriction_log.verify_replay_input(connection, independent_log, tenant.org_id).status == "closed"
    first = stop(connection, tenant, previous.version_ref, "suspended")
    with open_database(database_url) as same_database:
        assert restriction_log.deliver_pending(connection, same_database, tenant.org_id).status == "not_independent"
        assert restriction_log.verify_replay_input(connection, same_database, tenant.org_id).status == "closed"
    assert restriction_log.verify_replay_input(None, independent_log, tenant.org_id).status == "closed"
    assert restriction_log.verify_replay_input(connection, None, tenant.org_id).status == "closed"

    assert restriction_log.deliver_pending(connection, independent_log, tenant.org_id).confirmed == (first,)
    second = stop(connection, tenant, previous.version_ref)
    assert restriction_log.verify_replay_input(connection, independent_log, tenant.org_id).status == "closed"
    assert restriction_log.deliver_pending(connection, independent_log, tenant.org_id).confirmed == (second,)
    verified = restriction_log.verify_replay_input(connection, independent_log, tenant.org_id)
    assert verified.status == "verified"
    assert [item.decision_ref for item in verified.entries] == [first, second]
    assert {item.version_ref for item in verified.entries} == {previous.version_ref}
    assert replacement.version_ref not in {item.version_ref for item in verified.entries}


def test_recovery_rejects_mismatched_decision_at_same_generation(policy_db, independent_log):
    connection, tenant, _, previous, _ = policy_db
    decision = stop(connection, tenant, previous.version_ref)
    assert restriction_log.deliver_pending(connection, independent_log, tenant.org_id).confirmed == (decision,)
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        independent_log.execute("UPDATE thalion.rule_log_entry SET payload = '{}'")
    independent_log.execute("ALTER TABLE thalion.rule_log_entry DISABLE TRIGGER rule_log_entry_immutable")
    independent_log.execute(
        "UPDATE thalion.rule_log_entry SET payload = jsonb_set(payload, '{basis_ref}', to_jsonb(%s::text))",
        (str(uuid4()),),
    )
    result = restriction_log.verify_replay_input(connection, independent_log, tenant.org_id)
    assert (result.status, result.entries) == ("closed", ())


def test_recovery_rejects_gap_even_with_the_latest_generation_present(policy_db, independent_log):
    source, tenant, _, previous, replacement = policy_db
    first = stop(source, tenant, previous.version_ref)
    latest = stop(source, tenant, replacement.version_ref)
    assert restriction_log.deliver_pending(source, independent_log, tenant.org_id).confirmed == (first, latest)
    independent_log.execute("ALTER TABLE thalion.rule_log_entry DISABLE TRIGGER rule_log_entry_immutable")
    independent_log.execute("DELETE FROM thalion.rule_log_entry WHERE decision_ref = %s", (first,))
    assert independent_log.execute("SELECT max(generation) FROM thalion.rule_log_entry").fetchone() == (2,)
    assert restriction_log.verify_replay_input(source, independent_log, tenant.org_id).status == "closed"


def test_upgrade_captures_old_restrictions_and_failed_local_record_leaves_no_gap(database_url, tmp_path, independent_log):
    migrate_to_revision(database_url, "0031_backup_expiry")
    with open_database(database_url) as source:
        tenant = register_tenant(source, "Migration")
        db = create_evidence_db(source, tenant, database_url, tmp_path)
        version = register_markdown(db)
        first = stop(source, tenant, version.version_ref, "suspended")
        assert upgrade(database_url) == ["0113_source_connector_cursor"]
        assert source.execute("SELECT generation, decision_ref FROM thalion.rule_restriction_item").fetchall() == [
            (1, first),
        ]
        source.execute("ALTER TABLE thalion.rule_restriction_item ADD CONSTRAINT blocked_next CHECK (generation = 1)")
        with pytest.raises(errors.CheckViolation):
            stop(source, tenant, version.version_ref)
        assert source.execute("SELECT decision_ref FROM thalion.rule_use_stop").fetchall() == [(first,)]
        assert source.execute("SELECT generation FROM thalion.rule_restriction_stream").fetchone() == (1,)
        source.execute("ALTER TABLE thalion.rule_restriction_item DROP CONSTRAINT blocked_next")
        latest = stop(source, tenant, version.version_ref)
        assert restriction_log.deliver_pending(source, independent_log, tenant.org_id, limit=1).confirmed == (first,)
        assert restriction_log.verify_replay_input(source, independent_log, tenant.org_id).status == "closed"
        assert restriction_log.deliver_pending(source, independent_log, tenant.org_id, limit=1).confirmed == (latest,)
        result = restriction_log.verify_replay_input(source, independent_log, tenant.org_id)
        assert result.status == "verified"
        assert [(entry.generation, entry.decision_ref) for entry in result.entries] == [(1, first), (2, latest)]
