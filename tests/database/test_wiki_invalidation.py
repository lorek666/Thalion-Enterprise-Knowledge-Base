import json
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.modules.wiki import inputs
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from test_effectivity import BEFORE, SWITCH, approve, record
from test_evidence import approved, claim, evidence_db, review
from test_persisted_access import authority_for, ingress
from test_runtime import open_database, runtime_db
from test_travel_search import corpus, publish, search
from test_wiki_drafts import candidate, preview, submit, workspace
from test_wiki_inputs import assemble
from test_wiki_publication import authorize, configure, read_current
from test_wiki_search import reviewed


def causes(connection, publication_ref):
    return connection.execute(
        """
        SELECT event_ref, reason, cause_ref FROM thalion.wiki_availability_event
        WHERE publication_ref = %s ORDER BY reason
        """, (publication_ref,),
    ).fetchall()


def version_ref(connection, passage):
    return connection.execute(
        """
        SELECT version_ref.public_id FROM thalion.object_identity AS location
        JOIN thalion.passage AS passage ON passage.passage_id = location.object_id
        JOIN thalion.object_identity AS version_ref ON version_ref.object_id = passage.version_id
        WHERE location.public_id = %s AND version_ref.object_type = 'document_version'
        """, (passage.passage_ref,),
    ).fetchone()[0]


def test_withdrawal_stops_inherited_uncited_input_and_clean_rebuild_requires_new_review(workspace):
    db, parent, first, second = workspace
    connection, tenant, _, _, store = db
    configure(db, 2)
    child = assemble(db, (first,), (parent.manifest_ref,))
    assert child.status == "succeeded"
    old_revision, approval = reviewed((db, child, first, second))
    publication = authorize(db, old_revision, approval)
    assert publication.status == "succeeded"
    approval_version_ref = version_ref(connection, second)
    context = record(connection, tenant, "stop_rule_use", "withdraw-approval")
    basis = uuid4()
    decision = effectivity.stop_synthetic_rule(
        connection, context, tenant.space_id, approval_version_ref, "withdrawn", basis,
    )
    event, = causes(connection, publication.ref)
    assert event[1:] == ("withdrawn", decision)
    assert read_current(db).payload is None
    visible = json.loads(search(db, "限额", include_wiki=True).payload)
    assert not visible["wiki"] and len(visible["passages"]) == 1
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.wiki_availability_event WHERE event_ref = %s", (event[0],))

    def prepare(event_ref, direct):
        context = ingress(db, tenant.actor_id, BEFORE, operation="assemble_wiki_inputs", purpose="wiki_compilation",
                          destination="local_workspace")
        return inputs.prepare_clean_wiki_inputs(
            connection, context, tenant.space_id, event_ref, direct, store,
            region="shanghai", traveler_class="employee", check_authority=authority_for({tenant.actor_id}),
        )

    assert prepare(uuid4(), ((first.passage_ref, first.revision),)).status == "rejected"
    assert prepare(event[0], ((second.passage_ref, second.revision),)).status == "rejected"
    fresh = prepare(event[0], ((first.passage_ref, first.revision),))
    assert fresh.status == "succeeded"
    assert [excerpt.strip() for excerpt in json.loads(fresh.payload)] == ["上海住宿限额。"]
    assert connection.execute(
        "SELECT rebuild_event_ref, parent_refs FROM thalion.input_manifest WHERE manifest_ref = %s",
        (fresh.manifest_ref,),
    ).fetchone() == (event[0], [])
    rebuild = (db, fresh, first, second)
    assert candidate(rebuild, topic="unrelated").status == "rejected"
    waiting = candidate(rebuild)
    assert waiting.status == "succeeded"
    revised, new_review = reviewed(rebuild)
    assert read_current(db).payload is None
    assert authorize(db, revised, new_review).status == "succeeded"
    assert read_current(db).ref == revised
    assert json.loads(search(db, "限额", include_wiki=True).payload)["wiki"][0]["revision_id"] == str(revised)
    late_review = submit(db, waiting.ref, preview(db, waiting.ref))
    assert late_review.status == "input_changed" and late_review.ref is None
    assert prepare(event[0], ((first.passage_ref, first.revision),)).status == "rejected"
    assert causes(connection, publication.ref) == [event]


def test_withdrawal_during_final_search_drops_only_the_affected_wiki(workspace):
    db, _, first, second = workspace
    connection, tenant, database_url, _, _ = db
    configure(db, 2)
    publication = authorize(db, *reviewed(workspace))
    target = version_ref(connection, second)
    live = authority_for({tenant.actor_id})
    checks = 0

    def stop_before_receipt(probe):
        nonlocal checks
        checks += 1
        if checks == 3:
            with open_database(database_url) as writer:
                effectivity.stop_synthetic_rule(
                    writer, record(writer, tenant, "stop_rule_use", "withdraw-while-searching"),
                    tenant.space_id, target, "withdrawn", uuid4(),
                )
        return live(probe)

    found = json.loads(search(db, "限额", include_wiki=True, authority=stop_before_receipt).payload)
    assert not found["wiki"] and [part["passage_id"] for part in found["passages"]] == [str(first.passage_ref)]
    assert checks == 4 and [event[1] for event in causes(connection, publication.ref)] == ["withdrawn"]


def test_replacement_invalidates_only_publications_whose_business_day_is_displaced(workspace, corpus):
    db, *_ = workspace
    _, _, _, second, _, prior = corpus
    connection, tenant, *_ = db
    configure(db, 2)
    publication = authorize(db, *reviewed(workspace))
    replacement, _, _ = publish(db, "allowance", "新版限额", b"# Travel\n\nNew allowance.\n",
                                source_version_key="rev-b", version_label="B")
    approve(connection, tenant, replacement, SWITCH, replaces=prior)
    assert not causes(connection, publication.ref)
    assert read_current(db).payload is not None

    original_approval, = connection.execute(
        """
        SELECT decision_ref FROM thalion.rule_effectivity AS rule
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (rule.org_id, rule.space_id, 'document_version', rule.version_id)
        WHERE identity.public_id = %s
        """, (version_ref(connection, second),),
    ).fetchone()
    new_approval, _, _ = publish(db, "approval", "新版审批", b"# Travel\n\nNew approval.\n",
                                 source_version_key="rev-b", version_label="B")
    successor = approve(connection, tenant, new_approval, BEFORE, replaces=original_approval)
    assert [entry[1:] for entry in causes(connection, publication.ref)] == [("rule_replaced", successor)]
    assert read_current(db).payload is None


def test_quarantine_is_atomic_with_wiki_stop_record(workspace, corpus):
    db, *_ = workspace
    _, _, _, _, approval_run, _ = corpus
    connection, *_ = db
    configure(db, 2)
    publication = authorize(db, *reviewed(workspace))
    connection.execute("ALTER TABLE thalion.wiki_availability_event ADD CONSTRAINT test_stop CHECK (false)")
    with pytest.raises(errors.CheckViolation):
        review(db, approval_run, decision="quarantined")
    assert read_current(db).payload is not None
    connection.execute("ALTER TABLE thalion.wiki_availability_event DROP CONSTRAINT test_stop")
    decision = review(db, approval_run, decision="quarantined")
    assert [entry[1:] for entry in causes(connection, publication.ref)] == [("quarantined", decision)]
    assert read_current(db).payload is None


def test_local_policy_replacement_permanently_stops_old_publication_even_if_reader_still_has_access(workspace):
    db, *_ = workspace
    connection, *_ = db
    configure(db, 2)
    publication = authorize(db, *reviewed(workspace))
    configure(db, 3)
    policy_ref, = connection.execute("SELECT policy_ref FROM thalion.policy_revision WHERE revision = 4").fetchone()
    assert [entry[1:] for entry in causes(connection, publication.ref)] == [("policy_changed", policy_ref)]
    assert read_current(db).payload is None
    assert len(json.loads(search(db, "限额", include_wiki=True).payload)["passages"]) == 1


def test_reprocessing_does_not_restore_the_old_wiki_even_after_new_excerpt_is_approved(workspace, corpus):
    db, *_ = workspace
    _, allowance, first, *_ = corpus
    connection, tenant, _, _, store = db
    configure(db, 2)
    publication = authorize(db, *reviewed(workspace))
    connection.execute(
        """
        INSERT INTO thalion.processing_config_revision
            (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
        """,
    )
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, allowance.version_ref, "parse", allowance.digest, 2))
    rerun = processing.process_markdown_job(connection, claim(db), store)
    assert [entry[1:] for entry in causes(connection, publication.ref)] == [("reprocessed", rerun.run_ref)]
    assert read_current(db).payload is None
    review(db, rerun)
    current, = approved(db, allowance)
    assert (current.passage_ref, current.revision) == (first.passage_ref, first.revision + 1)
    found = json.loads(search(db, "限额", include_wiki=True).payload)
    assert found["wiki"] == [] and found["passages"][0]["excerpt_revision"] == current.revision
