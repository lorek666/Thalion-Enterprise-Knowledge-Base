from dataclasses import replace
from hashlib import sha256
import json
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.wiki import drafts

from test_effectivity import BEFORE
from test_evidence import evidence_db
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import runtime_db
from test_travel_search import corpus
from test_wiki_inputs import assemble, compile_rule


@pytest.fixture
def workspace(corpus):
    db, _, first, second, *_ = corpus
    _, tenant, *_ = db
    review_grant = replace(binding(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review",
                           destination="local_workspace")
    set_rules(db, compile_rule(tenant.actor_id), review_grant)
    sealed = assemble(db, (first, second))
    assert sealed.status == "succeeded"
    return db, sealed, first, second


def request(db, employee, operation):
    return ingress(db, employee, BEFORE, operation=operation, destination="local_workspace",
                   purpose="wiki_compilation" if operation == "create_wiki_candidate" else "wiki_review")


def candidate(workspace, *, actor=None, reviewer=None, cited=None, authority=None, key=None, topic="travel", **content):
    db, sealed, first, _ = workspace
    connection, tenant, *_ = db
    actor = actor or tenant.actor_id
    return drafts.create_manual_candidate(
        connection, request(db, actor, "create_wiki_candidate"), tenant.space_id,
        drafts.ManualCandidate(
            topic, "本地差旅", "## 住宿\n按上海差旅限额执行。", sealed.manifest_ref,
            reviewer or tenant.other_actor_id, uuid4() if key is None else key,
            tuple(cited if cited is not None else ((first.passage_ref, first.revision),)),
            **content,
        ), str(uuid4()) if key is None else str(key), region="shanghai", traveler_class="employee",
        check_authority=authority or authority_for({actor}),
    )


def preview(db, revision, *, actor=None, authority=None):
    connection, tenant, *_ = db
    actor = actor or tenant.other_actor_id
    return drafts.read_candidate_for_review(
        connection, request(db, actor, "read_wiki_candidate"), tenant.space_id, revision,
        region="shanghai", traveler_class="employee", check_authority=authority or authority_for({actor}),
    )


def submit(db, revision, reviewed, *, decision="approved", actor=None, authority=None, content_digest=None):
    connection, tenant, *_ = db
    actor = actor or tenant.other_actor_id
    return drafts.submit_review(
        connection, request(db, actor, "review_wiki_revision"), tenant.space_id, revision,
        content_digest or sha256(reviewed.payload).digest(), reviewed.input_digest, decision, "checked_sources",
        uuid4(), str(uuid4()), review_material_ref=reviewed.review_material_ref, region="shanghai", traveler_class="employee",
        check_authority=authority or authority_for({actor}),
    )


def test_manual_candidate_and_review_preserve_exact_draft_and_complete_inputs(workspace):
    db, sealed, first, second = workspace
    connection, tenant, *_ = db
    created = candidate(workspace)
    assert created.status == "succeeded" and created.payload is None
    reviewed = preview(db, created.ref)
    assert reviewed.status == "succeeded"
    assert json.loads(reviewed.payload) == {
        "title": "本地差旅", "markdown": "## 住宿\n按上海差旅限额执行。",
        "citations": [[str(first.passage_ref), first.revision]],
    }
    submitted = submit(db, created.ref, reviewed)
    assert submitted.status == "succeeded" and submitted.payload is None
    assert connection.execute(
        """
        SELECT manuscript.author_id, manuscript.manifest_ref, manuscript.authorship,
               review.reviewer_id, review.decision, review.content_digest
        FROM thalion.wiki_revision AS manuscript JOIN thalion.wiki_review AS review USING (revision_ref)
        """,
    ).fetchone() == (tenant.actor_id, sealed.manifest_ref, "manual", tenant.other_actor_id,
                     "approved", sha256(reviewed.payload).digest())
    assert connection.execute(
        """
        SELECT entry.passage_ref FROM thalion.wiki_review AS review
        JOIN thalion.delivery_dependency AS entry USING (check_id, org_id) ORDER BY position
        """,
    ).fetchall() == [(first.passage_ref,), (second.passage_ref,)]
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.wiki_revision SET content = %s", (b'{}',))


def test_wrong_author_reviewer_or_citation_cannot_create_or_review(workspace):
    db, _, _, _ = workspace
    connection, tenant, *_ = db
    assert candidate(workspace, actor=tenant.other_actor_id).status == "rejected"
    assert candidate(workspace, reviewer=tenant.actor_id).status == "rejected"
    assert candidate(workspace, cited=((uuid4(), 1),)).status == "rejected"
    created = candidate(workspace)
    reviewed = preview(db, created.ref)
    assert preview(db, created.ref, actor=tenant.actor_id).payload is None
    assert submit(db, created.ref, reviewed, actor=tenant.actor_id).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.wiki_review").fetchone() == (0,)


def test_statement_support_must_be_explicit_and_exact(workspace):
    db, _, first, second = workspace
    exact = (first.passage_ref, first.revision)
    other = (second.passage_ref, second.revision)
    for groups in ((), ((),), (((first.passage_ref, first.revision + 1),),), ((exact,), (other,))):
        result = candidate(workspace, statements=(drafts.WikiStatement("上海住宿限额。", groups),))
        assert result.status == "rejected"

    statement = drafts.WikiStatement("上海住宿限额。", ((exact,),))
    created = candidate(workspace, statements=(statement,))
    assert created.status == "succeeded"
    material = preview(db, created.ref)
    assert json.loads(material.payload)["statements"] == [{
        "text": statement.text, "support_groups": [[[str(first.passage_ref), first.revision]]],
    }]
    amended = candidate(workspace, statements=(replace(statement, text="上海住宿限额另见原文。"),))
    assert submit(db, amended.ref, material).status == "input_changed"
    assert submit(db, created.ref, material).status == "succeeded"


def test_uncited_source_revocation_blocks_preview_and_review_after_it_was_seen(workspace):
    db, _, first, second = workspace
    connection, tenant, *_ = db
    created = candidate(workspace, statements=(drafts.WikiStatement(
        "上海住宿限额。", (((first.passage_ref, first.revision),),),
    ),))
    reviewed = preview(db, created.ref)
    live = authority_for({tenant.other_actor_id})

    def revoke_uncited(probe):
        allowed = live(probe)
        return replace(allowed, permitted_fields={
            scope: fields if scope.object_id != second.passage_ref else frozenset()
            for scope, fields in allowed.permitted_fields.items()
        })

    denied = preview(db, created.ref, authority=revoke_uncited)
    assert (denied.status, denied.payload) == ("rejected", None)
    assert submit(db, created.ref, reviewed, authority=revoke_uncited).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.wiki_review").fetchone() == (0,)


def test_review_binds_exact_content_and_rejection_cannot_be_overwritten(workspace):
    db, _, _, _ = workspace
    connection, *_ = db
    created = candidate(workspace)
    reviewed = preview(db, created.ref)
    assert submit(db, created.ref, reviewed, content_digest=bytes(32)).status == "input_changed"
    assert submit(db, created.ref, reviewed, decision="rejected").status == "succeeded"
    assert submit(db, created.ref, reviewed).status == "input_changed"
    assert connection.execute("SELECT decision FROM thalion.wiki_review").fetchall() == [("rejected",)]


def test_candidate_replay_rechecks_permissions_and_does_not_duplicate(workspace):
    db, _, _, _ = workspace
    connection, *_ = db
    key = uuid4()
    first = candidate(workspace, key=key)
    assert candidate(workspace, key=key).ref == first.ref
    assert candidate(workspace, key=key, authority=authority_for(set())).status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.wiki_revision").fetchone() == (1,)


def test_matching_digests_do_not_replace_a_review_preview(workspace):
    db, _, _, _ = workspace
    connection, *_ = db
    created = candidate(workspace)
    content_digest, input_digest = connection.execute(
        "SELECT content_digest, input_digest FROM thalion.wiki_revision WHERE revision_ref = %s", (created.ref,),
    ).fetchone()
    rejected = submit(db, created.ref, drafts.WikiResult("succeeded", input_digest=input_digest),
                      content_digest=content_digest)
    assert rejected.status == "rejected"
    assert connection.execute("SELECT count(*) FROM thalion.wiki_review").fetchone() == (0,)


def test_review_rolls_back_with_its_receipt_when_its_event_cannot_append(workspace):
    db, _, _, _ = workspace
    connection, *_ = db
    created = candidate(workspace)
    reviewed = preview(db, created.ref)
    receipt_count = connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone()
    connection.execute("ALTER TABLE thalion.outbox_event ADD CHECK (event_type <> 'wiki.revision.reviewed')")
    assert submit(db, created.ref, reviewed).status == "dependency_unavailable"
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == receipt_count
    assert connection.execute("SELECT count(*) FROM thalion.wiki_review").fetchone() == (0,)
    assert connection.execute(
        "SELECT count(*) FROM thalion.command_receipt WHERE operation = 'review_wiki_revision'",
    ).fetchone() == (0,)
