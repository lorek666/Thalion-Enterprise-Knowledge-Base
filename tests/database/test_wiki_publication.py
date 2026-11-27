from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from threading import Barrier
from uuid import uuid4

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.modules.wiki import publication

from test_effectivity import BEFORE, record
from test_evidence import evidence_db
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import corpus
from test_wiki_drafts import candidate, preview, submit, workspace
from test_wiki_inputs import compile_rule


FIELDS = frozenset({"excerpt", "citation", "title", "location", "version"})


def configure(db, expected):
    _, tenant, *_ = db
    review = replace(binding(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review",
                     destination="local_workspace")
    publish = replace(review, operation="publish_wiki_revision", purpose="wiki_publication")
    read = replace(binding(tenant.actor_id), fields=FIELDS)
    set_rules(db, compile_rule(tenant.actor_id), review, publish, read, expected=expected)


def authorize(db, revision, review_ref, *, actor=None, authority=None, key=None):
    connection, tenant, *_ = db
    actor = actor or tenant.other_actor_id
    context = ingress(db, actor, BEFORE, operation="publish_wiki_revision", purpose="wiki_publication",
                      destination="local_workspace")
    return publication.publish_revision(
        connection, context, tenant.space_id, revision, review_ref, key or str(uuid4()),
        region="shanghai", traveler_class="employee", check_authority=authority or authority_for({actor}),
    )


def read_current(db, *, actor=None, authority=None):
    connection, tenant, *_ = db
    actor = actor or tenant.actor_id
    return publication.read_current_revision(
        connection, ingress(db, actor, BEFORE, operation="read_published_wiki"), tenant.space_id, "travel",
        region="shanghai", traveler_class="employee", check_authority=authority or authority_for({actor}),
    )


def approve(workspace):
    db, *_ = workspace
    revision = candidate(workspace).ref
    material = preview(db, revision)
    reviewed = submit(db, revision, material)
    assert reviewed.status == "succeeded"
    return revision, reviewed.ref


def test_approval_is_not_publication_and_published_reads_use_employee_authorization(workspace):
    db, *_ = workspace
    connection, tenant, *_ = db
    configure(db, 2)
    revision, approval = approve(workspace)
    assert read_current(db).payload is None
    assert authorize(db, revision, approval, actor=tenant.actor_id).status == "rejected"
    assert authorize(db, revision, approval).status == "succeeded"
    assert read_current(db, actor=tenant.other_actor_id).payload is None
    delivery = read_current(db)
    assert delivery.ref == revision and json.loads(delivery.payload)["title"] == "本地差旅"
    assert connection.execute("SELECT generation FROM thalion.wiki_publication_event").fetchall() == [(1,)]


def test_publication_rechecks_uncited_sources_and_rejects_old_review_after_policy_change(workspace):
    db, _, _, second = workspace
    _, tenant, *_ = db
    configure(db, 2)
    revision, approval = approve(workspace)
    live = authority_for({tenant.other_actor_id})

    def revoke_uncited(probe):
        allowed = live(probe)
        return replace(allowed, permitted_fields={
            scope: fields if scope.object_id != second.passage_ref else frozenset()
            for scope, fields in allowed.permitted_fields.items()
        })

    assert authorize(db, revision, approval, authority=revoke_uncited).status == "rejected"
    configure(db, 3)
    assert authorize(db, revision, approval).status == "input_changed"
    assert read_current(db).payload is None


def test_competing_publications_accept_only_one_review_for_the_same_pointer(workspace):
    db, *_ = workspace
    connection, tenant, database_url, source, store = db
    configure(db, 2)
    plans = [approve(workspace), approve(workspace)]
    ready = Barrier(2, timeout=5)

    def publish(plan):
        with open_database(database_url) as writer:
            ready.wait()
            return authorize((writer, tenant, database_url, source, store), *plan)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, plans))
    assert sorted(result.status for result in results) == ["input_changed", "succeeded"]
    winner, = connection.execute("SELECT revision_ref FROM thalion.wiki_publication_event").fetchall()
    assert read_current(db).ref == winner[0]


def test_withdrawal_and_authority_outage_never_return_published_body(workspace):
    db, _, _, second = workspace
    connection, tenant, *_ = db
    configure(db, 2)
    revision, approval = approve(workspace)
    assert authorize(db, revision, approval).status == "succeeded"
    live = authority_for({tenant.actor_id})

    def revoke_uncited(probe):
        permitted = live(probe)
        return replace(permitted, permitted_fields={
            scope: fields if scope.object_id != second.passage_ref else frozenset()
            for scope, fields in permitted.permitted_fields.items()
        })

    assert read_current(db, authority=revoke_uncited).payload is None

    def outage(probe):
        raise AuthorizationUnavailable()

    denied = read_current(db, authority=outage)
    assert (denied.status, denied.payload) == ("dependency_unavailable", None)
    version_ref, = connection.execute(
        """
        SELECT version_ref.public_id FROM thalion.object_identity AS part_ref
        JOIN thalion.passage AS part ON part.passage_id = part_ref.object_id
        JOIN thalion.object_identity AS version_ref ON version_ref.object_id = part.version_id
        WHERE part_ref.public_id = %s AND version_ref.object_type = 'document_version'
        """, (second.passage_ref,),
    ).fetchone()
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", str(uuid4())), tenant.space_id,
        version_ref, "withdrawn", uuid4(),
    )
    assert read_current(db).payload is None


def test_preview_from_an_older_pointer_must_be_redone_before_approval(workspace):
    db, *_ = workspace
    configure(db, 2)
    waiting = candidate(workspace).ref
    stale = preview(db, waiting)
    first, approval = approve(workspace)
    assert authorize(db, first, approval).status == "succeeded"
    assert submit(db, waiting, stale).status == "input_changed"
    fresh = preview(db, waiting)
    assert (stale.expected_generation, fresh.expected_generation) == (0, 1)
    reviewed = submit(db, waiting, fresh)
    assert authorize(db, waiting, reviewed.ref).status == "succeeded"
    assert read_current(db).ref == waiting


def test_current_read_does_not_deliver_superseded_payload_during_pointer_change(workspace):
    db, *_ = workspace
    connection, tenant, database_url, source, store = db
    configure(db, 2)
    first, first_review = approve(workspace)
    assert authorize(db, first, first_review).status == "succeeded"
    second, second_review = approve(workspace)
    live = authority_for({tenant.actor_id})
    checks = 0

    def replace_during_final_check(probe):
        nonlocal checks
        checks += 1
        if checks == 2:
            with open_database(database_url) as writer:
                writer_db = (writer, tenant, database_url, source, store)
                assert authorize(writer_db, second, second_review).status == "succeeded"
        return live(probe)

    raced = read_current(db, authority=replace_during_final_check)
    assert (raced.status, raced.payload) == ("input_changed", None)
    assert connection.execute(
        """
        SELECT count(*) FROM thalion.delivery_record AS delivery JOIN thalion.request_record USING (org_id, request_id)
        WHERE operation = 'read_published_wiki'
        """,
    ).fetchone() == (0,)
    assert read_current(db).ref == second
