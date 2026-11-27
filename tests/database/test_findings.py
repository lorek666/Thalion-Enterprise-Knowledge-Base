from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.wiki.drafts import WikiStatement

from test_effectivity import BEFORE
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_identity import space
from test_runtime import runtime_db
from test_travel_search import corpus
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble
from test_wiki_publication import authorize, configure


PATH = "/internal/feedback/findings"
CAPABILITY = "emit_finding"
LEFT = "合成甲侧"
RIGHT = "合成乙侧"


def publish_topic(db, topic, claim, cited, *other_inputs):
    sealed = assemble(db, (cited, *other_inputs))
    assert sealed.status == "succeeded"
    exact = (cited.passage_ref, cited.revision)
    created = candidate((db, sealed, cited, None), topic=topic, statements=(WikiStatement(claim, ((exact,),)),))
    assert created.status == "succeeded"
    approved = submit(db, created.ref, preview(db, created.ref))
    assert approved.status == "succeeded"
    assert authorize(db, created.ref, approved.ref).status == "succeeded"
    return created.ref


def find_wiki(client, token, query, *, via_mcp=False, include_wiki=True):
    arguments = {"query": query, "business_date": BEFORE.isoformat(), "include_wiki": include_wiki}
    if via_mcp:
        response = rpc(client, token, "tools/call", name="search", arguments=arguments)
        assert response.status_code == 200
        return response.json()["result"]["structuredContent"]
    response = client.post("/v1/search", headers=bearer(token), json=arguments)
    assert response.status_code == 200
    return response.json()


@pytest.fixture
def conflict(transport):
    client, db, (owner, _), _, _, first, second = transport
    configure(db, 2)
    left_candidate = publish_topic(db, "first-rule", f"{LEFT}：上限 400 元/晚。", first, second)
    right_candidate = publish_topic(db, "second-rule", f"{RIGHT}：上限 400 元/次。", second)
    left = find_wiki(client, owner, LEFT)
    right = find_wiki(client, owner, RIGHT, via_mcp=True)
    assert [item["revision_id"] for item in left["wiki"]] == [str(left_candidate)]
    assert [item["revision_id"] for item in right["wiki"]] == [str(right_candidate)]
    return transport, (observed(left), observed(right)), (left_candidate, right_candidate)


def observed(reply):
    return {"request_id": reply["request_id"], "revision_id": reply["wiki"][0]["revision_id"]}


def report(client, token, origins, key=None, **attributes):
    return client.post(PATH, headers=command_headers(token, key), json={
        "observations": list(origins), "rule": "unit_mismatch", **attributes,
    })


def test_finding_deduplicates_both_orders_and_keeps_all_inputs(conflict):
    (client, db, (owner, _), credentials, _, first, second), origins, (left, right) = conflict
    connection, tenant, *_ = db
    admit(credentials, owner, CAPABILITY)
    stable_key = str(uuid4())
    response = report(client, owner, origins, stable_key)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert set(response.json()) == {"request_id", "finding_id"}
    finding = response.json()["finding_id"]
    assert report(client, owner, origins[::-1], stable_key).json()["finding_id"] == finding
    assert report(client, owner, origins[::-1]).json()["finding_id"] == finding
    assert report(client, owner, origins, stable_key, rule="statement_conflict").status_code == 409
    rediscovered = observed(find_wiki(client, owner, LEFT))
    assert report(client, owner, (rediscovered, origins[1])).json()["finding_id"] == finding
    assert connection.execute(
        "SELECT finding_ref, business_date, rule, initial_owner_id FROM thalion.lint_finding",
    ).fetchall() == [(UUID(finding), BEFORE, "unit_mismatch", tenant.actor_id)]
    assert connection.execute("SELECT count(*) FROM thalion.lint_finding_observation").fetchone() == (2,)
    assert set(connection.execute(
        "SELECT finding_ref, revision_ref FROM thalion.lint_finding_revision",
    ).fetchall()) == {(UUID(finding), left), (UUID(finding), right)}
    assert set(connection.execute(
        "SELECT revision_ref, passage_ref, excerpt_revision FROM thalion.lint_finding_input",
    ).fetchall()) == {
        (left, first.passage_ref, first.revision), (left, second.passage_ref, second.revision),
        (right, second.passage_ref, second.revision),
    }
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.lint_finding_observation")


def test_finding_rejects_unauthorized_incomplete_or_cross_space_pairs(conflict):
    (client, db, (owner, employee), credentials, _, *_), origins, (left, _) = conflict
    connection, tenant, *_ = db
    assert report(client, owner, origins).status_code == 403
    admit(credentials, owner, CAPABILITY)
    admit(credentials, employee, CAPABILITY)
    refused = report(client, employee, origins)
    assert refused.status_code == 403
    assert report(client, owner, (origins[0],)).status_code == 400
    assert report(client, owner, (origins[0], origins[0])).status_code == 400
    assert report(client, owner, origins, auto_close=True).status_code == 400
    assert report(client, owner, (origins[0], origins[1] | {"request_id": str(left)})).status_code == 403
    mismatch = (origins[0], origins[1] | {"revision_id": str(left)})
    assert report(client, owner, mismatch).json()["error"] == refused.json()["error"]
    duplicate_side = observed(find_wiki(client, owner, LEFT, via_mcp=True))
    assert report(client, owner, (origins[0], duplicate_side)).status_code == 403
    rag_only = find_wiki(client, owner, "上海住宿", include_wiki=False)["request_id"]
    assert report(client, owner, (origins[0], origins[1] | {"request_id": rag_only})).status_code == 403
    with connection.transaction():
        _, other_space = space(connection, tenant.org_id, tenant.actor_id)
    credentials[owner] = replace(credentials[owner], space_ref=other_space)
    assert report(client, owner, origins).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.lint_finding").fetchone() == (0,)


def test_exact_links_survive_later_publication_and_cannot_exist_without_observation(conflict):
    (client, db, (owner, _), credentials, _, _, second), origins, revisions = conflict
    connection, tenant, *_ = db
    admit(credentials, owner, CAPABILITY)
    low_revision, high_revision = sorted(revisions)
    with pytest.raises(errors.CheckViolation, match="at least one verified observation"):
        connection.execute(
            """
            INSERT INTO thalion.lint_finding (
                org_id, space_id, business_date, rule, first_revision_ref, second_revision_ref, initial_owner_id
            ) VALUES (%s, %s, %s, 'unit_mismatch', %s, %s, %s)
            """, (tenant.org_id, tenant.space_id, BEFORE, low_revision, high_revision, tenant.actor_id),
        )
    response = report(client, owner, origins)
    assert response.status_code == 200
    replaced = publish_topic(db, "second-rule", f"{RIGHT}：上限改按每晚。", second)
    assert observed(find_wiki(client, owner, RIGHT))["revision_id"] == str(replaced)
    assert report(client, owner, origins).json()["finding_id"] == response.json()["finding_id"]
    assert set(connection.execute("SELECT revision_ref FROM thalion.lint_finding_revision").fetchall()) == {
        (revision,) for revision in revisions
    }


def test_finding_and_both_protection_links_roll_back_on_outbox_failure(conflict):
    (client, db, (owner, _), credentials, _, *_), origins, _ = conflict
    connection, *_ = db
    admit(credentials, owner, CAPABILITY)
    connection.execute(
        "ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_finding_event "
        "CHECK (event_type <> 'operations.finding.observed') NOT VALID"
    )
    stable_key = str(uuid4())
    assert report(client, owner, origins, stable_key).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.lint_finding_revision").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.lint_finding_observation").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_finding_event")
    assert report(client, owner, origins, stable_key).status_code == 200
    assert connection.execute("SELECT count(*) FROM thalion.lint_finding_revision").fetchone() == (2,)


def test_concurrent_reports_cannot_create_duplicate_observations(conflict):
    (client, db, (owner, _), credentials, _, *_), origins, _ = conflict
    connection, *_ = db
    admit(credentials, owner, CAPABILITY)
    with ThreadPoolExecutor(max_workers=2) as workers:
        pending = [workers.submit(report, client, owner, order) for order in (origins, origins[::-1])]
        replies = [attempt.result(timeout=10) for attempt in pending]
    assert all(reply.status_code == 200 for reply in replies)
    assert len({reply.json()["finding_id"] for reply in replies}) == 1
    assert connection.execute("SELECT count(*) FROM thalion.lint_finding_observation").fetchone() == (1,)
    assert connection.execute(
        "SELECT count(*) FROM thalion.outbox_event WHERE event_type = 'operations.finding.observed'",
    ).fetchone() == (1,)
