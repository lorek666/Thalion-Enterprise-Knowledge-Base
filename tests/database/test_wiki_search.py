from dataclasses import replace
from hashlib import sha256
import json
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence.processing import list_approved_passages
from enterprise_kb.modules.wiki.drafts import WikiStatement

from test_effectivity import BEGIN, BEFORE, approve as approve_rule
from test_evidence import evidence_db
from test_evidence_transport import add_search_source, bearer, evidence_transport, rpc, transport
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import open_database, runtime_db
from test_travel_search import SEARCH_FIELDS, corpus, publish, search
from test_wiki_drafts import candidate, preview, submit, workspace
from test_wiki_inputs import assemble, compile_rule
from test_wiki_publication import authorize, configure


def reviewed(workspace, *, structured=True):
    db, _, first, _ = workspace
    statements = (WikiStatement("上海住宿限额以原文为准。", (((first.passage_ref, first.revision),),)),)
    created = candidate(workspace, statements=statements if structured else ())
    assert created.status == "succeeded"
    review = submit(db, created.ref, preview(db, created.ref))
    assert review.status == "succeeded"
    return created.ref, review.ref


def test_http_and_mcp_deliver_same_claims_and_full_dependencies(transport):
    client, db, (employee, other), _, _, first, second = transport
    connection, tenant, *_ = db
    review = replace(compile_rule(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review")
    publication = replace(review, operation="publish_wiki_revision", purpose="wiki_publication")
    set_rules(db, compile_rule(tenant.actor_id), review, publication,
              replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
              replace(binding(tenant.other_actor_id, passage_ref=first.passage_ref), fields=SEARCH_FIELDS), expected=2)
    sealed = assemble(db, (first, second))
    revision, decision = reviewed((db, sealed, first, second))
    published = authorize(db, revision, decision)
    assert published.status == "succeeded"

    args = {"query": "限额", "business_date": BEFORE.isoformat(), "top_k": 1, "include_wiki": True}
    http = client.post("/v1/search", json=args, headers=bearer(employee))
    tool = rpc(client, employee, "tools/call", name="search", arguments=args).json()["result"]
    assert http.status_code == 200 and not tool["isError"]
    expected = http.json()
    structured = tool["structuredContent"]
    assert json.loads(tool["content"][0]["text"]) == structured
    assert structured | {"request_id": expected["request_id"]} == expected
    assert [part["passage_id"] for part in expected["passages"]] == [str(first.passage_ref)]
    assert len(expected["wiki"]) == 1
    assert expected["wiki"] == [{
        "source_type": "wiki", "wiki_id": str(connection.execute("SELECT wiki_ref FROM thalion.wiki").fetchone()[0]),
        "revision_id": str(revision), "title": "本地差旅",
        "claims": [{"text": "上海住宿限额以原文为准。", "passage_ids": [str(first.passage_ref)]}],
    }]
    for request_id, body in ((expected["request_id"], http.content),
                             (structured["request_id"], tool["content"][0]["text"].encode())):
        rows = connection.execute(
            """
            SELECT payload_digest, wiki_publication_ref, passage_ref, excerpt_revision
            FROM thalion.delivery_record JOIN thalion.delivery_dependency USING (check_id, org_id)
            WHERE request_id = %s ORDER BY position
            """, (request_id,),
        ).fetchall()
        assert rows == [(sha256(body).digest(), published.ref, part.passage_ref, part.revision)
                        for part in (first, second)]

    restricted = client.post("/v1/search", json=args, headers=bearer(other)).json()
    assert restricted["wiki"] == [] and restricted["passages"] == expected["passages"]
    opted_out = client.post("/v1/search", json=args | {"include_wiki": False}, headers=bearer(employee)).json()
    assert opted_out["wiki"] == [] and opted_out["passages"] == expected["passages"]

    same_source = client.post(
        "/v1/search", json=args | {"source_ids": [str(db[3])]}, headers=bearer(employee),
    ).json()
    assert same_source | {"request_id": expected["request_id"]} == expected
    other_source, passage = add_search_source(db)
    scoped = client.post(
        "/v1/search", json=args | {"source_ids": [str(other_source)]}, headers=bearer(employee),
    ).json()
    assert scoped["wiki"] == [] and [part["passage_id"] for part in scoped["passages"]] == [str(passage.passage_ref)]


def test_source_filter_excludes_wiki_with_an_uncited_input_from_another_source(transport):
    client, db, (employee, _), _, _, first, _ = transport
    connection, tenant, database_url, source, store = db
    other_source, other_passage = add_search_source(db)
    configure(db, 2)
    configure((connection, tenant, database_url, other_source, store), 2)
    sealed = assemble(db, (first, other_passage))
    assert sealed.status == "succeeded"
    revision, review = reviewed((db, sealed, first, other_passage))
    assert authorize(db, revision, review).status == "succeeded"

    args = {"query": "限额", "business_date": BEFORE.isoformat(), "include_wiki": True}
    scoped = client.post(
        "/v1/search", json=args | {"source_ids": [str(source)]}, headers=bearer(employee),
    )
    assert scoped.status_code == 200
    assert [part["passage_id"] for part in scoped.json()["passages"]] == [str(first.passage_ref)]
    assert scoped.json()["wiki"] == []

    combined = client.post(
        "/v1/search", json=args | {"source_ids": [str(source), str(other_source)]}, headers=bearer(employee),
    )
    assert combined.status_code == 200
    assert {part["passage_id"] for part in combined.json()["passages"]} == {
        str(first.passage_ref), str(other_passage.passage_ref),
    }
    assert [wiki["revision_id"] for wiki in combined.json()["wiki"]] == [str(revision)]
    assert combined.json()["wiki"][0]["claims"][0]["passage_ids"] == [str(first.passage_ref)]


def test_legacy_published_markdown_is_not_a_search_claim(workspace):
    db, *_ = workspace
    configure(db, 2)
    assert authorize(db, *reviewed(workspace, structured=False)).status == "succeeded"
    found = search(db, "限额", include_wiki=True)
    assert json.loads(found.payload)["wiki"] == []


def test_local_policy_change_makes_publication_ineligible_without_hiding_originals(workspace):
    db, *_ = workspace
    configure(db, 2)
    assert authorize(db, *reviewed(workspace)).status == "succeeded"
    configure(db, 3)
    found = search(db, "限额", include_wiki=True)
    body = json.loads(found.payload)
    assert body["wiki"] == [] and len(body["passages"]) == 1


def test_wiki_receipt_is_rejected_when_an_uncited_dependency_is_missing(workspace):
    db, *_ = workspace
    connection, tenant, *_ = db
    configure(db, 2)
    published = authorize(db, *reviewed(workspace))
    assert published.status == "succeeded"
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    incomplete = uuid4()
    with pytest.raises(errors.CheckViolation, match="all exact published dependencies"):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.delivery_record (
                    org_id, request_id, check_id, dependency_count, payload_digest, proof_digest,
                    checked_at, valid_until, wiki_publication_ref
                ) VALUES (%s, %s, %s, 1, %s, %s, clock_timestamp(), clock_timestamp() + interval '1 second', %s)
                """, (tenant.org_id, context.request_id, incomplete, bytes(32), bytes(32), published.ref),
            )
            connection.execute(
                """
                INSERT INTO thalion.delivery_dependency
                SELECT %s, dependency.org_id, position, dependency.space_id, source_id, passage_ref, excerpt_revision,
                       policy_revision, organization_epoch, space_epoch, source_epoch
                FROM thalion.wiki_publication_event JOIN thalion.delivery_dependency AS dependency USING (org_id, check_id)
                WHERE publication_ref = %s AND position = 1
                """, (incomplete, published.ref),
            )
    assert connection.execute(
        "SELECT 1 FROM thalion.delivery_record WHERE request_id = %s", (context.request_id,),
    ).fetchone() is None


def test_uncited_dependency_revoked_during_delivery_keeps_original(workspace):
    db, _, first, second = workspace
    connection, tenant, *_ = db
    configure(db, 2)
    assert authorize(db, *reviewed(workspace)).status == "succeeded"
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    live = authority_for({tenant.actor_id})
    calls = 0

    def authority(probe):
        nonlocal calls
        calls += 1
        proof = live(probe)
        if calls >= 3:
            return replace(proof, permitted_fields={
                scope: fields if scope.object_id != second.passage_ref else frozenset()
                for scope, fields in proof.permitted_fields.items()
            })
        return proof

    found = search(db, "限额", context=context, include_wiki=True, authority=authority)
    body = json.loads(found.payload)
    assert calls >= 4 and body["wiki"] == []
    assert [part["passage_id"] for part in body["passages"]] == [str(first.passage_ref)]
    assert connection.execute(
        "SELECT dependency_count, wiki_publication_ref FROM thalion.delivery_record WHERE request_id = %s",
        (context.request_id,),
    ).fetchone() == (1, None)


def test_authority_outage_is_not_plain_rag_fallback(workspace):
    db, *_ = workspace
    connection, tenant, *_ = db
    configure(db, 2)
    assert authorize(db, *reviewed(workspace)).status == "succeeded"
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    live = authority_for({tenant.actor_id})
    calls = 0

    def authority(probe):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise AuthorizationUnavailable()
        return live(probe)

    found = search(db, "限额", context=context, include_wiki=True, authority=authority)
    assert (found.status, found.payload) == ("dependency_unavailable", None)
    assert connection.execute(
        "SELECT 1 FROM thalion.delivery_record WHERE request_id = %s", (context.request_id,),
    ).fetchone() is None


def test_publication_switch_during_final_check_cannot_deliver_old_claims(workspace):
    db, *_ = workspace
    connection, tenant, database_url, source, store = db
    configure(db, 2)
    assert authorize(db, *reviewed(workspace)).status == "succeeded"
    replacement = reviewed(workspace)
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    live = authority_for({tenant.actor_id})
    calls = 0

    def authority(probe):
        nonlocal calls
        calls += 1
        if calls == 3:
            with open_database(database_url) as writer:
                assert authorize((writer, tenant, database_url, source, store), *replacement).status == "succeeded"
        return live(probe)

    raced = search(db, "限额", context=context, include_wiki=True, authority=authority)
    assert json.loads(raced.payload)["wiki"] == []
    assert connection.execute(
        "SELECT wiki_publication_ref FROM thalion.delivery_record WHERE request_id = %s", (context.request_id,),
    ).fetchone() == (None,)
    current = json.loads(search(db, "限额", include_wiki=True).payload)["wiki"]
    assert current[0]["revision_id"] == str(replacement[0])


def test_original_top_k_and_complete_wiki_manifest_fit_one_delivery(evidence_db):
    db = evidence_db
    connection, tenant, *_ = db
    versions = []
    for key, tag in (("allowance", "限额"), ("approval", "审批")):
        markdown = "# 差旅\n\n" + "\n\n".join(f"上海住宿{tag}第 {index} 项。" for index in range(20))
        version, _, _ = publish(db, key, "差旅", markdown.encode())
        approve_rule(connection, tenant, version, BEGIN)
        versions.append(version.version_ref)
    configure(db, 1)
    original, dependencies = [list_approved_passages(connection, tenant.org_id, tenant.space_id, version)
                              for version in versions]
    sealed = assemble(db, dependencies)
    created = candidate((db, sealed, dependencies[0], dependencies[-1]), statements=(WikiStatement(
        "上海住宿限额涉及审批。", (((dependencies[0].passage_ref, dependencies[0].revision),),),
    ),))
    approval = submit(db, created.ref, preview(db, created.ref))
    assert authorize(db, created.ref, approval.ref).status == "succeeded"
    context = ingress(db, tenant.actor_id, BEFORE, operation="search")
    result = search(db, "限额", context=context, top_k=20, include_wiki=True)
    body = json.loads(result.payload)
    assert len(body["passages"]) == 20 and len(body["wiki"]) == 1
    assert set(connection.execute(
        """
        SELECT passage_ref FROM thalion.delivery_record JOIN thalion.delivery_dependency USING (check_id, org_id)
        WHERE request_id = %s
        """, (context.request_id,),
    ).fetchall()) == {(part.passage_ref,) for part in original + dependencies}
