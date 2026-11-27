from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.modules.sources import (
    effectivity, reconciliation, registry, source_restrictions, sync,
)
from enterprise_kb.modules.wiki import publication
from enterprise_kb.modules.wiki.drafts import WikiStatement
from enterprise_kb.runtime.jobs import claim_job

from test_deletion_tombstone import (
    REGISTER as REGISTER_TOMBSTONE, approved as approve_disposition, register as register_tombstone, submitted,
)
from test_disposition import configure as configure_retention, plan as plan_disposition
from test_disposition_copy_receipts import OBSERVE as OBSERVE_COPIES, capture as capture_copies, presence
from test_disposition_verification import original
from test_effectivity import BEFORE, BEGIN, SWITCH, approve as approve_rule, record
from test_employee_original_download import OPERATION as DOWNLOAD_OP, download_path
from test_evidence import approved as approve_quality, claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_identity import migrate_to_revision
from test_ingest_transport import MARKDOWN, file as ingest_file, upload
from test_lexical_index import build as build_lexical_index
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import LEASE_FOR, open_database, register_tenant, runtime_db
from test_source_reconciliation import manifest, reconcile
from test_source_sync import sync_request
from test_sources import CONTENT, OTHER_CONTENT, candidate as version_candidate, source_for
from test_travel_search import SEARCH_FIELDS, corpus, publish
from test_wiki_drafts import candidate as wiki_candidate, preview as wiki_preview, submit as wiki_submit
from test_wiki_inputs import assemble, compile_rule
from test_wiki_invalidation import causes
from test_wiki_publication import authorize as publish_wiki, configure as configure_wiki


WIKI_DOC_TEXT = b"# Expense Note EXP-WIKI\n\nExpense EXP-WIKI note for travel wiki.\n"
EXP_TEXT = b"# Expense EXP-017\n\nExpense EXP-017 hotel amount 125.00 CNY.\n"
CONTROL_TEXT = b"# Control Expense EXP-099\n\nControl EXP-099 hotel amount 200.00 CNY.\n"
REBORN_TEXT = b"# Reborn Expense EXP-017\n\nReborn EXP-017 second incarnation 300.00 CNY.\n"
FRESH_TEXT = b"# Fresh Policy\n\nFresh policy after deletion.\n"


def _approve_and_index(db, version_ref, *, valid_from=BEGIN, valid_to=None, replaces_ref=None, key_suffix=""):
    connection, tenant, _, _, store = db
    processor_id, = connection.execute("""
        SELECT contract.processor_id
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id) =
             (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id) =
             (version.org_id, version.space_id, version.source_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
    """, (tenant.org_id, tenant.space_id, version_ref)).fetchone()
    while True:
        lease = claim_job(connection, tenant.org_id, "parse", processor_id, LEASE_FOR)
        assert lease is not None
        run_ref = processing.process_markdown_job(connection, lease, store)
        if lease.spec.target_ref == version_ref:
            break
    review(db, run_ref)
    passages = approve_quality(db, SimpleNamespace(version_ref=version_ref))
    effectivity_ref = approve_rule(
        connection, tenant, SimpleNamespace(version_ref=version_ref), valid_from,
        replaces=replaces_ref, end=valid_to,
    )
    index_ref = build_lexical_index(db, SimpleNamespace(version_ref=version_ref), run_ref)
    return passages[0], run_ref, effectivity_ref, index_ref


def _read_topic(db, topic, *, day=BEFORE):
    connection, tenant, *_ = db
    return publication.read_current_revision(
        connection, ingress(db, tenant.actor_id, day, operation="read_published_wiki"),
        tenant.space_id, topic, region="shanghai", traveler_class="employee",
        check_authority=authority_for({tenant.actor_id}),
    )


def _configure_wiki_and_original(db, version_ref, expected=2):
    _, tenant, *_ = db
    review_rule = replace(
        binding(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review",
        destination="local_workspace",
    )
    publish_rule = replace(review_rule, operation="publish_wiki_revision", purpose="wiki_publication")
    read_rule = replace(binding(tenant.actor_id), fields=SEARCH_FIELDS)
    download_rule = policy.LocalRule(
        tenant.actor_id, DOWNLOAD_OP, "allow", "employee_evidence", "employee", frozenset({"original"}),
        datetime.now(UTC) - timedelta(days=1), version_ref=version_ref,
    )
    set_rules(db, compile_rule(tenant.actor_id), review_rule, publish_rule, read_rule, download_rule, expected=expected)


def _publish_topic(db, topic, manifest_passages, cited_passage, statement_text):
    bundle = assemble(db, manifest_passages)
    assert bundle.status == "succeeded"
    statements = (WikiStatement(statement_text, (((cited_passage.passage_ref, cited_passage.revision),),)),)
    created = wiki_candidate((db, bundle, cited_passage, cited_passage), topic=topic, statements=statements)
    assert created.status == "succeeded"
    review_result = wiki_submit(db, created.ref, wiki_preview(db, created.ref))
    assert review_result.status == "succeeded"
    published = publish_wiki(db, created.ref, review_result.ref)
    assert published.status == "succeeded"
    return published, bundle, created.ref, review_result.ref


def test_upgrade_from_0101_preserves_existing_receipts_and_enforces_delete_isolation(database_url, tmp_path):
    from enterprise_kb.modules.sources.originals import SyntheticOriginalStore

    migrate_to_revision(database_url, "0101_source_perm_checkpoint")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Upgrade delete isolation")
        source_ref = source_for(connection, tenant)
        source = sync.SyncSource(tenant.space_id, source_ref, 1)
        store = SyntheticOriginalStore(tmp_path)
        ver = version_candidate(tenant, source_ref, object_key="legacy-doc", source_version_key="rev-1")
        page = sync.SourcePage(None, uuid4(), (sync.PageOriginal(ver, CONTENT),))
        receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert sync.read_content_position(
            connection, sync_request(connection, tenant, operation=sync.READ), source,
        ) == page.through
        assert len(receipt.version_refs) == 1


def test_s04_partial_inventory_never_deletes_while_explicit_source_deletion_isolates_all_channels_and_blocks_replays(
    transport,
):
    client, db, (owner, reviewer), credentials, live, *_ = transport
    connection, tenant, _, source_ref, store = db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)

    exp_ver = version_candidate(
        tenant, source_ref, object_key="exp-017", incarnation="upload", source_version_key="rev-a",
        display_name="Expense EXP-017", version_label="A", digest=sha256(EXP_TEXT).digest(),
    )
    wiki_doc_ver = version_candidate(
        tenant, source_ref, object_key="exp-wiki", incarnation="first", source_version_key="rev-a",
        display_name="Expense Note EXP-WIKI", version_label="A", digest=sha256(WIKI_DOC_TEXT).digest(),
    )
    control_ver = version_candidate(
        tenant, source_ref, object_key="exp-099", incarnation="first", source_version_key="rev-a",
        display_name="Control Expense EXP-099", version_label="A", digest=sha256(CONTROL_TEXT).digest(),
    )
    page1 = sync.SourcePage(None, uuid4(), (
        sync.PageOriginal(exp_ver, EXP_TEXT),
        sync.PageOriginal(wiki_doc_ver, WIKI_DOC_TEXT),
        sync.PageOriginal(control_ver, CONTROL_TEXT),
    ))
    page1_receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, page1, store)
    exp_ref, wiki_doc_ref, control_ref = page1_receipt.version_refs

    exp_passage, exp_run, _, _ = _approve_and_index(db, exp_ref, key_suffix="exp-017")
    wiki_doc_passage, _, _, _ = _approve_and_index(db, wiki_doc_ref, key_suffix="exp-wiki")
    control_passage, _, _, _ = _approve_and_index(db, control_ref, key_suffix="exp-099")
    live.update({exp_passage.passage_ref, wiki_doc_passage.passage_ref, control_passage.passage_ref})

    _configure_wiki_and_original(db, exp_ref, expected=2)
    affected_wiki, _, _, _ = _publish_topic(
        db, "s04-affected", (wiki_doc_passage, control_passage), control_passage,
        f"Summary referencing only control [p:{control_passage.passage_ref}].",
    )
    control_wiki, _, control_rev, _ = _publish_topic(
        db, "s04-control", (control_passage,), control_passage,
        f"Control 099 summary [p:{control_passage.passage_ref}].",
    )

    # Stage 1: Interrupted half-inventory must fail and never delete or block EXP-017.
    full_entries = (
        reconciliation.InventoryEntry(exp_ver.object_key, exp_ver.incarnation, exp_ver.source_version_key, exp_ver.digest),
        reconciliation.InventoryEntry(
            wiki_doc_ver.object_key, wiki_doc_ver.incarnation, wiki_doc_ver.source_version_key, wiki_doc_ver.digest,
        ),
        reconciliation.InventoryEntry(
            control_ver.object_key, control_ver.incarnation, control_ver.source_version_key, control_ver.digest,
        ),
    )
    partial_manifest = manifest(reconciliation, full_entries, content_position=page1.through)
    with pytest.raises(reconciliation.InventoryConflict):
        reconcile(reconciliation, connection, tenant, source, partial_manifest, (full_entries[2],))
    assert client.get(f"/v1/passages/{exp_passage.passage_ref}", headers=bearer(owner)).status_code == 200
    assert _read_topic(db, "s04-affected").payload is not None

    # Stage 2: Complete inventory omitting EXP-017 only flags not_enumerated and never auto-deletes.
    omitted_entries = (full_entries[1], full_entries[2])
    omitted_manifest = manifest(reconciliation, omitted_entries, content_position=page1.through)
    inv_receipt = reconcile(reconciliation, connection, tenant, source, omitted_manifest, omitted_entries)
    assert any(diff.object_key == "exp-017" and diff.kind == "not_enumerated" for diff in inv_receipt.differences)
    assert client.get(f"/v1/passages/{exp_passage.passage_ref}", headers=bearer(owner)).status_code == 200
    assert connection.execute("SELECT count(*) FROM thalion.rule_use_stop").fetchone() == (0,)

    # Stage 3: Explicit source deletion signal -> tombstone -> deletion receipt -> copy observations.
    admit(credentials, owner, DOWNLOAD_OP, "register_retention_policy", "plan_disposition", "submit_disposition_case")
    assert client.get(download_path(SimpleNamespace(version_ref=exp_ref)), headers=bearer(owner)).status_code == 200
    before_suggestions = client.post("/employee/search-suggestions", json={
        "prefix": "Expense", "business_date": BEFORE.isoformat(),
    }, headers=bearer(owner))
    assert before_suggestions.status_code == 200 and "Expense EXP-017" in before_suggestions.text
    original_bytes = original(db, SimpleNamespace(version_ref=exp_ref)).read_bytes()
    assert original_bytes == EXP_TEXT

    # A Wiki-referenced version stays protected from raw destruction and stops via explicit withdrawal first.
    assert configure_retention(client, owner, source_ref, action="destroy", expected=0).status_code == 200
    wiki_preview = plan_disposition(client, owner, wiki_doc_ref, action="destroy").json()
    assert wiki_preview["decision"] == "protected" and "wiki_full_input" in wiki_preview["protections"]
    wiki_stop_event = uuid4()
    wiki_stop = effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "s04-stop-wiki-doc"),
        tenant.space_id, wiki_doc_ref, "withdrawn", wiki_stop_event,
    )
    source_restrictions.acknowledge_removal(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, source_restrictions.Removal(
            wiki_stop_event, wiki_doc_ver.object_key, wiki_doc_ver.incarnation,
            wiki_doc_ver.source_version_key, "withdrawn", wiki_stop,
        ),
    )
    assert causes(connection, affected_wiki.ref) == [(causes(connection, affected_wiki.ref)[0][0], "withdrawn", wiki_stop)]
    assert _read_topic(db, "s04-affected").payload is None
    assert _read_topic(db, "s04-control").payload is not None

    # Unprotected EXP-017 stops current effectivity, receives independent destroy approval, tombstone & deleted receipt.
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "s04-stop-exp-017"),
        tenant.space_id, exp_ref, "withdrawn", uuid4(),
    )
    delete_event = uuid4()
    case = submitted(client, owner, credentials, source_ref, SimpleNamespace(version_ref=exp_ref), expected=1)
    approval_id = approve_disposition(client, reviewer, credentials, case, basis=delete_event)
    admit(credentials, reviewer, REGISTER_TOMBSTONE, OBSERVE_COPIES)
    tombstone_reply = register_tombstone(client, reviewer, case, approval_id)
    assert tombstone_reply.status_code == 200, tombstone_reply.text
    tombstone_id = UUID(tombstone_reply.json()["tombstone_id"])

    receipt = source_restrictions.acknowledge_removal(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, source_restrictions.Removal(
            delete_event, exp_ver.object_key, exp_ver.incarnation,
            exp_ver.source_version_key, "deleted", tombstone_id,
        ),
    )
    assert (receipt.kind, receipt.target_ref, receipt.decision_ref) == ("deleted", exp_ref, tombstone_id)

    copy_reply = capture_copies(client, reviewer, case, tombstone_id)
    assert copy_reply.status_code == 200, copy_reply.text
    copy_body = copy_reply.json()
    assert copy_body["restore_blocked_locally"] is True and copy_body["executable"] is False
    assert presence(copy_body)["original"] == "present_verified"
    assert presence(copy_body)["index"] == "present_in_database"
    assert original(db, SimpleNamespace(version_ref=exp_ref)).read_bytes() == EXP_TEXT

    # Verify complete isolation across HTTP search, MCP search, old citations, original download, suggestions, and Wiki.
    admit(credentials, owner, "read_source_sync_status", "upload_source_batch")
    http_exp = client.post("/v1/search", headers=bearer(owner), json={
        "query": "017", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert http_exp.status_code == 200
    assert http_exp.json()["passages"] == [] and http_exp.json()["wiki"] == []
    http_broad = client.post("/v1/search", headers=bearer(owner), json={
        "query": "Expense", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert http_broad.status_code == 200
    assert all(item["passage_id"] != str(exp_passage.passage_ref) for item in http_broad.json()["passages"])
    http_ctrl = client.post("/v1/search", headers=bearer(owner), json={
        "query": "099", "business_date": BEFORE.isoformat(), "include_wiki": True,
    })
    assert http_ctrl.status_code == 200
    assert len(http_ctrl.json()["passages"]) == 1
    assert [item["revision_id"] for item in http_ctrl.json()["wiki"]] == [str(control_rev)]

    mcp_exp = rpc(
        client, owner, "tools/call", name="search",
        arguments={"query": "017", "business_date": BEFORE.isoformat(), "include_wiki": True},
    ).json()["result"]["structuredContent"]
    assert mcp_exp["passages"] == [] and mcp_exp["wiki"] == []
    mcp_read = rpc(
        client, owner, "tools/call", name="read_passage",
        arguments={"id": str(exp_passage.passage_ref)},
    ).json()["result"]
    assert mcp_read["isError"] is True

    assert client.get(f"/v1/passages/{exp_passage.passage_ref}", headers=bearer(owner)).status_code == 404
    assert client.get(f"/v1/passages/{control_passage.passage_ref}", headers=bearer(owner)).status_code == 200
    assert client.get(download_path(SimpleNamespace(version_ref=exp_ref)), headers=bearer(owner)).status_code == 404

    suggestions = client.post("/employee/search-suggestions", json={
        "prefix": "Expense", "business_date": BEFORE.isoformat(),
    }, headers=bearer(owner))
    assert suggestions.status_code == 200
    assert suggestions.json()["suggestions"] == []
    ctrl_suggestions = client.post("/employee/search-suggestions", json={
        "prefix": "Control", "business_date": BEFORE.isoformat(),
    }, headers=bearer(owner))
    assert ctrl_suggestions.status_code == 200 and "Control Expense EXP-099" in ctrl_suggestions.text

    with pytest.raises(lexical.LexicalIndexUnavailable, match="source-deleted"):
        lexical.build_index(connection, store, tenant.space_ref, exp_ref, exp_run.run_ref)

    sync_status = client.get(f"/internal/sources/{source_ref}/sync-status", headers=bearer(owner)).json()
    assert sync_status["restriction_receipts"]["by_kind"]["deleted"] == 1
    assert sync_status["processing_and_review"]["blocked_versions"] >= 1

    # Stage 4: Old batch & late replay attempts must never republish or resurrect the deleted incarnation.
    # 4a. Exact idempotent replay of the already-committed page returns the prior receipt without resurrecting.
    assert sync.commit_content_page(connection, sync_request(connection, tenant), source, page1, store) == page1_receipt
    assert client.get(f"/v1/passages/{exp_passage.passage_ref}", headers=bearer(owner)).status_code == 404

    # 4b. A new content page attempting to re-deliver the deleted incarnation (same version or new version) is rejected.
    before_files = set(store.root.iterdir())
    replay_same_page = sync.SourcePage(page1.through, uuid4(), (sync.PageOriginal(exp_ver, EXP_TEXT),))
    with pytest.raises(registry.SourceDeletedConflict):
        sync.commit_content_page(connection, sync_request(connection, tenant), source, replay_same_page, store)
    replay_new_ver = replace(exp_ver, source_version_key="rev-replay", version_label="B", digest=sha256(OTHER_CONTENT).digest())
    replay_new_page = sync.SourcePage(page1.through, uuid4(), (sync.PageOriginal(replay_new_ver, OTHER_CONTENT),))
    with pytest.raises(registry.SourceDeletedConflict):
        sync.commit_content_page(connection, sync_request(connection, tenant), source, replay_new_page, store)
    assert sync.read_content_position(connection, sync_request(connection, tenant, operation=sync.READ), source) == page1.through
    assert set(store.root.iterdir()) == before_files

    # 4c. Direct collector registration for the deleted incarnation is rejected without writing orphan files.
    with pytest.raises(registry.SourceDeletedConflict):
        registry.register_synthetic_version(
            connection, sync_request(connection, tenant, operation="register_version"), replay_new_ver, OTHER_CONTENT, store,
        )
    assert set(store.root.iterdir()) == before_files

    # 4d. HTTP batch ingest rejects both same-version and new-version replays as source_deleted while admitting fresh docs.
    mixed_batch = upload(client, owner, source_ref, [
        ingest_file("exp-017.md", "Expense EXP-017", "A", "exp-017", EXP_TEXT),
        ingest_file("exp-017-v2.md", "Expense EXP-017", "B", "exp-017", OTHER_CONTENT, confirm=True),
        ingest_file("fresh.md", "Fresh Policy", "A", "fresh-after-delete", FRESH_TEXT),
    ], "replay-after-delete")
    assert mixed_batch.status_code == 200, mixed_batch.text
    files_by_pos = {item["position"]: item for item in mixed_batch.json()["files"]}
    assert (files_by_pos[0]["status"], files_by_pos[0]["reason"]) == ("rejected", "source_deleted")
    assert (files_by_pos[1]["status"], files_by_pos[1]["reason"]) == ("rejected", "source_deleted")
    assert files_by_pos[2]["status"] == "registered"

    # 4e. Raw SQL bypasses are blocked by database triggers.
    doc_id, source_id, asset_id = connection.execute("""
        SELECT version.document_id, version.source_id, version.asset_id
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version ON version.version_id = identity.object_id
        WHERE identity.public_id = %s AND identity.object_type = 'document_version'
    """, (exp_ref,)).fetchone()
    with pytest.raises(errors.CheckViolation), connection.transaction():
        connection.execute("""
            INSERT INTO thalion.document_version (
                org_id, space_id, source_id, document_id, contract_revision, asset_id,
                source_version_key, version_label, registration_sequence
            ) VALUES (%s, %s, %s, %s, 1, %s, 'raw-sql-rev', 'Z', 99)
        """, (tenant.org_id, tenant.space_id, source_id, doc_id, asset_id))
    with pytest.raises(errors.CheckViolation), connection.transaction():
        connection.execute("""
            INSERT INTO thalion.synthetic_lexical_index (
                org_id, space_id, version_id, run_ref, profile, entries, content_digest
            )
            SELECT org_id, space_id, version_id, run_ref, 'replay_profile_v1', '{}'::jsonb,
                   sha256(convert_to('{}'::jsonb::text, 'UTF8'))
            FROM thalion.processing_run WHERE run_ref = %s
        """, (exp_run.run_ref,))

    # Stage 5: A brand-new incarnation of the same object_key and updates to control_ver remain fully allowed.
    reborn_ver = version_candidate(
        tenant, source_ref, object_key="exp-017", incarnation="second", source_version_key="rev-a",
        display_name="Reborn Expense EXP-017", version_label="A", digest=sha256(REBORN_TEXT).digest(),
    )
    control_v2 = replace(control_ver, source_version_key="rev-b", version_label="B", digest=sha256(OTHER_CONTENT).digest())
    page2 = sync.SourcePage(page1.through, uuid4(), (
        sync.PageOriginal(reborn_ver, REBORN_TEXT),
        sync.PageOriginal(control_v2, OTHER_CONTENT),
    ))
    page2_receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, page2, store)
    reborn_ref = page2_receipt.version_refs[0]
    reborn_passage, _, _, _ = _approve_and_index(db, reborn_ref, key_suffix="reborn-exp-017")
    live.add(reborn_passage.passage_ref)
    reborn_search = client.post("/v1/search", headers=bearer(owner), json={
        "query": "Reborn", "business_date": BEFORE.isoformat(),
    })
    assert reborn_search.status_code == 200 and len(reborn_search.json()["passages"]) == 1
    assert client.get(f"/v1/passages/{exp_passage.passage_ref}", headers=bearer(owner)).status_code == 404


def test_source_deletion_of_latest_version_isolates_earlier_unstopped_version_and_its_wiki(transport):
    client, db, (owner, reviewer), credentials, live, *_ = transport
    connection, tenant, _, source_ref, store = db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)

    v1 = version_candidate(
        tenant, source_ref, object_key="multi-ver", incarnation="first", source_version_key="rev-1",
        display_name="Multi Version Policy", version_label="A", digest=sha256(EXP_TEXT).digest(),
    )
    v2 = replace(v1, source_version_key="rev-2", version_label="B", digest=sha256(OTHER_CONTENT).digest())
    v_unapproved = replace(v1, source_version_key="rev-0", version_label="0", digest=sha256(FRESH_TEXT).digest())
    page = sync.SourcePage(None, uuid4(), (
        sync.PageOriginal(v1, EXP_TEXT),
        sync.PageOriginal(v2, OTHER_CONTENT),
        sync.PageOriginal(v_unapproved, FRESH_TEXT),
    ))
    v1_ref, v2_ref, v0_ref = sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store).version_refs

    v1_passage, _, v1_eff, _ = _approve_and_index(db, v1_ref, valid_from=BEGIN, key_suffix="mv-1")
    v2_passage, _, _, _ = _approve_and_index(db, v2_ref, valid_from=SWITCH, replaces_ref=v1_eff, key_suffix="mv-2")
    live.update({v1_passage.passage_ref, v2_passage.passage_ref})

    configure_wiki(db, 2)
    old_wiki, _, _, _ = _publish_topic(
        db, "multi-ver-history", (v1_passage,), v1_passage,
        f"Historical rule [p:{v1_passage.passage_ref}].",
    )
    assert _read_topic(db, "multi-ver-history").payload is not None
    assert client.get(f"/v1/passages/{v1_passage.passage_ref}", headers=bearer(owner)).status_code == 200

    # Stop current effectivity on v2, then record tombstone & explicit source deletion receipt; v1 has no individual stop.
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "mv-stop-v2"),
        tenant.space_id, v2_ref, "withdrawn", uuid4(),
    )
    delete_event = uuid4()
    case = submitted(client, owner, credentials, source_ref, SimpleNamespace(version_ref=v2_ref))
    approval_id = approve_disposition(client, reviewer, credentials, case, basis=delete_event)
    admit(credentials, reviewer, REGISTER_TOMBSTONE)
    tombstone_id = UUID(register_tombstone(client, reviewer, case, approval_id).json()["tombstone_id"])
    source_restrictions.acknowledge_removal(
        connection, sync_request(connection, tenant, operation=source_restrictions.COMMIT),
        source, source_restrictions.Removal(delete_event, "multi-ver", "first", "rev-2", "deleted", tombstone_id),
    )

    # Earlier v1 is also isolated across search, old citation, original download, and Wiki; v0 cannot be approved.
    assert client.get(f"/v1/passages/{v1_passage.passage_ref}", headers=bearer(owner)).status_code == 404
    admit(credentials, owner, DOWNLOAD_OP)
    assert client.get(download_path(SimpleNamespace(version_ref=v1_ref)), headers=bearer(owner)).status_code == 404
    assert processing.read_source_processing_status(connection, tenant.org_id, tenant.space_id, tenant.actor_id, v1_ref) == "blocked"
    assert client.post("/v1/search", headers=bearer(owner), json={
        "query": "EXP-017", "business_date": BEFORE.isoformat(), "include_wiki": True,
    }).json()["passages"] == []
    assert _read_topic(db, "multi-ver-history").payload is None
    assert any(reason == "deletion_blocked" and cause == tombstone_id for _, reason, cause in causes(connection, old_wiki.ref))
    with pytest.raises(errors.CheckViolation), connection.transaction():
        connection.execute("""
            INSERT INTO thalion.synthetic_lexical_index (
                org_id, space_id, version_id, run_ref, profile, entries, content_digest
            )
            SELECT run.org_id, run.space_id, run.version_id, run.run_ref, 'replay_v1_profile', '{}'::jsonb,
                   sha256(convert_to('{}'::jsonb::text, 'UTF8'))
            FROM thalion.object_identity AS identity
            JOIN thalion.processing_run AS run ON run.version_id = identity.object_id
            WHERE identity.public_id = %s AND identity.object_type = 'document_version'
            LIMIT 1
        """, (v1_ref,))

    with pytest.raises(effectivity.EffectivityConflict):
        approve_rule(connection, tenant, SimpleNamespace(version_ref=v0_ref), BEGIN)

    # Non-source-deleted version (retention-only deletion_blocked without source deletion receipt) still allows new versions.
    retention_v1 = version_candidate(
        tenant, source_ref, object_key="retention-only", incarnation="first", source_version_key="rev-1",
        display_name="Retention Policy", version_label="A", digest=sha256(EXP_TEXT).digest(),
    )
    p_ret = sync.SourcePage(page.through, uuid4(), (sync.PageOriginal(retention_v1, EXP_TEXT),))
    ret_v1_ref, = sync.commit_content_page(connection, sync_request(connection, tenant), source, p_ret, store).version_refs
    ret_case = submitted(client, owner, credentials, source_ref, SimpleNamespace(version_ref=ret_v1_ref), expected=1)
    ret_approval = approve_disposition(client, reviewer, credentials, ret_case)
    assert register_tombstone(client, reviewer, ret_case, ret_approval).status_code == 200
    retention_v2 = replace(retention_v1, source_version_key="rev-2", version_label="B", digest=sha256(OTHER_CONTENT).digest())
    p_ret2 = sync.SourcePage(p_ret.through, uuid4(), (sync.PageOriginal(retention_v2, OTHER_CONTENT),))
    assert len(sync.commit_content_page(connection, sync_request(connection, tenant), source, p_ret2, store).version_refs) == 1
