from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
from types import SimpleNamespace
from uuid import UUID, uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from psycopg import errors
import pytest

from enterprise_kb.database import local_connection_factory, rehearsal_marker, upgrade
from enterprise_kb.modules.access import governance, policy
from enterprise_kb.modules.evidence import processing, quality_restrictions
from enterprise_kb.modules.lifecycle import archive_rehearsal, disposition, space_archive
from enterprise_kb.modules.operations import release
from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.modules.sources import (
    effectivity, registry, restriction_log, source_restrictions, source_revocations, sync,
)
from enterprise_kb.modules.wiki import drafts, inputs as wiki_inputs, publication
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.runtime.jobs import JobSpec, claim_job, enqueue_job
from enterprise_kb.transport.api import SPACE_ARCHIVES_PATH
from enterprise_kb.transport.evidence import SyntheticCredential

from conftest import temporary_database
from docx_fixture import docx_package
from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import endpoint
from test_deletion_tombstone import (
    REGISTER as REGISTER_TOMBSTONE, approved as approve_disposition, register as register_tombstone, submitted,
)
from test_disposition import configure as configure_retention
from test_docx_processing import DOCX_TYPE
from test_effectivity import BEFORE, BEGIN, approve as approve_rule, record
from test_evidence import approved as approve_quality, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_identity import migrate_to_revision
from test_persisted_access import authority_for, binding, ingress, set_rules
from test_runtime import LEASE_FOR, open_database, register_tenant, runtime_db
from test_source_sync import sync_request
from test_sources import candidate as version_candidate, register as register_version, request_for, source_for
from test_travel_search import SEARCH_FIELDS, corpus, publish
from test_wiki_inputs import compile_rule


KEEP_MD = b"# Travel Policy Keep\n\nKeep hotel allowance 600 CNY per night in Shanghai.\n"
KEEP_MD2 = b"# Travel Transport Keep\n\nSecond source railway ticket limit 450 CNY.\n"
WITHDRAW_MD = b"# Travel Policy Withdraw\n\nWithdraw legacy meal subsidy 350 CNY per day.\n"
DELETE_MD = b"# Travel Policy Delete\n\nDeleted confidential contractor rate 999 CNY.\n"


def _principal_ref(connection, org_id: int, principal_id: int) -> UUID:
    return connection.execute(
        """
        SELECT public_id FROM thalion.object_identity
        WHERE (org_id, object_type, object_id) = (%s, 'principal', %s)
        """,
        (org_id, principal_id),
    ).fetchone()[0]


def _add_employee(connection, org_id: int, key: str) -> tuple[int, UUID]:
    with connection.transaction():
        pid, = connection.execute(
            """
            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
            VALUES (%s, 'employee', 'https://synthetic.invalid', %s)
            RETURNING principal_id
            """,
            (org_id, key),
        ).fetchone()
        pref, = connection.execute(
            """
            INSERT INTO thalion.object_identity (object_type, object_id, org_id)
            VALUES ('principal', %s, %s)
            RETURNING public_id
            """,
            (pid, org_id),
        ).fetchone()
    return pid, pref


def _create_second_source(connection, tenant, *, source_key: str = "travel-docx", namespace: str = "docx-docs") -> tuple[int, UUID]:
    with connection.transaction():
        src_id, = connection.execute(
            """
            INSERT INTO thalion.source (org_id, space_id, source_key, owner_principal_id)
            VALUES (%s, %s, %s, %s)
            RETURNING source_id
            """,
            (tenant.org_id, tenant.space_id, source_key, tenant.actor_id),
        ).fetchone()
        src_ref, = connection.execute(
            """
            INSERT INTO thalion.object_identity (object_type, object_id, org_id, space_id)
            VALUES ('source', %s, %s, %s)
            RETURNING public_id
            """,
            (src_id, tenant.org_id, tenant.space_id),
        ).fetchone()
        collector_id, processor_id = connection.execute(
            """
            SELECT c.collector_id, c.processor_id
            FROM thalion.source AS s
            JOIN thalion.source_contract_revision AS c
              ON (c.org_id, c.space_id, c.source_id, c.revision) = (s.org_id, s.space_id, s.source_id, s.contract_revision)
            WHERE (s.org_id, s.space_id) = (%s, %s)
            ORDER BY s.source_id LIMIT 1
            """,
            (tenant.org_id, tenant.space_id),
        ).fetchone()
        connection.execute(
            """
            INSERT INTO thalion.source_contract_revision (
                org_id, space_id, source_id, revision, admission, collector_id,
                object_namespace, approver_id, processor_id, quality_reviewer_id
            ) VALUES (%s, %s, %s, 1, 'synthetic_only', %s, %s, %s, %s, %s)
            """,
            (
                tenant.org_id, tenant.space_id, src_id, collector_id, namespace,
                tenant.other_actor_id, processor_id, tenant.actor_id,
            ),
        )
    return src_id, src_ref


def _ingest_and_approve_markdown(db, source_ref: UUID, *, object_key: str, display_name: str, payload: bytes):
    connection, tenant, _, _, store = db
    source = sync.SyncSource(tenant.space_id, source_ref, 1)
    ver_cand = version_candidate(
        tenant, source_ref, object_key=object_key, incarnation="inc-1", source_version_key="v1",
        display_name=display_name, version_label="V1", digest=sha256(payload).digest(),
    )
    prev_pos = sync.read_content_position(connection, sync_request(connection, tenant, operation=sync.READ), source)
    page = sync.SourcePage(prev_pos, uuid4(), (sync.PageOriginal(ver_cand, payload),))
    receipt = sync.commit_content_page(connection, sync_request(connection, tenant), source, page, store)
    ver_ref = receipt.version_refs[0]
    processor_id, = connection.execute(
        """
        SELECT c.processor_id FROM thalion.source AS s
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (s.org_id, s.space_id, 'source', s.source_id)
        JOIN thalion.source_contract_revision AS c
          ON (c.org_id, c.space_id, c.source_id, c.revision) = (s.org_id, s.space_id, s.source_id, s.contract_revision)
        WHERE (s.org_id, s.space_id, oi.public_id) = (%s, %s, %s)
        """,
        (tenant.org_id, tenant.space_id, source_ref),
    ).fetchone()
    while True:
        lease = claim_job(connection, tenant.org_id, "parse", processor_id, LEASE_FOR)
        assert lease is not None
        run = processing.process_markdown_job(connection, lease, store)
        if lease.spec.target_ref == ver_ref:
            break
    review(db, run)
    passages = approve_quality(db, SimpleNamespace(version_ref=ver_ref))
    approve_rule(connection, tenant, SimpleNamespace(version_ref=ver_ref), BEGIN)
    lexical.build_index(connection, store, tenant.space_ref, ver_ref, run.run_ref)
    return ver_cand, ver_ref, passages[0], run.run_ref


def _ingest_and_approve_docx(db, source_ref: UUID, *, object_key: str, display_name: str, payload: bytes):
    connection, tenant, _, _, store = db
    digest = sha256(payload).digest()
    ver = register_version(
        connection, tenant, source_ref, store,
        key=f"reg-docx-{object_key}-{uuid4()}", payload=payload,
        object_key=object_key, incarnation="inc-1", source_version_key="v1",
        display_name=display_name, version_label="V1", digest=digest, media_type=DOCX_TYPE,
    )
    processor_id, = connection.execute(
        """
        SELECT c.processor_id FROM thalion.source AS s
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (s.org_id, s.space_id, 'source', s.source_id)
        JOIN thalion.source_contract_revision AS c
          ON (c.org_id, c.space_id, c.source_id, c.revision) = (s.org_id, s.space_id, s.source_id, s.contract_revision)
        WHERE (s.org_id, s.space_id, oi.public_id) = (%s, %s, %s)
        """,
        (tenant.org_id, tenant.space_id, source_ref),
    ).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, ver.version_ref, "parse", digest, 1))
    while True:
        lease = claim_job(connection, tenant.org_id, "parse", processor_id, LEASE_FOR)
        assert lease is not None
        run = processing.process_evidence_job(connection, lease, store)
        if lease.spec.target_ref == ver.version_ref:
            break
    review(db, run)
    docx_passages = processing.list_approved_docx_paragraphs(connection, tenant.org_id, tenant.space_id, ver.version_ref)
    assert docx_passages
    approve_rule(connection, tenant, ver, BEGIN)
    return ver.version_ref, docx_passages[0], run.run_ref


def _publish_cross_source_wiki(db, topic_key: str, title: str, markdown_body: str, input_passages: tuple, cited_passages: tuple):
    connection, tenant, _, _, store = db
    all_actors = {tenant.actor_id, tenant.other_actor_id}
    auth = authority_for(all_actors)
    direct = tuple((p.passage_ref, p.revision) for p in input_passages)
    assembled = wiki_inputs.prepare_wiki_inputs(
        connection,
        ingress(db, tenant.actor_id, BEFORE, operation="assemble_wiki_inputs", purpose="wiki_compilation", destination="local_workspace"),
        tenant.space_id, direct, (), store,
        region="shanghai", traveler_class="employee", check_authority=auth,
    )
    assert assembled.status == "succeeded", assembled
    citations = tuple((p.passage_ref, p.revision) for p in cited_passages)
    statements = (
        drafts.WikiStatement(
            markdown_body,
            (tuple((p.passage_ref, p.revision) for p in cited_passages),),
        ),
    )
    created = drafts.create_manual_candidate(
        connection,
        ingress(db, tenant.actor_id, BEFORE, operation="create_wiki_candidate", purpose="wiki_compilation", destination="local_workspace"),
        tenant.space_id,
        drafts.ManualCandidate(
            topic_key=topic_key,
            title=title,
            markdown=markdown_body,
            manifest_ref=assembled.manifest_ref,
            reviewer_id=tenant.other_actor_id,
            basis_ref=uuid4(),
            citations=citations,
            statements=statements,
        ),
        f"draft-{topic_key}-{uuid4()}",
        region="shanghai", traveler_class="employee", check_authority=auth,
    )
    assert created.status == "succeeded", created
    preview = drafts.read_candidate_for_review(
        connection,
        ingress(db, tenant.other_actor_id, BEFORE, operation="read_wiki_candidate", purpose="wiki_review", destination="local_workspace"),
        tenant.space_id, created.ref,
        region="shanghai", traveler_class="employee", check_authority=auth,
    )
    assert preview.status == "succeeded", preview
    reviewed = drafts.submit_review(
        connection,
        ingress(db, tenant.other_actor_id, BEFORE, operation="review_wiki_revision", purpose="wiki_review", destination="local_workspace"),
        tenant.space_id, created.ref, sha256(preview.payload).digest(), preview.input_digest,
        "approved", "verified_multisource", uuid4(), f"review-{topic_key}-{uuid4()}",
        region="shanghai", traveler_class="employee", check_authority=auth, review_material_ref=preview.review_material_ref,
    )
    assert reviewed.status == "succeeded", reviewed
    published = publication.publish_revision(
        connection,
        ingress(db, tenant.other_actor_id, BEFORE, operation="publish_wiki_revision", purpose="wiki_publication", destination="local_workspace"),
        tenant.space_id, created.ref, reviewed.ref, f"publish-{topic_key}-{uuid4()}",
        region="shanghai", traveler_class="employee", check_authority=auth,
    )
    assert published.status == "succeeded", published
    return created.ref, published.ref


def _set_source_policy(connection, tenant, source_ref: UUID, *local_rules: policy.LocalRule):
    req_id = uuid4()
    cur_epoch, = connection.execute(
        """
        SELECT s.safety_epoch FROM thalion.source AS s
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (s.org_id, s.space_id, 'source', s.source_id)
        WHERE (s.org_id, s.space_id, oi.public_id) = (%s, %s, %s)
        """,
        (tenant.org_id, tenant.space_id, source_ref),
    ).fetchone()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, req_id, tenant.actor_id, None, "test-policy",
            policy.REPLACE, policy.DESTINATION, BEFORE, 1, space_id=tenant.space_id, ingress="internal",
        ),
    )
    policy.replace_synthetic_policy(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, req_id, f"pol-{uuid4()}"),
        tenant.space_id, source_ref, cur_epoch, local_rules, uuid4(),
    )
    finish_request(connection, tenant.org_id, req_id, "succeeded", 0)


def test_migration_0106_upgrade_db_guards_and_mcp_boundary(postgres_server, transport):
    with temporary_database(postgres_server) as fresh_url:
        migrate_to_revision(fresh_url, "0105_space_release_eval")
        assert upgrade(fresh_url) == ["0112_flexible_vector_dimensions"]

    client, db, (owner, reviewer), credentials, live, *_ = transport
    connection, tenant, _, source_ref, _ = db
    src_id, = connection.execute(
        "SELECT object_id FROM thalion.object_identity WHERE (org_id, space_id, object_type, public_id) = (%s, %s, 'source', %s)",
        (tenant.org_id, tenant.space_id, source_ref),
    ).fetchone()
    ver_id, = connection.execute(
        "SELECT version_id FROM thalion.document_version WHERE (org_id, space_id, source_id) = (%s, %s, %s) LIMIT 1",
        (tenant.org_id, tenant.space_id, src_id),
    ).fetchone()

    # Non-owner direct insert into space_archive_request rejected by DB trigger.
    non_owner_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, non_owner_req, tenant.other_actor_id, None, "guard-test",
            space_archive.REQUEST, "internal_lifecycle", BEFORE, 1, space_id=tenant.space_id, ingress="internal",
        ),
    )
    with pytest.raises(errors.CheckViolation):
        connection.execute(
            """
            INSERT INTO thalion.space_archive_request (
                org_id, space_id, requester_id, source_ids, version_ids,
                scope_digest, watermark_digest, safety_snapshot, request_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, ARRAY[1,1,1]::bigint[], %s)
            """,
            (tenant.org_id, tenant.space_id, tenant.other_actor_id, [src_id], [ver_id], b"\x01" * 32, b"\x02" * 32, non_owner_req),
        )
    finish_request(connection, tenant.org_id, non_owner_req, "rejected", 0)

    # Unfenced database cannot record space_archive_rebuild.
    with pytest.raises(errors.CheckViolation):
        connection.execute(
            """
            INSERT INTO thalion.space_archive_rebuild (
                org_id, space_id, origin_org_id, origin_space_id, origin_space_ref,
                export_ref, format_version, archive_digest, recovery_watermark,
                rule_authority_ref, rule_log_ref, rule_stream_ref, rule_generation,
                source_authority_ref, source_stream_ref, source_generation,
                alternate_model_profile, lexical_index_mode,
                rebuilt_sources, rebuilt_versions, rebuilt_wikis,
                replayed_stops, replayed_deletions, replayed_revocations,
                verified_references, blocked_references,
                duration_ms, scratch_bytes, affected_services
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, '{}'::jsonb,
                %s, %s, %s, 0,
                %s, %s, 0,
                'alt-v1', 'indexed',
                1, 1, 0,
                0, 0, 0,
                0, 0,
                1, 100, ARRAY['search_api']
            )
            """,
            (
                tenant.org_id, tenant.space_id, tenant.org_id, tenant.space_id, tenant.space_ref,
                uuid4(), space_archive.SPACE_ARCHIVE_FORMAT, b"\x03" * 32,
                uuid4(), uuid4(), uuid4(), uuid4(), uuid4(),
            ),
        )

    # Unauthenticated HTTP call rejected 401; missing Idempotency-Key rejected 400.
    assert client.post(
        SPACE_ARCHIVES_PATH,
        headers={"Idempotency-Key": "unauth-space-arch"},
        json={"source_ids": [], "version_ids": []},
    ).status_code == 401
    admit(credentials, owner, space_archive.REQUEST)
    assert client.post(
        SPACE_ARCHIVES_PATH,
        headers=bearer(owner),
        json={"source_ids": [str(source_ref)], "version_ids": [str(uuid4())]},
    ).status_code == 400

    # MCP never exposes internal space archive routes or operations.
    tools_resp = rpc(client, owner, "tools/list").json()
    tool_names = {tool["name"] for tool in tools_resp["result"]["tools"]}
    assert not any("archive" in name or "space_archive" in name for name in tool_names)
    for op in space_archive.OPERATIONS:
        denied = rpc(client, owner, "tools/call", name=op, arguments={}).json()
        assert "error" in denied


def test_multisource_space_archive_http_closure_approval_idempotency_and_offline_verify(transport, evidence_transport):
    client, db, (owner, reviewer), credentials, live, *_ = transport
    service, *_ = evidence_transport
    connection, tenant, _, src1_ref, _ = db
    _, src2_ref = _create_second_source(connection, tenant)

    _, keep_md_ref, keep_md_p, _ = _ingest_and_approve_markdown(
        db, src1_ref, object_key="ms-keep-md", display_name="Keep Policy", payload=KEEP_MD,
    )
    _, withdraw_md_ref, withdraw_md_p, _ = _ingest_and_approve_markdown(
        db, src1_ref, object_key="ms-withdraw-md", display_name="Withdraw Policy", payload=WITHDRAW_MD,
    )
    _, keep_md2_ref, keep_md2_p, _ = _ingest_and_approve_markdown(
        db, src2_ref, object_key="ms-keep-md2", display_name="Keep Transport Policy", payload=KEEP_MD2,
    )
    keep_docx_ref, keep_docx_p, _ = _ingest_and_approve_docx(
        db, src2_ref, object_key="ms-keep-docx", display_name="Keep DOCX Policy", payload=docx_package(),
    )

    emp_c_id, emp_c_ref = _add_employee(connection, tenant.org_id, "ms-emp-c")
    now = datetime.now(UTC)
    grp_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, grp_req, tenant.actor_id, None, "ms-grp",
            governance.MANAGE_SHARED_GROUP, governance.DESTINATION, BEFORE, 1, space_id=tenant.space_id, ingress="internal",
        ),
    )
    grp = governance.create_shared_group(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, grp_req, f"grp-{uuid4()}"),
        tenant.space_id,
        target_source_ref=src1_ref,
        name="Temp Finance Readers",
        purpose="quarterly_audit",
        scope_summary="Read-only travel allowance",
        starts_at=now - timedelta(hours=1),
        review_at=now + timedelta(days=3),
        expires_at=now + timedelta(days=7),
        basis_ref=uuid4(),
    )
    finish_request(connection, tenant.org_id, grp_req, "succeeded", 0)
    mem_req = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, mem_req, tenant.actor_id, None, "ms-grp",
            governance.MANAGE_SHARED_GROUP, governance.DESTINATION, BEFORE, 1, space_id=tenant.space_id, ingress="internal",
        ),
    )
    governance.add_shared_group_member(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, mem_req, f"mem-{uuid4()}"),
        tenant.space_id, UUID(grp["group_id"]), member_ref=emp_c_ref,
        starts_at=now - timedelta(minutes=30), expires_at=now + timedelta(days=7), basis_ref=uuid4(),
    )
    finish_request(connection, tenant.org_id, mem_req, "succeeded", 0)

    compile_ws = replace(compile_rule(tenant.actor_id), fields=policy.WORKSPACE_EVIDENCE_FIELDS)
    review_rule = replace(
        binding(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review",
        destination="local_workspace", fields=policy.WORKSPACE_EVIDENCE_FIELDS,
    )
    publish_rule = replace(review_rule, operation="publish_wiki_revision", purpose="wiki_publication")
    owner_read = replace(binding(tenant.actor_id), fields=SEARCH_FIELDS)
    group_read = policy.LocalRule(
        UUID(grp["group_principal_id"]), "read_passage", "allow", "employee_evidence", "employee",
        SEARCH_FIELDS, now - timedelta(hours=1), now + timedelta(days=7),
    )
    _set_source_policy(connection, tenant, src1_ref, compile_ws, review_rule, publish_rule, owner_read, group_read)
    _set_source_policy(connection, tenant, src2_ref, compile_ws, review_rule, publish_rule, owner_read)

    wiki_rev_ref, _ = _publish_cross_source_wiki(
        db,
        "cross-source-guide",
        "Cross-Source Travel Guide",
        f"Combined policy [p:{keep_md_p.passage_ref}] and transport rule [p:{keep_md2_p.passage_ref}].",
        (keep_md_p, keep_md2_p),
        (keep_md_p, keep_md2_p),
    )

    admit(credentials, owner, space_archive.REQUEST, space_archive.APPROVE, space_archive.EXPORT)
    admit(credentials, reviewer, space_archive.APPROVE)
    live.update({
        src1_ref, src2_ref, keep_md_ref, withdraw_md_ref, keep_md2_ref, keep_docx_ref,
        keep_md_p.passage_ref, withdraw_md_p.passage_ref, keep_md2_p.passage_ref, keep_docx_p.passage_ref, wiki_rev_ref,
    })
    # Include every DOCX passage/cell ref in live authority for sealing.
    for row in connection.execute(
        """
        SELECT oi.public_id FROM thalion.object_identity AS oi
        JOIN thalion.passage AS p ON (p.org_id, p.space_id, p.passage_id) = (oi.org_id, oi.space_id, oi.object_id)
        WHERE oi.org_id = %s AND oi.space_id = %s AND oi.object_type = 'passage'
        """,
        (tenant.org_id, tenant.space_id),
    ).fetchall():
        live.add(row[0])

    # 1. Dependency closure check: omitting src2's keep_md2 version while selecting cross-source Wiki MUST return 409.
    incomplete = client.post(
        SPACE_ARCHIVES_PATH,
        headers=bearer(owner) | {"Idempotency-Key": "space-arch-incomplete"},
        json={
            "source_ids": [str(src1_ref), str(src2_ref)],
            "version_ids": [str(keep_md_ref), str(withdraw_md_ref), str(keep_docx_ref)],
            "wiki_revision_ids": [str(wiki_rev_ref)],
        },
    )
    assert incomplete.status_code == 409, incomplete.text

    # 2. Complete multi-source request succeeds & is idempotent; conflicting payload returns 409.
    complete_body = {
        "source_ids": [str(src1_ref), str(src2_ref)],
        "version_ids": [str(keep_md_ref), str(withdraw_md_ref), str(keep_md2_ref), str(keep_docx_ref)],
        "wiki_revision_ids": [str(wiki_rev_ref)],
    }
    created = client.post(
        SPACE_ARCHIVES_PATH,
        headers=bearer(owner) | {"Idempotency-Key": "space-arch-ok"},
        json=complete_body,
    )
    assert created.status_code == 200, created.text
    export_id = created.json()["export_id"]
    replayed = client.post(
        SPACE_ARCHIVES_PATH,
        headers=bearer(owner) | {"Idempotency-Key": "space-arch-ok"},
        json=complete_body,
    )
    assert replayed.status_code == 200 and replayed.json()["export_id"] == export_id
    conflicted = client.post(
        SPACE_ARCHIVES_PATH,
        headers=bearer(owner) | {"Idempotency-Key": "space-arch-ok"},
        json={"source_ids": [str(src1_ref)], "version_ids": [str(keep_md_ref)]},
    )
    assert conflicted.status_code == 409

    # 3. Self-approval by requester/owner MUST be rejected 403; independent approver succeeds 200.
    exp_iso = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
    self_app = client.post(
        f"{SPACE_ARCHIVES_PATH}/{export_id}/approve",
        headers=bearer(owner) | {"Idempotency-Key": "space-arch-self-app"},
        json={"expires_at": exp_iso},
    )
    assert self_app.status_code == 403, self_app.text
    approved = client.post(
        f"{SPACE_ARCHIVES_PATH}/{export_id}/approve",
        headers=bearer(reviewer) | {"Idempotency-Key": "space-arch-app"},
        json={"expires_at": exp_iso},
    )
    assert approved.status_code == 200, approved.text

    # 4. Sealing fails closed (503) without configured archive authority, then succeeds once configured.
    no_auth_seal = client.post(
        f"{SPACE_ARCHIVES_PATH}/{export_id}/seal",
        headers=bearer(owner) | {"Idempotency-Key": "space-arch-seal-noauth"},
        json={},
    )
    assert no_auth_seal.status_code == 503, no_auth_seal.text
    service.check_archive_source = lambda credential, probe: authority_for({tenant.actor_id})(probe)
    sealed = client.post(
        f"{SPACE_ARCHIVES_PATH}/{export_id}/seal",
        headers=bearer(owner) | {"Idempotency-Key": "space-arch-seal"},
        json={},
    )
    assert sealed.status_code == 200, sealed.text
    sealed_body = sealed.json()
    assert sealed_body["format_version"] == space_archive.SPACE_ARCHIVE_FORMAT
    assert sealed_body["source_count"] == 2
    assert sealed_body["version_count"] == 4
    assert sealed_body["wiki_count"] == 1
    assert sealed_body["restorable"] is False

    # Immutability guards on persisted rows.
    for tbl in ("space_archive_request", "space_archive_approval", "space_archive_package"):
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            connection.execute(f"DELETE FROM thalion.{tbl}")
        with pytest.raises((errors.FeatureNotSupported, errors.ObjectNotInPrerequisiteState)):
            connection.execute(f"TRUNCATE thalion.{tbl}")
        with pytest.raises(errors.ObjectNotInPrerequisiteState):
            connection.execute(f"TRUNCATE thalion.{tbl} CASCADE")

    # 5. Offline digest & structure verification succeeds and rejects tampering.
    pkg_bytes, pkg_digest = connection.execute(
        "SELECT archive_bytes, archive_digest FROM thalion.space_archive_package WHERE export_ref = %s",
        (UUID(export_id),),
    ).fetchone()
    permit = space_archive.SpaceArchivePermit(
        tenant.org_id, tenant.space_id, tenant.space_ref, UUID(export_id), bytes(pkg_digest), "rehearsal_db",
    )
    verified = space_archive.verify_space_archive(permit, bytes(pkg_bytes))
    assert set(verified.source_refs) == {src1_ref, src2_ref}
    assert set(verified.version_refs) == {keep_md_ref, withdraw_md_ref, keep_md2_ref, keep_docx_ref}
    assert verified.wiki_revision_refs == (wiki_rev_ref,)
    assert len(verified.authorization_rules["shared_groups"]) == 1
    assert verified.recovery_watermark["space_id"] == str(tenant.space_ref)

    # Tampering any byte or repacking with altered auth rules fails offline verification.
    tampered_buf = BytesIO()
    with ZipFile(BytesIO(bytes(pkg_bytes)), "r") as zin, ZipFile(tampered_buf, "w", ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == "authorization/rules.json":
                data = data + b" "
            zout.writestr(info, data)
    tampered_bytes = tampered_buf.getvalue()
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        space_archive.verify_space_archive(permit, tampered_bytes)
    tampered_permit = replace(permit, digest=sha256(tampered_bytes).digest())
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        space_archive.verify_space_archive(tampered_permit, tampered_bytes)


def test_fenced_empty_rebuild_replays_post_backup_stops_deletions_revocations_and_switches_alt_model(
    postgres_server, transport, empty_rehearsal, tmp_path_factory,
):
    client, db, (owner, reviewer), credentials, live, *_ = transport
    connection, tenant, _, src1_ref, store = db
    _, src2_ref = _create_second_source(connection, tenant, source_key="travel-docx-rebuild", namespace="docx-rebuild")

    _, keep_md_ref, keep_md_p, _ = _ingest_and_approve_markdown(
        db, src1_ref, object_key="rb-keep-md", display_name="Rebuild Keep MD", payload=KEEP_MD,
    )
    _, withdraw_md_ref, withdraw_md_p, _ = _ingest_and_approve_markdown(
        db, src1_ref, object_key="rb-withdraw-md", display_name="Rebuild Withdraw MD", payload=WITHDRAW_MD,
    )
    del_cand, delete_md_ref, delete_md_p, _ = _ingest_and_approve_markdown(
        db, src1_ref, object_key="rb-delete-md", display_name="Rebuild Delete MD", payload=DELETE_MD,
    )
    _, keep_md2_ref, keep_md2_p, _ = _ingest_and_approve_markdown(
        db, src2_ref, object_key="rb-keep-md2", display_name="Rebuild Keep Transport MD", payload=KEEP_MD2,
    )
    keep_docx_ref, keep_docx_p, _ = _ingest_and_approve_docx(
        db, src2_ref, object_key="rb-keep-docx", display_name="Rebuild Keep DOCX", payload=docx_package(),
    )

    emp_keep_id, emp_keep_ref = _add_employee(connection, tenant.org_id, "emp-keep")
    emp_revoked_id, emp_revoked_ref = _add_employee(connection, tenant.org_id, "emp-revoked")
    emp_group_id, emp_group_ref = _add_employee(connection, tenant.org_id, "emp-group")

    # Create one active shared group (must survive rebuild) and one revoked shared group (must NOT resurrect).
    now = datetime.now(UTC)
    def _mk_group(name: str):
        rid = uuid4()
        start_request(
            connection,
            RequestStart(
                tenant.org_id, rid, tenant.actor_id, None, "rb-grp",
                governance.MANAGE_SHARED_GROUP, governance.DESTINATION, BEFORE, 1, space_id=tenant.space_id, ingress="internal",
            ),
        )
        res = governance.create_shared_group(
            connection,
            registry.SourceWrite(tenant.org_id, tenant.actor_id, rid, f"grp-{name}-{uuid4()}"),
            tenant.space_id,
            target_source_ref=src1_ref, name=name, purpose="audit_review", scope_summary="Temporary read scope",
            starts_at=now - timedelta(hours=1), review_at=now + timedelta(days=2), expires_at=now + timedelta(days=7),
            basis_ref=uuid4(),
        )
        finish_request(connection, tenant.org_id, rid, "succeeded", 0)
        return res

    active_grp = _mk_group("Active Audit Group")
    revoked_grp = _mk_group("Revoked Audit Group")
    for g_info in (active_grp, revoked_grp):
        rid = uuid4()
        start_request(
            connection,
            RequestStart(
                tenant.org_id, rid, tenant.actor_id, None, "rb-grp",
                governance.MANAGE_SHARED_GROUP, governance.DESTINATION, BEFORE, 1, space_id=tenant.space_id, ingress="internal",
            ),
        )
        governance.add_shared_group_member(
            connection,
            registry.SourceWrite(tenant.org_id, tenant.actor_id, rid, f"mem-{uuid4()}"),
            tenant.space_id, UUID(g_info["group_id"]), member_ref=emp_group_ref,
            starts_at=now - timedelta(minutes=30), expires_at=now + timedelta(days=7), basis_ref=uuid4(),
        )
        finish_request(connection, tenant.org_id, rid, "succeeded", 0)

    compile_ws = replace(compile_rule(tenant.actor_id), fields=policy.WORKSPACE_EVIDENCE_FIELDS)
    review_rule = replace(
        binding(tenant.other_actor_id), operation="review_wiki_revision", purpose="wiki_review",
        destination="local_workspace", fields=policy.WORKSPACE_EVIDENCE_FIELDS,
    )
    publish_rule = replace(review_rule, operation="publish_wiki_revision", purpose="wiki_publication")
    emp_keep_read = replace(binding(emp_keep_id), fields=SEARCH_FIELDS)
    emp_revoked_read = replace(binding(emp_revoked_id), fields=SEARCH_FIELDS)
    active_grp_read = policy.LocalRule(
        UUID(active_grp["group_principal_id"]), "read_passage", "allow", "employee_evidence", "employee",
        SEARCH_FIELDS, now - timedelta(hours=1), now + timedelta(days=7),
    )
    revoked_grp_read = policy.LocalRule(
        UUID(revoked_grp["group_principal_id"]), "read_passage", "allow", "employee_evidence", "employee",
        SEARCH_FIELDS, now - timedelta(hours=1), now + timedelta(days=7),
    )
    _set_source_policy(
        connection, tenant, src1_ref,
        compile_ws, review_rule, publish_rule,
        emp_keep_read, emp_revoked_read,
        active_grp_read, revoked_grp_read,
    )
    _set_source_policy(
        connection, tenant, src2_ref,
        compile_ws, review_rule, publish_rule,
        emp_keep_read, replace(emp_keep_read, passage_ref=keep_docx_p.passage_ref), emp_revoked_read,
    )
    rev_rid = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id, rev_rid, tenant.actor_id, None, "rb-grp",
            governance.MANAGE_SHARED_GROUP, governance.DESTINATION, BEFORE, 1, space_id=tenant.space_id, ingress="internal",
        ),
    )
    governance.revoke_shared_group(
        connection,
        registry.SourceWrite(tenant.org_id, tenant.actor_id, rev_rid, f"rev-{uuid4()}"),
        tenant.space_id, UUID(revoked_grp["group_id"]), reason_code="ended_project", basis_ref=uuid4(),
    )
    finish_request(connection, tenant.org_id, rev_rid, "succeeded", 0)

    keep_wiki_rev, _ = _publish_cross_source_wiki(
        db,
        "keep-wiki",
        "Keep Cross-Source Wiki",
        f"Retained Shanghai hotel rule [p:{keep_md_p.passage_ref}] and transport limit [p:{keep_md2_p.passage_ref}].",
        (keep_md_p, keep_md2_p),
        (keep_md_p, keep_md2_p),
    )
    affected_wiki_rev, _ = _publish_cross_source_wiki(
        db,
        "affected-wiki",
        "Affected Wiki Using Withdrawn Input",
        f"Summary referencing keep [p:{keep_md_p.passage_ref}] with uncited withdrawn dependency.",
        (keep_md_p, withdraw_md_p),
        (keep_md_p,),
    )

    # Prepare independent rule/quality log DB and independent source revocation authority DB.
    with temporary_database(postgres_server) as log_url, temporary_database(postgres_server) as src_auth_url:
        upgrade(log_url)
        upgrade(src_auth_url)
        with open_database(log_url) as log_conn, open_database(src_auth_url) as src_auth_writer:
            src_auth_ref = endpoint(src_auth_writer)
            source_revocations.enroll_space(src_auth_writer, src_auth_ref, tenant.space_ref)
            source_authority = source_revocations.SourceRevocationAuthority(
                lambda: open_database(src_auth_url), src_auth_ref,
            )

            # Seal the multi-source archive BEFORE post-backup withdrawals, deletions, and revocations!
            admit(credentials, owner, space_archive.REQUEST, space_archive.EXPORT, "register_retention_policy", "submit_disposition_case")
            admit(credentials, reviewer, space_archive.APPROVE, REGISTER_TOMBSTONE)
            for row in connection.execute(
                "SELECT public_id FROM thalion.object_identity WHERE (org_id, space_id) = (%s, %s)",
                (tenant.org_id, tenant.space_id),
            ).fetchall():
                live.add(row[0])
            live.update({keep_wiki_rev, affected_wiki_rev})

            req_resp = client.post(
                SPACE_ARCHIVES_PATH,
                headers=bearer(owner) | {"Idempotency-Key": "rb-space-req"},
                json={
                    "source_ids": [str(src1_ref), str(src2_ref)],
                    "version_ids": [
                        str(keep_md_ref), str(withdraw_md_ref), str(delete_md_ref),
                        str(keep_md2_ref), str(keep_docx_ref),
                    ],
                    "wiki_revision_ids": [str(keep_wiki_rev), str(affected_wiki_rev)],
                },
            )
            assert req_resp.status_code == 200, req_resp.text
            export_id = UUID(req_resp.json()["export_id"])

            app_resp = client.post(
                f"{SPACE_ARCHIVES_PATH}/{export_id}/approve",
                headers=bearer(reviewer) | {"Idempotency-Key": "rb-space-app"},
                json={"expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat()},
            )
            assert app_resp.status_code == 200, app_resp.text

            seal_req_id = uuid4()
            start_request(
                connection,
                RequestStart(
                    tenant.org_id, seal_req_id, tenant.actor_id, None, "rb-seal",
                    space_archive.EXPORT, "internal_lifecycle", BEFORE, 1, space_id=tenant.space_id, ingress="internal",
                ),
            )
            seal_call = space_archive.OperationsCall(
                tenant.org_id, tenant.space_id, tenant.actor_id, seal_req_id, "rb-seal-cmd", 1,
            )
            seal_ctx = space_archive.delivery.DeliveryContext(
                seal_req_id, tenant.org_id, tenant.actor_id, "rb-seal",
                space_archive.EXPORT, space_archive.PURPOSE, space_archive.ARCHIVE_DESTINATION,
                datetime.now(UTC) + timedelta(minutes=2),
            )
            with connection.transaction():
                sealed_meta = space_archive.seal_space_archive(
                    connection, seal_call, export_id, store, seal_ctx,
                    authority_for({tenant.actor_id}),
                    rule_log=log_conn, source_authority=source_authority,
                )
            finish_request(connection, tenant.org_id, seal_req_id, "succeeded", 0)
            assert sealed_meta["watermark_generation"] if "watermark_generation" in sealed_meta else True
            assert sealed_meta["recovery_watermark"]["source_authority_generation"] == 0
            assert sealed_meta["recovery_watermark"]["rule_log_generation"] == 0

            pkg_bytes, pkg_digest = connection.execute(
                "SELECT archive_bytes, archive_digest FROM thalion.space_archive_package WHERE export_ref = %s",
                (export_id,),
            ).fetchone()

            # === POST-BACKUP SAFETY TIGHTENING ===
            # 1. Withdraw withdraw_md in primary DB.
            withdraw_stop = effectivity.stop_synthetic_rule(
                connection, record(connection, tenant, "stop_rule_use", "rb-stop-withdraw"),
                tenant.space_id, withdraw_md_ref, "withdrawn", uuid4(),
            )
            # 2. Source-delete delete_md (retention -> withdraw -> disposition case -> approval -> tombstone -> deleted receipt).
            assert configure_retention(client, owner, src1_ref, action="destroy", expected=0).status_code == 200
            effectivity.stop_synthetic_rule(
                connection, record(connection, tenant, "stop_rule_use", "rb-stop-delete"),
                tenant.space_id, delete_md_ref, "withdrawn", uuid4(),
            )
            delete_event = uuid4()
            case_id = submitted(client, owner, credentials, src1_ref, SimpleNamespace(version_ref=delete_md_ref), expected=1)
            disp_app_id = approve_disposition(client, reviewer, credentials, case_id, basis=delete_event)
            tomb_reply = register_tombstone(client, reviewer, case_id, disp_app_id)
            assert tomb_reply.status_code == 200, tomb_reply.text
            tombstone_id = UUID(tomb_reply.json()["tombstone_id"])
            source_restrictions.acknowledge_removal(
                connection,
                sync_request(connection, tenant, operation=source_restrictions.COMMIT),
                sync.SyncSource(tenant.space_id, src1_ref, 1),
                source_restrictions.Removal(
                    delete_event, del_cand.object_key, del_cand.incarnation,
                    del_cand.source_version_key, "deleted", tombstone_id,
                ),
            )
            # 3. Revoke emp_revoked's read permission on keep_md in independent source revocation authority.
            source_revocations.revoke(
                src_auth_writer, src_auth_ref, tenant.space_ref, emp_revoked_ref, keep_md_p.passage_ref,
                "evidence", basis_ref=uuid4(),
            )

            target, rehearsal_url = empty_rehearsal
            permit = space_archive.SpaceArchivePermit(
                tenant.org_id, tenant.space_id, tenant.space_ref, export_id, bytes(pkg_digest), target.info.dbname,
            )
            scratch = tmp_path_factory.mktemp("space-archive-rebuild")

            # Negative check 1: Lagging independent rule log MUST reject rebuild & leave target completely empty!
            with pytest.raises(archive_rehearsal.ArchiveRejected, match="rule restriction log"):
                space_archive.rebuild_space_archive_in_rehearsal(
                    target, permit, bytes(pkg_bytes), scratch,
                    authority=connection, log=log_conn,
                    authority_ref=endpoint(connection), log_ref=endpoint(log_conn),
                    source_authority=source_authority,
                    alternate_model_profile="synthetic-alt-model-v2",
                )
            assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
            assert list(scratch.iterdir()) == []

            # Deliver latest rule & quality restrictions to independent log DB.
            delivered_rules = restriction_log.deliver_pending(connection, log_conn, tenant.org_id)
            assert withdraw_stop in delivered_rules.confirmed and tombstone_id in delivered_rules.confirmed
            assert quality_restrictions.deliver_pending(connection, log_conn, tenant.org_id).status == "ok"

            # Negative check 2: Non-distinct endpoint identifiers rejected.
            with pytest.raises(archive_rehearsal.ArchiveRejected, match="distinct endpoints"):
                space_archive.rebuild_space_archive_in_rehearsal(
                    target, permit, bytes(pkg_bytes), scratch,
                    authority=connection, log=log_conn,
                    authority_ref=endpoint(connection), log_ref=endpoint(connection),
                    source_authority=source_authority,
                    alternate_model_profile="synthetic-alt-model-v2",
                )

            # Positive full fenced rebuild with alternate model profile & pre-open old-reference checks.
            ref_checks = (
                space_archive.OldReferenceCheck(
                    label="keep_md_allowed_for_emp_keep",
                    kind="passage",
                    principal_ref=emp_keep_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=True,
                    passage_ref=keep_md_p.passage_ref,
                    version_ref=keep_md_ref,
                    query="Shanghai hotel allowance 600",
                ),
                space_archive.OldReferenceCheck(
                    label="keep_md2_allowed_for_emp_keep",
                    kind="passage",
                    principal_ref=emp_keep_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=True,
                    passage_ref=keep_md2_p.passage_ref,
                    version_ref=keep_md2_ref,
                    query="railway ticket limit 450",
                ),
                space_archive.OldReferenceCheck(
                    label="keep_docx_allowed_for_emp_keep",
                    kind="passage",
                    principal_ref=emp_keep_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=True,
                    passage_ref=keep_docx_p.passage_ref,
                    version_ref=keep_docx_ref,
                ),
                space_archive.OldReferenceCheck(
                    label="keep_wiki_allowed_for_emp_keep",
                    kind="wiki",
                    principal_ref=emp_keep_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=True,
                    topic_key="keep-wiki",
                ),
                space_archive.OldReferenceCheck(
                    label="withdrawn_md_blocked_no_resurrection",
                    kind="passage",
                    principal_ref=emp_keep_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=False,
                    passage_ref=withdraw_md_p.passage_ref,
                    version_ref=withdraw_md_ref,
                    query="Withdraw legacy meal subsidy",
                ),
                space_archive.OldReferenceCheck(
                    label="affected_wiki_blocked_by_withdrawn_input",
                    kind="wiki",
                    principal_ref=emp_keep_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=False,
                    topic_key="affected-wiki",
                ),
                space_archive.OldReferenceCheck(
                    label="deleted_md_blocked_no_resurrection",
                    kind="passage",
                    principal_ref=emp_keep_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=False,
                    passage_ref=delete_md_p.passage_ref,
                    version_ref=delete_md_ref,
                    query="Deleted confidential contractor rate",
                ),
                space_archive.OldReferenceCheck(
                    label="source_revoked_employee_blocked_on_keep_md",
                    kind="passage",
                    principal_ref=emp_revoked_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=False,
                    passage_ref=keep_md_p.passage_ref,
                    version_ref=keep_md_ref,
                    query="Shanghai hotel allowance 600",
                ),
                space_archive.OldReferenceCheck(
                    label="active_shared_group_member_allowed_on_keep_md",
                    kind="passage",
                    principal_ref=emp_group_ref,
                    business_date=BEFORE,
                    region="shanghai",
                    traveler_class="employee",
                    expected_accessible=True,
                    passage_ref=keep_md_p.passage_ref,
                    version_ref=keep_md_ref,
                ),
            )

            report = space_archive.rebuild_space_archive_in_rehearsal(
                target, permit, bytes(pkg_bytes), scratch,
                authority=connection, log=log_conn,
                authority_ref=endpoint(connection), log_ref=endpoint(log_conn),
                source_authority=source_authority,
                alternate_model_profile="synthetic-alt-model-v2",
                lexical_index_mode="indexed",
                reference_checks=ref_checks,
            )

            # Verify report metrics, alternate model switch, selective indexing, and persisted audit row.
            report_dict = report.to_dict()
            assert report_dict["format_version"] == space_archive.SPACE_ARCHIVE_FORMAT
            assert report_dict["alternate_model_profile"] == "synthetic-alt-model-v2"
            assert report_dict["lexical_index_mode"] == "indexed"
            assert report_dict["rebuilt_sources"] == 2
            assert report_dict["rebuilt_versions"] == 5
            assert report_dict["rebuilt_wikis"] == 2
            assert set(report.indexed_versions) == {keep_md_ref, keep_md2_ref}
            assert report.replayed_stops >= 2
            assert report.replayed_deletions >= 1
            assert report.replayed_revocations == 1
            assert report_dict["verified_references"] == 5
            assert report_dict["blocked_references"] == 4
            assert report.duration_ms >= 0
            assert report.scratch_bytes > 0
            assert tuple(report_dict["affected_services"]) == space_archive.AFFECTED_SERVICES

            # Verify alternate model template & space release config in fenced DB.
            cfg = target.execute(
                """
                SELECT c.template_key, c.lexical_index_mode, t.model_profile, t.prompt
                FROM thalion.current_space_release_config AS c
                JOIN thalion.compile_template_revision AS t
                  ON (t.org_id, t.space_id, t.revision_ref) = (c.org_id, c.space_id, c.template_revision_ref)
                WHERE (c.org_id, c.space_id) = (%s, %s)
                """,
                (report.org_id, report.space_id),
            ).fetchone()
            assert cfg[0] == "rebuilt-alt-model"
            assert cfg[1] == "indexed"
            assert cfg[2] == "synthetic-local"
            assert "synthetic-alt-model-v2" in cfg[3]

            # Verify ONLY active shared group survived; revoked shared group did NOT resurrect.
            restored_groups = target.execute(
                "SELECT name FROM thalion.shared_group WHERE (org_id, owner_space_id) = (%s, %s)",
                (report.org_id, report.space_id),
            ).fetchall()
            assert restored_groups == [("Active Audit Group",)]

            # Verify persisted space_archive_rebuild row & immutability + fencing protection.
            persisted = target.execute(
                """
                SELECT format_version, alternate_model_profile, rebuilt_sources, rebuilt_versions,
                       rebuilt_wikis, replayed_stops, replayed_deletions, replayed_revocations,
                       verified_references, blocked_references, scratch_bytes
                FROM thalion.space_archive_rebuild
                WHERE rebuild_ref = %s
                """,
                (report.rebuild_ref,),
            ).fetchone()
            assert persisted == (
                space_archive.SPACE_ARCHIVE_FORMAT, "synthetic-alt-model-v2",
                2, 5, 2, report.replayed_stops, report.replayed_deletions, 1, 5, 4, report.scratch_bytes,
            )
            with pytest.raises(errors.ObjectNotInPrerequisiteState):
                target.execute("UPDATE thalion.space_archive_rebuild SET rebuilt_sources = 1")
            with pytest.raises((errors.FeatureNotSupported, errors.ObjectNotInPrerequisiteState)):
                target.execute("TRUNCATE thalion.space_archive_rebuild")
            with pytest.raises(errors.ObjectNotInPrerequisiteState):
                target.execute("TRUNCATE thalion.space_archive_rebuild CASCADE")
            assert rehearsal_marker(target) == target.info.dbname
            with pytest.raises(errors.OperationalError, match="rehearsal"):
                local_connection_factory(rehearsal_url)()


def test_lexical_build_index_still_rejects_fenced_rehearsal_by_default(empty_rehearsal, corpus):
    db, *_ = corpus
    connection, tenant, _, _, store = db
    rehearsal_conn, _ = empty_rehearsal
    with pytest.raises(lexical.LexicalIndexUnavailable):
        lexical.build_index(rehearsal_conn, store, tenant.space_ref, uuid4(), uuid4())
    with pytest.raises(lexical.LexicalIndexUnavailable):
        lexical.build_index(connection, store, tenant.space_ref, uuid4(), uuid4(), allow_rehearsal=True)
