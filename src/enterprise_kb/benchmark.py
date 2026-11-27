import argparse
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
import math
import os
from pathlib import Path
import platform
from secrets import token_urlsafe
import socket
import sys
from threading import Event, Thread
from time import monotonic, sleep
from typing import Literal
from uuid import UUID, uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi.testclient import TestClient
import httpx2
import psycopg
from sqlalchemy.exc import ArgumentError
import uvicorn

from enterprise_kb.database import local_connection_factory, require_current_schema
from enterprise_kb.modules.access import delivery, policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.operations import evaluation, release
from enterprise_kb.modules.retrieval import lexical, vector
from enterprise_kb.modules.sources import effectivity, originals, registry
from enterprise_kb.modules.wiki import drafts, inputs, publication
from enterprise_kb.runtime.audit import RequestStart, start_request
from enterprise_kb.runtime.jobs import claim_job
from enterprise_kb.transport import api, evidence


DATASET_KIND = "synthetic_local"
QA_LATENCY_STATUS = "unmeasured_no_approved_agent"
DISCLAIMER = (
    "本报告仅基于本机隔离合成差旅语料与 HTTP/MCP 取证边界端到端实测，"
    "不替代真实域冻结盲测、双人业务判分、完整问答延迟或生产放行结论。"
)
MCP_PROTOCOL_VERSION = "2026-07-28"
DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
SEARCH_FIELDS = frozenset({"excerpt", "citation", "title", "location", "version"})
HISTORICAL_START = date(2026, 1, 1)
HISTORICAL_END = date(2026, 6, 30)
CURRENT_START = date(2026, 7, 1)
HISTORICAL_DAY = date(2026, 3, 15)
CURRENT_DAY = date(2026, 11, 12)
EXEC_SECRET_MARKER = "EXEC_SECRET_1800"

DOCX_CONTENT_TYPES = """<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
 <Default Extension="xml" ContentType="application/xml"/>
 <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
 <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""
DOCX_ROOT_RELS = """<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
DOCX_DOCUMENT_RELS = """<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
DOCX_STYLES = """<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:styleId="Base"><w:pPr><w:outlineLvl w:val="1"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Section"><w:basedOn w:val="Base"/></w:style>
</w:styles>"""

TransportMode = Literal["asgi", "loopback_http"]
CaseCategory = Literal["supported", "unsupported", "authority_revoked", "dependency_fault"]


@dataclass(frozen=True)
class _BenchmarkArm:
    name: str
    lexical_index_mode: Literal["indexed", "hybrid_vector"]
    wiki_enabled: bool
    vector_model_id: str | None = None


BENCHMARK_ARMS: tuple[_BenchmarkArm, ...] = (
    _BenchmarkArm("indexed__rag_only", "indexed", False, None),
    _BenchmarkArm("indexed__rag_plus_wiki", "indexed", True, None),
    _BenchmarkArm("hybrid_vector__rag_only", "hybrid_vector", False, vector.DEFAULT_MODEL_ID),
    _BenchmarkArm("hybrid_vector__rag_plus_wiki", "hybrid_vector", True, vector.DEFAULT_MODEL_ID),
)


@dataclass(frozen=True)
class _BenchmarkCase:
    case_id: str
    family_id: str
    kind: CaseCategory
    actor_key: Literal["full", "restricted"]
    business_date: date
    query: str = field(repr=False)
    required_groups: tuple[tuple[tuple[str, str], ...], ...] = ()
    forbidden_passage_ids: frozenset[str] = frozenset()
    forbidden_substrings: tuple[str, ...] = field(default=(), repr=False)
    cross_document: bool = False
    historical_date: bool = False
    semantic_synonym: bool = False
    top_k: int = 5
    sla_ms: int = 3000


def _build_docx_bytes(paragraphs: Sequence[tuple[str, Sequence[str]]]) -> bytes:
    body_parts = ['<w:p><w:pPr><w:outlineLvl w:val="0"/></w:pPr><w:r><w:t>差旅补充细则</w:t></w:r></w:p>']
    for heading, lines in paragraphs:
        body_parts.append(
            f'<w:p><w:pPr><w:pStyle w:val="Section"/></w:pPr><w:r><w:t>{heading}</w:t></w:r></w:p>'
        )
        for line in lines:
            body_parts.append(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>")
    document_xml = (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{''.join(body_parts)}<w:sectPr/></w:body></w:document>"
    )
    entries = {
        "[Content_Types].xml": DOCX_CONTENT_TYPES,
        "_rels/.rels": DOCX_ROOT_RELS,
        "word/document.xml": document_xml,
        "word/styles.xml": DOCX_STYLES,
        "word/_rels/document.xml.rels": DOCX_DOCUMENT_RELS,
    }
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for filename, literal in entries.items():
            archive.writestr(filename, literal)
    return buffer.getvalue()


def _rate(numerator: int, denominator: int) -> dict:
    if denominator == 0:
        return {"numerator": 0, "denominator": 0, "rate": None, "status": "unmeasured"}
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": round(numerator / denominator, 6),
        "status": "measured",
    }


def _percentile(sorted_values: Sequence[float], fraction: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return round(float(sorted_values[0]), 3)
    index = max(0, math.ceil(len(sorted_values) * fraction) - 1)
    return round(float(sorted_values[min(index, len(sorted_values) - 1)]), 3)


def _latency_summary(values: Sequence[float]) -> dict:
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "p50": _percentile(ordered, 0.50),
        "p95": _percentile(ordered, 0.95),
        "p99": _percentile(ordered, 0.99),
        "max": round(float(ordered[-1]), 3) if ordered else None,
    }


def _write_context(
    connection: psycopg.Connection,
    org_id: int,
    space_id: int,
    principal_id: int,
    operation: str,
    destination: str = "internal_benchmark",
) -> registry.SourceWrite:
    request_id = uuid4()
    start_request(
        connection,
        RequestStart(
            org_id,
            request_id,
            principal_id,
            None,
            "synthetic-benchmark",
            operation,
            destination,
            CURRENT_DAY,
            1,
            space_id=space_id,
            ingress="internal",
        ),
    )
    return registry.SourceWrite(org_id, principal_id, request_id, str(uuid4()))


def _delivery_context(
    connection: psycopg.Connection,
    org_id: int,
    space_id: int,
    principal_id: int,
    operation: str,
    purpose: str,
    destination: str,
) -> delivery.DeliveryContext:
    request_id = uuid4()
    start_request(
        connection,
        RequestStart(
            org_id,
            request_id,
            principal_id,
            None,
            "synthetic-benchmark",
            operation,
            destination,
            CURRENT_DAY,
            1,
            space_id=space_id,
            ingress="internal",
        ),
    )
    return delivery.DeliveryContext(
        request_id,
        org_id,
        principal_id,
        "synthetic-benchmark",
        operation,
        purpose,
        destination,
        datetime.now(UTC) + timedelta(seconds=20),
    )


def _static_authority(allowed_principals: frozenset[int], allowed_objects_by_principal: dict[int, frozenset[UUID]]):
    def check(probe: delivery.DeliveryCheck) -> delivery.AuthorityDecision:
        checked_at = datetime.now(UTC)
        principal_id = probe.context.principal_id
        if principal_id not in allowed_principals:
            granted = {scope: frozenset() for scope in probe.scopes}
        else:
            allowed_objects = allowed_objects_by_principal.get(principal_id)
            granted = {
                scope: scope.fields if (allowed_objects is None or scope.object_id in allowed_objects) else frozenset()
                for scope in probe.scopes
            }
        return delivery.AuthorityDecision(
            probe.check_id,
            checked_at,
            checked_at + timedelta(seconds=10),
            frozenset({principal_id}),
            granted,
            f"synthetic-benchmark:{uuid4()}",
        )

    return check


def _setup_synthetic_corpus(connection: psycopg.Connection, store: originals.SyntheticOriginalStore) -> dict:
    label = f"Synthetic Benchmark Org {uuid4().hex[:8]}"
    with connection.transaction():
        org_id, = connection.execute(
            "INSERT INTO thalion.organization (name, business_timezone) "
            "VALUES (%s, 'Asia/Shanghai') RETURNING org_id",
            (label,),
        ).fetchone()
        principals: list[int] = []
        principal_refs: list[UUID] = []
        for role in ("employee", "employee", "service", "service"):
            principal_id, = connection.execute(
                "INSERT INTO thalion.principal "
                "(org_id, principal_type, authority_issuer, authority_subject_key) "
                "VALUES (%s, %s, 'https://synthetic.invalid', %s) RETURNING principal_id",
                (org_id, role, str(uuid4())),
            ).fetchone()
            principal_ref, = connection.execute(
                "INSERT INTO thalion.object_identity (org_id, object_type, object_id) "
                "VALUES (%s, 'principal', %s) RETURNING public_id",
                (org_id, principal_id),
            ).fetchone()
            principals.append(principal_id)
            principal_refs.append(principal_ref)
        full_emp, restricted_emp, ingest_worker, parse_worker = principals
        full_ref, restricted_ref = principal_refs[0], principal_refs[1]
        space_id, = connection.execute(
            "INSERT INTO thalion.space (org_id, name, classification, owner_principal_id) "
            "VALUES (%s, 'Travel Benchmark', 'internal', %s) RETURNING space_id",
            (org_id, full_emp),
        ).fetchone()
        space_ref, = connection.execute(
            "INSERT INTO thalion.object_identity (org_id, object_type, object_id, space_id) "
            "VALUES (%s, 'space', %s, %s) RETURNING public_id",
            (org_id, space_id, space_id),
        ).fetchone()

    source_ref = registry.register_synthetic_source(
        connection,
        _write_context(connection, org_id, space_id, full_emp, "register_source_contract"),
        space_id,
        registry.SyntheticSource(
            "travel-benchmark",
            "travel-archive",
            ingest_worker,
            approver_id=restricted_emp,
            processor_id=parse_worker,
            quality_reviewer_id=full_emp,
        ),
    )

    historical_md = (
        "# 差旅住宿标准\n\n"
        "上海普通住宿上限为500元每晚。\n"
    ).encode("utf-8")
    current_md = (
        "# 差旅住宿标准\n\n"
        "上海普通住宿上限为600元每晚，会议统一安排另有规定。\n"
    ).encode("utf-8")
    approval_md = (
        "# 超标事前审批\n\n"
        "上海差旅超标须事前取得部门负责人书面批准。\n"
    ).encode("utf-8")
    supplement_docx = _build_docx_bytes(
        (
            ("北京餐补", ("京区出勤伙食补贴每日80元。",)),
            ("高管专车", (f"高管专车补贴每日上限1800元，内部标识{EXEC_SECRET_MARKER}。",)),
        )
    )

    def register_and_approve(
        object_key: str,
        version_key: str,
        title: str,
        version_label: str,
        payload: bytes,
        media_type: str,
        start_day: date,
        *,
        end_day: date | None = None,
        replaces: UUID | None = None,
    ):
        version = registry.register_synthetic_version(
            connection,
            _write_context(connection, org_id, space_id, ingest_worker, "register_version"),
            registry.SourceVersion(
                space_id,
                source_ref,
                1,
                "travel-benchmark",
                object_key,
                version_key,
                title,
                version_label,
                sha256(payload).digest(),
                media_type=media_type,
            ),
            payload,
            store,
        )
        lease = claim_job(connection, org_id, "parse", parse_worker, timedelta(minutes=2))
        if lease is None or lease.spec.target_ref != version.version_ref:
            raise RuntimeError("Failed to claim parse job for synthetic benchmark document.")
        run = processing.process_evidence_job(connection, lease, store)
        processing.decide_quality(
            connection,
            _write_context(connection, org_id, space_id, full_emp, "decide_evidence_quality"),
            space_id,
            run.run_ref,
            run.manifest_digest,
            "approved",
            uuid4(),
        )
        decision_ref = effectivity.approve_synthetic_rule(
            connection,
            _write_context(connection, org_id, space_id, restricted_emp, "approve_effectivity"),
            space_id,
            version.version_ref,
            effectivity.Approval(start_day, end_day, None, None, uuid4(), replaces),
        )
        if media_type == DOCX_MEDIA_TYPE:
            passages = processing.list_approved_docx_paragraphs(connection, org_id, space_id, version.version_ref)
        else:
            passages = processing.list_approved_passages(connection, org_id, space_id, version.version_ref)
        return version, run, passages, decision_ref

    hist_ver, hist_run, hist_passages, hist_decision = register_and_approve(
        "lodging-policy",
        "rev-2026h1",
        "差旅住宿标准",
        "2026H1",
        historical_md,
        "text/markdown",
        HISTORICAL_START,
    )
    curr_ver, curr_run, curr_passages, _ = register_and_approve(
        "lodging-policy",
        "rev-2026h2",
        "差旅住宿标准",
        "2026H2",
        current_md,
        "text/markdown",
        CURRENT_START,
        replaces=hist_decision,
    )
    appr_ver, appr_run, appr_passages, _ = register_and_approve(
        "approval-policy",
        "rev-2026-appr",
        "差旅超标事前审批规定",
        "2026.1",
        approval_md,
        "text/markdown",
        HISTORICAL_START,
    )
    docx_ver, docx_run, docx_passages, _ = register_and_approve(
        "meal-and-exec-policy",
        "rev-2026-docx",
        "差旅餐补与专项补充细则",
        "2026.1",
        supplement_docx,
        DOCX_MEDIA_TYPE,
        HISTORICAL_START,
    )

    provider = vector.SyntheticLocalEmbeddingProvider(model_id=vector.DEFAULT_MODEL_ID)
    for version, run in ((hist_ver, hist_run), (curr_ver, curr_run), (appr_ver, appr_run), (docx_ver, docx_run)):
        lexical.build_index(connection, store, space_ref, version.version_ref, run.run_ref)
        vector.build_vector_index(connection, store, space_ref, version.version_ref, run.run_ref, provider)

    hist_shanghai = hist_passages[0]
    curr_shanghai = curr_passages[0]
    md_approval = appr_passages[0]
    docx_meal, docx_exec_secret = docx_passages[0], docx_passages[1]

    public_passages = (
        *hist_passages,
        *curr_passages,
        *appr_passages,
        docx_meal,
    )
    public_passage_refs = frozenset(item.passage_ref for item in public_passages)
    valid_from = datetime.now(UTC) - timedelta(days=1)
    rules: list[policy.LocalRule] = [
        policy.LocalRule(full_emp, "read_passage", "allow", "employee_evidence", "employee", SEARCH_FIELDS, valid_from),
        policy.LocalRule(
            full_emp, "assemble_wiki_inputs", "allow", "wiki_compilation", "local_workspace",
            policy.WORKSPACE_EVIDENCE_FIELDS, valid_from,
        ),
        policy.LocalRule(
            restricted_emp, "review_wiki_revision", "allow", "wiki_review", "local_workspace",
            policy.WORKSPACE_EVIDENCE_FIELDS, valid_from,
        ),
        policy.LocalRule(
            restricted_emp, "publish_wiki_revision", "allow", "wiki_publication", "local_workspace",
            policy.WORKSPACE_EVIDENCE_FIELDS, valid_from,
        ),
    ]
    for passage in public_passages:
        rules.append(
            policy.LocalRule(
                restricted_emp,
                "read_passage",
                "allow",
                "employee_evidence",
                "employee",
                SEARCH_FIELDS,
                valid_from,
                None,
                passage.passage_ref,
            )
        )
    policy.replace_synthetic_policy(
        connection,
        _write_context(connection, org_id, space_id, full_emp, "replace_local_policy"),
        space_id,
        source_ref,
        1,
        tuple(rules),
        uuid4(),
    )

    auth_all_public = _static_authority(
        frozenset({full_emp, restricted_emp}),
        {restricted_emp: public_passage_refs},
    )
    sealed_inputs = inputs.prepare_wiki_inputs(
        connection,
        _delivery_context(
            connection, org_id, space_id, full_emp,
            "assemble_wiki_inputs", "wiki_compilation", "local_workspace",
        ),
        space_id,
        ((curr_shanghai.passage_ref, curr_shanghai.revision), (md_approval.passage_ref, md_approval.revision)),
        (),
        store,
        region="shanghai",
        traveler_class="employee",
        check_authority=auth_all_public,
    )
    if sealed_inputs.status != "succeeded" or sealed_inputs.manifest_ref is None:
        raise RuntimeError(f"Failed to seal synthetic wiki inputs: {sealed_inputs.status}")

    wiki_candidate = drafts.create_manual_candidate(
        connection,
        _delivery_context(
            connection, org_id, space_id, full_emp,
            "create_wiki_candidate", "wiki_compilation", "local_workspace",
        ),
        space_id,
        drafts.ManualCandidate(
            "travel-shanghai-lodging",
            "上海差旅住宿上限与超标审批指引",
            "## 上海住宿上限与超标审批\n上海普通住宿上限为600元每晚；超标须事前取得部门负责人书面批准。",
            sealed_inputs.manifest_ref,
            restricted_emp,
            uuid4(),
            ((curr_shanghai.passage_ref, curr_shanghai.revision), (md_approval.passage_ref, md_approval.revision)),
            statements=(
                drafts.WikiStatement(
                    "上海普通住宿上限为600元每晚，会议统一安排另有规定。",
                    (((curr_shanghai.passage_ref, curr_shanghai.revision),),),
                ),
                drafts.WikiStatement(
                    "上海差旅超标须事前取得部门负责人书面批准。",
                    (((md_approval.passage_ref, md_approval.revision),),),
                ),
            ),
        ),
        str(uuid4()),
        region="shanghai",
        traveler_class="employee",
        check_authority=auth_all_public,
    )
    if wiki_candidate.status != "succeeded" or wiki_candidate.ref is None:
        raise RuntimeError(f"Failed to create synthetic wiki candidate: {wiki_candidate.status}")

    preview = drafts.read_candidate_for_review(
        connection,
        _delivery_context(
            connection, org_id, space_id, restricted_emp,
            "read_wiki_candidate", "wiki_review", "local_workspace",
        ),
        space_id,
        wiki_candidate.ref,
        region="shanghai",
        traveler_class="employee",
        check_authority=auth_all_public,
    )
    if preview.status != "succeeded" or preview.payload is None or preview.input_digest is None:
        raise RuntimeError(f"Failed to preview synthetic wiki candidate: {preview.status}")

    reviewed = drafts.submit_review(
        connection,
        _delivery_context(
            connection, org_id, space_id, restricted_emp,
            "review_wiki_revision", "wiki_review", "local_workspace",
        ),
        space_id,
        wiki_candidate.ref,
        sha256(preview.payload).digest(),
        preview.input_digest,
        "approved",
        "verified_against_synthetic_originals",
        uuid4(),
        str(uuid4()),
        review_material_ref=preview.review_material_ref,
        region="shanghai",
        traveler_class="employee",
        check_authority=auth_all_public,
    )
    if reviewed.status != "succeeded" or reviewed.ref is None:
        raise RuntimeError(f"Failed to approve synthetic wiki candidate: {reviewed.status}")

    published = publication.publish_revision(
        connection,
        _delivery_context(
            connection, org_id, space_id, restricted_emp,
            "publish_wiki_revision", "wiki_publication", "local_workspace",
        ),
        space_id,
        wiki_candidate.ref,
        reviewed.ref,
        str(uuid4()),
        region="shanghai",
        traveler_class="employee",
        check_authority=auth_all_public,
    )
    if published.status != "succeeded":
        raise RuntimeError(f"Failed to publish synthetic wiki revision: {published.status}")

    cases = (
        _BenchmarkCase(
            case_id="exact_lodging",
            family_id="fam_exact_lodging",
            kind="supported",
            actor_key="full",
            business_date=CURRENT_DAY,
            query="上海 住宿上限",
            required_groups=(((str(curr_ver.version_ref), str(curr_shanghai.passage_ref)),),),
        ),
        _BenchmarkCase(
            case_id="exact_docx_meal",
            family_id="fam_exact_docx_meal",
            kind="supported",
            actor_key="restricted",
            business_date=CURRENT_DAY,
            query="京区 伙食补贴",
            required_groups=(((str(docx_ver.version_ref), str(docx_meal.passage_ref)),),),
            forbidden_passage_ids=frozenset({str(docx_exec_secret.passage_ref)}),
            forbidden_substrings=(EXEC_SECRET_MARKER,),
        ),
        _BenchmarkCase(
            case_id="cross_doc_lodging_approval",
            family_id="fam_cross_doc",
            kind="supported",
            actor_key="full",
            business_date=CURRENT_DAY,
            query="上海 住宿上限 超标 书面批准",
            required_groups=(
                ((str(curr_ver.version_ref), str(curr_shanghai.passage_ref)),),
                ((str(appr_ver.version_ref), str(md_approval.passage_ref)),),
            ),
            cross_document=True,
        ),
        _BenchmarkCase(
            case_id="historical_lodging",
            family_id="fam_historical",
            kind="supported",
            actor_key="full",
            business_date=HISTORICAL_DAY,
            query="上海 住宿上限",
            required_groups=(((str(hist_ver.version_ref), str(hist_shanghai.passage_ref)),),),
            forbidden_passage_ids=frozenset({str(curr_shanghai.passage_ref)}),
            forbidden_substrings=("600元",),
            historical_date=True,
        ),
        _BenchmarkCase(
            case_id="synonym_hotel_allowance",
            family_id="fam_synonym_lodging",
            kind="supported",
            actor_key="full",
            business_date=CURRENT_DAY,
            query="沪宾馆房费额度",
            required_groups=(((str(curr_ver.version_ref), str(curr_shanghai.passage_ref)),),),
            semantic_synonym=True,
        ),
        _BenchmarkCase(
            case_id="synonym_docx_beijing_meal",
            family_id="fam_synonym_docx_meal",
            kind="supported",
            actor_key="restricted",
            business_date=CURRENT_DAY,
            query="北京餐饮饭补",
            required_groups=(((str(docx_ver.version_ref), str(docx_meal.passage_ref)),),),
            forbidden_passage_ids=frozenset({str(docx_exec_secret.passage_ref)}),
            forbidden_substrings=(EXEC_SECRET_MARKER,),
            semantic_synonym=True,
        ),
        _BenchmarkCase(
            case_id="unsupported_qingdao_flight",
            family_id="fam_unsupported",
            kind="unsupported",
            actor_key="full",
            business_date=CURRENT_DAY,
            query="青岛航空舱位",
        ),
        _BenchmarkCase(
            case_id="authority_revoked_exec_car",
            family_id="fam_revoked",
            kind="authority_revoked",
            actor_key="restricted",
            business_date=CURRENT_DAY,
            query="高管专车补贴",
            forbidden_passage_ids=frozenset({str(docx_exec_secret.passage_ref)}),
            forbidden_substrings=(EXEC_SECRET_MARKER, "1800"),
        ),
        _BenchmarkCase(
            case_id="dependency_fault_probe",
            family_id="fam_dep_fault",
            kind="dependency_fault",
            actor_key="full",
            business_date=CURRENT_DAY,
            query="上海 住宿上限",
        ),
    )

    return {
        "org_id": org_id,
        "space_id": space_id,
        "space_ref": space_ref,
        "full_emp": full_emp,
        "full_ref": full_ref,
        "restricted_emp": restricted_emp,
        "restricted_ref": restricted_ref,
        "public_passage_refs": public_passage_refs,
        "cases": cases,
        "corpus_summary": {
            "documents": 3,
            "versions": 4,
            "formats": ["text/markdown", DOCX_MEDIA_TYPE],
            "published_wiki_topics": 1,
            "vector_model_id": vector.DEFAULT_MODEL_ID,
        },
    }


def _check_leakage(case: _BenchmarkCase, payload: dict | None) -> int:
    if payload is None:
        return 0
    leaked = 0
    texts: list[str] = []
    for passage in payload.get("passages", []):
        if str(passage.get("passage_id", "")) in case.forbidden_passage_ids:
            leaked += 1
        texts.append(str(passage.get("title", "")))
        texts.append(str(passage.get("excerpt", "")))
    for wiki_item in payload.get("wiki", []):
        texts.append(str(wiki_item.get("title", "")))
        for claim in wiki_item.get("claims", []):
            texts.append(str(claim.get("text", "")))
            for passage_id in claim.get("passage_ids", []):
                if str(passage_id) in case.forbidden_passage_ids:
                    leaked += 1
    haystack = "\n".join(texts)
    for needle in case.forbidden_substrings:
        if needle and needle in haystack:
            leaked += 1
    return leaked


def _dedup_keys(payload: dict | None, limit: int = 5) -> list[tuple[str, str]]:
    if payload is None:
        return []
    seen: set[tuple[str, str]] = set()
    ordered: list[tuple[str, str]] = []
    for passage in payload.get("passages", []):
        key = (str(passage["version_id"]), str(passage["passage_id"]))
        if key not in seen:
            seen.add(key)
            ordered.append(key)
            if len(ordered) >= limit:
                break
    return ordered


def _invoke_http(client, token: str, arguments: dict) -> tuple[str, dict | None, float]:
    started = monotonic()
    response = client.post(
        "/v1/search",
        json=arguments,
        headers={"Authorization": f"Bearer {token}"},
    )
    elapsed_ms = round((monotonic() - started) * 1000.0, 3)
    body = response.json()
    if response.status_code == 200:
        status = "succeeded" if body.get("status") == "hits" else str(body.get("status", "unknown"))
        return status, body, elapsed_ms
    error_code = str(body.get("error", {}).get("code", f"http_{response.status_code}"))
    return error_code, None, elapsed_ms


def _invoke_mcp(client, token: str, arguments: dict, rpc_id: int) -> tuple[str, dict | None, float]:
    started = monotonic()
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Mcp-Protocol-Version": MCP_PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "search",
        },
    )
    elapsed_ms = round((monotonic() - started) * 1000.0, 3)
    body = response.json()
    if response.status_code != 200:
        return f"http_{response.status_code}", None, elapsed_ms
    result = body.get("result", {})
    structured = result.get("structuredContent", {})
    if "error" in structured:
        return str(structured["error"].get("code", "mcp_error")), None, elapsed_ms
    status = "succeeded" if structured.get("status") == "hits" else str(structured.get("status", "unknown"))
    return status, structured, elapsed_ms


def _evaluate_record(case: _BenchmarkCase, status: str, payload: dict | None, elapsed_ms: float) -> dict:
    top5_keys = set(_dedup_keys(payload, limit=5))
    required_sets = [frozenset(group) for group in case.required_groups]
    first_hit = any(bool(group & top5_keys) for group in required_sets) if required_sets else False
    first_complete = all(bool(group & top5_keys) for group in required_sets) if required_sets else False
    leaked = _check_leakage(case, payload)

    wiki_delivered = False
    wiki_claims_cited = 0
    wiki_claims_supported = 0
    wiki_claims_uncited = 0
    wiki_claims_unsupported = 0
    if payload is not None:
        delivered_pids = {str(item["passage_id"]) for item in payload.get("passages", [])}
        allowed_pids = {pair[1] for group in case.required_groups for pair in group} | delivered_pids
        for wiki_item in payload.get("wiki", []):
            wiki_delivered = True
            for claim in wiki_item.get("claims", []):
                passage_ids = [str(item) for item in claim.get("passage_ids", [])]
                if not passage_ids:
                    wiki_claims_uncited += 1
                    continue
                wiki_claims_cited += 1
                if all(item in allowed_pids for item in passage_ids):
                    wiki_claims_supported += 1
                else:
                    wiki_claims_unsupported += 1

    had_error = status not in {"succeeded", "no_evidence"}
    if case.kind == "supported":
        complete_success = (not had_error) and leaked == 0 and first_complete
    elif case.kind == "unsupported":
        complete_success = status == "no_evidence" and leaked == 0
    elif case.kind == "authority_revoked":
        complete_success = (not had_error) and leaked == 0
    else:
        complete_success = status == "dependency_unavailable" and leaked == 0

    return {
        "case_id": case.case_id,
        "family_id": case.family_id,
        "kind": case.kind,
        "cross_document": case.cross_document,
        "historical_date": case.historical_date,
        "semantic_synonym": case.semantic_synonym,
        "status": status,
        "first_hit": first_hit,
        "first_complete": first_complete,
        "had_error": had_error,
        "unauthorized_disclosures": leaked,
        "wiki_delivered": wiki_delivered,
        "wiki_claims_cited": wiki_claims_cited,
        "wiki_claims_supported": wiki_claims_supported,
        "wiki_claims_uncited": wiki_claims_uncited,
        "wiki_claims_unsupported": wiki_claims_unsupported,
        "complete_success": complete_success,
        "within_sla": complete_success and elapsed_ms <= case.sla_ms,
        "elapsed_ms": elapsed_ms,
    }


def _summarize_entrance(records: Sequence[dict]) -> dict:
    supported = [item for item in records if item["kind"] == "supported"]
    cross_doc = [item for item in supported if item["cross_document"]]
    historical = [item for item in supported if item["historical_date"]]
    synonyms = [item for item in supported if item["semantic_synonym"]]
    unsupported = [item for item in records if item["kind"] == "unsupported"]
    revoked = [item for item in records if item["kind"] == "authority_revoked"]
    faults = [item for item in records if item["kind"] == "dependency_fault"]
    normal = [item for item in records if item["kind"] != "dependency_fault"]

    success_latencies = [item["elapsed_ms"] for item in normal if item["complete_success"]]
    all_normal_latencies = [item["elapsed_ms"] for item in normal]
    wiki_cited = sum(item["wiki_claims_cited"] for item in records)
    wiki_supported = sum(item["wiki_claims_supported"] for item in records)

    return {
        "case_counts": {
            "total": len(records),
            "normal": len(normal),
            "supported": len(supported),
            "cross_document_supported": len(cross_doc),
            "historical_date_supported": len(historical),
            "semantic_synonym_supported": len(synonyms),
            "unsupported": len(unsupported),
            "authority_revoked": len(revoked),
            "dependency_fault": len(faults),
        },
        "first_search_top5_hit_rate": _rate(sum(item["first_hit"] for item in supported), len(supported)),
        "first_search_complete_rate": _rate(sum(item["first_complete"] for item in supported), len(supported)),
        "first_search_cross_doc_complete_rate": _rate(sum(item["first_complete"] for item in cross_doc), len(cross_doc)),
        "historical_date_hit_rate": _rate(sum(item["first_complete"] for item in historical), len(historical)),
        "semantic_synonym_hit_rate": _rate(sum(item["first_complete"] for item in synonyms), len(synonyms)),
        "correct_abstention_rate": _rate(sum(item["complete_success"] for item in unsupported), len(unsupported)),
        "authority_revoked_zero_leak_rate": _rate(sum(item["complete_success"] for item in revoked), len(revoked)),
        "unauthorized_disclosures": sum(item["unauthorized_disclosures"] for item in records),
        "wiki_delivery_count": sum(1 for item in records if item["wiki_delivered"]),
        "wiki_citation_support_rate": _rate(wiki_supported, wiki_cited),
        "wiki_uncited_claims": sum(item["wiki_claims_uncited"] for item in records),
        "wiki_unsupported_citations": sum(item["wiki_claims_unsupported"] for item in records),
        "normal_requests": {
            "total": len(normal),
            "complete_success": sum(1 for item in normal if item["complete_success"]),
            "within_sla_success": sum(1 for item in normal if item["within_sla"]),
            "within_sla_success_rate": _rate(sum(item["within_sla"] for item in normal), len(normal)),
            "error_or_fault_count": sum(1 for item in normal if item["had_error"]),
            "conditional_success_latency_ms": _latency_summary(success_latencies),
            "all_normal_latency_ms": _latency_summary(all_normal_latencies),
        },
        "dependency_fault_requests": {
            "total": len(faults),
            "accuracy": _rate(sum(item["complete_success"] for item in faults), len(faults)),
        },
    }


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _transport_client(app, transport: TransportMode):
    if transport == "asgi":
        with TestClient(app, base_url="http://127.0.0.1") as client:
            yield client
        return
    port = _free_loopback_port()
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
        timeout_keep_alive=5,
    )
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None
    failed = Event()

    def run_server():
        try:
            server.run()
        except Exception:
            failed.set()

    thread = Thread(target=run_server, daemon=True)
    thread.start()
    deadline = monotonic() + 15.0
    while not server.started:
        if failed.is_set() or not thread.is_alive() or monotonic() >= deadline:
            server.should_exit = True
            thread.join(timeout=3.0)
            raise RuntimeError("Loopback benchmark server failed to start.")
        sleep(0.02)
    try:
        with httpx2.Client(base_url=f"http://127.0.0.1:{port}", timeout=10.0) as client:
            yield client
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def _collect_environment(connection: psycopg.Connection, transport: TransportMode, iterations: int) -> dict:
    postgres_version, pgvector_version = connection.execute(
        """
        SELECT current_setting('server_version'),
               (SELECT extversion FROM pg_extension WHERE extname = 'vector')
        """
    ).fetchone()
    return {
        "sampled_at": datetime.now(UTC).isoformat(),
        "transport": transport,
        "iterations": iterations,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count() or 1,
        "postgres_version": postgres_version,
        "pgvector_version": pgvector_version,
    }


def run_synthetic_e2e_benchmark(
    database_url: str,
    *,
    originals_dir: Path,
    iterations: int = 3,
    transport: TransportMode = "loopback_http",
) -> dict:
    if type(iterations) is not int or not 1 <= iterations <= 100:
        raise ValueError("Benchmark iterations must be an integer between 1 and 100.")
    if transport not in {"asgi", "loopback_http"}:
        raise ValueError("Benchmark transport must be 'asgi' or 'loopback_http'.")
    connect = local_connection_factory(database_url)
    store = originals.SyntheticOriginalStore(originals_dir)

    with connect() as connection:
        revisions = require_current_schema(connection)
        environment = _collect_environment(connection, transport, iterations)
        environment["schema_revisions"] = list(revisions)
        fixture = _setup_synthetic_corpus(connection, store)

    full_token = token_urlsafe(32)
    restricted_token = token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(minutes=30)
    credentials = {
        full_token: evidence.SyntheticCredential(
            fixture["full_ref"],
            fixture["space_ref"],
            "synthetic-benchmark",
            "shanghai",
            "employee",
            frozenset({"search", "read_passage"}),
            expires_at,
        ),
        restricted_token: evidence.SyntheticCredential(
            fixture["restricted_ref"],
            fixture["space_ref"],
            "synthetic-benchmark",
            "shanghai",
            "employee",
            frozenset({"search", "read_passage"}),
            expires_at,
        ),
    }
    tokens_by_actor = {"full": full_token, "restricted": restricted_token}
    fault_state = {"enabled": False}
    public_refs = fixture["public_passage_refs"]
    restricted_ref = fixture["restricted_ref"]

    def check_source(credential: evidence.SyntheticCredential, probe: delivery.DeliveryCheck) -> delivery.AuthorityDecision:
        if fault_state["enabled"]:
            raise delivery.AuthorizationUnavailable("Injected synthetic dependency fault.")
        checked_at = datetime.now(UTC)
        if credential.employee_ref == restricted_ref:
            granted = {
                scope: scope.fields if scope.object_id in public_refs else frozenset()
                for scope in probe.scopes
            }
        else:
            granted = {scope: scope.fields for scope in probe.scopes}
        return delivery.AuthorityDecision(
            probe.check_id,
            checked_at,
            min(checked_at + timedelta(seconds=10), credential.expires_at),
            frozenset({probe.context.principal_id}),
            granted,
            f"synthetic-benchmark-live:{uuid4()}",
        )

    service = evidence.EvidenceService(connect, credentials.get, check_source, store)
    application = api.create_app(service)
    arms_report: dict[str, dict] = {}
    cases: tuple[_BenchmarkCase, ...] = fixture["cases"]
    distinct_families = len({case.family_id for case in cases if case.kind != "dependency_fault"})

    with _transport_client(application, transport) as client:
        rpc_counter = 1
        for arm in BENCHMARK_ARMS:
            with connect() as connection:
                release.switch_space_release(
                    connection,
                    _write_context(
                        connection,
                        fixture["org_id"],
                        fixture["space_id"],
                        fixture["full_emp"],
                        release.SWITCH_SPACE_RELEASE,
                        release.DESTINATION,
                    ),
                    fixture["space_id"],
                    action="trial_switch",
                    wiki_delivery_enabled=arm.wiki_enabled,
                    lexical_index_mode=arm.lexical_index_mode,
                    vector_model_id=arm.vector_model_id,
                    rollback_trigger_summary=f"benchmark arm {arm.name}",
                    reason_code="synthetic_benchmark",
                    basis_ref=uuid4(),
                )
            http_records: list[dict] = []
            mcp_records: list[dict] = []
            for _ in range(iterations):
                for case in cases:
                    token = tokens_by_actor[case.actor_key]
                    arguments = {
                        "query": case.query,
                        "business_date": case.business_date.isoformat(),
                        "top_k": case.top_k,
                        "include_wiki": arm.wiki_enabled,
                    }
                    fault_state["enabled"] = case.kind == "dependency_fault"
                    try:
                        http_status, http_payload, http_ms = _invoke_http(client, token, arguments)
                        mcp_status, mcp_payload, mcp_ms = _invoke_mcp(client, token, arguments, rpc_counter)
                        rpc_counter += 1
                    finally:
                        fault_state["enabled"] = False
                    http_records.append(_evaluate_record(case, http_status, http_payload, http_ms))
                    mcp_records.append(_evaluate_record(case, mcp_status, mcp_payload, mcp_ms))

            arms_report[arm.name] = {
                "config": {
                    "lexical_index_mode": arm.lexical_index_mode,
                    "vector_model_id": arm.vector_model_id,
                    "wiki_delivery_enabled": arm.wiki_enabled,
                },
                "entrances": {
                    "http": _summarize_entrance(http_records),
                    "mcp": _summarize_entrance(mcp_records),
                },
            }

    return {
        "dataset_kind": DATASET_KIND,
        "replaces_frozen_blind_eval": False,
        "qa_answer_latency_status": QA_LATENCY_STATUS,
        "disclaimer": DISCLAIMER,
        "distinct_normal_families": distinct_families,
        "sample_insufficient": distinct_families < evaluation.MIN_STATISTICAL_FAMILIES,
        "environment": environment,
        "corpus": fixture["corpus_summary"],
        "arms": arms_report,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="在本机隔离数据库运行合成差旅 HTTP/MCP 端到端性能与质量基准")
    parser.add_argument("--originals", type=Path, required=True, help="已存在的 0700 私有合成原件目录")
    parser.add_argument("--iterations", type=int, default=5, help="每个对照臂的重复执行轮次（默认 5）")
    parser.add_argument("--transport", choices=["loopback_http", "asgi"], default="loopback_http")
    arguments = parser.parse_args()
    try:
        report = run_synthetic_e2e_benchmark(
            os.environ.get("THALION_DATABASE_URL", ""),
            originals_dir=arguments.originals,
            iterations=arguments.iterations,
            transport=arguments.transport,
        )
    except (OSError, ValueError, RuntimeError, ArgumentError, psycopg.Error):
        print("FAIL 无法执行本机合成基准。请核对隔离 PostgreSQL 迁移状态与私有原件目录。", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
