from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
import json
import math
from time import monotonic
from typing import Literal
from uuid import UUID, uuid4

from psycopg import Connection

from enterprise_kb.database import rehearsal_marker
from enterprise_kb.modules.access.delivery import AuthorityDecision, DeliveryCheck, DeliveryContext
from enterprise_kb.modules.access.travel import search_travel
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request


DATASET_KIND = "synthetic_local"
QA_LATENCY_STATUS = "unmeasured_no_approved_agent"
DISCLAIMER = (
    "本报告仅基于本机合成样本与检索/取证边界实测，"
    "不替代真实域冻结盲测、双人业务判分或生产放行结论。"
)
MIN_STATISTICAL_FAMILIES = 20
CaseKind = Literal["supported", "partial", "unsupported", "authority_revoked", "dependency_fault"]


@dataclass(frozen=True)
class EvidenceTarget:
    version_id: UUID
    passage_id: UUID

    def key(self) -> tuple[str, str]:
        return (str(self.version_id), str(self.passage_id))


@dataclass(frozen=True)
class EvalCase:
    case_id: str
    family_id: str
    kind: CaseKind
    principal_id: int
    business_date: date
    region: str
    traveler_class: str
    query: str = field(repr=False)
    cross_document: bool = False
    followup_query: str | None = field(default=None, repr=False)
    required_evidence_groups: tuple[tuple[EvidenceTarget, ...], ...] = ()
    forbidden_passage_ids: frozenset[UUID] = frozenset()
    forbidden_substrings: tuple[str, ...] = field(default=(), repr=False)
    top_k: int = 5
    sla_ms: int = 3000
    client_id: str = "synthetic-eval-harness"

    def __post_init__(self):
        if not self.case_id.strip() or not self.family_id.strip():
            raise ValueError("EvalCase requires non-empty case_id and family_id.")
        if not self.query.strip():
            raise ValueError("EvalCase requires a non-empty query.")
        if not 1 <= self.top_k <= 20:
            raise ValueError("EvalCase top_k must be between 1 and 20.")
        if self.sla_ms < 1:
            raise ValueError("EvalCase sla_ms must be positive.")
        if self.kind in {"supported", "partial"} and not self.required_evidence_groups:
            raise ValueError("Supported or partial cases require required_evidence_groups.")
        if any(len(group) == 0 for group in self.required_evidence_groups):
            raise ValueError("Each required evidence group must contain at least one EvidenceTarget.")


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


def _dedup_original_keys(payload: dict, limit: int = 5) -> list[tuple[str, str]]:
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


def _check_leakage(case: EvalCase, payload: dict | None) -> int:
    if payload is None:
        return 0
    forbidden_ids = {str(item) for item in case.forbidden_passage_ids}
    leaked = 0
    texts: list[str] = []
    for passage in payload.get("passages", []):
        if str(passage.get("passage_id", "")) in forbidden_ids:
            leaked += 1
        texts.append(str(passage.get("title", "")))
        texts.append(str(passage.get("excerpt", "")))
    for wiki in payload.get("wiki", []):
        texts.append(str(wiki.get("title", "")))
        for claim in wiki.get("claims", []):
            texts.append(str(claim.get("text", "")))
            for pid in claim.get("passage_ids", []):
                if str(pid) in forbidden_ids:
                    leaked += 1
    haystack = "\n".join(texts)
    for needle in case.forbidden_substrings:
        if needle and needle in haystack:
            leaked += 1
    return leaked


def _execute_single_search(
    connection: Connection,
    org_id: int,
    space_id: int,
    config_revision: int,
    store: SyntheticOriginalStore,
    case: EvalCase,
    query_text: str,
    *,
    include_wiki: bool,
    check_authority: Callable[[EvalCase, DeliveryCheck], AuthorityDecision],
) -> tuple[UUID, str, dict | None, float]:
    request_id = uuid4()
    started = monotonic()
    start_request(
        connection,
        RequestStart(
            org_id, request_id, case.principal_id, None, case.client_id,
            "search", "employee", case.business_date, config_revision,
            space_id=space_id, ingress="internal",
        ),
    )
    context = DeliveryContext(
        request_id, org_id, case.principal_id, case.client_id,
        "search", "employee_evidence", "employee",
        datetime.now(UTC) + timedelta(seconds=max(5, math.ceil(case.sla_ms / 1000) + 5)),
    )
    decision = search_travel(
        connection, context, space_id, query_text, store,
        region=case.region, traveler_class=case.traveler_class,
        check_authority=lambda check: check_authority(case, check),
        top_k=case.top_k, include_wiki=include_wiki,
    )
    elapsed_ms = round((monotonic() - started) * 1000.0, 3)
    if decision.status != "no_evidence":
        finish_request(connection, org_id, request_id, decision.status, int(elapsed_ms))
    payload = json.loads(decision.payload.decode("utf-8")) if decision.payload is not None else None
    return request_id, decision.status, payload, elapsed_ms


def _evaluate_case_arm(
    connection: Connection,
    org_id: int,
    space_id: int,
    config_revision: int,
    store: SyntheticOriginalStore,
    case: EvalCase,
    *,
    include_wiki: bool,
    check_authority: Callable[[EvalCase, DeliveryCheck], AuthorityDecision],
) -> dict:
    task_chain_id = uuid4()
    first_req_id, first_status, first_payload, first_ms = _execute_single_search(
        connection, org_id, space_id, config_revision, store, case, case.query,
        include_wiki=include_wiki, check_authority=check_authority,
    )
    first_keys = _dedup_original_keys(first_payload, limit=5) if first_payload is not None else []
    first_key_set = set(first_keys)
    required_sets = [frozenset(target.key() for target in group) for group in case.required_evidence_groups]
    first_hit = any(bool(group & first_key_set) for group in required_sets) if required_sets else False
    first_complete = all(bool(group & first_key_set) for group in required_sets) if required_sets else False

    followup_req_id: UUID | None = None
    followup_status: str | None = None
    followup_payload: dict | None = None
    followup_ms = 0.0
    combined_key_set = set(first_key_set)
    if case.followup_query and case.kind in {"supported", "partial"} and not first_complete:
        followup_req_id, followup_status, followup_payload, followup_ms = _execute_single_search(
            connection, org_id, space_id, config_revision, store, case, case.followup_query,
            include_wiki=include_wiki, check_authority=check_authority,
        )
        if followup_payload is not None:
            combined_key_set.update(_dedup_original_keys(followup_payload, limit=case.top_k))
    followup_complete = all(bool(group & combined_key_set) for group in required_sets) if required_sets else False

    total_ms = round(first_ms + followup_ms, 3)
    leaked = _check_leakage(case, first_payload) + _check_leakage(case, followup_payload)

    wiki_claims_total = 0
    wiki_claims_cited = 0
    wiki_claims_supported = 0
    wiki_claims_uncited = 0
    wiki_claims_unsupported = 0
    wiki_delivered = False
    allowed_required_pids = {str(target.passage_id) for group in case.required_evidence_groups for target in group}
    for payload in (first_payload, followup_payload):
        if payload is None:
            continue
        delivered_pids = {str(item["passage_id"]) for item in payload.get("passages", [])}
        valid_pids = allowed_required_pids | delivered_pids
        for wiki in payload.get("wiki", []):
            wiki_delivered = True
            for claim in wiki.get("claims", []):
                wiki_claims_total += 1
                pids = [str(pid) for pid in claim.get("passage_ids", [])]
                if not pids:
                    wiki_claims_uncited += 1
                    continue
                wiki_claims_cited += 1
                if all(pid in valid_pids for pid in pids) and (
                    not allowed_required_pids or any(pid in allowed_required_pids for pid in pids)
                ):
                    wiki_claims_supported += 1
                else:
                    wiki_claims_unsupported += 1

    had_error = first_status in {"dependency_unavailable", "input_changed"} or followup_status in {
        "dependency_unavailable", "input_changed",
    }
    false_abstention = case.kind == "supported" and first_status == "no_evidence" and followup_status in (None, "no_evidence")
    if case.kind == "supported":
        complete_success = (not had_error) and leaked == 0 and followup_complete
    elif case.kind == "partial":
        complete_success = (not had_error) and leaked == 0 and followup_complete
    elif case.kind == "unsupported":
        complete_success = first_status == "no_evidence" and leaked == 0
    elif case.kind == "authority_revoked":
        complete_success = (not had_error) and leaked == 0
    else:
        complete_success = first_status == "dependency_unavailable" and leaked == 0

    within_sla = complete_success and total_ms <= case.sla_ms
    return {
        "case_id": case.case_id,
        "family_id": case.family_id,
        "kind": case.kind,
        "cross_document": case.cross_document,
        "task_chain_id": str(task_chain_id),
        "first_request_id": str(first_req_id),
        "followup_request_id": str(followup_req_id) if followup_req_id else None,
        "first_status": first_status,
        "followup_status": followup_status,
        "first_search_top5_hit": first_hit,
        "first_search_complete": first_complete,
        "followup_complete": followup_complete,
        "used_followup": followup_req_id is not None,
        "false_abstention": false_abstention,
        "had_error": had_error,
        "unauthorized_disclosures": leaked,
        "wiki_delivered": wiki_delivered,
        "wiki_claims_total": wiki_claims_total,
        "wiki_claims_cited": wiki_claims_cited,
        "wiki_claims_supported": wiki_claims_supported,
        "wiki_claims_uncited": wiki_claims_uncited,
        "wiki_claims_unsupported": wiki_claims_unsupported,
        "complete_success": complete_success,
        "within_sla": within_sla,
        "first_latency_ms": first_ms,
        "total_latency_ms": total_ms,
    }


def _summarize_arm(records: Sequence[dict]) -> dict:
    supported = [r for r in records if r["kind"] == "supported"]
    cross_doc = [r for r in supported if r["cross_document"]]
    partial = [r for r in records if r["kind"] == "partial"]
    unsupported = [r for r in records if r["kind"] == "unsupported"]
    revoked = [r for r in records if r["kind"] == "authority_revoked"]
    faults = [r for r in records if r["kind"] == "dependency_fault"]
    normal = [r for r in records if r["kind"] != "dependency_fault"]

    success_latencies = sorted(r["total_latency_ms"] for r in normal if r["complete_success"])
    first_latencies = sorted(r["first_latency_ms"] for r in normal if r["complete_success"])
    wiki_cited = sum(r["wiki_claims_cited"] for r in records)
    wiki_supported = sum(r["wiki_claims_supported"] for r in records)
    wiki_uncited = sum(r["wiki_claims_uncited"] for r in records)
    wiki_unsupported = sum(r["wiki_claims_unsupported"] for r in records)

    return {
        "case_counts": {
            "total": len(records),
            "normal": len(normal),
            "supported": len(supported),
            "cross_document_supported": len(cross_doc),
            "partial": len(partial),
            "unsupported": len(unsupported),
            "authority_revoked": len(revoked),
            "dependency_fault": len(faults),
        },
        "first_search_top5_hit_rate": _rate(sum(r["first_search_top5_hit"] for r in supported), len(supported)),
        "first_search_complete_rate": _rate(sum(r["first_search_complete"] for r in supported), len(supported)),
        "first_search_cross_doc_complete_rate": _rate(
            sum(r["first_search_complete"] for r in cross_doc), len(cross_doc),
        ),
        "followup_complete_rate": _rate(sum(r["followup_complete"] for r in supported), len(supported)),
        "followup_cross_doc_complete_rate": _rate(
            sum(r["followup_complete"] for r in cross_doc), len(cross_doc),
        ),
        "false_abstention_rate": _rate(sum(r["false_abstention"] for r in supported), len(supported)),
        "partial_correct_rate": _rate(sum(r["complete_success"] for r in partial), len(partial)),
        "correct_abstention_rate": _rate(sum(r["complete_success"] for r in unsupported), len(unsupported)),
        "authority_revoked_zero_leak_rate": _rate(sum(r["complete_success"] for r in revoked), len(revoked)),
        "dependency_fault_accuracy": _rate(sum(r["complete_success"] for r in faults), len(faults)),
        "wiki_delivery_count": sum(1 for r in records if r["wiki_delivered"]),
        "wiki_citation_support_rate": _rate(wiki_supported, wiki_cited),
        "wiki_uncited_claims": wiki_uncited,
        "wiki_unsupported_citations": wiki_unsupported,
        "unauthorized_disclosures": sum(r["unauthorized_disclosures"] for r in records),
        "normal_requests": {
            "total": len(normal),
            "complete_success": sum(1 for r in normal if r["complete_success"]),
            "within_sla_success": sum(1 for r in normal if r["within_sla"]),
            "within_sla_success_rate": _rate(sum(1 for r in normal if r["within_sla"]), len(normal)),
            "error_or_fault_count": sum(1 for r in normal if r["had_error"]),
            "conditional_first_search_p50_ms": _percentile(first_latencies, 0.50),
            "conditional_first_search_p95_ms": _percentile(first_latencies, 0.95),
            "conditional_total_p50_ms": _percentile(success_latencies, 0.50),
            "conditional_total_p95_ms": _percentile(success_latencies, 0.95),
            "conditional_total_max_ms": round(success_latencies[-1], 3) if success_latencies else None,
        },
    }


def _paired_comparison(rag_records: Sequence[dict], wiki_records: Sequence[dict]) -> dict:
    both_pass = 0
    rag_only_pass = 0
    wiki_only_pass = 0
    both_fail = 0
    rag_only_cases: list[str] = []
    wiki_only_cases: list[str] = []
    family_deltas: dict[str, list[float]] = {}

    for rag, wiki in zip(rag_records, wiki_records, strict=True):
        if rag["kind"] == "dependency_fault":
            continue
        r_ok = bool(rag["complete_success"])
        w_ok = bool(wiki["complete_success"])
        if r_ok and w_ok:
            both_pass += 1
        elif r_ok and not w_ok:
            rag_only_pass += 1
            rag_only_cases.append(rag["case_id"])
        elif not r_ok and w_ok:
            wiki_only_pass += 1
            wiki_only_cases.append(wiki["case_id"])
        else:
            both_fail += 1
        family_deltas.setdefault(rag["family_id"], []).append((1.0 if w_ok else 0.0) - (1.0 if r_ok else 0.0))

    family_means = [sum(vals) / len(vals) for vals in family_deltas.values()]
    family_count = len(family_means)
    if family_count == 0:
        mean_delta = None
        ci_low = None
        ci_high = None
    elif family_count == 1:
        mean_delta = round(family_means[0], 6)
        ci_low = None
        ci_high = None
    else:
        mean_val = sum(family_means) / family_count
        variance = sum((val - mean_val) ** 2 for val in family_means) / (family_count - 1)
        margin = 1.96 * math.sqrt(variance / family_count)
        mean_delta = round(mean_val, 6)
        ci_low = round(mean_val - margin, 6)
        ci_high = round(mean_val + margin, 6)

    return {
        "paired_normal_cases": both_pass + rag_only_pass + wiki_only_pass + both_fail,
        "distinct_families": family_count,
        "sample_insufficient": family_count < MIN_STATISTICAL_FAMILIES,
        "both_pass": both_pass,
        "rag_only_pass": rag_only_pass,
        "wiki_only_pass": wiki_only_pass,
        "both_fail": both_fail,
        "rag_only_case_ids": rag_only_cases,
        "wiki_only_case_ids": wiki_only_cases,
        "family_paired_delta": mean_delta,
        "ci95_low": ci_low,
        "ci95_high": ci_high,
    }


def _space_wiki_maintenance_burden(connection: Connection, org_id: int, space_id: int) -> dict:
    published_topics, available_topics, total_publications, invalidations, rollbacks, pending_reviews = (
        connection.execute(
            """
            SELECT
                (SELECT count(*) FROM thalion.current_wiki_publication WHERE (org_id, space_id) = (%s, %s)),
                (SELECT count(*) FROM thalion.available_wiki_publication WHERE (org_id, space_id) = (%s, %s)),
                (SELECT count(*) FROM thalion.wiki_publication_event WHERE (org_id, space_id) = (%s, %s)),
                (SELECT count(*) FROM thalion.wiki_availability_event WHERE (org_id, space_id) = (%s, %s)),
                (SELECT count(*) FROM thalion.wiki_topic_rollback WHERE (org_id, space_id) = (%s, %s)),
                (
                    SELECT count(*) FROM thalion.wiki_revision AS rev
                    WHERE (rev.org_id, rev.space_id) = (%s, %s)
                      AND NOT EXISTS (
                          SELECT 1 FROM thalion.wiki_review AS r WHERE r.revision_ref = rev.revision_ref
                      )
                )
            """,
            (org_id, space_id) * 6,
        ).fetchone()
    )
    return {
        "published_topics": published_topics,
        "available_topics": available_topics,
        "total_publications": total_publications,
        "invalidation_events": invalidations,
        "topic_rollbacks": rollbacks,
        "pending_reviews": pending_reviews,
    }


def run_synthetic_comparison(
    connection: Connection,
    org_id: int,
    space_id: int,
    store: SyntheticOriginalStore,
    cases: Sequence[EvalCase],
    *,
    check_authority: Callable[[EvalCase, DeliveryCheck], AuthorityDecision],
    run_label: str = "synthetic-local-comparison",
) -> dict:
    if connection.info.hostaddr not in {"127.0.0.1", "::1"} or rehearsal_marker(connection) is not None:
        raise RuntimeError("Synthetic evaluation requires an isolated local development database.")
    if not cases:
        raise ValueError("Synthetic evaluation requires at least one EvalCase.")
    config_revision, = connection.execute(
        "SELECT config_revision FROM thalion.organization WHERE org_id = %s",
        (org_id,),
    ).fetchone()
    space_ref, = connection.execute(
        """
        SELECT public_id FROM thalion.object_identity
        WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'space', %s)
        """,
        (org_id, space_id, space_id),
    ).fetchone()

    rag_records: list[dict] = []
    wiki_records: list[dict] = []
    for index, case in enumerate(cases):
        if index % 2 == 0:
            rag_res = _evaluate_case_arm(
                connection, org_id, space_id, config_revision, store, case,
                include_wiki=False, check_authority=check_authority,
            )
            wiki_res = _evaluate_case_arm(
                connection, org_id, space_id, config_revision, store, case,
                include_wiki=True, check_authority=check_authority,
            )
        else:
            wiki_res = _evaluate_case_arm(
                connection, org_id, space_id, config_revision, store, case,
                include_wiki=True, check_authority=check_authority,
            )
            rag_res = _evaluate_case_arm(
                connection, org_id, space_id, config_revision, store, case,
                include_wiki=False, check_authority=check_authority,
            )
        rag_records.append(rag_res)
        wiki_records.append(wiki_res)

    maintenance = _space_wiki_maintenance_burden(connection, org_id, space_id)
    return {
        "run_label": run_label,
        "dataset_kind": DATASET_KIND,
        "replaces_frozen_blind_eval": False,
        "qa_answer_latency_status": QA_LATENCY_STATUS,
        "disclaimer": DISCLAIMER,
        "space_id": str(space_ref),
        "evaluated_at": datetime.now(UTC).isoformat(),
        "interleaved_order": True,
        "arms": {
            "rag_only": _summarize_arm(rag_records),
            "rag_plus_wiki": _summarize_arm(wiki_records),
        },
        "paired_comparison": _paired_comparison(rag_records, wiki_records),
        "wiki_maintenance_burden": maintenance,
        "case_results": {
            "rag_only": rag_records,
            "rag_plus_wiki": wiki_records,
        },
    }
