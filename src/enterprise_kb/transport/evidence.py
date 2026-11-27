from collections.abc import Callable
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from hmac import digest as hmac_digest
import json
import re
from time import monotonic
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from psycopg import Connection, Error

from enterprise_kb.modules.access import governance, original_download, policy
from enterprise_kb.modules.access.delivery import AuthorityDecision, AuthorizationUnavailable, DeliveryCheck, DeliveryContext
from enterprise_kb.modules.access.rules import require_aware
from enterprise_kb.modules.access.travel import ReferenceBinding, list_employee_discovery, open_travel_reference, search_travel
from enterprise_kb.modules.evidence import docx_review, pdf_evidence, pdf_review, processing, repair_review, rule_rollback
from enterprise_kb.modules.lifecycle import (
    archive_rehearsal, archives, backup_expiry, backup_inventory, disposition, holds, receipts, space_archive, verification,
)
from enterprise_kb.modules.operations import (
    feedback, findings, gaps, handoffs, release, runtime_backlog, source_audit, source_catalog, source_sync_status,
)
from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, require_scope
from enterprise_kb.modules import glossary
from enterprise_kb.modules.sources import connector_sync, departments, effectivity, ingest, responsibility
from enterprise_kb.modules.sources.originals import (
    ObjectStorageOriginalStore, OriginalIntegrityError, SyntheticOriginalStore,
)
from enterprise_kb.modules.sources.registry import (
    PRODUCTION_ADMISSION, SYNTHETIC_ADMISSION, SYNTHETIC_ISSUER, SourceNotAdmitted, SourceWrite,
    admission_for_issuer, is_admitted_issuer, is_production_issuer, issuer_matches_admission, store_admission,
)
from enterprise_kb.modules.wiki import ai_drafting, drafts, inputs, management, publication
from enterprise_kb.ports.contracts import (
    EmbeddingProviderPort,
    ModelGatewayPort,
    PortRegistry,
    PortUnavailable,
    ProductionIsolationError,
    SecurityAuditLogPort,
    SecurityLogUnavailable,
    SourceConnectorPort,
)
from enterprise_kb.runtime.audit_sink import (
    SecurityAuditDispatcher,
    SecurityAuditEvent,
    metadata_digest,
)
from enterprise_kb.runtime.audit import (
    RequestAuditConflict, RequestIngress, RequestStart, finish_open_request, finish_request, start_request,
)
from enterprise_kb.runtime.commands import IdempotencyConflict


OPERATIONS = frozenset({"search", "read_passage"})
INTERNAL_CREATES = frozenset({
    feedback.RECORD, findings.EMIT, gaps.RECORD, disposition.REGISTER, disposition.SUBMIT, holds.DECIDE,
    backup_inventory.REGISTER_BACKUP, archives.REQUEST, space_archive.REQUEST, handoffs.AUTHORIZE,
})
ARCHIVE_WRITES = frozenset({
    archives.REQUEST, archives.APPROVE, archives.EXPORT,
    space_archive.REQUEST, space_archive.APPROVE, space_archive.EXPORT,
})
BACKUP_WRITES = frozenset({backup_inventory.REGISTER_BACKUP, backup_expiry.SCHEDULE, backup_expiry.OBSERVE})
DISPOSITION_CASE_OPERATIONS = frozenset({
    disposition.SUBMIT, disposition.REJECT, disposition.APPROVE, disposition.REGISTER_TOMBSTONE, verification.VERIFY_ORIGINAL,
    receipts.OBSERVE,
})
INTERNAL_WRITES = INTERNAL_CREATES | DISPOSITION_CASE_OPERATIONS | ARCHIVE_WRITES | BACKUP_WRITES | policy.WRITE_OPERATIONS | {
    feedback.TRANSITION, feedback.QUARANTINE, gaps.RECLASSIFY, handoffs.ACCEPT, handoffs.REVOKE, repair_review.DECIDE,
    pdf_review.SUBMIT_CORRECTION, pdf_review.DECIDE_CORRECTION, pdf_review.APPROVE_REPAIR, docx_review.DECIDE,
    responsibility.SET,
} | effectivity.WRITE_OPERATIONS
INTERNAL_PAGES = frozenset({feedback.QUEUE, feedback.NOTICES, gaps.QUEUE})
SOURCE_PAGES = frozenset({ingest.LIST_BATCHES, source_audit.READ})
PDF_REVIEW_OPERATIONS = frozenset({
    pdf_review.SUBMIT_CORRECTION, pdf_review.PREVIEW_CORRECTION, pdf_review.DECIDE_CORRECTION,
    pdf_review.PREVIEW_REPAIR, pdf_review.APPROVE_REPAIR,
})
REPAIR_OPERATIONS = frozenset({repair_review.PREVIEW, repair_review.DECIDE, docx_review.PREVIEW, docx_review.DECIDE})
INTERNAL_OPERATIONS = INTERNAL_WRITES | INTERNAL_PAGES | SOURCE_PAGES | policy.OPERATIONS | {
    feedback.STATUS, disposition.PLAN, repair_review.PREVIEW, pdf_review.PREVIEW, docx_review.PREVIEW,
    pdf_review.PREVIEW_CORRECTION, pdf_review.PREVIEW_REPAIR, processing.STATUS_OPERATION, responsibility.READ,
    runtime_backlog.READ, source_sync_status.READ,
} | effectivity.READ_OPERATIONS
CREDENTIAL_OPERATIONS = OPERATIONS | INTERNAL_OPERATIONS | {
    feedback.EVIDENCE, management.WIKI_STATUS_OPERATION, "upload_source_batch", policy.ORIGINAL_DOWNLOAD_ACCESS[0],
    policy.WIKI_INPUT_ACCESS[0], policy.WIKI_CANDIDATE_ACCESS[0], policy.WIKI_PREVIEW_ACCESS[0],
    policy.WIKI_REVIEW_ACCESS[0], policy.WIKI_PUBLISH_ACCESS[0],
} | rule_rollback.OPERATIONS | governance.OPERATIONS | release.OPERATIONS | glossary.OPERATIONS | departments.OPERATIONS | source_catalog.OPERATIONS | {space_archive.LIST, space_archive.VERIFY}
MAX_REQUEST_TIME = timedelta(seconds=8)
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
CLIENT_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}")
SCOPE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
IDEMPOTENCY_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}")
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}")
ERRORS = {
    "invalid_arguments": (400, "请求参数无效。"),
    "unauthenticated": (401, "需要有效的员工凭据。"),
    "forbidden": (403, "此操作未获授权。"),
    "citation_unavailable": (404, "该引用不可用。"),
    "original_unavailable": (404, "该版本原件不可下载。"),
    "feedback_conflict": (409, "反馈已变化或不满足本次操作条件，请重新核对。"),
    "retention_policy_conflict": (409, "保留策略已变化，请重新核对。"),
    "disposition_case_conflict": (409, "处置申请已变化或不满足本次操作条件，请重新核对。"),
    "backup_copy_conflict": (409, "备份操作已办理或不满足当前条件。"),
    "original_archive_conflict": (409, "原件导出已办理、已失效或条件已变化。"),
    "hold_conflict": (409, "保全状态已变化或不符合本次决定，请重新核对。"),
    "repair_review_conflict": (409, "校订批次或预览已失效，请重新核对。"),
    "ingest_conflict": (409, "该批次的幂等键已用于不同来源或文件，请重新发起上传。"),
    "effectivity_conflict": (409, "生效范围与已记录的决定冲突，请重新核对。"),
    "local_policy_conflict": (409, "规则已变化或请求与现有记录冲突，请重新读取。"),
    "responsibility_conflict": (409, "资料责任人已变化或提交冲突，请重新读取。"),
    "wiki_input_changed": (409, "依赖来源或主题发布代次已变化，请核对受影响项并重新审核。"),
    "rule_rollback_conflict": (409, "清洗规则版本或受影响批次状态冲突，请重新核对影响清单。"),
    "governance_conflict": (409, "空间治理、共享组、委派或交接状态冲突，请重新核对。"),
    "release_conflict": (409, "空间发布配置或主题回退状态冲突，请重新核对当前版本。"),
    "glossary_conflict": (409, "业务词条已存在或与现有记录冲突，请核对后重试。"),
    "glossary_not_found": (404, "未找到指定的业务词条。"),
    "connector_not_configured": (409, "当前服务未配置外部来源连接器，请先配置连接器端口。"),
    "archive_verification_failed": (409, "归档包离线完整性核验未通过，请检查封存数据。"),
    "request_too_large": (413, "请求体超出大小限制。"),
    "dependency_unavailable": (503, "取证服务暂不可用，请稍后重试。"),
}


class ServiceRefusal(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SyntheticCredential:
    employee_ref: UUID
    space_ref: UUID
    client_id: str
    region: str
    traveler_class: str
    operations: frozenset[str]
    expires_at: datetime

    def __post_init__(self):
        require_aware(self.expires_at)
        object.__setattr__(self, "operations", frozenset(self.operations))
        if (
            not CLIENT_PATTERN.fullmatch(self.client_id) or not self.operations <= CREDENTIAL_OPERATIONS
            or not SCOPE_PATTERN.fullmatch(self.region) or not SCOPE_PATTERN.fullmatch(self.traveler_class)
        ):
            raise ValueError("Invalid synthetic credential scope.")


@dataclass(frozen=True)
class EmployeeCall:
    token: str = field(repr=False)
    credential: SyntheticCredential
    org_id: int
    principal_id: int
    space_id: int
    business_timezone: ZoneInfo
    configuration_revision: int
    ingress: RequestIngress | None = None


@dataclass(frozen=True)
class EvidenceReply:
    request_id: UUID
    status_code: int
    body: bytes = field(repr=False)
    valid_until: datetime | None = None
    attachment_name: str | None = None


@dataclass(frozen=True, kw_only=True)
class GuardedMetadataReply(EvidenceReply):
    started: float


@dataclass(frozen=True, kw_only=True)
class SourceAuditReply(GuardedMetadataReply):
    source_ref: UUID


@dataclass(frozen=True, kw_only=True)
class SourceSyncStatusReply(GuardedMetadataReply):
    source_ref: UUID


class RuntimeBacklogReply(GuardedMetadataReply):
    pass


@dataclass(frozen=True)
class _SearchInput:
    query: str = field(repr=False)
    business_date: date
    top_k: int
    include_wiki: bool
    space_ids: frozenset[UUID] | None
    source_ids: frozenset[UUID] | None
    include_source_facets: bool
    departments: frozenset[str] | None = None
    include_department_facets: bool = False

    def within(self, caller: EmployeeCall) -> bool:
        return self.space_ids is None or caller.credential.space_ref in self.space_ids

    def feedback_fingerprint(self, caller: EmployeeCall, key: bytes) -> bytes:
        scope = (
            "thalion-feedback-search-v1", str(caller.credential.space_ref), str(caller.credential.employee_ref),
            caller.credential.client_id, "employee", self.business_date.isoformat(), caller.credential.region,
            caller.credential.traveler_class, self.query, self.top_k, self.include_wiki,
            sorted(map(str, self.space_ids)) if self.space_ids is not None else None,
        )
        if self.source_ids is not None:
            scope += (sorted(map(str, self.source_ids)),)
        if self.departments is not None:
            scope += (sorted(self.departments),)
        return hmac_digest(key, encode(scope), "sha256")


def encode(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def error_reply(code: str, request_id: UUID | None = None) -> EvidenceReply:
    status, message = ERRORS[code]
    request_id = request_id or uuid4()
    return EvidenceReply(request_id, status, encode({
        "request_id": str(request_id), "error": {"code": code, "message": message},
    }))


def parse_ref(text: str) -> UUID:
    if len(text) != 36:
        raise ValueError("Expected an opaque UUID.")
    ref = UUID(text)
    if str(ref) != text.lower():
        raise ValueError("Expected an opaque UUID.")
    return ref


def _search_input(value: dict, today: date) -> _SearchInput:
    if set(value) - {"query", "business_date", "top_k", "include_wiki", "space_ids", "source_ids", "include_source_facets", "departments", "include_department_facets"}:
        raise ValueError("Unexpected search parameters.")
    query, top_k = value.get("query"), value.get("top_k", 5)
    if (
        not isinstance(query, str) or not 1 <= len(query) <= 1000 or not query.strip()
        or type(top_k) is not int or not 1 <= top_k <= 20 or type(value.get("include_wiki", False)) is not bool
        or type(value.get("include_source_facets", False)) is not bool
        or type(value.get("include_department_facets", False)) is not bool
    ):
        raise ValueError("Invalid search parameters.")
    business_date = _parse_business_date(value["business_date"]) if "business_date" in value else today

    def parse_filter(name):
        if name not in value:
            return None
        raw = value[name]
        if not isinstance(raw, list) or len(raw) > 20 or not all(isinstance(item, str) for item in raw):
            raise ValueError("Invalid search scope filter.")
        return frozenset(parse_ref(item) for item in raw)

    raw_depts = value.get("departments")
    parsed_depts = None
    if "departments" in value:
        if not isinstance(raw_depts, list) or len(raw_depts) > 20 or not all(isinstance(item, str) for item in raw_depts):
            raise ValueError("Invalid departments filter.")
        parsed_depts = frozenset(departments.validate_department_code(item) for item in raw_depts)
    return _SearchInput(
        query, business_date, top_k, value.get("include_wiki", False), parse_filter("space_ids"), parse_filter("source_ids"),
        value.get("include_source_facets", False), parsed_depts, value.get("include_department_facets", False),
    )


def _parse_business_date(raw: str) -> date:
    if not isinstance(raw, str) or not DATE_PATTERN.fullmatch(raw):
        raise ValueError("Invalid business date.")
    return date.fromisoformat(raw)


def _optional_ref(value: dict, name: str) -> UUID | None:
    if name not in value:
        return None
    if not isinstance(value[name], str):
        raise ValueError("Expected an opaque reference.")
    return parse_ref(value[name])


def _parse_wiki_pairs(value: object, *, min_len: int = 1, max_len: int = 20) -> tuple[tuple[UUID, int], ...]:
    if not isinstance(value, list) or not min_len <= len(value) <= max_len:
        raise ValueError("Expected a bounded list of passage references.")
    pairs = []
    for item in value:
        if (not isinstance(item, list) or len(item) != 2
                or not isinstance(item[0], str) or type(item[1]) is not int or item[1] < 1):
            raise ValueError("Expected [passage_id, revision] pairs.")
        pairs.append((parse_ref(item[0]), item[1]))
    return tuple(pairs)


def _parse_wiki_statements(value: object) -> tuple[drafts.WikiStatement, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError("Expected a bounded list of statements.")
    statements = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"text", "support_groups"}:
            raise ValueError("Invalid statement entry.")
        text = item["text"]
        groups = item["support_groups"]
        if not isinstance(text, str) or not isinstance(groups, list) or not 1 <= len(groups) <= 20:
            raise ValueError("Invalid statement content or support groups.")
        parsed_groups = tuple(_parse_wiki_pairs(group, min_len=1, max_len=20) for group in groups)
        statements.append(drafts.WikiStatement(text, parsed_groups))
    return tuple(statements)


def _parse_business_date(value: object) -> date:
    if not isinstance(value, str) or DATE_PATTERN.fullmatch(value) is None:
        raise ValueError("Expected an ISO business date.")
    return date.fromisoformat(value)


def _parse_hex_digest(value: object) -> bytes:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("Expected a 64-character lowercase SHA-256 hex digest.")
    return bytes.fromhex(value)


def _inventory_snapshot(arguments: dict) -> bytes:
    snapshot = arguments["inventory_snapshot"]
    if not isinstance(snapshot, str) or not SHA256_PATTERN.fullmatch(snapshot):
        raise ValueError("Expected a lowercase SHA-256 inventory snapshot.")
    return bytes.fromhex(snapshot)


def _policy_input(arguments: dict, *, allowed_model_destinations: frozenset[str] = frozenset({policy.SYNTHETIC_MODEL_DESTINATION})):
    if set(arguments) != {"expected_epoch", "basis_id", "rules"}:
        raise ValueError("Invalid local policy parameters.")
    epoch, rules = arguments["expected_epoch"], arguments["rules"]
    if (type(epoch) is not int or not 1 <= epoch < 2**63 - 1
            or not isinstance(rules, list) or len(rules) > policy.MAX_LOCAL_POLICY_RULES):
        raise ValueError("Invalid policy epoch or rule count.")
    fields = {"subject_id", "operation", "effect", "purpose", "destination", "fields", "valid_from"}
    optional = {"passage_id", "version_id", "valid_until"}
    parsed = []
    for item in rules:
        if (not isinstance(item, dict) or not fields <= item.keys() <= fields | optional
                or not all(isinstance(value, str) for name, value in item.items() if name != "fields")
                or not isinstance(item["fields"], list) or not 1 <= len(item["fields"]) <= len(policy.PASSAGE_FIELDS)
                or not all(isinstance(name, str) for name in item["fields"])
                or len(set(item["fields"])) != len(item["fields"])):
            raise ValueError("Invalid local policy rule.")
        parsed.append(policy.LocalRule(
            parse_ref(item["subject_id"]), item["operation"], item["effect"], item["purpose"], item["destination"],
            frozenset(item["fields"]),
            datetime.fromisoformat(item["valid_from"]),
            datetime.fromisoformat(item["valid_until"]) if "valid_until" in item else None,
            _optional_ref(item, "passage_id"),
            _optional_ref(item, "version_id"),
            allowed_model_destinations=allowed_model_destinations,
        ))
    return epoch, _optional_ref(arguments, "basis_id"), tuple(parsed)


def _internal_input(
    operation: str,
    arguments: dict,
    *,
    allowed_model_destinations: frozenset[str] = frozenset({policy.SYNTHETIC_MODEL_DESTINATION}),
):
    if not isinstance(arguments, dict):
        raise ValueError("Internal operation arguments must be an object.")
    if operation in policy.WRITE_OPERATIONS:
        return _policy_input(arguments, allowed_model_destinations=allowed_model_destinations)
    if operation == responsibility.SET:
        required = {"expected_generation", "responsible_id", "basis_id"}
        if not required <= arguments.keys() <= required | {"expires_at"}:
            raise ValueError("Invalid responsibility parameters.")
        expires = arguments.get("expires_at")
        if "expires_at" in arguments and not isinstance(expires, str):
            raise ValueError("Expected a zoned expiry.")
        return (
            arguments["expected_generation"],
            _optional_ref(arguments, "responsible_id") if arguments["responsible_id"] is not None else None,
            _optional_ref(arguments, "basis_id"), datetime.fromisoformat(expires) if expires is not None else None,
        )
    if operation == effectivity.APPROVE:
        required = {"valid_from", "basis_id"}
        optional = {"valid_to", "region", "traveler_class", "replaces_id"}
        if not required <= arguments.keys() <= required | optional:
            raise ValueError("Invalid effectivity parameters.")
        for name in ("valid_from", "valid_to"):
            if name in arguments and (not isinstance(arguments[name], str) or not DATE_PATTERN.fullmatch(arguments[name])):
                raise ValueError("Invalid business date.")
        for name in ("region", "traveler_class"):
            if name in arguments and (not isinstance(arguments[name], str) or not SCOPE_PATTERN.fullmatch(arguments[name])):
                raise ValueError("Invalid effectivity scope.")
        return effectivity.Approval(
            date.fromisoformat(arguments["valid_from"]),
            date.fromisoformat(arguments["valid_to"]) if "valid_to" in arguments else None,
            arguments.get("region"), arguments.get("traveler_class"),
            _optional_ref(arguments, "basis_id"), _optional_ref(arguments, "replaces_id"),
        )
    if operation == effectivity.PREVIEW:
        required = {"valid_from"}
        optional = {"valid_to", "region", "traveler_class", "replaces_id"}
        if not required <= arguments.keys() <= required | optional:
            raise ValueError("Invalid effectivity preview parameters.")
        for name in ("valid_from", "valid_to"):
            if name in arguments and (not isinstance(arguments[name], str) or not DATE_PATTERN.fullmatch(arguments[name])):
                raise ValueError("Invalid business date.")
        for name in ("region", "traveler_class"):
            if name in arguments and (not isinstance(arguments[name], str) or not SCOPE_PATTERN.fullmatch(arguments[name])):
                raise ValueError("Invalid effectivity scope.")
        return effectivity.PreviewRequest(
            date.fromisoformat(arguments["valid_from"]),
            date.fromisoformat(arguments["valid_to"]) if "valid_to" in arguments else None,
            arguments.get("region"), arguments.get("traveler_class"),
            _optional_ref(arguments, "replaces_id"),
        )
    if operation == effectivity.PREVIEW_STOP:
        if not arguments.keys() <= {"kind"}:
            raise ValueError("Invalid rule stop preview parameters.")
        kind = arguments.get("kind", "withdrawn")
        if kind not in ("suspended", "withdrawn"):
            raise ValueError("Invalid rule stop kind.")
        return kind
    if operation == effectivity.STOP:
        if set(arguments) != {"kind", "basis_id", "reason"}:
            raise ValueError("Invalid rule stop parameters.")
        kind, reason = arguments["kind"], arguments["reason"]
        if kind not in ("suspended", "withdrawn") or not isinstance(reason, str):
            raise ValueError("Invalid rule stop kind or reason.")
        return effectivity.StopRequest(kind, _optional_ref(arguments, "basis_id"), reason)
    if operation == effectivity.RECORD_CONFLICT:
        required = {"existing_decision_id", "valid_from", "basis_id", "summary"}
        optional = {"valid_to", "region", "traveler_class"}
        if not required <= arguments.keys() <= required | optional:
            raise ValueError("Invalid effectivity conflict parameters.")
        for name in ("valid_from", "valid_to"):
            if name in arguments and (not isinstance(arguments[name], str) or not DATE_PATTERN.fullmatch(arguments[name])):
                raise ValueError("Invalid business date.")
        for name in ("region", "traveler_class"):
            if name in arguments and (not isinstance(arguments[name], str) or not SCOPE_PATTERN.fullmatch(arguments[name])):
                raise ValueError("Invalid effectivity scope.")
        if not isinstance(arguments["summary"], str):
            raise ValueError("Invalid conflict summary.")
        return effectivity.ConflictRegistration(
            _optional_ref(arguments, "existing_decision_id"),
            date.fromisoformat(arguments["valid_from"]),
            date.fromisoformat(arguments["valid_to"]) if "valid_to" in arguments else None,
            arguments.get("region"), arguments.get("traveler_class"),
            _optional_ref(arguments, "basis_id"), arguments["summary"],
        )
    if operation == effectivity.LIST_CONFLICTS:
        if arguments:
            raise ValueError("Unexpected effectivity conflict list parameters.")
        return None
    if operation == effectivity.RESOLVE_CONFLICT:
        required = {"outcome", "basis_id", "conclusion"}
        optional = {"linked_decision_id"}
        if not required <= arguments.keys() <= required | optional:
            raise ValueError("Invalid effectivity conflict resolution parameters.")
        if not isinstance(arguments["outcome"], str) or not isinstance(arguments["conclusion"], str):
            raise ValueError("Invalid conflict resolution outcome or conclusion.")
        return effectivity.ConflictResolution(
            arguments["outcome"], _optional_ref(arguments, "basis_id"),
            arguments["conclusion"], _optional_ref(arguments, "linked_decision_id"),
        )
    if operation in {disposition.PLAN, disposition.SUBMIT}:
        action, reason = arguments.get("action"), arguments.get("reason")
        fields = {"version_id", "action", "reason"}
        if operation == disposition.SUBMIT:
            fields.add("inventory_snapshot")
        if set(arguments) != fields or not isinstance(action, str) or not isinstance(reason, str):
            raise ValueError("Invalid disposition parameters.")
        subject = (_optional_ref(arguments, "version_id"), action, reason)
        return (*subject, _inventory_snapshot(arguments)) if operation == disposition.SUBMIT else subject
    if operation in {disposition.REJECT, disposition.APPROVE}:
        fields = {"inventory_snapshot", "basis_id"}
        if operation == disposition.APPROVE:
            fields.add("expires_at")
        if set(arguments) != fields:
            raise ValueError("Invalid disposition decision parameters.")
        decision = (_inventory_snapshot(arguments), _optional_ref(arguments, "basis_id"))
        if operation == disposition.REJECT:
            return decision
        if not isinstance(arguments["expires_at"], str):
            raise ValueError("Invalid disposition approval expiry.")
        return (*decision, datetime.fromisoformat(arguments["expires_at"]))
    if operation == verification.VERIFY_ORIGINAL:
        if set(arguments) != {"inventory_snapshot"}:
            raise ValueError("Invalid original verification parameters.")
        return _inventory_snapshot(arguments)
    if operation == disposition.REGISTER_TOMBSTONE:
        if set(arguments) != {"approval_id", "inventory_snapshot"}:
            raise ValueError("Invalid deletion tombstone parameters.")
        return _optional_ref(arguments, "approval_id"), _inventory_snapshot(arguments)
    if operation == receipts.OBSERVE:
        if set(arguments) != {"tombstone_id", "inventory_snapshot"}:
            raise ValueError("Invalid disposition copy observation parameters.")
        return _optional_ref(arguments, "tombstone_id"), _inventory_snapshot(arguments)
    if operation == backup_inventory.REGISTER_BACKUP:
        if set(arguments) != {"version_id", "backup_id"}:
            raise ValueError("Invalid backup enrollment parameters.")
        return _optional_ref(arguments, "version_id"), _optional_ref(arguments, "backup_id")
    if operation == backup_expiry.SCHEDULE:
        if set(arguments) != {"expected_expiry_at"} or not isinstance(arguments["expected_expiry_at"], str):
            raise ValueError("Invalid backup expiry plan.")
        return datetime.fromisoformat(arguments["expected_expiry_at"])
    if operation == backup_expiry.OBSERVE:
        if arguments:
            raise ValueError("Backup expiry observations do not receive overrides.")
        return None
    if operation == archives.REQUEST:
        if set(arguments) not in ({"version_id", "scope"}, {"version_id", "scope", "wiki_revision_id"}) or not isinstance(arguments["scope"], str):
            raise ValueError("Invalid archive scope.")
        return _optional_ref(arguments, "version_id"), arguments["scope"], _optional_ref(arguments, "wiki_revision_id")
    if operation == archives.APPROVE:
        if set(arguments) != {"expires_at"} or not isinstance(arguments["expires_at"], str):
            raise ValueError("Invalid archive approval expiry.")
        return datetime.fromisoformat(arguments["expires_at"])
    if operation == archives.EXPORT:
        if arguments:
            raise ValueError("Archive sealing does not receive overrides.")
        return None
    if operation == space_archive.REQUEST:
        if set(arguments) not in ({"source_ids", "version_ids"}, {"source_ids", "version_ids", "wiki_revision_ids"}):
            raise ValueError("Invalid space archive scope.")
        src_raw = arguments["source_ids"]
        ver_raw = arguments["version_ids"]
        wiki_raw = arguments.get("wiki_revision_ids", [])
        if (
            not isinstance(src_raw, list) or not isinstance(ver_raw, list) or not isinstance(wiki_raw, list)
            or any(not isinstance(item, str) for item in (*src_raw, *ver_raw, *wiki_raw))
        ):
            raise ValueError("Space archive identifiers must be UUID strings.")
        return (
            tuple(UUID(item) for item in src_raw),
            tuple(UUID(item) for item in ver_raw),
            tuple(UUID(item) for item in wiki_raw),
        )
    if operation == space_archive.APPROVE:
        if set(arguments) != {"expires_at"} or not isinstance(arguments["expires_at"], str):
            raise ValueError("Invalid space archive approval expiry.")
        return datetime.fromisoformat(arguments["expires_at"])
    if operation == space_archive.EXPORT:
        if arguments:
            raise ValueError("Space archive sealing does not receive overrides.")
        return None
    if operation == disposition.REGISTER:
        action = arguments.get("action")
        if set(arguments) != {"source_id", "expected_revision", "keep_days", "action", "basis_id"} or not isinstance(action, str):
            raise ValueError("Invalid retention policy parameters.")
        return (_optional_ref(arguments, "source_id"), arguments["expected_revision"], arguments["keep_days"],
                action, _optional_ref(arguments, "basis_id"))
    if operation == holds.DECIDE:
        action = arguments.get("action")
        if set(arguments) != {"version_id", "expected_generation", "action", "basis_id"} or not isinstance(action, str):
            raise ValueError("Invalid hold decision parameters.")
        return _optional_ref(arguments, "version_id"), action, arguments["expected_generation"], _optional_ref(arguments, "basis_id")
    if operation == feedback.RECORD:
        origin = _optional_ref(arguments, "origin_request_id")
        note, category = arguments.get("note"), arguments.get("category")
        if (
            origin is None or set(arguments) - {"origin_request_id", "category", "passage_id", "note"}
            or not isinstance(category, str) or ("note" in arguments and not isinstance(note, str))
        ):
            raise ValueError("Invalid feedback recording parameters.")
        return feedback.FeedbackSpec(origin, category, _optional_ref(arguments, "passage_id"), note)
    if operation == feedback.TRANSITION:
        expected, action = arguments.get("expected_generation"), arguments.get("action")
        assignee, retest = _optional_ref(arguments, "assignee_ref"), _optional_ref(arguments, "retest_request_id")
        basis = _optional_ref(arguments, "basis_request_id")
        correction = _optional_ref(arguments, "correction_request_id")
        conclusion = arguments.get("conclusion_code")
        if (
            set(arguments) - {
                "expected_generation", "action", "assignee_ref", "retest_request_id", "basis_request_id",
                "conclusion_code", "correction_request_id",
            }
            or type(expected) is not int or not isinstance(action, str) or action not in feedback.ACTION_STATES
            or (action == "assign") != (assignee is not None) or (action == "verify_correction") != (retest is not None)
            or (action == "explain") != (basis is not None)
            or ("correction_request_id" in arguments and (action != "mark_corrected" or correction is None))
            or ("conclusion_code" in arguments and (
                action != "explain" or not isinstance(conclusion, str) or conclusion not in feedback.EXPLANATION_CODES
            ))
        ):
            raise ValueError("Invalid feedback transition parameters.")
        return expected, action, assignee, retest, basis, conclusion, correction
    if operation == feedback.QUARANTINE:
        expected, basis = arguments.get("expected_generation"), _optional_ref(arguments, "basis_request_id")
        if set(arguments) - {"expected_generation", "basis_request_id"} or type(expected) is not int or basis is None:
            raise ValueError("Invalid feedback quarantine parameters.")
        return expected, basis
    if operation in {pdf_review.PREVIEW, pdf_review.PREVIEW_REPAIR, pdf_review.SUBMIT_CORRECTION}:
        page = arguments.get("page_number")
        if not isinstance(page, str) or not re.fullmatch(r"[1-9]|1[0-6]", page):
            raise ValueError("Invalid physical PDF page number.")
        if operation != pdf_review.SUBMIT_CORRECTION and set(arguments) == {"page_number"}:
            return int(page)
        if operation == pdf_review.SUBMIT_CORRECTION and set(arguments) == {
            "page_number", "preview_request_id", "basis_id", "transcript",
        }:
            return (
                int(page), _optional_ref(arguments, "preview_request_id"), _optional_ref(arguments, "basis_id"),
                arguments["transcript"],
            )
        raise ValueError("Invalid PDF review arguments.")
    if operation == pdf_review.APPROVE_REPAIR:
        previews, basis = arguments.get("preview_request_ids"), _optional_ref(arguments, "basis_id")
        if set(arguments) != {"preview_request_ids", "basis_id"} or basis is None or (
            not isinstance(previews, list) or not 1 <= len(previews) <= pdf_evidence.MAX_PAGES
            or not all(isinstance(item, str) for item in previews)
        ):
            raise ValueError("A PDF repair approval requires an ordered set of preview requests.")
        refs = tuple(map(parse_ref, previews))
        if len(set(refs)) != len(refs):
            raise ValueError("Each physical page requires a distinct preview request.")
        return refs, basis
    if operation == docx_review.PREVIEW:
        if arguments and arguments != {"format": docx_review.TABLE_BATCH_FORMAT}:
            raise ValueError("Invalid DOCX preview format.")
        return bool(arguments)
    if operation in {repair_review.DECIDE, pdf_review.DECIDE_CORRECTION, docx_review.DECIDE}:
        pdf = operation == pdf_review.DECIDE_CORRECTION
        preview_key = "preview_request_id" if pdf else "preview_id"
        if set(arguments) != {preview_key, "outcome", "basis_id"}:
            raise ValueError("Invalid repair decision parameters.")
        preview, basis = _optional_ref(arguments, preview_key), _optional_ref(arguments, "basis_id")
        outcome = arguments["outcome"]
        if preview is None or basis is None or outcome not in ("approved", "rejected" if pdf else "quarantined"):
            raise ValueError("A repair decision requires a preview, outcome and basis.")
        return preview, outcome, basis
    if operation == handoffs.AUTHORIZE:
        if set(arguments) != {"from_employee_ref", "to_employee_ref", "basis_id", "expires_at", "items"}:
            raise ValueError("Invalid feedback handoff parameters.")
        incumbent = _optional_ref(arguments, "from_employee_ref")
        successor = _optional_ref(arguments, "to_employee_ref")
        basis = _optional_ref(arguments, "basis_id")
        expires, items = arguments["expires_at"], arguments["items"]
        if None in (incumbent, successor, basis) or not isinstance(expires, str) or (
            not isinstance(items, list) or not 1 <= len(items) <= handoffs.MAX_ITEMS
        ):
            raise ValueError("Invalid feedback handoff scope.")
        selected = []
        for item in items:
            if not isinstance(item, dict) or set(item) != {"feedback_id", "expected_generation"}:
                raise ValueError("Invalid feedback handoff item.")
            ref = _optional_ref(item, "feedback_id")
            if ref is None:
                raise ValueError("A feedback handoff item requires a feedback identity.")
            selected.append((ref, item["expected_generation"]))
        return handoffs.HandoffSpec(incumbent, successor, basis, datetime.fromisoformat(expires), tuple(selected))
    if operation in {handoffs.ACCEPT, handoffs.REVOKE}:
        if arguments:
            raise ValueError("A feedback handoff decision cannot override the sealed scope.")
        return None
    if operation == gaps.RECORD:
        origin = _optional_ref(arguments, "origin_request_id")
        if origin is None or set(arguments) != {"origin_request_id"}:
            raise ValueError("Invalid gap recording parameters.")
        return origin
    if operation == findings.EMIT:
        observations, rule = arguments.get("observations"), arguments.get("rule")
        if set(arguments) != {"observations", "rule"} or not isinstance(rule, str) or (
            not isinstance(observations, list) or len(observations) != 2
        ):
            raise ValueError("Invalid conflict report parameters.")
        pairs = []
        for observation in observations:
            if not isinstance(observation, dict) or set(observation) != {"request_id", "revision_id"}:
                raise ValueError("Invalid conflict observation.")
            pairs.append((_optional_ref(observation, "request_id"), _optional_ref(observation, "revision_id")))
        return tuple(pairs), rule
    if operation == gaps.RECLASSIFY:
        expected, classification = arguments.get("expected_generation"), arguments.get("classification")
        if set(arguments) != {"expected_generation", "classification"} or not isinstance(classification, str):
            raise ValueError("Invalid gap review parameters.")
        return expected, classification
    if operation == source_audit.READ:
        if len(arguments) > 1 or set(arguments) - {"after", "request_id"}:
            raise ValueError("Invalid source audit query.")
        return _optional_ref(arguments, "after"), _optional_ref(arguments, "request_id")
    if operation in (INTERNAL_PAGES | SOURCE_PAGES) and not (set(arguments) - {"after"}):
        return _optional_ref(arguments, "after")
    if arguments:
        raise ValueError("Unexpected progress query parameters.")
    return None


class EvidenceService:
    def __init__(
        self, connect: Callable[[], Connection], verify_token: Callable[[str], SyntheticCredential | None],
        check_source: Callable[[SyntheticCredential, DeliveryCheck], AuthorityDecision],
        store: SyntheticOriginalStore | ObjectStorageOriginalStore,
        *, retest_key: bytes | None = None, backup_store: backup_inventory.SyntheticBackupStore | None = None,
        check_archive_source: Callable[[SyntheticCredential, DeliveryCheck], AuthorityDecision] | None = None,
        pin_original_source: Callable[[SyntheticCredential, DeliveryCheck], AbstractContextManager[AuthorityDecision]] | None = None,
        authority_issuer: str = SYNTHETIC_ISSUER,
        embedding_provider: EmbeddingProviderPort | None = None,
        model_gateway: ModelGatewayPort | None = None,
        security_audit_log: SecurityAuditLogPort | None = None,
        strict_audit_sink: bool = False,
        source_connector: SourceConnectorPort | None = None,
    ):
        if retest_key is not None and (not isinstance(retest_key, bytes) or len(retest_key) != 32):
            raise ValueError("Search retest matching requires a 32-byte private key.")
        if not is_admitted_issuer(authority_issuer):
            raise ProductionIsolationError(f"Unsupported authority issuer: {authority_issuer!r}.")
        try:
            resolved_store_admission = store_admission(store)
        except ValueError as exc:
            raise ProductionIsolationError(str(exc)) from None
        if not issuer_matches_admission(authority_issuer, resolved_store_admission):
            raise ProductionIsolationError(
                f"Authority issuer mode ({admission_for_issuer(authority_issuer)}) does not match original store mode ({resolved_store_admission})."
            )
        if is_production_issuer(authority_issuer) and backup_store is not None:
            raise ProductionIsolationError("Synthetic backup store is forbidden in production mode.")
        self.connect = connect
        self.verify_token = verify_token
        self.check_source = check_source
        self.store = store
        self.retest_key = retest_key
        self.backup_store = backup_store
        self.check_archive_source = check_archive_source
        self.pin_original_source = pin_original_source
        self.authority_issuer = authority_issuer
        self.embedding_provider = embedding_provider
        self.model_gateway = model_gateway
        self.security_audit_log = security_audit_log
        self.audit_dispatcher = SecurityAuditDispatcher(security_audit_log, strict=strict_audit_sink)
        self.source_connector = source_connector
        destinations = set() if is_production_issuer(authority_issuer) else {policy.SYNTHETIC_MODEL_DESTINATION}
        if model_gateway is not None:
            destinations.add(model_gateway.destination_id)
        self.allowed_model_destinations = frozenset(destinations)

    @classmethod
    def from_port_registry(
        cls,
        connect: Callable[[], Connection],
        registry: PortRegistry,
        *,
        store: SyntheticOriginalStore | ObjectStorageOriginalStore | None = None,
        retest_key: bytes | None = None,
        backup_store: backup_inventory.SyntheticBackupStore | None = None,
    ) -> "EvidenceService":
        registry.validate()
        if registry.identity is None or registry.source_authority is None:
            raise ValueError("PortRegistry requires both identity and source_authority ports.")
        if store is None:
            if registry.object_storage is None:
                raise ValueError("PortRegistry requires an object_storage port when store is omitted.")
            resolved_store: SyntheticOriginalStore | ObjectStorageOriginalStore = ObjectStorageOriginalStore(
                registry.object_storage
            )
        else:
            resolved_store = store

        identity_port = registry.identity
        authority_port = registry.source_authority
        if registry.mode == "production":
            if not is_production_issuer(identity_port.issuer):
                raise ProductionIsolationError("Production mode forbids synthetic or non-HTTPS identity issuers.")
            if store_admission(resolved_store) != PRODUCTION_ADMISSION:
                raise ProductionIsolationError("Production mode requires a production_approved original store.")
        else:
            if identity_port.issuer != SYNTHETIC_ISSUER:
                raise ProductionIsolationError("synthetic_local mode forbids non-synthetic identity issuers.")
            if store_admission(resolved_store) != SYNTHETIC_ADMISSION:
                raise ProductionIsolationError("synthetic_local mode requires a synthetic_only original store.")

        def verify_token(token: str) -> SyntheticCredential | None:
            try:
                verified = identity_port.verify_bearer_token(token)
            except PortUnavailable:
                raise AuthorizationUnavailable("Identity verifier port is unavailable.") from None
            if verified is None or verified.issuer != identity_port.issuer:
                return None
            try:
                return SyntheticCredential(
                    verified.subject_ref,
                    verified.space_ref,
                    verified.client_id,
                    verified.region,
                    verified.traveler_class,
                    verified.operations,
                    verified.expires_at,
                )
            except ValueError:
                return None

        return cls(
            connect,
            verify_token,
            authority_port.authorize_scopes,
            resolved_store,
            retest_key=retest_key,
            backup_store=backup_store,
            check_archive_source=authority_port.authorize_scopes if registry.mode == "production" else None,
            authority_issuer=identity_port.issuer,
            embedding_provider=registry.embedding_provider,
            model_gateway=registry.model_gateway,
            security_audit_log=registry.security_audit_log,
            strict_audit_sink=(registry.mode == "production"),
            source_connector=registry.source_connector,
        )

    def identify(self, token: str) -> EmployeeCall:
        try:
            credential = self.verify_token(token)
            if credential is None or datetime.now(UTC) >= credential.expires_at:
                raise ServiceRefusal("unauthenticated")
            with self.connect() as connection:
                row = connection.execute(
                    """
                    SELECT employee.org_id, employee.principal_id, space.space_id, organization.business_timezone,
                           organization.config_revision, space.lifecycle
                    FROM thalion.object_identity AS employee_ref
                    JOIN thalion.principal AS employee
                      ON (employee_ref.org_id, employee_ref.object_type, employee_ref.object_id)
                       = (employee.org_id, employee.identity_type, employee.principal_id)
                    JOIN thalion.organization AS organization ON organization.org_id = employee.org_id
                    JOIN thalion.object_identity AS space_ref
                      ON space_ref.org_id = employee.org_id AND space_ref.object_type = 'space'
                        AND space_ref.public_id = %s
                    JOIN thalion.space AS space
                      ON (space.org_id, space.space_id) = (space_ref.org_id, space_ref.space_id)
                    WHERE employee_ref.public_id = %s AND employee.authority_issuer = %s
                      AND employee.principal_type = 'employee' AND NOT employee.disabled
                    """,
                    (credential.space_ref, credential.employee_ref, self.authority_issuer),
                ).fetchone()
            if row is None:
                raise ServiceRefusal("unauthenticated")
            if row[5] != "active":
                raise ServiceRefusal("forbidden")
            return EmployeeCall(token, credential, *row[:3], ZoneInfo(row[3]), row[4])
        except (Error, ZoneInfoNotFoundError, AuthorizationUnavailable, PortUnavailable):
            raise ServiceRefusal("dependency_unavailable") from None

    def authority_for(self, caller: EmployeeCall, probe: DeliveryCheck) -> AuthorityDecision:
        try:
            if self.verify_token(caller.token) != caller.credential:
                raise AuthorizationUnavailable("The synthetic credential changed during delivery.")
            return self.check_source(caller.credential, probe)
        except PortUnavailable:
            raise AuthorizationUnavailable("Authority dependency is unavailable.") from None

    def _delivery_context(
        self, request_id: UUID, caller: EmployeeCall, operation: str,
        purpose: str, destination: str, deadline: datetime,
    ) -> DeliveryContext:
        return DeliveryContext(
            request_id, caller.org_id, caller.principal_id, caller.credential.client_id,
            operation, purpose, destination, deadline, authority_issuer=self.authority_issuer,
        )

    def _emit_security_audit(
        self,
        caller: EmployeeCall,
        request_id: UUID,
        event_type: str,
        operation: str,
        outcome: str,
        *,
        resource_ref: str | None = None,
        detail_digest: str | None = None,
    ):
        return self.audit_dispatcher.emit(
            SecurityAuditEvent(
                event_type=event_type,
                request_id=request_id,
                org_id=caller.org_id,
                space_ref=caller.credential.space_ref,
                actor_principal_id=caller.principal_id,
                operation=operation,
                outcome=outcome,
                resource_ref=resource_ref,
                detail_digest=detail_digest,
            )
        )

    def execute_internal(
        self, caller: EmployeeCall, operation: str, arguments, ref: UUID | None = None, key: str = "",
    ) -> EvidenceReply:
        request_id = uuid4()
        if operation not in INTERNAL_OPERATIONS or operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            unscoped = INTERNAL_PAGES | INTERNAL_CREATES | {disposition.PLAN, runtime_backlog.READ}
            if (operation in unscoped) != (ref is None) or (
                operation in INTERNAL_WRITES and not IDEMPOTENCY_PATTERN.fullmatch(key)
            ):
                raise ValueError("Invalid internal request identity.")
            data = _internal_input(operation, arguments, allowed_model_destinations=self.allowed_model_destinations)
        except ValueError:
            return error_reply("invalid_arguments", request_id)

        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        call = feedback.FeedbackCall(caller.org_id, caller.space_id, caller.principal_id, request_id, key,
                                     caller.configuration_revision)
        lifecycle = operation in ({disposition.PLAN, disposition.REGISTER, holds.DECIDE}
                                  | DISPOSITION_CASE_OPERATIONS | ARCHIVE_WRITES | BACKUP_WRITES)
        repair = operation in REPAIR_OPERATIONS or operation in PDF_REVIEW_OPERATIONS or operation == pdf_review.PREVIEW
        destination = (repair_review.DESTINATION if repair else
                       disposition.DESTINATION if lifecycle else
                       effectivity.DESTINATION if operation in (effectivity.OPERATIONS | {processing.STATUS_OPERATION})
                       else ingest.DESTINATION if operation == ingest.LIST_BATCHES
                       else source_audit.DESTINATION if operation == source_audit.READ
                       else source_sync_status.DESTINATION if operation == source_sync_status.READ
                       else runtime_backlog.DESTINATION if operation == runtime_backlog.READ
                       else policy.DESTINATION if operation in policy.OPERATIONS
                       else responsibility.DESTINATION if operation in {responsibility.READ, responsibility.SET}
                       else feedback.DESTINATION)

        def check_credential():
            if datetime.now(UTC) >= caller.credential.expires_at or self.verify_token(caller.token) != caller.credential:
                raise ServiceRefusal("unauthenticated")
            if datetime.now(UTC) >= deadline:
                raise ServiceRefusal("dependency_unavailable")

        def check_archive_authority(probe):
            check_credential()
            if self.check_archive_source is None:
                raise AuthorizationUnavailable("No synthetic archive authority is configured.")
            return self.check_archive_source(caller.credential, probe)

        try:
            check_credential()
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    processing.QUALITY_OPERATION if operation == feedback.QUARANTINE else operation, destination,
                    now.astimezone(caller.business_timezone).date(), caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                try:
                    with connection.transaction():
                        connection.execute("SET LOCAL synchronous_commit = on")
                        try:
                            with connection.transaction():
                                valid_until = deadline
                                body = None
                                if repair:
                                    context = self._delivery_context(
                                        request_id, caller,
                                        operation, repair_review.PURPOSE, destination, deadline,
                                    )

                                    def check_repair_authority(probe):
                                        return self.authority_for(caller, probe)

                                    if operation in PDF_REVIEW_OPERATIONS and pdf_review.PREVIEW not in caller.credential.operations:
                                        raise ServiceRefusal("forbidden")
                                    if operation == docx_review.PREVIEW:
                                        payload, valid_until = docx_review.preview(
                                            connection, call, context, ref, self.store, check_repair_authority, allow_tables=data,
                                        )
                                    elif operation == docx_review.DECIDE:
                                        if docx_review.PREVIEW not in caller.credential.operations:
                                            raise ServiceRefusal("forbidden")
                                        payload, valid_until = docx_review.decide(
                                            connection, call, context, ref, *data, self.store, check_repair_authority,
                                        )
                                    elif operation == pdf_review.PREVIEW:
                                        body, valid_until = pdf_review.preview(
                                            connection, call, context, ref, data, self.store, check_repair_authority,
                                            allow_author=pdf_review.SUBMIT_CORRECTION in caller.credential.operations,
                                        )
                                    elif operation == pdf_review.SUBMIT_CORRECTION:
                                        payload, valid_until = pdf_review.submit_correction(
                                            connection, call, context, ref, *data, self.store, check_repair_authority,
                                        )
                                    elif operation == pdf_review.PREVIEW_CORRECTION:
                                        body, valid_until = pdf_review.preview_correction(
                                            connection, call, context, ref, self.store, check_repair_authority,
                                        )
                                    elif operation == pdf_review.DECIDE_CORRECTION:
                                        if pdf_review.PREVIEW_CORRECTION not in caller.credential.operations:
                                            raise ServiceRefusal("forbidden")
                                        payload, valid_until = pdf_review.decide_correction(
                                            connection, call, context, ref, *data, self.store, check_repair_authority,
                                        )
                                    elif operation == pdf_review.PREVIEW_REPAIR:
                                        body, valid_until = pdf_review.preview_repair_page(
                                            connection, call, context, ref, data, self.store, check_repair_authority,
                                        )
                                    elif operation == pdf_review.APPROVE_REPAIR:
                                        if pdf_review.PREVIEW_REPAIR not in caller.credential.operations:
                                            raise ServiceRefusal("forbidden")
                                        payload, valid_until = pdf_review.approve_repair(
                                            connection, call, context, ref, *data, self.store, check_repair_authority,
                                        )
                                    elif operation == repair_review.PREVIEW:
                                        payload, valid_until = repair_review.preview(
                                            connection, call, context, ref, self.store, check_repair_authority,
                                        )
                                    else:
                                        payload = repair_review.decide(
                                            connection, call, context, ref, *data, self.store, check_repair_authority,
                                        )
                                elif operation == feedback.QUEUE:
                                    payload = feedback.list_feedback_work(connection, call, data)
                                elif operation == feedback.NOTICES:
                                    payload = feedback.list_feedback_notices(connection, call, data)
                                elif operation == feedback.QUARANTINE:
                                    decision = feedback.quarantine_feedback_evidence(connection, call, ref, *data)
                                    payload = {"decision_id": str(decision)}
                                elif operation == gaps.RECORD:
                                    payload = {"gap_id": str(gaps.record_gap(connection, call, data))}
                                elif operation == gaps.QUEUE:
                                    payload = gaps.list_gap_work(connection, call, data)
                                elif operation == gaps.RECLASSIFY:
                                    payload = gaps.reclassify_gap(connection, call, ref, *data)
                                elif operation == effectivity.APPROVE:
                                    require_scope(connection, call, operation, destination=destination)
                                    decision = effectivity.approve_synthetic_rule(
                                        connection, SourceWrite(caller.org_id, caller.principal_id, request_id, key),
                                        caller.space_id, ref, data,
                                    )
                                    payload = {"decision_id": str(decision)}
                                elif operation == effectivity.PREVIEW:
                                    require_scope(connection, call, operation, destination=destination)
                                    payload = effectivity.preview_synthetic_rule(
                                        connection, SourceWrite(caller.org_id, caller.principal_id, request_id, ""),
                                        caller.space_id, ref, data,
                                    )
                                elif operation == effectivity.PREVIEW_STOP:
                                    require_scope(connection, call, operation, destination=destination)
                                    payload = effectivity.preview_synthetic_rule_stop(
                                        connection, SourceWrite(caller.org_id, caller.principal_id, request_id, ""),
                                        caller.space_id, ref, data,
                                    )
                                elif operation == effectivity.STOP:
                                    require_scope(connection, call, operation, destination=destination)
                                    decision = effectivity.stop_synthetic_rule(
                                        connection, SourceWrite(caller.org_id, caller.principal_id, request_id, key),
                                        caller.space_id, ref, data.kind, data.basis_ref, reason=data.reason,
                                    )
                                    affected = effectivity.read_stop_affected_wiki_topics(
                                        connection, caller.org_id, caller.space_id, decision,
                                    )
                                    payload = {
                                        "decision_id": str(decision),
                                        "kind": data.kind,
                                        "affected_wiki_topics": affected,
                                    }
                                elif operation == effectivity.RECORD_CONFLICT:
                                    require_scope(connection, call, operation, destination=destination)
                                    payload = effectivity.record_synthetic_effectivity_conflict(
                                        connection, SourceWrite(caller.org_id, caller.principal_id, request_id, key),
                                        caller.space_id, ref, data,
                                    )
                                elif operation == effectivity.LIST_CONFLICTS:
                                    require_scope(connection, call, operation, destination=destination)
                                    payload = effectivity.list_synthetic_effectivity_conflicts(
                                        connection, SourceWrite(caller.org_id, caller.principal_id, request_id, ""),
                                        caller.space_id, ref,
                                    )
                                elif operation == effectivity.RESOLVE_CONFLICT:
                                    require_scope(connection, call, operation, destination=destination)
                                    payload = effectivity.resolve_synthetic_effectivity_conflict(
                                        connection, SourceWrite(caller.org_id, caller.principal_id, request_id, key),
                                        caller.space_id, ref, data,
                                    )
                                elif operation == processing.STATUS_OPERATION:
                                    if require_scope(connection, call, operation, destination=destination) != caller.principal_id:
                                        raise ServiceRefusal("forbidden")
                                    state = processing.read_source_processing_status(
                                        connection, caller.org_id, caller.space_id, caller.principal_id, ref,
                                    )
                                    payload = {"version_id": str(ref), "state": state}
                                elif operation == ingest.LIST_BATCHES:
                                    if require_scope(connection, call, operation, destination=destination) != caller.principal_id:
                                        raise ServiceRefusal("forbidden")
                                    payload = ingest.list_synthetic_batches(
                                        connection, caller.org_id, caller.space_id, caller.principal_id, ref, data,
                                    )
                                elif operation == source_audit.READ:
                                    connection.execute("SET LOCAL statement_timeout = '6s'")
                                    payload = source_audit.list_source_requests(connection, call, ref, *data)
                                elif operation == source_sync_status.READ:
                                    connection.execute("SET LOCAL lock_timeout = '500ms'")
                                    connection.execute("SET LOCAL statement_timeout = '6s'")
                                    payload = source_sync_status.observe(connection, call, ref)
                                elif operation == runtime_backlog.READ:
                                    connection.execute("SET LOCAL lock_timeout = '500ms'")
                                    connection.execute("SET LOCAL statement_timeout = '6s'")
                                    payload = runtime_backlog.observe(connection, call)
                                elif operation in policy.OPERATIONS:
                                    require_scope(connection, call, operation, destination=destination)
                                    context = SourceWrite(caller.org_id, caller.principal_id, request_id, key)
                                    model_egress = operation in {policy.READ_MODEL, policy.REPLACE_MODEL}
                                    if operation not in policy.WRITE_OPERATIONS:
                                        payload = policy.read_synthetic_policy(
                                            connection, context, caller.space_id, ref, model_egress=model_egress,
                                        )
                                    else:
                                        expected, basis, rules = data
                                        revision = policy.replace_synthetic_policy(
                                            connection, context, caller.space_id, ref, expected, rules, basis, model_egress=model_egress,
                                        )
                                        payload = {"policy_revision": revision}
                                elif operation in {responsibility.READ, responsibility.SET}:
                                    require_scope(connection, call, operation, destination=destination)
                                    context = SourceWrite(caller.org_id, caller.principal_id, request_id, key)
                                    if operation == responsibility.READ:
                                        payload = responsibility.read_synthetic_responsibility(connection, context, caller.space_id, ref)
                                    else:
                                        payload = responsibility.set_synthetic_responsibility(
                                            connection, context, caller.space_id, ref, *data,
                                        )
                                elif operation == findings.EMIT:
                                    payload = {"finding_id": str(findings.emit_finding(connection, call, *data))}
                                elif operation == disposition.PLAN:
                                    payload = disposition.plan_disposition(connection, call, *data)
                                elif operation == disposition.REGISTER:
                                    payload = disposition.register_retention_policy(connection, call, *data)
                                elif operation == disposition.SUBMIT:
                                    payload = disposition.submit_disposition_case(connection, call, *data)
                                elif operation in {disposition.REJECT, disposition.APPROVE}:
                                    payload = disposition.decide_disposition_case(connection, call, ref, *data)
                                elif operation == verification.VERIFY_ORIGINAL:
                                    payload = verification.verify_disposition_original(connection, call, ref, data, self.store)
                                elif operation == disposition.REGISTER_TOMBSTONE:
                                    payload = disposition.register_deletion_tombstone(connection, call, ref, *data)
                                elif operation == receipts.OBSERVE:
                                    payload = receipts.record_copy_observations(
                                        connection, call, ref, *data, self.store, self.backup_store,
                                    )
                                elif operation == backup_inventory.REGISTER_BACKUP:
                                    payload = backup_inventory.register_backup_copy(connection, call, *data, self.backup_store)
                                elif operation == backup_expiry.SCHEDULE:
                                    payload = backup_expiry.schedule_expiry(connection, call, ref, data, self.backup_store)
                                elif operation == backup_expiry.OBSERVE:
                                    payload = backup_expiry.observe_expiry(connection, call, ref, self.backup_store)
                                elif operation == archives.REQUEST:
                                    payload = archives.request_export(connection, call, *data)
                                elif operation == archives.APPROVE:
                                    payload = archives.approve_export(connection, call, ref, data)
                                elif operation == archives.EXPORT:
                                    context = self._delivery_context(
                                        request_id, caller,
                                        operation, archives.PURPOSE, archives.ARCHIVE_DESTINATION, deadline,
                                    )
                                    payload = archives.seal_export(connection, call, ref, self.store, context, check_archive_authority)
                                elif operation == space_archive.REQUEST:
                                    src_refs, ver_refs, wiki_revs = data
                                    payload = space_archive.request_space_archive(
                                        connection, call,
                                        source_refs=src_refs, version_refs=ver_refs, wiki_revisions=wiki_revs,
                                    )
                                elif operation == space_archive.APPROVE:
                                    payload = space_archive.approve_space_archive(connection, call, ref, data)
                                elif operation == space_archive.EXPORT:
                                    context = self._delivery_context(
                                        request_id, caller,
                                        operation, archives.PURPOSE, archives.ARCHIVE_DESTINATION, deadline,
                                    )
                                    payload = space_archive.seal_space_archive(
                                        connection, call, ref, self.store, context, check_archive_authority,
                                    )
                                elif operation == holds.DECIDE:
                                    payload = holds.decide_hold(connection, call, *data)
                                elif operation == handoffs.AUTHORIZE:
                                    payload = handoffs.authorize(connection, call, data)
                                elif operation in {handoffs.ACCEPT, handoffs.REVOKE}:
                                    payload = handoffs.resolve(connection, call, ref, accept=operation == handoffs.ACCEPT)
                                else:
                                    if operation == feedback.RECORD:
                                        recorded = feedback.record_feedback(connection, call, data)
                                        progress = feedback.FeedbackProgress(recorded, "pending", 1)
                                    elif operation == feedback.TRANSITION:
                                        expected, action, assignee, retest, basis, conclusion, correction = data
                                        assignee_id = feedback.resolve_assignee(connection, caller.org_id, assignee)
                                        progress = feedback.transition_feedback(
                                            connection, call, ref, expected, action, assignee_id=assignee_id,
                                            retest_id=retest, basis_id=basis, conclusion_code=conclusion,
                                            correction_id=correction,
                                        )
                                    else:
                                        progress = feedback.get_feedback_progress(connection, call, ref)
                                    payload = {"feedback_id": str(progress.feedback_ref), "state": progress.state,
                                               "generation": progress.generation}
                                    if progress.conclusion_code is not None:
                                        payload["conclusion_code"] = progress.conclusion_code
                                check_credential()
                                if datetime.now(UTC) >= valid_until:
                                    raise ServiceRefusal("dependency_unavailable")
                                if operation in {
                                    policy.REPLACE,
                                    policy.REPLACE_MODEL,
                                    effectivity.STOP,
                                    disposition.REGISTER_TOMBSTONE,
                                    holds.DECIDE,
                                    governance.MANAGE_SHARED_GROUP,
                                    governance.MANAGE_DELEGATION,
                                    governance.ARCHIVE_SPACE,
                                    governance.HANDOFF_TRANSITION,
                                    release.SWITCH_SPACE_RELEASE,
                                    release.ROLLBACK_WIKI_TOPIC,
                                }:
                                    self._emit_security_audit(
                                        caller,
                                        request_id,
                                        f"security.{operation}",
                                        operation,
                                        "succeeded",
                                        resource_ref=str(ref) if ref is not None else None,
                                        detail_digest=metadata_digest(operation, ref, payload),
                                    )
                            outcome = "succeeded"
                            if body is None:
                                body = encode({"request_id": str(request_id), **payload})
                            if operation == source_audit.READ:
                                reply = SourceAuditReply(request_id, 200, body, valid_until, source_ref=ref, started=started)
                            elif operation == source_sync_status.READ:
                                reply = SourceSyncStatusReply(request_id, 200, body, valid_until, source_ref=ref, started=started)
                            elif operation == runtime_backlog.READ:
                                reply = RuntimeBacklogReply(request_id, 200, body, valid_until, started=started)
                            else:
                                reply = EvidenceReply(request_id, 200, body, valid_until)
                        except (ValueError, feedback.FeedbackConflict, feedback.FeedbackNotAdmitted, gaps.GapConflict,
                                disposition.DispositionConflict, holds.HoldConflict, IdempotencyConflict,
                                processing.ProcessingNotAdmitted, processing.QualityConflict, ServiceRefusal,
                                effectivity.EffectivityConflict, SourceNotAdmitted, OperationsNotAdmitted,
                                policy.PolicyNotAdmitted, policy.PolicyConflict, responsibility.ResponsibilityConflict) as error:
                            code = (
                                error.code if isinstance(error, ServiceRefusal)
                                else "forbidden" if isinstance(error, (feedback.FeedbackNotAdmitted, processing.ProcessingNotAdmitted,
                                                                       SourceNotAdmitted, OperationsNotAdmitted,
                                                                       policy.PolicyNotAdmitted))
                                else "local_policy_conflict" if operation in policy.OPERATIONS and isinstance(
                                    error, (policy.PolicyConflict, IdempotencyConflict),
                                )
                                else "responsibility_conflict" if operation == responsibility.SET and isinstance(
                                    error, (responsibility.ResponsibilityConflict, IdempotencyConflict),
                                )
                                else "effectivity_conflict" if operation in effectivity.OPERATIONS and isinstance(
                                    error, (effectivity.EffectivityConflict, IdempotencyConflict),
                                )
                                else "repair_review_conflict" if repair and isinstance(error, (processing.QualityConflict, IdempotencyConflict))
                                else "hold_conflict" if operation == holds.DECIDE and isinstance(error, (holds.HoldConflict, IdempotencyConflict))
                                else "retention_policy_conflict" if operation == disposition.REGISTER and isinstance(
                                    error, (disposition.DispositionConflict, IdempotencyConflict),
                                )
                                else "disposition_case_conflict" if operation in DISPOSITION_CASE_OPERATIONS and isinstance(
                                    error, (disposition.DispositionConflict, IdempotencyConflict),
                                )
                                else "backup_copy_conflict" if operation in BACKUP_WRITES and isinstance(
                                    error, (disposition.DispositionConflict, IdempotencyConflict),
                                )
                                else "original_archive_conflict" if operation in ARCHIVE_WRITES and isinstance(
                                    error, (disposition.DispositionConflict, IdempotencyConflict),
                                )
                                else "invalid_arguments" if isinstance(error, ValueError) else "feedback_conflict"
                            )
                            outcome = "dependency_unavailable" if code == "dependency_unavailable" else "rejected"
                            reply = error_reply(code, request_id)
                        if not isinstance(reply, GuardedMetadataReply) and not finish_open_request(
                            connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000),
                        ):
                            raise RequestAuditConflict("Internal operation audit could not be finalized.")
                    return reply
                except (Error, RequestAuditConflict, AuthorizationUnavailable, OriginalIntegrityError,
                        SecurityLogUnavailable,
                        processing.ProcessingDependencyUnavailable,
                        disposition.DispositionInventoryUnavailable):
                    finish_request(connection, caller.org_id, request_id, "dependency_unavailable", int((monotonic() - started) * 1000))
                    return error_reply("dependency_unavailable", request_id)
        except ServiceRefusal as error:
            return error_reply(error.code, request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def release_guarded_metadata(
        self, caller: EmployeeCall, reply: SourceAuditReply | SourceSyncStatusReply | RuntimeBacklogReply,
        release_stack: ExitStack, dispatch_at: datetime,
    ) -> EvidenceReply:
        call = feedback.FeedbackCall(
            caller.org_id, caller.space_id, caller.principal_id, reply.request_id, "", caller.configuration_revision,
        )

        def check_credential():
            if datetime.now(UTC) >= caller.credential.expires_at or self.verify_token(caller.token) != caller.credential:
                raise ServiceRefusal("unauthenticated")
            if reply.valid_until is None or max(dispatch_at, datetime.now(UTC)) >= reply.valid_until:
                raise ServiceRefusal("dependency_unavailable")

        finalized = False
        try:
            check_credential()
            with ExitStack() as guard:
                authority = guard.enter_context(self.connect())
                guard.enter_context(authority.transaction())
                authority.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                authority.execute("SET LOCAL lock_timeout = '500ms'")
                if isinstance(reply, SourceAuditReply):
                    source_id = source_audit.pin_release_scope(authority, call, reply.source_ref)
                elif isinstance(reply, SourceSyncStatusReply):
                    source_sync_status.pin_release_scope(authority, call, reply.source_ref)
                else:
                    runtime_backlog.pin_release_scope(authority, call)
                with self.connect() as audit, audit.transaction():
                    audit.execute("SET LOCAL lock_timeout = '500ms'")
                    audit.execute("SET LOCAL synchronous_commit = on")
                    check_credential()
                    if isinstance(reply, SourceAuditReply):
                        source_audit.record_access(audit, call, source_id)
                    if not finish_open_request(audit, caller.org_id, reply.request_id, "succeeded",
                                               int((monotonic() - reply.started) * 1000)):
                        raise RequestAuditConflict("Protected metadata audit could not be finalized.")
                finalized = True
                check_credential()
                release_stack.enter_context(guard.pop_all())
                return reply
        except ServiceRefusal as error:
            code = error.code
        except OperationsNotAdmitted:
            code = "forbidden"
        except (Error, AuthorizationUnavailable, RequestAuditConflict):
            code = "dependency_unavailable"
        if finalized:
            return error_reply(code, reply.request_id)
        try:
            with self.connect() as connection:
                outcome = "dependency_unavailable" if code == "dependency_unavailable" else "rejected"
                if not finish_request(connection, caller.org_id, reply.request_id, outcome,
                                      int((monotonic() - reply.started) * 1000)):
                    code = "dependency_unavailable"
        except (Error, RequestAuditConflict):
            code = "dependency_unavailable"
        return error_reply(code, reply.request_id)

    def execute_wiki_status(self, caller: EmployeeCall, after: UUID | None = None) -> EvidenceReply:
        request_id = uuid4()
        operation = management.WIKI_STATUS_OPERATION
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        start = monotonic()
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    operation, "internal_management", now.astimezone(caller.business_timezone).date(),
                    caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
                ))
                with connection.transaction():
                    connection.execute("SET LOCAL synchronous_commit = on")
                    if not management.may_read_topic_status(connection, caller.org_id, caller.space_id, caller.principal_id):
                        reply, outcome = error_reply("forbidden", request_id), "rejected"
                    else:
                        topics, cursor = management.list_topic_status(connection, caller.org_id, caller.space_id, after)
                        if self.verify_token(caller.token) != caller.credential:
                            reply, outcome = error_reply("unauthenticated", request_id), "rejected"
                        elif datetime.now(UTC) >= deadline:
                            reply, outcome = error_reply("dependency_unavailable", request_id), "dependency_unavailable"
                        else:
                            reply = EvidenceReply(request_id, 200, encode({
                                "request_id": str(request_id), "topics": topics, "next_cursor": cursor,
                            }), deadline)
                            outcome = "succeeded"
                    if not finish_open_request(connection, caller.org_id, request_id, outcome, int((monotonic() - start) * 1000)):
                        return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_revisions(self, caller: EmployeeCall, wiki_ref: UUID | None = None) -> EvidenceReply:
        request_id = uuid4()
        allowed_ops = caller.credential.operations & management.WIKI_WORKFLOW_READ_OPERATIONS
        if not allowed_ops:
            return error_reply("forbidden", request_id)
        operation = (
            management.WIKI_STATUS_OPERATION
            if management.WIKI_STATUS_OPERATION in allowed_ops
            else policy.WIKI_PREVIEW_ACCESS[0]
            if policy.WIKI_PREVIEW_ACCESS[0] in allowed_ops
            else policy.WIKI_REVIEW_ACCESS[0]
            if policy.WIKI_REVIEW_ACCESS[0] in allowed_ops
            else policy.WIKI_PUBLISH_ACCESS[0]
        )
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        start = monotonic()
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    operation, "internal_management", now.astimezone(caller.business_timezone).date(),
                    caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
                ))
                with connection.transaction():
                    connection.execute("SET LOCAL synchronous_commit = on")
                    is_owner = (
                        management.WIKI_STATUS_OPERATION in allowed_ops
                        and management.may_read_topic_status(connection, caller.org_id, caller.space_id, caller.principal_id)
                    )
                    can_review = bool(allowed_ops - {management.WIKI_STATUS_OPERATION})
                    if not is_owner and not can_review:
                        reply, outcome = error_reply("forbidden", request_id), "rejected"
                    else:
                        payload = management.list_workflow_revisions(
                            connection, caller.org_id, caller.space_id, caller.principal_id,
                            is_owner=is_owner, wiki_ref=wiki_ref,
                        )
                        if self.verify_token(caller.token) != caller.credential:
                            reply, outcome = error_reply("unauthenticated", request_id), "rejected"
                        elif datetime.now(UTC) >= deadline:
                            reply, outcome = error_reply("dependency_unavailable", request_id), "dependency_unavailable"
                        else:
                            reply = EvidenceReply(request_id, 200, encode({
                                "request_id": str(request_id),
                                "role": "owner" if is_owner else "reviewer",
                                **payload,
                            }), deadline)
                            outcome = "succeeded"
                    if not finish_open_request(connection, caller.org_id, request_id, outcome, int((monotonic() - start) * 1000)):
                        return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_inputs(self, caller: EmployeeCall, arguments) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.WIKI_INPUT_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            if not isinstance(arguments, dict) or set(arguments) - {"business_date", "direct", "parents", "rebuild_event_id"}:
                raise ValueError("Unexpected wiki input arguments.")
            business_date = _parse_business_date(arguments.get("business_date"))
            rebuild_event_id = _optional_ref(arguments, "rebuild_event_id")
            raw_parents = arguments.get("parents", [])
            if not isinstance(raw_parents, list) or len(raw_parents) > 8 or any(not isinstance(item, str) for item in raw_parents):
                raise ValueError("Invalid parent manifest references.")
            parents = tuple(parse_ref(item) for item in raw_parents)
            if rebuild_event_id is not None and parents:
                raise ValueError("Clean rebuild cannot inherit parent manifests.")
            min_direct = 1 if (rebuild_event_id is not None or not parents) else 0
            direct = _parse_wiki_pairs(arguments.get("direct", []), min_len=min_direct, max_len=20)
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        context = self._delivery_context(
            request_id, caller,
            operation, purpose, destination, deadline,
        )
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                if rebuild_event_id is not None:
                    result = inputs.prepare_clean_wiki_inputs(
                        connection, context, caller.space_id, rebuild_event_id, direct, self.store,
                        region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                        check_authority=lambda probe: self.authority_for(caller, probe),
                    )
                else:
                    result = inputs.prepare_wiki_inputs(
                        connection, context, caller.space_id, direct, parents, self.store,
                        region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                        check_authority=lambda probe: self.authority_for(caller, probe),
                    )
                if not finish_request(connection, caller.org_id, request_id, result.status, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "succeeded" and result.manifest_ref is not None and result.payload is not None and result.valid_until is not None:
                    if self.verify_token(caller.token) != caller.credential:
                        return error_reply("unauthenticated", request_id)
                    valid_until = min(deadline, result.valid_until)
                    if datetime.now(UTC) >= valid_until:
                        return error_reply("dependency_unavailable", request_id)
                    return EvidenceReply(request_id, 200, encode({
                        "request_id": str(request_id),
                        "manifest_id": str(result.manifest_ref),
                        "valid_until": valid_until.astimezone(UTC).isoformat(),
                        "excerpts": json.loads(result.payload),
                    }), valid_until)
                if result.status == "input_changed":
                    return error_reply("wiki_input_changed", request_id)
                if result.status == "dependency_unavailable":
                    return error_reply("dependency_unavailable", request_id)
                return error_reply("forbidden", request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_candidate(self, caller: EmployeeCall, arguments, key: str) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.WIKI_CANDIDATE_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            if IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                raise ValueError("Invalid idempotency key.")
            allowed = {"business_date", "topic_key", "title", "markdown", "manifest_id", "reviewer_ref",
                       "basis_id", "citations", "statements"}
            if not isinstance(arguments, dict) or not set(arguments) <= allowed:
                raise ValueError("Unexpected candidate arguments.")
            business_date = _parse_business_date(arguments.get("business_date"))
            topic_key = arguments.get("topic_key")
            title = arguments.get("title")
            markdown = arguments.get("markdown")
            if not (isinstance(topic_key, str) and isinstance(title, str) and isinstance(markdown, str)):
                raise ValueError("Expected text fields for wiki candidate.")
            manifest_ref = parse_ref(arguments["manifest_id"]) if isinstance(arguments.get("manifest_id"), str) else None
            reviewer_ref = parse_ref(arguments["reviewer_ref"]) if isinstance(arguments.get("reviewer_ref"), str) else None
            basis_ref = parse_ref(arguments["basis_id"]) if isinstance(arguments.get("basis_id"), str) else None
            if manifest_ref is None or reviewer_ref is None or basis_ref is None:
                raise ValueError("Missing required identifiers.")
            citations = _parse_wiki_pairs(arguments.get("citations"), min_len=1, max_len=20)
            statements = _parse_wiki_statements(arguments.get("statements"))
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        context = self._delivery_context(
            request_id, caller,
            operation, purpose, destination, deadline,
        )
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                with connection.transaction():
                    reviewer_id = management.resolve_reviewer(connection, caller.org_id, reviewer_ref)
                if reviewer_id is None or reviewer_id == caller.principal_id:
                    if not finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000)):
                        return error_reply("dependency_unavailable", request_id)
                    return error_reply("forbidden", request_id)
                candidate = drafts.ManualCandidate(
                    topic_key, title, markdown, manifest_ref, reviewer_id, basis_ref, citations, statements,
                )
                result = drafts.create_manual_candidate(
                    connection, context, caller.space_id, candidate, key,
                    region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                )
                if not finish_request(connection, caller.org_id, request_id, result.status, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "succeeded" and result.ref is not None:
                    return EvidenceReply(request_id, 200, encode({
                        "request_id": str(request_id),
                        "revision_id": str(result.ref),
                    }), deadline)
                if result.status == "input_changed":
                    return error_reply("wiki_input_changed", request_id)
                if result.status == "dependency_unavailable":
                    return error_reply("dependency_unavailable", request_id)
                return error_reply("forbidden", request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_generate(self, caller: EmployeeCall, arguments, key: str) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.WIKI_CANDIDATE_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            if IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                raise ValueError("Invalid idempotency key.")
            allowed = {
                "business_date", "topic_key", "manifest_id", "reviewer_ref", "basis_id",
                "title_hint", "instructions", "max_microunits", "currency",
            }
            if not isinstance(arguments, dict) or not set(arguments) <= allowed:
                raise ValueError("Unexpected wiki generation arguments.")
            business_date = _parse_business_date(arguments.get("business_date"))
            topic_key = arguments.get("topic_key")
            manifest_ref = parse_ref(arguments["manifest_id"]) if isinstance(arguments.get("manifest_id"), str) else None
            reviewer_ref = parse_ref(arguments["reviewer_ref"]) if isinstance(arguments.get("reviewer_ref"), str) else None
            basis_ref = parse_ref(arguments["basis_id"]) if isinstance(arguments.get("basis_id"), str) else None
            title_hint = arguments.get("title_hint", "")
            instructions = arguments.get("instructions", "")
            max_microunits = arguments.get("max_microunits", 100_000)
            currency = arguments.get("currency", "USD")
            if (
                not isinstance(topic_key, str)
                or manifest_ref is None
                or reviewer_ref is None
                or basis_ref is None
                or not isinstance(title_hint, str)
                or not isinstance(instructions, str)
                or type(max_microunits) is not int
                or not isinstance(currency, str)
            ):
                raise ValueError("Invalid wiki generation fields.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        context = self._delivery_context(request_id, caller, operation, purpose, destination, deadline)
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                with connection.transaction():
                    reviewer_id = management.resolve_reviewer(connection, caller.org_id, reviewer_ref)
                if reviewer_id is None or reviewer_id == caller.principal_id:
                    if not finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000)):
                        return error_reply("dependency_unavailable", request_id)
                    return error_reply("forbidden", request_id)
                spec = ai_drafting.AiDraftSpec(
                    topic_key=topic_key,
                    manifest_ref=manifest_ref,
                    reviewer_id=reviewer_id,
                    basis_ref=basis_ref,
                    title_hint=title_hint,
                    instructions=instructions,
                    max_microunits=max_microunits,
                    currency=currency,
                )
                result = ai_drafting.generate_wiki_candidate(
                    connection,
                    context,
                    caller.space_id,
                    spec,
                    key,
                    self.store,
                    self.model_gateway,
                    region=caller.credential.region,
                    traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                    ingress=caller.ingress,
                )
                if result.status == "succeeded" and result.revision_ref is not None:
                    self._emit_security_audit(
                        caller,
                        request_id,
                        "security.wiki_ai_draft_generated",
                        operation,
                        "succeeded",
                        resource_ref=str(result.revision_ref),
                        detail_digest=metadata_digest(
                            topic_key, manifest_ref, result.provider_call_id, result.billed_microunits
                        ),
                    )
                if not finish_request(connection, caller.org_id, request_id, result.status, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "succeeded" and result.revision_ref is not None:
                    return EvidenceReply(request_id, 200, encode({
                        "request_id": str(request_id),
                        "revision_id": str(result.revision_ref),
                        "provider_call_id": result.provider_call_id,
                        "input_tokens": result.input_tokens,
                        "output_tokens": result.output_tokens,
                        "billed_microunits": result.billed_microunits,
                        "title": result.title,
                        "markdown": result.markdown,
                        "citations": [[str(ref), rev] for ref, rev in result.citations],
                    }), result.valid_until or deadline)
                if result.status == "input_changed":
                    return error_reply("wiki_input_changed", request_id)
                if result.status in {"dependency_unavailable", "outcome_unknown"}:
                    return error_reply("dependency_unavailable", request_id)
                return error_reply("forbidden", request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable, SecurityLogUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_preview(self, caller: EmployeeCall, revision_id: str, arguments) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.WIKI_PREVIEW_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            revision_ref = parse_ref(revision_id)
            if not isinstance(arguments, dict) or set(arguments) != {"business_date"}:
                raise ValueError("Expected business_date.")
            business_date = _parse_business_date(arguments.get("business_date"))
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        context = self._delivery_context(
            request_id, caller,
            operation, purpose, destination, deadline,
        )
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                result = drafts.read_candidate_for_review(
                    connection, context, caller.space_id, revision_ref,
                    region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                )
                if not finish_request(connection, caller.org_id, request_id, result.status, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "input_changed":
                    return error_reply("wiki_input_changed", request_id)
                if result.status == "dependency_unavailable":
                    return error_reply("dependency_unavailable", request_id)
                if (result.status != "succeeded" or result.payload is None or result.input_digest is None
                        or result.review_material_ref is None or result.valid_until is None):
                    return error_reply("forbidden", request_id)
                content = json.loads(result.payload)
                cited = {(ref, rev) for ref, rev in content.get("citations", ())}
                with connection.transaction():
                    manifest_inputs = management.list_manifest_inputs(
                        connection, caller.org_id, caller.space_id, revision_ref, cited,
                    )
                    topic_info = management.topic_key_for_revision(
                        connection, caller.org_id, caller.space_id, revision_ref, caller.principal_id,
                    )
                previous_payload = None
                if (
                    topic_info is not None and topic_info[1] and result.expected_generation
                    and "read_passage" in caller.credential.operations
                ):
                    prev_request_id = uuid4()
                    prev_op, prev_purpose, prev_dest = policy.WIKI_READ_ACCESS
                    prev_started = monotonic()
                    prev_ctx = self._delivery_context(
                        prev_request_id, caller,
                        prev_op, prev_purpose, prev_dest, min(deadline, result.valid_until),
                    )
                    start_request(connection, RequestStart(
                        caller.org_id, prev_request_id, caller.principal_id, None, prev_ctx.client_id,
                        prev_op, prev_dest, business_date, caller.configuration_revision,
                        space_id=caller.space_id, ingress=caller.ingress,
                    ))
                    prev_result = publication.read_current_revision(
                        connection, prev_ctx, caller.space_id, topic_info[0],
                        region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                        check_authority=lambda probe: self.authority_for(caller, probe),
                    )
                    finish_request(
                        connection, caller.org_id, prev_request_id, prev_result.status,
                        int((monotonic() - prev_started) * 1000),
                    )
                    if prev_result.status == "succeeded" and prev_result.payload is not None:
                        previous_payload = prev_result.payload
                comparison = management.build_previous_comparison(
                    connection, caller.org_id, caller.space_id, revision_ref, result.expected_generation,
                    content, previous_payload=previous_payload,
                )
                if self.verify_token(caller.token) != caller.credential:
                    return error_reply("unauthenticated", request_id)
                valid_until = min(deadline, result.valid_until)
                if datetime.now(UTC) >= valid_until:
                    return error_reply("dependency_unavailable", request_id)
                return EvidenceReply(request_id, 200, encode({
                    "request_id": str(request_id),
                    "revision_id": str(revision_ref),
                    "content": content,
                    "content_digest": sha256(result.payload).hexdigest(),
                    "input_digest": result.input_digest.hex(),
                    "review_material_id": str(result.review_material_ref),
                    "expected_generation": result.expected_generation,
                    "valid_until": valid_until.astimezone(UTC).isoformat(),
                    "manifest_inputs": manifest_inputs,
                    "comparison": comparison,
                }), valid_until)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_review(self, caller: EmployeeCall, revision_id: str, arguments, key: str) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.WIKI_REVIEW_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            if IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                raise ValueError("Invalid idempotency key.")
            revision_ref = parse_ref(revision_id)
            expected_keys = {
                "business_date", "content_digest", "input_digest", "review_material_id",
                "decision", "reason_code", "basis_id",
            }
            if not isinstance(arguments, dict) or set(arguments) != expected_keys:
                raise ValueError("Unexpected review arguments.")
            business_date = _parse_business_date(arguments["business_date"])
            content_digest = _parse_hex_digest(arguments["content_digest"])
            input_digest = _parse_hex_digest(arguments["input_digest"])
            review_material_ref = parse_ref(arguments["review_material_id"]) if isinstance(arguments["review_material_id"], str) else None
            basis_ref = parse_ref(arguments["basis_id"]) if isinstance(arguments["basis_id"], str) else None
            decision = arguments["decision"]
            reason_code = arguments["reason_code"]
            if (review_material_ref is None or basis_ref is None or decision not in ("approved", "rejected")
                    or not isinstance(reason_code, str)):
                raise ValueError("Invalid review payload.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        context = self._delivery_context(
            request_id, caller,
            operation, purpose, destination, deadline,
        )
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                result = drafts.submit_review(
                    connection, context, caller.space_id, revision_ref, content_digest, input_digest,
                    decision, reason_code, basis_ref, key, review_material_ref=review_material_ref,
                    region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                )
                if not finish_request(connection, caller.org_id, request_id, result.status, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "succeeded" and result.ref is not None:
                    return EvidenceReply(request_id, 200, encode({
                        "request_id": str(request_id),
                        "review_id": str(result.ref),
                        "decision": decision,
                    }), deadline)
                if result.status == "input_changed":
                    return error_reply("wiki_input_changed", request_id)
                if result.status == "dependency_unavailable":
                    return error_reply("dependency_unavailable", request_id)
                return error_reply("forbidden", request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_publish(self, caller: EmployeeCall, revision_id: str, arguments, key: str) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.WIKI_PUBLISH_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            if IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                raise ValueError("Invalid idempotency key.")
            revision_ref = parse_ref(revision_id)
            if not isinstance(arguments, dict) or set(arguments) != {"business_date", "review_id"}:
                raise ValueError("Unexpected publish arguments.")
            business_date = _parse_business_date(arguments["business_date"])
            review_ref = parse_ref(arguments["review_id"]) if isinstance(arguments["review_id"], str) else None
            if review_ref is None:
                raise ValueError("Expected a review identifier.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        context = self._delivery_context(
            request_id, caller,
            operation, purpose, destination, deadline,
        )
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                result = publication.publish_revision(
                    connection, context, caller.space_id, revision_ref, review_ref, key,
                    region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                )
                if not finish_request(connection, caller.org_id, request_id, result.status, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "succeeded" and result.ref is not None:
                    self._emit_security_audit(
                        caller,
                        request_id,
                        "security.wiki_published",
                        operation,
                        "succeeded",
                        resource_ref=str(result.ref),
                        detail_digest=metadata_digest(revision_ref, review_ref, result.ref),
                    )
                    return EvidenceReply(request_id, 200, encode({
                        "request_id": str(request_id),
                        "publication_id": str(result.ref),
                    }), deadline)
                if result.status == "dependency_unavailable":
                    return error_reply("dependency_unavailable", request_id)
                if result.status in ("input_changed", "no_evidence", "rejected"):
                    with connection.transaction():
                        diagnosis = management.diagnose_publish_change(
                            connection, caller.org_id, caller.space_id, revision_ref, review_ref, caller.principal_id,
                        )
                    if diagnosis is not None and (
                        result.status == "input_changed" or diagnosis["topic_generation_changed"] or diagnosis["changed_passages"]
                    ):
                        status_code, message = ERRORS["wiki_input_changed"]
                        return EvidenceReply(request_id, status_code, encode({
                            "request_id": str(request_id),
                            "error": {"code": "wiki_input_changed", "message": message},
                            **diagnosis,
                        }), deadline)
                return error_reply("forbidden", request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable, SecurityLogUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_rule_revisions(self, caller: EmployeeCall) -> EvidenceReply:
        request_id = uuid4()
        if rule_rollback.READ_IMPACT not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    rule_rollback.READ_IMPACT, rule_rollback.DESTINATION,
                    now.astimezone(caller.business_timezone).date(), caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                with connection.transaction():
                    connection.execute("SET LOCAL synchronous_commit = on")
                    try:
                        payload = rule_rollback.list_rule_revisions(
                            connection, caller.org_id, caller.space_id, caller.principal_id,
                        )
                    except rule_rollback.RuleRollbackNotAdmitted:
                        reply, outcome = error_reply("forbidden", request_id), "rejected"
                    else:
                        if self.verify_token(caller.token) != caller.credential:
                            reply, outcome = error_reply("unauthenticated", request_id), "rejected"
                        elif datetime.now(UTC) >= deadline:
                            reply, outcome = error_reply("dependency_unavailable", request_id), "dependency_unavailable"
                        else:
                            reply = EvidenceReply(request_id, 200, encode({
                                "request_id": str(request_id), **payload,
                            }), deadline)
                            outcome = "succeeded"
                    if not finish_open_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                        return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_rule_impact(
        self, caller: EmployeeCall, configuration_revision: int, source_ref: UUID | None = None,
    ) -> EvidenceReply:
        request_id = uuid4()
        if rule_rollback.READ_IMPACT not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        if type(configuration_revision) is not int or configuration_revision < 1:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    rule_rollback.READ_IMPACT, rule_rollback.DESTINATION,
                    now.astimezone(caller.business_timezone).date(), caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                with connection.transaction():
                    connection.execute("SET LOCAL synchronous_commit = on")
                    try:
                        payload = rule_rollback.read_rule_impact(
                            connection, caller.org_id, caller.space_id, caller.principal_id,
                            configuration_revision, source_ref=source_ref,
                        )
                    except rule_rollback.RuleRollbackNotAdmitted:
                        reply, outcome = error_reply("forbidden", request_id), "rejected"
                    except rule_rollback.RuleRollbackConflict:
                        reply, outcome = error_reply("rule_rollback_conflict", request_id), "rejected"
                    else:
                        if self.verify_token(caller.token) != caller.credential:
                            reply, outcome = error_reply("unauthenticated", request_id), "rejected"
                        elif datetime.now(UTC) >= deadline:
                            reply, outcome = error_reply("dependency_unavailable", request_id), "dependency_unavailable"
                        else:
                            reply = EvidenceReply(request_id, 200, encode({
                                "request_id": str(request_id), **payload,
                            }), deadline)
                            outcome = "succeeded"
                    if not finish_open_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                        return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_rule_rollback(
        self, caller: EmployeeCall, configuration_revision: int, arguments, key: str,
    ) -> EvidenceReply:
        request_id = uuid4()
        if rule_rollback.PLAN_ROLLBACK not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            if (type(configuration_revision) is not int or configuration_revision < 1
                    or IDEMPOTENCY_PATTERN.fullmatch(key) is None):
                raise ValueError("Invalid configuration revision or idempotency key.")
            allowed = {"reason_code", "basis_id", "source_id", "target_configuration_revision", "quarantine_ineligible"}
            if not isinstance(arguments, dict) or not set(arguments) <= allowed:
                raise ValueError("Unexpected rule rollback arguments.")
            reason_code = arguments.get("reason_code")
            if not isinstance(reason_code, str) or rule_rollback.REASON_PATTERN.fullmatch(reason_code) is None:
                raise ValueError("Invalid reason_code.")
            basis_ref = parse_ref(arguments["basis_id"]) if isinstance(arguments.get("basis_id"), str) else None
            if basis_ref is None:
                raise ValueError("Missing basis_id.")
            source_ref = _optional_ref(arguments, "source_id")
            target_cfg = arguments.get("target_configuration_revision")
            if target_cfg is not None and (type(target_cfg) is not int or target_cfg <= configuration_revision):
                raise ValueError("Invalid target_configuration_revision.")
            quarantine_ineligible = arguments.get("quarantine_ineligible", True)
            if type(quarantine_ineligible) is not bool:
                raise ValueError("quarantine_ineligible must be boolean.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    rule_rollback.PLAN_ROLLBACK, rule_rollback.DESTINATION,
                    now.astimezone(caller.business_timezone).date(), caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                context = SourceWrite(caller.org_id, caller.principal_id, request_id, key)
                try:
                    receipt = rule_rollback.plan_rule_rollback(
                        connection, context, caller.space_id, configuration_revision, reason_code, basis_ref,
                        source_ref=source_ref, target_configuration_revision=target_cfg,
                        quarantine_ineligible=quarantine_ineligible,
                    )
                except rule_rollback.RuleRollbackNotAdmitted:
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("forbidden", request_id)
                except (rule_rollback.RuleRollbackConflict, IdempotencyConflict):
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("rule_rollback_conflict", request_id)
                if not finish_request(connection, caller.org_id, request_id, "succeeded", int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if self.verify_token(caller.token) != caller.credential:
                    return error_reply("unauthenticated", request_id)
                if datetime.now(UTC) >= deadline:
                    return error_reply("dependency_unavailable", request_id)
                return EvidenceReply(request_id, 200, encode({"request_id": str(request_id), **receipt}), deadline)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_governance(
        self, caller: EmployeeCall, action: str, *,
        ref: UUID | None = None, sub_ref: UUID | None = None,
        arguments: dict | None = None, key: str | None = None,
    ) -> EvidenceReply:
        request_id = uuid4()
        action_ops = {
            "overview": (governance.READ_GOVERNANCE, False),
            "inspect_transition": (governance.READ_GOVERNANCE, False),
            "create_shared_group": (governance.MANAGE_SHARED_GROUP, True),
            "add_shared_group_member": (governance.MANAGE_SHARED_GROUP, True),
            "revoke_shared_group_member": (governance.MANAGE_SHARED_GROUP, True),
            "revoke_shared_group": (governance.MANAGE_SHARED_GROUP, True),
            "create_delegation": (governance.MANAGE_DELEGATION, True),
            "revoke_delegation": (governance.MANAGE_DELEGATION, True),
            "archive_space": (governance.ARCHIVE_SPACE, True),
            "record_transition_handoff": (governance.HANDOFF_TRANSITION, True),
        }
        if action not in action_ops:
            return error_reply("invalid_arguments", request_id)
        operation, is_write = action_ops[action]
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        args = {} if arguments is None else arguments
        try:
            if not isinstance(args, dict):
                raise ValueError("Invalid governance arguments.")
            if is_write and (key is None or IDEMPOTENCY_PATTERN.fullmatch(key) is None):
                raise ValueError("Missing or invalid idempotency key.")
            parsed_args = self._parse_governance_args(action, ref, sub_ref, args)
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    operation, governance.DESTINATION,
                    now.astimezone(caller.business_timezone).date(), caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                context = SourceWrite(caller.org_id, caller.principal_id, request_id, key or "")
                try:
                    if action == "overview":
                        payload = governance.read_governance_overview(connection, context, caller.space_id)
                    elif action == "inspect_transition":
                        payload = governance.inspect_transition(connection, context, caller.space_id, parsed_args["principal_ref"])
                    elif action == "create_shared_group":
                        payload = governance.create_shared_group(connection, context, caller.space_id, **parsed_args)
                    elif action == "add_shared_group_member":
                        payload = governance.add_shared_group_member(connection, context, caller.space_id, **parsed_args)
                    elif action == "revoke_shared_group_member":
                        payload = governance.revoke_shared_group_member(connection, context, caller.space_id, **parsed_args)
                    elif action == "revoke_shared_group":
                        payload = governance.revoke_shared_group(connection, context, caller.space_id, **parsed_args)
                    elif action == "create_delegation":
                        payload = governance.create_delegation(connection, context, caller.space_id, **parsed_args)
                    elif action == "revoke_delegation":
                        payload = governance.revoke_delegation(connection, context, caller.space_id, **parsed_args)
                    elif action == "archive_space":
                        payload = governance.archive_space(connection, context, caller.space_id, **parsed_args)
                    else:
                        payload = governance.record_transition_handoff(connection, context, caller.space_id, **parsed_args)
                except ValueError:
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("invalid_arguments", request_id)
                except governance.GovernanceNotAdmitted:
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("forbidden", request_id)
                except (governance.GovernanceConflict, IdempotencyConflict):
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("governance_conflict", request_id)
                if not finish_request(connection, caller.org_id, request_id, "succeeded", int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if self.verify_token(caller.token) != caller.credential:
                    return error_reply("unauthenticated", request_id)
                if datetime.now(UTC) >= deadline:
                    return error_reply("dependency_unavailable", request_id)
                return EvidenceReply(request_id, 200, encode({"request_id": str(request_id), **payload}), deadline)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    @staticmethod
    def _parse_governance_args(action: str, ref: UUID | None, sub_ref: UUID | None, args: dict) -> dict:
        def req_ref(field_name: str) -> UUID:
            val = args.get(field_name)
            if not isinstance(val, str):
                raise ValueError(f"Missing {field_name}.")
            return parse_ref(val)

        def req_ts(field_name: str) -> datetime:
            val = args.get(field_name)
            if not isinstance(val, str):
                raise ValueError(f"Missing {field_name}.")
            parsed = datetime.fromisoformat(val)
            require_aware(parsed)
            return parsed

        if action == "overview":
            if args:
                raise ValueError("Unexpected arguments.")
            return {}
        if action == "inspect_transition":
            if ref is None or args:
                raise ValueError("Invalid transition inspect parameters.")
            return {"principal_ref": ref}
        if action == "create_shared_group":
            allowed = {"target_source_id", "name", "purpose", "scope_summary", "starts_at", "review_at", "expires_at", "basis_id"}
            if set(args) != allowed:
                raise ValueError("Invalid create_shared_group arguments.")
            return {
                "target_source_ref": req_ref("target_source_id"),
                "name": args["name"],
                "purpose": args["purpose"],
                "scope_summary": args["scope_summary"],
                "starts_at": req_ts("starts_at"),
                "review_at": req_ts("review_at"),
                "expires_at": req_ts("expires_at"),
                "basis_ref": req_ref("basis_id"),
            }
        if action == "add_shared_group_member":
            allowed = {"member_id", "starts_at", "expires_at", "basis_id"}
            if ref is None or set(args) != allowed:
                raise ValueError("Invalid add_shared_group_member arguments.")
            return {
                "group_ref": ref,
                "member_ref": req_ref("member_id"),
                "starts_at": req_ts("starts_at"),
                "expires_at": req_ts("expires_at"),
                "basis_ref": req_ref("basis_id"),
            }
        if action == "revoke_shared_group_member":
            allowed = {"reason_code", "basis_id"}
            if ref is None or sub_ref is None or set(args) != allowed:
                raise ValueError("Invalid revoke_shared_group_member arguments.")
            return {
                "group_ref": ref,
                "membership_ref": sub_ref,
                "reason_code": args["reason_code"],
                "basis_ref": req_ref("basis_id"),
            }
        if action == "revoke_shared_group":
            allowed = {"reason_code", "basis_id"}
            if ref is None or set(args) != allowed:
                raise ValueError("Invalid revoke_shared_group arguments.")
            return {
                "group_ref": ref,
                "reason_code": args["reason_code"],
                "basis_ref": req_ref("basis_id"),
            }
        if action == "create_delegation":
            allowed = {"delegate_id", "scopes", "purpose", "starts_at", "review_at", "expires_at", "basis_id"}
            if set(args) != allowed or not isinstance(args["scopes"], list) or not all(isinstance(s, str) for s in args["scopes"]):
                raise ValueError("Invalid create_delegation arguments.")
            return {
                "delegate_ref": req_ref("delegate_id"),
                "scopes": tuple(args["scopes"]),
                "purpose": args["purpose"],
                "starts_at": req_ts("starts_at"),
                "review_at": req_ts("review_at"),
                "expires_at": req_ts("expires_at"),
                "basis_ref": req_ref("basis_id"),
            }
        if action == "revoke_delegation":
            allowed = {"reason_code", "basis_id"}
            if ref is None or set(args) != allowed:
                raise ValueError("Invalid revoke_delegation arguments.")
            return {
                "delegation_ref": ref,
                "reason_code": args["reason_code"],
                "basis_ref": req_ref("basis_id"),
            }
        if action == "archive_space":
            allowed = {"reason_code", "basis_id"}
            if set(args) != allowed:
                raise ValueError("Invalid archive_space arguments.")
            return {
                "reason_code": args["reason_code"],
                "basis_ref": req_ref("basis_id"),
            }
        if action == "record_transition_handoff":
            allowed = {
                "transition_kind", "successor_id", "delegation_id", "review_at", "basis_id",
                "reassign_documents", "revoke_outgoing_delegations", "accepted_feedback_handoff_ids",
            }
            if ref is None or not set(args) <= allowed:
                raise ValueError("Invalid transition handoff arguments.")
            if "transition_kind" not in args or "review_at" not in args or "basis_id" not in args:
                raise ValueError("Missing required transition handoff arguments.")
            reassign_docs = args.get("reassign_documents", True)
            revoke_out = args.get("revoke_outgoing_delegations", False)
            if type(reassign_docs) is not bool or type(revoke_out) is not bool:
                raise ValueError("Boolean flags required.")
            fb_ids = args.get("accepted_feedback_handoff_ids", [])
            if not isinstance(fb_ids, list) or not all(isinstance(item, str) for item in fb_ids):
                raise ValueError("accepted_feedback_handoff_ids must be list of UUID strings.")
            return {
                "incumbent_ref": ref,
                "transition_kind": args["transition_kind"],
                "successor_ref": _optional_ref(args, "successor_id"),
                "delegation_ref": _optional_ref(args, "delegation_id"),
                "review_at": req_ts("review_at"),
                "basis_ref": req_ref("basis_id"),
                "reassign_documents": reassign_docs,
                "revoke_outgoing_delegations": revoke_out,
                "accepted_feedback_handoff_refs": tuple(parse_ref(item) for item in fb_ids),
            }
        raise ValueError("Unknown governance action.")

    def execute_original_download(self, caller: EmployeeCall, version: str, release_stack: ExitStack) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.ORIGINAL_DOWNLOAD_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            version_ref = parse_ref(version)
        except ValueError:
            return error_reply("original_unavailable", request_id)
        now = datetime.now(UTC)
        started = monotonic()
        context = self._delivery_context(
            request_id, caller, operation, purpose,
            destination, min(caller.credential.expires_at, now + MAX_REQUEST_TIME),
        )

        def check_final_authority(probe):
            if self.pin_original_source is None:
                return self.authority_for(caller, probe)
            if self.verify_token(caller.token) != caller.credential:
                raise AuthorizationUnavailable("The synthetic credential changed during original download.")
            return release_stack.enter_context(self.pin_original_source(caller.credential, probe))

        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id, operation, destination,
                    now.astimezone(caller.business_timezone).date(), caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                decision, name = original_download.download_original(
                    connection, context, caller.space_id, version_ref, self.store, region=caller.credential.region,
                    traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                    check_final_authority=check_final_authority,
                )
                if decision.status == "succeeded":
                    self._emit_security_audit(
                        caller,
                        request_id,
                        "security.original_downloaded",
                        operation,
                        "succeeded",
                        resource_ref=str(version_ref),
                        detail_digest=decision.payload_sha256,
                    )
                    return EvidenceReply(request_id, 200, decision.payload, decision.valid_until, name)
                if not finish_request(connection, caller.org_id, request_id, decision.status, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return error_reply(
                    "original_unavailable" if decision.status == "rejected" else "dependency_unavailable", request_id,
                )
        except (Error, RequestAuditConflict, AuthorizationUnavailable, SecurityLogUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_source_options(self, caller: EmployeeCall, day: str | None) -> EvidenceReply:
        return self._execute_discovery(caller, day)

    def execute_department_options(self, caller: EmployeeCall, day: str | None) -> EvidenceReply:
        return self._execute_discovery(caller, day, departments_only=True)

    def execute_search_suggestions(self, caller: EmployeeCall, arguments) -> EvidenceReply:
        try:
            if not isinstance(arguments, dict) or set(arguments) - {"prefix", "business_date", "source_id"}:
                raise ValueError("Unexpected suggestion arguments.")
            prefix = arguments.get("prefix")
            if not isinstance(prefix, str) or not 1 <= len(prefix) <= 64:
                raise ValueError("Invalid suggestion prefix length.")
            prefix = prefix.strip()
            if not prefix.isprintable() or not any(character.isalnum() for character in prefix):
                raise ValueError("Invalid suggestion prefix.")
            day = arguments.get("business_date")
            if "business_date" in arguments and not isinstance(day, str):
                raise ValueError("Expected a business date.")
            source_ref = _optional_ref(arguments, "source_id")
        except ValueError:
            return error_reply("invalid_arguments")
        return self._execute_discovery(caller, day, prefix=prefix, source_ref=source_ref)

    def _execute_discovery(
        self, caller: EmployeeCall, day: str | None, *, prefix: str | None = None, source_ref: UUID | None = None,
        departments_only: bool = False,
    ) -> EvidenceReply:
        request_id = uuid4()
        if "search" not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        try:
            business_day = _parse_business_date(day) if day is not None else now.astimezone(caller.business_timezone).date()
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        if departments_only:
            operation, purpose, destination = policy.EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS
            key = "departments"
        else:
            operation, purpose, destination = (
                policy.EMPLOYEE_SOURCE_OPTIONS_ACCESS if prefix is None else policy.EMPLOYEE_TITLE_SUGGESTIONS_ACCESS
            )
            key = "options" if prefix is None else "suggestions"
        context = self._delivery_context(
            request_id, caller, operation,
            purpose, destination, min(caller.credential.expires_at, now + MAX_REQUEST_TIME),
        )
        started = monotonic()
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_day, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                result = list_employee_discovery(
                    connection, context, caller.space_id, region=caller.credential.region,
                    traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                    prefix=prefix, source_ref=source_ref, departments_only=departments_only,
                )
                outcome = result.status
                if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                if outcome == "succeeded" and result.payload is not None and result.valid_until is not None:
                    return EvidenceReply(request_id, 200, result.payload, result.valid_until)
                if outcome == "no_evidence":
                    return EvidenceReply(request_id, 200, encode({
                        "request_id": str(request_id), "business_date": business_day.isoformat(), key: [],
                    }), context.deadline)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)
        return error_reply("dependency_unavailable" if outcome != "rejected" else "forbidden", request_id)

    def execute(self, caller: EmployeeCall, operation: str, arguments, *, feedback_ref: UUID | None = None) -> EvidenceReply:
        request_id = uuid4()
        if operation not in OPERATIONS or operation not in caller.credential.operations or (
            feedback_ref is not None and (operation != "read_passage" or feedback.EVIDENCE not in caller.credential.operations)
        ):
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        if now >= caller.credential.expires_at:
            return error_reply("unauthenticated", request_id)
        business_date = now.astimezone(caller.business_timezone).date()
        parsed = None
        fingerprint = None
        passage_ref = None
        try:
            if not isinstance(arguments, dict):
                raise ValueError("Tool arguments must be an object.")
            if operation == "search":
                parsed = _search_input(arguments, business_date)
                business_date = parsed.business_date
                if self.retest_key is not None and parsed.within(caller):
                    fingerprint = parsed.feedback_fingerprint(caller, self.retest_key)
            elif feedback_ref is not None:
                if arguments:
                    raise ValueError("Feedback evidence must use the recorded reference.")
            else:
                if set(arguments) != {"id"} or not isinstance(arguments["id"], str):
                    raise ValueError("Invalid citation parameters.")
                try:
                    passage_ref = parse_ref(arguments["id"])
                except ValueError:
                    pass
        except ValueError:
            return error_reply("invalid_arguments", request_id)

        start = monotonic()
        context = self._delivery_context(
            request_id, caller, operation,
            "employee_evidence", "employee", min(caller.credential.expires_at, now + MAX_REQUEST_TIME),
        )

        def check_authority(probe):
            return self.authority_for(caller, probe)

        def seal_search(transaction, decision):
            feedback.seal_search_match(
                transaction, caller.org_id, caller.space_id, request_id, decision.check.check_id, fingerprint,
            )

        def seal_scope(transaction, visibility_limited, empty):
            gaps.note_search_scope(
                transaction, caller.org_id, caller.space_id, request_id, visibility_limited,
                empty_fingerprint=fingerprint if empty and not visibility_limited else None,
            )

        decision = None
        outcome = "rejected"
        reply = error_reply("citation_unavailable" if operation == "read_passage" else "forbidden", request_id)
        in_scope = parsed is not None and parsed.within(caller)
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, context.destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id if in_scope or passage_ref is not None or feedback_ref is not None else None,
                    ingress=caller.ingress,
                ))
                try:
                    if in_scope:
                        decision = search_travel(
                            connection, context, caller.space_id, parsed.query, self.store,
                            region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                            check_authority=check_authority, top_k=parsed.top_k, include_wiki=parsed.include_wiki,
                            source_refs=parsed.source_ids, include_source_facets=parsed.include_source_facets,
                            departments=parsed.departments, include_department_facets=parsed.include_department_facets,
                            seal=seal_search if fingerprint is not None else None,
                            seal_scope=seal_scope,
                            embedding_provider=self.embedding_provider,
                        )
                    elif feedback_ref is not None:
                        decision = self._read_feedback_evidence(connection, caller, context, feedback_ref, check_authority)
                    elif passage_ref is not None:
                        decision = open_travel_reference(
                            connection, context, caller.space_id, passage_ref, self.store,
                            region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                            check_authority=check_authority,
                        )
                except ValueError:
                    reply = error_reply("invalid_arguments", request_id)
                if decision is not None:
                    outcome = decision.status
                    if decision.status == "succeeded":
                        if decision.payload is None or decision.valid_until is None:
                            raise RuntimeError("Successful evidence has no payload or release deadline.")
                        reply = EvidenceReply(request_id, 200, decision.payload, decision.valid_until)
                    elif decision.status in {"dependency_unavailable", "input_changed"}:
                        reply = error_reply("dependency_unavailable", request_id)
                elif parsed is not None and reply.status_code != 400:
                    outcome = "no_evidence"
                if outcome == "no_evidence":
                    empty_view = {
                        "request_id": str(request_id), "business_date": business_date.isoformat(),
                        "status": "no_evidence", "passages": [], "wiki": [],
                    }
                    if parsed is not None and parsed.include_source_facets:
                        empty_view["source_facets"] = []
                    if parsed is not None and parsed.include_department_facets:
                        empty_view["department_facets"] = []
                    reply = EvidenceReply(request_id, 200, encode(empty_view))
                if decision is None or decision.status != "no_evidence":
                    if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - start) * 1000)):
                        return error_reply("dependency_unavailable", request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)
        return reply

    def _read_feedback_evidence(self, connection, caller, context, ref, check_authority):
        call = feedback.FeedbackCall(caller.org_id, caller.space_id, caller.principal_id, context.request_id, "",
                                     caller.configuration_revision)
        try:
            with connection.transaction():
                target = feedback.get_feedback_evidence(connection, call, ref)
        except feedback.FeedbackNotAdmitted:
            return None
        if target is None:
            return None

        def recheck(transaction):
            try:
                return feedback.get_feedback_evidence(transaction, call, ref) == target
            except feedback.FeedbackNotAdmitted:
                return False

        def seal(transaction, decision):
            feedback.seal_feedback_evidence(transaction, call, target, decision.check.check_id)

        return open_travel_reference(
            connection, context, caller.space_id, target.passage_ref, self.store,
            region=caller.credential.region, traveler_class=caller.credential.traveler_class, check_authority=check_authority,
            binding=ReferenceBinding(target.excerpt_revision, recheck, seal),
        )

    def execute_space_release(
        self, caller: EmployeeCall, action: str, *, arguments: dict | None = None, key: str | None = None,
    ) -> EvidenceReply:
        request_id = uuid4()
        if action == "overview":
            operation, is_write = release.READ_SPACE_RELEASE, False
        elif action == "switch":
            operation, is_write = release.SWITCH_SPACE_RELEASE, True
        else:
            return error_reply("invalid_arguments", request_id)
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        args = {} if arguments is None else arguments
        try:
            if not isinstance(args, dict):
                raise ValueError("Invalid release arguments.")
            if is_write:
                if key is None or IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                    raise ValueError("Invalid idempotency key.")
                allowed_keys = {
                    "action", "wiki_delivery_enabled", "lexical_index_mode", "vector_model_id", "target_release_id",
                    "template_key", "template_revision_id", "observation_window_minutes",
                    "min_sample_requests", "rollback_trigger_summary", "reason_code", "basis_ref",
                }
                if not set(args) <= allowed_keys:
                    raise ValueError("Unexpected release switch fields.")
                switch_action = args.get("action")
                if switch_action not in release.RELEASE_ACTIONS:
                    raise ValueError("Invalid release action.")
                wiki_enabled = args.get("wiki_delivery_enabled")
                if wiki_enabled is not None and type(wiki_enabled) is not bool:
                    raise ValueError("Invalid wiki_delivery_enabled.")
                lexical_mode = args.get("lexical_index_mode")
                if lexical_mode is not None and lexical_mode not in release.LEXICAL_MODES:
                    raise ValueError("Invalid lexical_index_mode.")
                vector_model_id = args.get("vector_model_id")
                if vector_model_id is not None and not isinstance(vector_model_id, str):
                    raise ValueError("Invalid vector_model_id.")
                target_release = parse_ref(args["target_release_id"]) if args.get("target_release_id") is not None else None
                template_key = args.get("template_key")
                template_rev = parse_ref(args["template_revision_id"]) if args.get("template_revision_id") is not None else None
                obs_minutes = args.get("observation_window_minutes")
                min_samples = args.get("min_sample_requests")
                trigger = args.get("rollback_trigger_summary")
                reason = args.get("reason_code")
                basis_raw = args.get("basis_ref")
                if not isinstance(basis_raw, str):
                    raise ValueError("Missing basis_ref.")
                basis_ref = parse_ref(basis_raw)
                parsed_switch = {
                    "action": switch_action,
                    "wiki_delivery_enabled": wiki_enabled,
                    "lexical_index_mode": lexical_mode,
                    "vector_model_id": vector_model_id,
                    "target_release_ref": target_release,
                    "template_key": template_key,
                    "template_revision_ref": template_rev,
                    "observation_window_minutes": obs_minutes,
                    "min_sample_requests": min_samples,
                    "rollback_trigger_summary": trigger,
                    "reason_code": reason,
                    "basis_ref": basis_ref,
                }
            elif args:
                raise ValueError("Overview does not accept body arguments.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    operation, release.DESTINATION,
                    now.astimezone(caller.business_timezone).date(), caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                context = SourceWrite(caller.org_id, caller.principal_id, request_id, key or "")
                try:
                    if action == "overview":
                        payload = release.read_space_release_overview(connection, context, caller.space_id)
                    else:
                        payload = release.switch_space_release(connection, context, caller.space_id, **parsed_switch)
                except ValueError:
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("invalid_arguments", request_id)
                except release.ReleaseNotAdmitted:
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("forbidden", request_id)
                except (release.ReleaseConflict, IdempotencyConflict):
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("release_conflict", request_id)
                if self.verify_token(caller.token) != caller.credential:
                    finish_request(connection, caller.org_id, request_id, "rejected", int((monotonic() - started) * 1000))
                    return error_reply("unauthenticated", request_id)
                if datetime.now(UTC) >= deadline:
                    finish_request(
                        connection, caller.org_id, request_id, "dependency_unavailable", int((monotonic() - started) * 1000),
                    )
                    return error_reply("dependency_unavailable", request_id)
                if not finish_request(connection, caller.org_id, request_id, "succeeded", int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return EvidenceReply(request_id, 200, encode({"request_id": str(request_id), **payload}), deadline)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)

    def execute_wiki_topic_rollback(self, caller: EmployeeCall, wiki_id: str, arguments, key: str) -> EvidenceReply:
        request_id = uuid4()
        operation, purpose, destination = policy.WIKI_ROLLBACK_ACCESS
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        try:
            if IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                raise ValueError("Invalid idempotency key.")
            wiki_ref = parse_ref(wiki_id)
            if not isinstance(arguments, dict) or set(arguments) != {
                "target_revision_id", "business_date", "reason_code", "basis_ref",
            }:
                raise ValueError("Unexpected rollback arguments.")
            if not all(isinstance(arguments[name], str) for name in arguments):
                raise ValueError("Expected string rollback parameters.")
            target_revision_ref = parse_ref(arguments["target_revision_id"])
            business_date = _parse_business_date(arguments["business_date"])
            basis_ref = parse_ref(arguments["basis_ref"])
            reason_code = arguments["reason_code"]
            if release.CODE_PATTERN.fullmatch(reason_code) is None:
                raise ValueError("Invalid reason_code.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        now = datetime.now(UTC)
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        started = monotonic()
        context = self._delivery_context(
            request_id, caller,
            operation, purpose, destination, deadline,
        )
        try:
            if now >= deadline or self.verify_token(caller.token) != caller.credential:
                return error_reply("unauthenticated", request_id)
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, context.client_id,
                    operation, destination, business_date, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                result = release.rollback_wiki_topic(
                    connection, context, caller.space_id, wiki_ref, target_revision_ref,
                    basis_ref=basis_ref, reason_code=reason_code, key=key,
                    region=caller.credential.region, traveler_class=caller.credential.traveler_class,
                    check_authority=lambda probe: self.authority_for(caller, probe),
                )
                audit_outcome = "rejected" if result.status == "conflict" else result.status
                if not finish_request(
                    connection, caller.org_id, request_id, audit_outcome, int((monotonic() - started) * 1000),
                ):
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "succeeded" and result.rollback_ref is not None:
                    return EvidenceReply(request_id, 200, encode({
                        "request_id": str(request_id),
                        "rollback_id": str(result.rollback_ref),
                        "target_publication_id": str(result.target_publication_ref),
                        "target_revision_id": str(result.target_revision_ref),
                    }), deadline)
                if result.status == "dependency_unavailable":
                    return error_reply("dependency_unavailable", request_id)
                if result.status == "conflict":
                    return error_reply("release_conflict", request_id)
                if result.status == "input_changed":
                    status_code, message = ERRORS["wiki_input_changed"]
                    return EvidenceReply(request_id, status_code, encode({
                        "request_id": str(request_id),
                        "error": {"code": "wiki_input_changed", "message": message},
                        "stop_reasons": list(result.stop_reasons),
                        "disable_wiki_fallback_recommended": True,
                    }), deadline)
                return error_reply("forbidden", request_id)
        except (Error, RequestAuditConflict, AuthorizationUnavailable):
            return error_reply("dependency_unavailable", request_id)


    def execute_glossary(
        self,
        caller: EmployeeCall,
        action: str,
        *,
        entry_id: str | None = None,
        arguments: dict | None = None,
        key: str | None = None,
        include_inactive: bool = True,
        query: str | None = None,
    ) -> EvidenceReply:
        request_id = uuid4()
        if action == "list":
            operation, is_write = glossary.LIST, False
        elif action in {"create", "update"}:
            operation, is_write = glossary.UPSERT, True
        elif action == "status":
            operation, is_write = glossary.SET_STATUS, True
        else:
            return error_reply("invalid_arguments", request_id)
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        if now >= caller.credential.expires_at:
            return error_reply("unauthenticated", request_id)
        args = {} if arguments is None else arguments
        try:
            if not isinstance(args, dict):
                raise ValueError("Invalid glossary payload.")
            entry_ref = parse_ref(entry_id) if entry_id is not None else None
            if is_write and (key is None or IDEMPOTENCY_PATTERN.fullmatch(key) is None):
                raise ValueError("Invalid idempotency key.")
            if action in {"create", "update"}:
                if not set(args) <= {"term", "synonyms", "definition"}:
                    raise ValueError("Unexpected glossary fields.")
                term = args.get("term")
                synonyms = args.get("synonyms", [])
                definition = args.get("definition")
                if not isinstance(term, str) or not isinstance(definition, str) or not isinstance(synonyms, list):
                    raise ValueError("Invalid glossary fields.")
                if action == "update" and entry_ref is None:
                    raise ValueError("Missing entry_id.")
            elif action == "status":
                if entry_ref is None or set(args) != {"status"} or args["status"] not in {"active", "inactive"}:
                    raise ValueError("Invalid status payload.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)

        business_day = now.astimezone(caller.business_timezone).date()
        started = monotonic()
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    operation, glossary.DESTINATION, business_day, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                try:
                    if action == "list":
                        entries = glossary.list_entries(
                            connection, caller.org_id, caller.space_id,
                            include_inactive=include_inactive, query=query,
                        )
                        body = {"request_id": str(request_id), "entries": [e.to_dict() for e in entries]}
                    else:
                        ctx = glossary.GlossaryWrite(caller.org_id, request_id, caller.principal_id, key or "")
                        if action == "create":
                            entry = glossary.create_entry(
                                connection, ctx, caller.space_id,
                                term=args["term"], synonyms=args.get("synonyms", []), definition=args["definition"],
                            )
                        elif action == "update":
                            entry = glossary.update_entry(
                                connection, ctx, caller.space_id, entry_ref,
                                term=args["term"], synonyms=args.get("synonyms", []), definition=args["definition"],
                            )
                        else:
                            entry = glossary.set_entry_status(connection, ctx, caller.space_id, entry_ref, args["status"])
                        body = {"request_id": str(request_id), "entry": entry.to_dict()}
                    outcome = "succeeded"
                    reply = EvidenceReply(request_id, 200, encode(body), deadline)
                except ValueError:
                    outcome = "rejected"
                    reply = error_reply("invalid_arguments", request_id)
                except glossary.GlossaryNotAdmitted:
                    outcome = "rejected"
                    reply = error_reply("forbidden", request_id)
                except glossary.GlossaryNotFound:
                    outcome = "rejected"
                    reply = error_reply("glossary_not_found", request_id)
                except (glossary.GlossaryConflict, IdempotencyConflict):
                    outcome = "rejected"
                    reply = error_reply("glossary_conflict", request_id)
                if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict):
            return error_reply("dependency_unavailable", request_id)

    def execute_document_department(
        self,
        caller: EmployeeCall,
        action: str,
        document_id: str,
        *,
        arguments: dict | None = None,
        key: str | None = None,
    ) -> EvidenceReply:
        request_id = uuid4()
        if action == "read":
            operation, is_write = departments.READ, False
        elif action == "set":
            operation, is_write = departments.SET, True
        else:
            return error_reply("invalid_arguments", request_id)
        if operation not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        if now >= caller.credential.expires_at:
            return error_reply("unauthenticated", request_id)
        args = {} if arguments is None else arguments
        try:
            document_ref = parse_ref(document_id)
            if not isinstance(args, dict):
                raise ValueError("Invalid department arguments.")
            if is_write:
                if key is None or IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                    raise ValueError("Invalid idempotency key.")
                if not set(args) <= {"department_code", "department_name"}:
                    raise ValueError("Unexpected department fields.")
                dept_code = args.get("department_code")
                dept_name = args.get("department_name")
                if dept_code is not None:
                    departments.validate_department_code(dept_code)
                if dept_name is not None:
                    departments.validate_department_name(dept_name)
                if (dept_code is None) != (dept_name is None):
                    raise ValueError("department_code and department_name must both be set or both null.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)

        business_day = now.astimezone(caller.business_timezone).date()
        started = monotonic()
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    operation, departments.DESTINATION, business_day, caller.configuration_revision,
                    space_id=caller.space_id, ingress=caller.ingress,
                ))
                try:
                    ctx = SourceWrite(caller.org_id, caller.principal_id, request_id, key or "")
                    if action == "read":
                        dept = departments.read_document_department(connection, ctx, caller.space_id, document_ref)
                    else:
                        dept = departments.set_document_department(
                            connection, ctx, caller.space_id, document_ref,
                            args.get("department_code"), args.get("department_name"),
                        )
                    outcome = "succeeded"
                    reply = EvidenceReply(request_id, 200, encode({"request_id": str(request_id), **dept.to_dict()}), deadline)
                except ValueError:
                    outcome = "rejected"
                    reply = error_reply("invalid_arguments", request_id)
                except SourceNotAdmitted:
                    outcome = "rejected"
                    reply = error_reply("forbidden", request_id)
                except IdempotencyConflict:
                    outcome = "rejected"
                    reply = error_reply("responsibility_conflict", request_id)
                if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict):
            return error_reply("dependency_unavailable", request_id)


    def execute_source_catalog(self, caller: EmployeeCall) -> EvidenceReply:
        request_id = uuid4()
        if source_catalog.READ_CATALOG not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        if now >= caller.credential.expires_at:
            return error_reply("unauthenticated", request_id)
        business_day = now.astimezone(caller.business_timezone).date()
        started = monotonic()
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    source_catalog.READ_CATALOG, source_catalog.DESTINATION, business_day,
                    caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
                ))
                try:
                    call = OperationsCall(
                        caller.org_id, caller.space_id, caller.principal_id, request_id, "",
                        caller.configuration_revision,
                    )
                    with connection.transaction():
                        payload = source_catalog.read_catalog(
                            connection, call, connector_configured=(self.source_connector is not None),
                        )
                    outcome = "succeeded"
                    reply = EvidenceReply(request_id, 200, encode({"request_id": str(request_id), **payload}), deadline)
                except OperationsNotAdmitted:
                    outcome = "rejected"
                    reply = error_reply("forbidden", request_id)
                if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict):
            return error_reply("dependency_unavailable", request_id)

    def execute_connector_sync(
        self,
        caller: EmployeeCall,
        source_id: str,
        *,
        arguments: dict | None = None,
        key: str | None = None,
    ) -> EvidenceReply:
        request_id = uuid4()
        if source_catalog.SYNC_CONNECTOR not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        if now >= caller.credential.expires_at:
            return error_reply("unauthenticated", request_id)
        args = {} if arguments is None else arguments
        try:
            source_ref = parse_ref(source_id)
            if key is None or IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                raise ValueError("Invalid idempotency key.")
            if not isinstance(args, dict) or not set(args) <= {"reconcile", "max_pages"}:
                raise ValueError("Unexpected connector sync arguments.")
            reconcile = args.get("reconcile", False)
            max_pages = args.get("max_pages", connector_sync.DEFAULT_MAX_PAGES)
            if type(reconcile) is not bool or type(max_pages) is not int or not 1 <= max_pages <= 500:
                raise ValueError("Invalid connector sync parameters.")
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        if self.source_connector is None:
            return error_reply("connector_not_configured", request_id)

        business_day = now.astimezone(caller.business_timezone).date()
        started = monotonic()
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    source_catalog.SYNC_CONNECTOR, source_catalog.DESTINATION, business_day,
                    caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
                ))
                try:
                    call = OperationsCall(
                        caller.org_id, caller.space_id, caller.principal_id, request_id, key,
                        caller.configuration_revision,
                    )
                    source_catalog.authorize_connector_sync(
                        connection, call, source_ref, reconcile=reconcile, max_pages=max_pages,
                    )
                    report = connector_sync.sync_source_from_connector(
                        connection,
                        source_ref,
                        self.source_connector,
                        self.store,
                        reconcile=reconcile,
                        max_pages=max_pages,
                        business_day=business_day,
                        audit_dispatcher=self.audit_dispatcher,
                    )
                    if report.status == "dependency_unavailable":
                        outcome = "rejected"
                        reply = error_reply("dependency_unavailable", request_id)
                    elif report.status == "source_not_admitted":
                        outcome = "rejected"
                        reply = error_reply("forbidden", request_id)
                    elif report.status == "rejected":
                        outcome = "rejected"
                        reply = error_reply("ingest_conflict", request_id)
                    else:
                        outcome = "succeeded"
                        reply = EvidenceReply(
                            request_id, 200,
                            encode({"request_id": str(request_id), **report.to_dict()}),
                            deadline,
                        )
                        self._emit_security_audit(
                            event_type="security.connector_sync_triggered",
                            request_id=request_id,
                            caller=caller,
                            operation=source_catalog.SYNC_CONNECTOR,
                            outcome="succeeded",
                            resource_ref=str(source_ref),
                            detail_digest=metadata_digest(
                                source_ref, report.status, report.pages_committed, len(report.versions_registered),
                            ),
                        )
                except OperationsNotAdmitted:
                    outcome = "rejected"
                    reply = error_reply("forbidden", request_id)
                except IdempotencyConflict:
                    outcome = "rejected"
                    reply = error_reply("ingest_conflict", request_id)
                except SecurityLogUnavailable:
                    outcome = "rejected"
                    reply = error_reply("dependency_unavailable", request_id)
                if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict):
            return error_reply("dependency_unavailable", request_id)

    def execute_space_archive_list(self, caller: EmployeeCall) -> EvidenceReply:
        request_id = uuid4()
        if space_archive.LIST not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        if now >= caller.credential.expires_at:
            return error_reply("unauthenticated", request_id)
        business_day = now.astimezone(caller.business_timezone).date()
        started = monotonic()
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    space_archive.LIST, disposition.DESTINATION, business_day,
                    caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
                ))
                try:
                    call = OperationsCall(
                        caller.org_id, caller.space_id, caller.principal_id, request_id, "",
                        caller.configuration_revision,
                    )
                    with connection.transaction():
                        payload = space_archive.list_space_archives(connection, call)
                    outcome = "succeeded"
                    reply = EvidenceReply(request_id, 200, encode({"request_id": str(request_id), **payload}), deadline)
                except OperationsNotAdmitted:
                    outcome = "rejected"
                    reply = error_reply("forbidden", request_id)
                if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict):
            return error_reply("dependency_unavailable", request_id)

    def execute_space_archive_verify(self, caller: EmployeeCall, export_id: str) -> EvidenceReply:
        request_id = uuid4()
        if space_archive.VERIFY not in caller.credential.operations:
            return error_reply("forbidden", request_id)
        now = datetime.now(UTC)
        if now >= caller.credential.expires_at:
            return error_reply("unauthenticated", request_id)
        try:
            export_ref = parse_ref(export_id)
        except ValueError:
            return error_reply("invalid_arguments", request_id)
        business_day = now.astimezone(caller.business_timezone).date()
        started = monotonic()
        deadline = min(caller.credential.expires_at, now + MAX_REQUEST_TIME)
        try:
            with self.connect() as connection:
                start_request(connection, RequestStart(
                    caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                    space_archive.VERIFY, disposition.DESTINATION, business_day,
                    caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
                ))
                try:
                    call = OperationsCall(
                        caller.org_id, caller.space_id, caller.principal_id, request_id, "",
                        caller.configuration_revision,
                    )
                    with connection.transaction():
                        payload = space_archive.verify_sealed_space_archive(connection, call, export_ref)
                    outcome = "succeeded"
                    reply = EvidenceReply(request_id, 200, encode({"request_id": str(request_id), **payload}), deadline)
                except OperationsNotAdmitted:
                    outcome = "rejected"
                    reply = error_reply("forbidden", request_id)
                except disposition.DispositionConflict:
                    outcome = "rejected"
                    reply = error_reply("original_archive_conflict", request_id)
                except archive_rehearsal.ArchiveRejected:
                    outcome = "rejected"
                    reply = error_reply("archive_verification_failed", request_id)
                if not finish_request(connection, caller.org_id, request_id, outcome, int((monotonic() - started) * 1000)):
                    return error_reply("dependency_unavailable", request_id)
                return reply
        except (Error, RequestAuditConflict):
            return error_reply("dependency_unavailable", request_id)
