from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import re
from time import monotonic
from typing import Literal
from uuid import UUID, uuid4

from psycopg import Connection, Error
from psycopg.pq import TransactionStatus

from enterprise_kb.modules.access.delivery import (
    AuthorityDecision,
    AuthorizationUnavailable,
    DeliveryCheck,
    DeliveryContext,
)
from enterprise_kb.modules.access.policy import MODEL_RULE_OPERATION, WIKI_CANDIDATE_ACCESS
from enterprise_kb.modules.access.travel import (
    prepare_synthetic_model_excerpts,
    synthetic_model_request_operation,
)
from enterprise_kb.modules.sources.originals import ObjectStorageOriginalStore, SyntheticOriginalStore
from enterprise_kb.ports.contracts import (
    ModelGatewayPort,
    ModelGatewayUnavailable,
    ModelGenerationRequest,
    ModelOutcomeUnknown,
)
from enterprise_kb.runtime import external
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.runtime.jobs import JobSpec, LeaseLost, claim_job

from . import drafts


WIKI_AI_DRAFT_STAGE = "wiki_ai_draft"
WIKI_AI_PURPOSE = "wiki_compilation"
MAX_INSTRUCTIONS_CHARS = 2000
MAX_AI_BUDGET_MICROUNITS = 50_000_000
TOPIC_KEY_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}")


@dataclass(frozen=True)
class AiDraftSpec:
    topic_key: str
    manifest_ref: UUID
    reviewer_id: int
    basis_ref: UUID
    title_hint: str = ""
    instructions: str = ""
    max_microunits: int = 100_000
    currency: str = "USD"


@dataclass(frozen=True)
class AiDraftResult:
    status: Literal[
        "succeeded",
        "no_evidence",
        "rejected",
        "input_changed",
        "dependency_unavailable",
        "outcome_unknown",
    ]
    revision_ref: UUID | None = None
    provider_call_id: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    billed_microunits: int = 0
    title: str | None = field(default=None, repr=False)
    markdown: str | None = field(default=None, repr=False)
    citations: tuple[tuple[UUID, int], ...] = ()
    statements: tuple[drafts.WikiStatement, ...] = ()
    valid_until: datetime | None = None


def _parse_generated_payload(
    raw_utf8: str,
    allowed_entries: set[tuple[UUID, int]],
) -> tuple[str, str, tuple[tuple[UUID, int], ...], tuple[drafts.WikiStatement, ...]]:
    parsed = json.loads(raw_utf8)
    if not isinstance(parsed, dict):
        raise ValueError("Generated wiki draft must be a JSON object.")
    title = parsed.get("title")
    markdown = parsed.get("markdown")
    raw_citations = parsed.get("citations")
    raw_statements = parsed.get("statements", [])
    if (
        not isinstance(title, str)
        or not title.strip()
        or len(title) > 256
        or "\x00" in title
        or not isinstance(markdown, str)
        or not markdown.strip()
        or "\x00" in markdown
        or not isinstance(raw_citations, list)
        or not 1 <= len(raw_citations) <= 20
        or not isinstance(raw_statements, list)
        or len(raw_statements) > 20
    ):
        raise ValueError("Generated draft failed structural validation.")

    citations: list[tuple[UUID, int]] = []
    seen: set[tuple[UUID, int]] = set()
    for item in raw_citations:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not isinstance(item[0], str)
            or type(item[1]) is not int
            or item[1] < 1
        ):
            raise ValueError("Malformed generated citation pair.")
        pair = (UUID(item[0]), item[1])
        if pair in seen or pair not in allowed_entries:
            raise ValueError("Generated citation is duplicate or outside sealed manifest.")
        seen.add(pair)
        citations.append(pair)

    statements: list[drafts.WikiStatement] = []
    for entry in raw_statements:
        if not isinstance(entry, dict):
            raise ValueError("Generated statement must be an object.")
        text = entry.get("text")
        groups_raw = entry.get("support_groups")
        if (
            not isinstance(text, str)
            or not text.strip()
            or len(text) > 2000
            or "\x00" in text
            or not isinstance(groups_raw, list)
            or not 1 <= len(groups_raw) <= 20
        ):
            raise ValueError("Malformed generated statement.")
        groups: list[tuple[tuple[UUID, int], ...]] = []
        for group in groups_raw:
            if not isinstance(group, list) or not 1 <= len(group) <= 20:
                raise ValueError("Malformed generated support group.")
            pairs: list[tuple[UUID, int]] = []
            for ref_pair in group:
                if (
                    not isinstance(ref_pair, (list, tuple))
                    or len(ref_pair) != 2
                    or not isinstance(ref_pair[0], str)
                    or type(ref_pair[1]) is not int
                    or ref_pair[1] < 1
                ):
                    raise ValueError("Malformed generated support reference.")
                pair = (UUID(ref_pair[0]), ref_pair[1])
                if pair not in seen:
                    raise ValueError("Generated statement references uncited passage.")
                pairs.append(pair)
            if len(set(pairs)) != len(pairs):
                raise ValueError("Duplicate reference in generated support group.")
            groups.append(tuple(pairs))
        statements.append(drafts.WikiStatement(text.strip(), tuple(groups)))

    return title.strip(), markdown, tuple(citations), tuple(statements)


def generate_wiki_candidate(
    connection: Connection,
    context: DeliveryContext,
    space_id: int,
    spec: AiDraftSpec,
    idempotency_key: str,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
    gateway: ModelGatewayPort | None,
    *,
    region: str,
    traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    ingress: str = "http",
) -> AiDraftResult:
    """Generate a Wiki draft via an approved ModelGatewayPort and save it for independent review."""
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("AI wiki drafting requires independent committed transactions.")
    if (context.operation, context.purpose, context.destination) != WIKI_CANDIDATE_ACCESS:
        return AiDraftResult("rejected")
    if gateway is None:
        return AiDraftResult("dependency_unavailable")
    if WIKI_AI_PURPOSE not in gateway.allowed_purposes:
        return AiDraftResult("rejected")
    if (
        spec.reviewer_id == context.principal_id
        or not TOPIC_KEY_PATTERN.fullmatch(spec.topic_key)
        or not isinstance(spec.title_hint, str)
        or len(spec.title_hint) > 256
        or "\x00" in spec.title_hint
        or not isinstance(spec.instructions, str)
        or len(spec.instructions) > MAX_INSTRUCTIONS_CHARS
        or "\x00" in spec.instructions
        or type(spec.max_microunits) is not int
        or not 1 <= spec.max_microunits <= MAX_AI_BUDGET_MICROUNITS
        or not isinstance(spec.currency, str)
        or not re.fullmatch(r"[A-Z]{3}", spec.currency)
    ):
        return AiDraftResult("rejected")

    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        req_row = connection.execute(
            """
            SELECT business_date, configuration_revision
            FROM thalion.request_record
            WHERE org_id = %s AND request_id = %s AND principal_id = %s AND outcome IS NULL
            """,
            (context.org_id, context.request_id, context.principal_id),
        ).fetchone()
        if req_row is None:
            return AiDraftResult("rejected")
        business_date, config_revision = req_row
        manifest_row = connection.execute(
            """
            SELECT manifest.expanded_digest
            FROM thalion.input_manifest AS manifest
            LEFT JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
            LEFT JOIN thalion.wiki_publication_event AS previous ON previous.publication_ref = stopped.publication_ref
            WHERE (manifest.org_id, manifest.space_id, manifest.author_id, manifest.manifest_ref) = (%s, %s, %s, %s)
              AND (manifest.rebuild_event_ref IS NULL OR previous.topic_key = %s)
            """,
            (context.org_id, space_id, context.principal_id, spec.manifest_ref, spec.topic_key),
        ).fetchone()
        if manifest_row is None:
            return AiDraftResult("rejected")
        expanded_digest = bytes(manifest_row[0])
        worker_row = connection.execute(
            """
            SELECT COALESCE(
                (SELECT contract.processor_id
                 FROM thalion.source_contract_revision AS contract
                 JOIN thalion.source AS src
                   ON (src.org_id, src.space_id, src.source_id, src.contract_revision)
                    = (contract.org_id, contract.space_id, contract.source_id, contract.revision)
                 JOIN thalion.principal AS p
                   ON (p.org_id, p.principal_id) = (contract.org_id, contract.processor_id)
                 WHERE src.org_id = %s AND src.space_id = %s
                   AND p.principal_type = 'service' AND NOT p.disabled
                 ORDER BY src.source_id LIMIT 1),
                (SELECT principal_id
                 FROM thalion.principal
                 WHERE org_id = %s AND principal_type = 'service' AND NOT disabled
                 ORDER BY principal_id LIMIT 1)
            )
            """,
            (context.org_id, space_id, context.org_id),
        ).fetchone()
        worker_id = worker_row[0] if worker_row is not None else None
        space_row = connection.execute(
            """
            SELECT public_id
            FROM thalion.object_identity
            WHERE org_id = %s AND space_id = %s AND object_type = 'space' AND object_id = %s
            """,
            (context.org_id, space_id, space_id),
        ).fetchone()
        space_ref = space_row[0] if space_row is not None else None
        entries = tuple(
            connection.execute(
                """
                SELECT entry.passage_ref, entry.excerpt_revision
                FROM thalion.input_manifest_entry AS entry
                JOIN thalion.delivery_record AS origin USING (org_id, check_id)
                JOIN thalion.request_record AS origin_request
                  ON (origin.org_id, origin.request_id) = (origin_request.org_id, origin_request.request_id)
                WHERE (entry.org_id, entry.space_id, entry.manifest_ref) = (%s, %s, %s)
                  AND origin_request.business_date = %s
                ORDER BY entry.position
                """,
                (context.org_id, space_id, spec.manifest_ref, business_date),
            ).fetchall()
        )
    if not entries:
        return AiDraftResult("rejected")
    if worker_id is None or space_ref is None:
        return AiDraftResult("dependency_unavailable")

    egress_request_id = uuid4()
    egress_started = monotonic()
    egress_operation = synthetic_model_request_operation(WIKI_AI_PURPOSE)
    try:
        start_request(
            connection,
            RequestStart(
                context.org_id,
                egress_request_id,
                context.principal_id,
                None,
                context.client_id,
                egress_operation,
                gateway.destination_id,
                business_date,
                config_revision,
                space_id=space_id,
                ingress=ingress,
            ),
        )
    except Error:
        return AiDraftResult("dependency_unavailable")

    egress_context = DeliveryContext(
        egress_request_id,
        context.org_id,
        context.principal_id,
        context.client_id,
        MODEL_RULE_OPERATION,
        WIKI_AI_PURPOSE,
        gateway.destination_id,
        context.deadline,
        authority_issuer=context.authority_issuer,
    )

    egress_decision = prepare_synthetic_model_excerpts(
        connection,
        egress_context,
        space_id,
        entries,
        store,
        region=region,
        traveler_class=traveler_class,
        check_authority=check_authority,
        destination=gateway.destination_id,
    )
    if egress_decision.status != "succeeded" or egress_decision.payload is None:
        finish_request(
            connection,
            context.org_id,
            egress_request_id,
            egress_decision.status,
            int((monotonic() - egress_started) * 1000),
        )
        return AiDraftResult(egress_decision.status)

    prompt_envelope = {
        "purpose": WIKI_AI_PURPOSE,
        "topic_key": spec.topic_key,
        "title_hint": spec.title_hint.strip(),
        "instructions": spec.instructions.strip(),
        "business_date": business_date.isoformat(),
        "manifest_id": str(spec.manifest_ref),
        "allowed_citations": [[str(passage_ref), excerpt_revision] for passage_ref, excerpt_revision in entries],
        "excerpts": json.loads(egress_decision.payload.decode("utf-8")),
        "response_schema": {
            "title": "string",
            "markdown": "string",
            "citations": [["passage_uuid", "excerpt_revision_int"]],
            "statements": [{"text": "string", "support_groups": [[["passage_uuid", "excerpt_revision_int"]]]}],
        },
    }
    prompt_bytes = json.dumps(prompt_envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    prompt_digest = sha256(prompt_bytes).digest()

    job_spec = JobSpec(
        org_id=context.org_id,
        space_id=space_id,
        target_ref=space_ref,
        stage=WIKI_AI_DRAFT_STAGE,
        input_digest=sha256(spec.manifest_ref.bytes + expanded_digest + prompt_digest + idempotency_key.encode("utf-8")).digest(),
        configuration_revision=config_revision,
    )
    budget = external.CallBudget(spec.currency, spec.max_microunits, 1, allow_unknown_retry=False)

    call_id: UUID | None = None
    lease = None
    try:
        job_id = external.enqueue_external_job(connection, job_spec, budget, request_id=egress_request_id)
        lease = claim_job(
            connection,
            context.org_id,
            WIKI_AI_DRAFT_STAGE,
            worker_id,
            timedelta(minutes=2),
            job_id=job_id,
        )
        if lease is None:
            finish_request(
                connection, context.org_id, egress_request_id, "rejected", int((monotonic() - egress_started) * 1000)
            )
            return AiDraftResult("rejected")
        call_id = external.reserve_external_call(
            connection,
            lease,
            route=gateway.destination_id,
            provider_namespace=gateway.admission,
            input_digest=prompt_digest,
            maximum_microunits=spec.max_microunits,
        )
        external.mark_call_sent(
            connection,
            lease,
            call_id,
            route=gateway.destination_id,
            provider_namespace=gateway.admission,
            input_digest=prompt_digest,
        )
    except (Error, LeaseLost, external.CallBudgetExceeded, external.ExternalCallConflict):
        finish_request(
            connection, context.org_id, egress_request_id, "rejected", int((monotonic() - egress_started) * 1000)
        )
        return AiDraftResult("rejected")

    try:
        receipt = gateway.invoke_generation(
            ModelGenerationRequest(
                request_id=egress_request_id,
                purpose=WIKI_AI_PURPOSE,
                destination_id=gateway.destination_id,
                input_manifest_digest=expanded_digest,
                payload_bytes=prompt_bytes,
                max_microunits=spec.max_microunits,
            )
        )
    except ModelOutcomeUnknown:
        try:
            external.mark_call_unknown(connection, context.org_id, call_id)
        except (Error, external.ExternalCallConflict):
            pass
        finish_request(
            connection, context.org_id, egress_request_id, "outcome_unknown", int((monotonic() - egress_started) * 1000)
        )
        return AiDraftResult("outcome_unknown")
    except ModelGatewayUnavailable:
        try:
            external.record_call_receipt(
                connection,
                context.org_id,
                call_id,
                external.UsageReceipt(uuid4(), f"unavailable:{call_id}", False, 0, 0, 0),
            )
        except (Error, external.ExternalCallConflict):
            pass
        finish_request(
            connection,
            context.org_id,
            egress_request_id,
            "dependency_unavailable",
            int((monotonic() - egress_started) * 1000),
        )
        return AiDraftResult("dependency_unavailable")

    if not receipt.accepted or receipt.output_utf8 is None:
        try:
            external.record_call_receipt(
                connection,
                context.org_id,
                call_id,
                external.UsageReceipt(
                    uuid4(),
                    receipt.provider_call_id,
                    False,
                    receipt.input_tokens,
                    receipt.output_tokens,
                    receipt.billed_microunits,
                ),
            )
        except (Error, external.ExternalCallConflict):
            pass
        finish_request(
            connection, context.org_id, egress_request_id, "rejected", int((monotonic() - egress_started) * 1000)
        )
        return AiDraftResult(
            "rejected",
            provider_call_id=receipt.provider_call_id,
            input_tokens=receipt.input_tokens,
            output_tokens=receipt.output_tokens,
            billed_microunits=receipt.billed_microunits,
        )

    if sha256(receipt.output_utf8.encode("utf-8")).digest() != receipt.output_digest:
        try:
            external.mark_call_unknown(connection, context.org_id, call_id)
        except (Error, external.ExternalCallConflict):
            pass
        finish_request(
            connection, context.org_id, egress_request_id, "outcome_unknown", int((monotonic() - egress_started) * 1000)
        )
        return AiDraftResult("outcome_unknown", provider_call_id=receipt.provider_call_id)

    try:
        title, markdown, citations, statements = _parse_generated_payload(receipt.output_utf8, set(entries))
    except (ValueError, json.JSONDecodeError):
        try:
            external.record_call_receipt(
                connection,
                context.org_id,
                call_id,
                external.UsageReceipt(
                    uuid4(),
                    receipt.provider_call_id,
                    False,
                    receipt.input_tokens,
                    receipt.output_tokens,
                    receipt.billed_microunits,
                ),
            )
        except (Error, external.ExternalCallConflict):
            pass
        finish_request(
            connection, context.org_id, egress_request_id, "rejected", int((monotonic() - egress_started) * 1000)
        )
        return AiDraftResult(
            "rejected",
            provider_call_id=receipt.provider_call_id,
            input_tokens=receipt.input_tokens,
            output_tokens=receipt.output_tokens,
            billed_microunits=receipt.billed_microunits,
        )

    artifact_ref = uuid4()
    try:
        external.record_call_receipt(
            connection,
            context.org_id,
            call_id,
            external.UsageReceipt(
                uuid4(),
                receipt.provider_call_id,
                True,
                receipt.input_tokens,
                receipt.output_tokens,
                receipt.billed_microunits,
            ),
            artifact=external.CallArtifact(artifact_ref, receipt.output_digest),
        )
    except (Error, external.ExternalCallConflict):
        finish_request(
            connection, context.org_id, egress_request_id, "dependency_unavailable", int((monotonic() - egress_started) * 1000)
        )
        return AiDraftResult("dependency_unavailable", provider_call_id=receipt.provider_call_id)

    candidate = drafts.ManualCandidate(
        topic_key=spec.topic_key,
        title=title,
        markdown=markdown,
        manifest_ref=spec.manifest_ref,
        reviewer_id=spec.reviewer_id,
        basis_ref=spec.basis_ref,
        citations=citations,
        statements=statements,
    )
    created = drafts.create_manual_candidate(
        connection,
        context,
        space_id,
        candidate,
        idempotency_key,
        region=region,
        traveler_class=traveler_class,
        check_authority=check_authority,
    )
    if created.status != "succeeded" or created.ref is None:
        finish_request(
            connection, context.org_id, egress_request_id, created.status, int((monotonic() - egress_started) * 1000)
        )
        return AiDraftResult(
            created.status,
            provider_call_id=receipt.provider_call_id,
            input_tokens=receipt.input_tokens,
            output_tokens=receipt.output_tokens,
            billed_microunits=receipt.billed_microunits,
        )

    try:
        external.complete_external_job(connection, lease, lambda _tx, _call: created.ref)
    except (Error, LeaseLost, external.ExternalCallConflict):
        pass
    finish_request(
        connection, context.org_id, egress_request_id, "succeeded", int((monotonic() - egress_started) * 1000)
    )
    return AiDraftResult(
        "succeeded",
        revision_ref=created.ref,
        provider_call_id=receipt.provider_call_id,
        input_tokens=receipt.input_tokens,
        output_tokens=receipt.output_tokens,
        billed_microunits=receipt.billed_microunits,
        title=title,
        markdown=markdown,
        citations=citations,
        statements=statements,
        valid_until=min(context.deadline, egress_decision.valid_until) if egress_decision.valid_until else context.deadline,
    )
