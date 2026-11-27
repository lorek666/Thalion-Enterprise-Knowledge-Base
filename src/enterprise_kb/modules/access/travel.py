from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from hashlib import sha256
from itertools import chain, groupby
import json
import re
from time import monotonic
from uuid import UUID

from psycopg import Connection, Error
from psycopg.pq import TransactionStatus

from enterprise_kb.modules.evidence.csv_evidence import AMOUNT_ROLES, EXCEPTION_LINK_ROLES
from enterprise_kb.modules.evidence.docx_evidence import MEDIA_TYPE as DOCX_MEDIA_TYPE
from enterprise_kb.modules.evidence.multiformat_evidence import MEDIA_SOURCE_TYPE, STRUCTURED_MEDIA_TYPES
from enterprise_kb.modules.evidence.processing import (
    ApprovedCsvCell,
    ApprovedCsvUnit,
    ApprovedDocxCell,
    ApprovedDocxParagraph,
    ApprovedDocxUnit,
    ApprovedPassage,
    ApprovedPdfPage,
    ApprovedStructuredPassage,
    list_approved_csv_cells,
    list_approved_csv_units,
    list_approved_docx_paragraphs,
    list_approved_docx_units,
    list_approved_passages,
    list_approved_pdf_pages,
    list_approved_structured_passages,
    resolve_csv_cell,
    resolve_csv_cells,
    resolve_docx_paragraph,
    resolve_docx_paragraphs,
    resolve_docx_units,
    resolve_pdf_transcripts,
    resolve_structured_excerpt,
    resolve_structured_excerpts,
)
from enterprise_kb.modules import glossary
from enterprise_kb.modules.retrieval import lexical, vector
from enterprise_kb.modules.sources import departments as department_store
from enterprise_kb.modules.sources.effectivity import RuleSelection, select_rule
from enterprise_kb.modules.sources.originals import OriginalAsset, OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.modules.sources.registry import (
    SYNTHETIC_ISSUER, admission_for_issuer, issuer_matches_admission,
    storage_kind_for_admission, store_admission,
)
from enterprise_kb.modules.wiki import projection
from enterprise_kb.ports.contracts import EmbeddingPortUnavailable, EmbeddingProviderPort
from enterprise_kb.runtime.audit import finish_open_request

from .delivery import (
    AuthorityDecision,
    AuthorizationUnavailable,
    DeliveryCandidate,
    DeliveryCheck,
    DeliveryContext,
    DeliveryDecision,
    EvidenceScope,
    LocalAuthorization,
    SafetyEpochs,
    authorize_delivery,
)
from .policy import (
    EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS,
    EMPLOYEE_SOURCE_OPTIONS_ACCESS,
    EMPLOYEE_TITLE_SUGGESTIONS_ACCESS,
    MODEL_RULE_OPERATION,
    MODEL_RULE_PURPOSES,
    ORIGINAL_DOWNLOAD_ACCESS,
    PASSAGE_FIELDS,
    SYNTHETIC_MODEL_DESTINATION,
    WIKI_CANDIDATE_ACCESS,
    WIKI_INPUT_ACCESS,
    WIKI_PREVIEW_ACCESS,
    WIKI_REVIEW_ACCESS,
    WIKI_PUBLISH_ACCESS,
    WIKI_ROLLBACK_ACCESS,
    WIKI_DERIVED_ACCESS,
    WIKI_READ_ACCESS,
    WORKSPACE_EVIDENCE_FIELDS,
)
from .rules import PermissionBinding


MAX_SEARCH_DOCUMENTS = 128
MAX_SEARCH_PASSAGES = 512
MAX_TITLE_SUGGESTIONS = 5
MAX_TITLE_SUGGESTION_DEPENDENCIES = 20
SEARCH_TERM = re.compile(r"[^\W_]+")
EXACT_LOCATIONS = (ApprovedCsvCell, ApprovedPdfPage, ApprovedDocxParagraph, ApprovedDocxCell)
EMPLOYEE_PASSAGE_ACCESS = ("read_passage", "employee_evidence", "employee")
EMPLOYEE_DISCOVERY_OPERATIONS = {"search", EMPLOYEE_SOURCE_OPTIONS_ACCESS[0], EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS[0], EMPLOYEE_TITLE_SUGGESTIONS_ACCESS[0]}
SHARED_GROUP_OPERATIONS = frozenset({
    EMPLOYEE_PASSAGE_ACCESS[0],
    "search",
    EMPLOYEE_SOURCE_OPTIONS_ACCESS[0],
    EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS[0],
    EMPLOYEE_TITLE_SUGGESTIONS_ACCESS[0],
    WIKI_READ_ACCESS[0],
    ORIGINAL_DOWNLOAD_ACCESS[0],
})
MAX_MODEL_EXCERPT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class _TravelSelection:
    space_id: int
    business_date: date
    region: str
    traveler_class: str
    retained_version: UUID | None = None
    allow_csv_reference: bool = False
    allow_pdf: bool = False
    allow_docx: bool = False
    allow_docx_tables: bool = False


@dataclass(frozen=True)
class _CurrentVersion:
    document_ref: UUID
    rule: RuleSelection
    title: str = field(repr=False)
    version_label: str = field(repr=False)
    source_id: int
    epochs: SafetyEpochs
    policy_revision: int
    asset: OriginalAsset
    media_type: str = "text/markdown"


@dataclass(frozen=True)
class _CurrentPassage:
    version: _CurrentVersion
    location: ApprovedPassage | ApprovedCsvCell | ApprovedPdfPage | ApprovedDocxParagraph | ApprovedDocxCell | ApprovedStructuredPassage
    csv_units: tuple[ApprovedCsvUnit, ...] = field(default=(), repr=False)
    docx_unit: ApprovedDocxUnit | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _MatchedPassage:
    scope: EvidenceScope
    part: _CurrentPassage
    excerpt: str = field(repr=False)
    cell_header: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ReferenceBinding:
    revision: int
    recheck: Callable[[Connection], bool]
    seal: Callable[[Connection, DeliveryDecision], None]


@dataclass(frozen=True)
class _WikiHit:
    publication: projection.SearchPublication
    dependencies: Mapping[EvidenceScope, _CurrentPassage] = field(repr=False)
    view: dict = field(repr=False)
    score: int


class _ExpiredDelivery(Exception):
    pass


class _SearchLimitExceeded(Exception):
    pass


class _PublicationChanged(Exception):
    pass


def _require_ingress(
    connection: Connection, context: DeliveryContext, operation: str,
    purpose: str = "employee_evidence", destination: str = "employee",
) -> bool:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Evidence delivery requires independent current access snapshots.")
    return (
        (context.operation, context.purpose, context.destination) == (operation, purpose, destination)
        and datetime.now(UTC) < context.deadline
    )


def synthetic_model_request_operation(purpose: str) -> str:
    if purpose not in MODEL_RULE_PURPOSES:
        raise ValueError("Unsupported synthetic model purpose.")
    return f"{MODEL_RULE_OPERATION}.{purpose}"


def _request_day(connection: Connection, context: DeliveryContext, *, lock=False, model_space_id=None, scope_space_id=None) -> date | None:
    scope_filter = ""
    operation = synthetic_model_request_operation(context.purpose) if model_space_id is not None else context.operation
    parameters = (context.org_id, context.request_id, context.principal_id, context.client_id,
                  operation, context.destination, context.authority_issuer)
    request_space = model_space_id if model_space_id is not None else scope_space_id
    if request_space is not None:
        scope_filter = """
          AND request.scope_space_id = %s AND request.configuration_revision = (
              SELECT config_revision FROM thalion.organization WHERE org_id = request.org_id
          )
        """
        parameters += (request_space,)
    row = connection.execute(
        """
        SELECT request.business_date
        FROM thalion.request_record AS request
        JOIN thalion.principal AS employee ON (employee.org_id, employee.principal_id)
            = (request.org_id, request.principal_id)
        WHERE request.org_id = %s AND request.request_id = %s AND request.principal_id = %s
          AND request.client_id = %s AND request.operation = %s AND request.destination = %s
          AND request.delegated_principal_id IS NULL AND request.outcome IS NULL
          AND employee.principal_type = 'employee' AND employee.authority_issuer = %s AND NOT employee.disabled
        """ + scope_filter + (" FOR UPDATE OF request FOR SHARE OF employee" if lock else ""),
        parameters,
    ).fetchone()
    if row is None or connection.execute(
        "SELECT 1 FROM thalion.delivery_record WHERE org_id = %s AND request_id = %s",
        (context.org_id, context.request_id),
    ).fetchone():
        return None
    return row[0]


def _passage_version(
    connection: Connection, org_id: int, space_id: int, passage_ref: UUID,
) -> tuple[UUID, UUID] | None:
    return connection.execute(
        """
        SELECT document_ref.public_id, version_ref.public_id
        FROM thalion.object_identity AS identity
        JOIN thalion.passage AS passage
          ON (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.document_version AS version ON version.version_id = passage.version_id
        JOIN thalion.object_identity AS document_ref
          ON (document_ref.org_id, document_ref.space_id, document_ref.object_type, document_ref.object_id)
           = (version.org_id, version.space_id, 'document', version.document_id)
        JOIN thalion.object_identity AS version_ref
          ON (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id)
           = (version.org_id, version.space_id, 'document_version', version.version_id)
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
        """,
        (org_id, space_id, passage_ref),
    ).fetchone()


def _load_document(
    connection: Connection, org_id: int, selection: _TravelSelection, document_ref: UUID,
    *, passage_ref: UUID | None = None, lock=False, include_csv_units=False,
    authority_issuer: str = SYNTHETIC_ISSUER,
) -> tuple[_CurrentPassage, ...]:
    expected_admission = admission_for_issuer(authority_issuer)
    if expected_admission is None:
        return ()
    expected_storage_kind = storage_kind_for_admission(expected_admission)
    space_id = selection.space_id
    row = connection.execute(
        """
        SELECT document.display_name, source.source_id, organization.safety_epoch, space.safety_epoch,
               source.safety_epoch, source.local_policy_revision
        FROM thalion.object_identity AS identity
        JOIN thalion.document AS document
          ON (document.org_id, document.space_id, document.identity_type, document.document_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source AS source ON source.source_id = document.source_id
        JOIN thalion.space AS space ON space.space_id = document.space_id
        JOIN thalion.organization AS organization ON organization.org_id = document.org_id
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
          AND source.local_policy_revision IS NOT NULL AND contract.admission = %s
        """ + (" FOR SHARE OF organization, space, source, document" if lock else ""),
        (org_id, space_id, document_ref, expected_admission),
    ).fetchone()
    if row is None:
        return ()
    rule = select_rule(
        connection, org_id, space_id, document_ref, selection.business_date,
        region=selection.region, traveler_class=selection.traveler_class, retained_version=selection.retained_version,
    )
    if rule.status != "applicable":
        return ()
    row_asset = connection.execute(
        """
        SELECT version.version_label, asset.storage_key, asset.content_digest, asset.byte_length, asset.media_type
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.asset AS asset ON asset.asset_id = version.asset_id
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
          AND asset.storage_kind = %s
          AND NOT EXISTS (
              SELECT 1 FROM thalion.current_version_hold AS hold
              WHERE (hold.org_id, hold.space_id, hold.version_id) = (version.org_id, version.space_id, version.version_id)
                AND hold.action = 'establish'
          )
        """,
        (org_id, space_id, rule.version_ref, expected_storage_kind),
    ).fetchone()
    if row_asset is None:
        return ()
    version = _CurrentVersion(
        document_ref, rule, row[0], row_asset[0], row[1], SafetyEpochs(*row[2:5]), row[5],
        OriginalAsset(*row_asset[1:4]), row_asset[4],
    )
    if row_asset[4] == "text/csv" and include_csv_units:
        memberships = {}
        for unit in list_approved_csv_units(connection, org_id, space_id, rule.version_ref):
            for member in unit.members:
                memberships.setdefault(member.cell, []).append(unit)
        return tuple(
            _CurrentPassage(version, cell, tuple(units)) for cell, units in memberships.items()
        )
    if row_asset[4] == DOCX_MEDIA_TYPE and selection.allow_docx_tables:
        units = list_approved_docx_units(connection, org_id, space_id, rule.version_ref, passage_ref=passage_ref)
        if units:
            return tuple(_CurrentPassage(version, member.cell, docx_unit=unit) for unit in units for member in unit.members)
    if row_asset[4] == "text/csv" and selection.allow_csv_reference and passage_ref is not None:
        passages = list_approved_csv_cells
    elif row_asset[4] == "text/markdown":
        passages = list_approved_passages
    elif row_asset[4] == "application/pdf" and selection.allow_pdf:
        passages = list_approved_pdf_pages
    elif row_asset[4] == DOCX_MEDIA_TYPE and selection.allow_docx:
        passages = list_approved_docx_paragraphs
    elif row_asset[4] in STRUCTURED_MEDIA_TYPES:
        passages = list_approved_structured_passages
    else:
        return ()
    return tuple(
        _CurrentPassage(version, part) for part in passages(
            connection, org_id, space_id, rule.version_ref, passage_ref=passage_ref,
            limit=MAX_SEARCH_PASSAGES + 1,
        )
    )


def _extract_excerpt(body: bytes, part: ApprovedPassage) -> bytes:
    if 0 <= part.byte_start < part.byte_end <= len(body):
        excerpt = body[part.byte_start:part.byte_end]
        if sha256(excerpt).digest() == part.digest:
            return excerpt
    raise OriginalIntegrityError("The excerpt does not match the approved location.")


def read_travel_passage(
    connection: Connection,
    context: DeliveryContext,
    space_id: int,
    passage_ref: UUID,
    revision: int,
    store: SyntheticOriginalStore,
    *,
    region: str,
    traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> DeliveryDecision:
    """Read the exact approved revision selected for the request's business day."""
    if revision < 1:
        return DeliveryDecision("rejected")
    return _read_travel_reference(
        connection, context, space_id, passage_ref, store, revision=revision, region=region,
        traveler_class=traveler_class, check_authority=check_authority,
    )


def open_travel_reference(
    connection: Connection,
    context: DeliveryContext,
    space_id: int,
    passage_ref: UUID,
    store: SyntheticOriginalStore,
    *,
    region: str,
    traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    binding: ReferenceBinding | None = None,
) -> DeliveryDecision:
    """Open a retained synthetic location without promoting old evidence into today's search."""
    return _read_travel_reference(
        connection, context, space_id, passage_ref, store, revision=None, region=region,
        traveler_class=traveler_class, check_authority=check_authority, binding=binding,
    )


def _read_travel_reference(
    connection: Connection, context: DeliveryContext, space_id: int, passage_ref: UUID,
    store: SyntheticOriginalStore, *, revision: int | None, region: str, traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    binding: ReferenceBinding | None = None,
) -> DeliveryDecision:
    if not issuer_matches_admission(context.authority_issuer, store_admission(store)):
        return DeliveryDecision("rejected")
    if not _require_ingress(connection, context, "read_passage"):
        return DeliveryDecision("rejected")
    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            business_day = _request_day(connection, context)
            if business_day is None:
                return DeliveryDecision("rejected")
            reference = _passage_version(connection, context.org_id, space_id, passage_ref)
            if reference is None:
                return DeliveryDecision("rejected")
            document_ref, version_ref = reference
            selection = _TravelSelection(
                space_id, business_day, region, traveler_class, version_ref if revision is None else None,
                allow_csv_reference=revision is None and (context.purpose, context.destination) == (
                    "employee_evidence", "employee",
                ),
                allow_pdf=True, allow_docx=True, allow_docx_tables=True,
            )
            matches = _load_document(
                connection, context.org_id, selection, document_ref,
                passage_ref=passage_ref, authority_issuer=context.authority_issuer,
            )
            required_revision = binding.revision if binding else revision
            original = next((part for part in matches if part.location.passage_ref == passage_ref), None)
            if original is None or (required_revision is not None and original.location.revision != required_revision):
                return DeliveryDecision("rejected")
    except Error:
        return DeliveryDecision("dependency_unavailable")

    location = original.location
    fields = PASSAGE_FIELDS if revision is None else frozenset({"excerpt"})
    if original.docx_unit is not None:
        return _read_docx_reference(connection, context, selection, original, matches, fields,
                                    store, check_authority, structured=revision is None, binding=binding)
    scope = EvidenceScope(
        space_id, original.version.source_id, passage_ref, fields,
        revision=location.revision if isinstance(location, EXACT_LOCATIONS) else None,
    )
    if isinstance(location, (ApprovedPdfPage, ApprovedDocxParagraph, ApprovedStructuredPassage)):
        eligible = _assess_passages(
            connection, context, selection, {scope: original},
            _encode_json([str(passage_ref), location.revision]), check_authority,
            record=False, recheck=binding.recheck if binding else None,
        )
        if eligible.status != "succeeded":
            return DeliveryDecision(eligible.status)

    payload = None
    try:
        body = store.read(original.version.asset)
        if isinstance(location, ApprovedCsvCell):
            header, value = resolve_csv_cell(body, location)
            payload = _encode_json({
                "request_id": str(context.request_id), "passage": _passage_view(original, value, cell_header=header),
            })
        else:
            if isinstance(location, ApprovedPdfPage):
                excerpt = resolve_pdf_transcripts(connection, (location,))[location]
            elif isinstance(location, ApprovedDocxParagraph):
                excerpt = resolve_docx_paragraph(body, location)
            elif isinstance(location, ApprovedStructuredPassage):
                excerpt = resolve_structured_excerpt(body, original.version.media_type, location)
            else:
                excerpt = _extract_excerpt(body, location)
            payload = excerpt if revision is not None else _encode_json({
                "request_id": str(context.request_id), "passage": _passage_view(original, excerpt.decode("utf-8")),
            })
    except (Error, OriginalIntegrityError, UnicodeError):
        pass
    return _assess_passages(
        connection, context, selection, {scope: original}, payload, check_authority, record=True,
        recheck=binding.recheck if binding else None, seal=binding.seal if binding else None,
        visible_citations=frozenset({passage_ref}) if revision is None else frozenset(),
    )


def _read_docx_reference(connection, context, selection, original, matches, fields, store, check_authority, *, structured, binding):
    unit = original.docx_unit
    if {part.location for part in matches} != {member.cell for member in unit.members}:
        return DeliveryDecision("rejected")
    scopes = {
        EvidenceScope(selection.space_id, part.version.source_id, part.location.passage_ref, fields, part.location.revision): part
        for part in matches
    }
    recheck = binding.recheck if binding else None
    eligible = _assess_passages(connection, context, selection, scopes, _encode_json([
        [str(scope.object_id), scope.revision] for scope in scopes
    ]), check_authority, record=False, recheck=recheck)
    if eligible.status != "succeeded":
        return DeliveryDecision(eligible.status)
    try:
        _check_deadline(eligible.valid_until)
        materials = resolve_docx_units(store.read(original.version.asset), (unit,))
        excerpt = "\n".join(f"{header}：{value}" for header, value in materials.values())
        if structured:
            passage = _passage_view(original, excerpt, cell_header=materials[original.location][0])
            passage["location"]["columns"] = [
                {"column": cell.column_number, "header": header} for cell, (header, _) in materials.items()
            ]
            payload = _encode_json({"request_id": str(context.request_id), "passage": passage})
        else:
            payload = excerpt.encode("utf-8")
    except (OriginalIntegrityError, UnicodeError, _ExpiredDelivery):
        return DeliveryDecision("dependency_unavailable")
    return _assess_passages(
        connection, context, selection, scopes, payload, check_authority, record=True,
        recheck=recheck, seal=binding.seal if binding else None,
        visible_citations=frozenset({original.location.passage_ref}) if structured else frozenset(),
    )


def prepare_synthetic_model_excerpts(
    connection: Connection, context: DeliveryContext, space_id: int, references: tuple[tuple[UUID, int], ...],
    store: SyntheticOriginalStore, *, region: str, traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    seal: Callable[[Connection, DeliveryDecision], None] | None = None,
    destination: str = SYNTHETIC_MODEL_DESTINATION,
) -> DeliveryDecision:
    if not issuer_matches_admission(context.authority_issuer, store_admission(store)):
        return DeliveryDecision("rejected")
    if context.purpose not in MODEL_RULE_PURPOSES or not _require_ingress(
        connection, context, MODEL_RULE_OPERATION, context.purpose, destination,
    ):
        return DeliveryDecision("rejected")
    references = tuple(references)
    if (not 1 <= len(references) <= 20 or len({ref for ref, _ in references}) != len(references)
            or any(not isinstance(ref, UUID) or type(revision) is not int or revision < 1 for ref, revision in references)):
        return DeliveryDecision("rejected")
    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            business_day = _request_day(connection, context, model_space_id=space_id)
            if business_day is None:
                return DeliveryDecision("rejected")
            selection = _TravelSelection(
                space_id, business_day, region, traveler_class, allow_pdf=True, allow_docx=True, allow_docx_tables=True,
            )
            passages = {}
            located_parts = {}
            for ref, revision in references:
                _check_deadline(context.deadline)
                if ref not in located_parts:
                    located = _passage_version(connection, context.org_id, space_id, ref)
                    if located is None:
                        return DeliveryDecision("rejected")
                    matching = _load_document(
                        connection, context.org_id, selection, located[0],
                        passage_ref=ref, include_csv_units=True, authority_issuer=context.authority_issuer,
                    )
                    located_parts.update((part.location.passage_ref, part) for part in matching)
                part = located_parts.get(ref)
                if part is None or part.location.revision != revision:
                    return DeliveryDecision("rejected")
                scope = EvidenceScope(space_id, part.version.source_id, ref, frozenset({"excerpt"}), revision)
                passages[scope] = part
            csv_units = _complete_csv_units(passages)
            covered = {member.cell for unit in csv_units for member in unit.members}
            if any(len(unit.members) != len({member.role for member in unit.members}) for unit in csv_units) or any(
                part.csv_units and part.location not in covered for part in passages.values()
            ):
                return DeliveryDecision("rejected")
            docx_cells = _covered_docx_cells(passages)
            if any(part.docx_unit is not None and part.location not in docx_cells for part in passages.values()):
                return DeliveryDecision("rejected")
        eligibility = _assess_passages(
            connection, context, selection, passages, _encode_json([[str(ref), rev] for ref, rev in references]),
            check_authority, record=False,
        )
        if eligibility.status != "succeeded":
            return DeliveryDecision(eligibility.status)
        if eligibility.valid_until is None:
            return DeliveryDecision("dependency_unavailable")
        transcripts = resolve_pdf_transcripts(connection, tuple(
            part.location for part in passages.values() if isinstance(part.location, ApprovedPdfPage)
        ))
        csv_cells = _read_csv_passages(store, passages, eligibility.valid_until)
        excerpts = []
        total_bytes = 0
        for part in passages.values():
            _check_deadline(eligibility.valid_until)
            location = part.location
            if isinstance(location, (ApprovedCsvCell, ApprovedDocxCell)):
                continue
            content = store.read(part.version.asset)
            if isinstance(location, ApprovedPdfPage):
                excerpt = transcripts[location]
            elif isinstance(location, ApprovedDocxParagraph):
                excerpt = resolve_docx_paragraph(content, location)
            elif isinstance(location, ApprovedStructuredPassage):
                excerpt = resolve_structured_excerpt(content, part.version.media_type, location)
            else:
                excerpt = _extract_excerpt(content, location)
            total_bytes += len(excerpt)
            if total_bytes > MAX_MODEL_EXCERPT_BYTES:
                return DeliveryDecision("rejected")
            excerpts.append(excerpt.decode("utf-8"))
        view = {"excerpts": excerpts}
        if csv_units:
            view["csv_units"] = [
                {member.role: csv_cells[member.cell].excerpt for member in unit.members} for unit in csv_units
            ]
        if docx_cells:
            view["docx_units"] = [
                {role: member.excerpt for role, member in unit.items()}
                for unit in _read_docx_units(store, passages, eligibility.valid_until)
            ]
        payload = _encode_json(view)
        if len(payload) > MAX_MODEL_EXCERPT_BYTES:
            return DeliveryDecision("rejected")
        return _assess_passages(
            connection, context, selection, passages, payload, check_authority, record=True, seal=seal,
        )
    except _ExpiredDelivery:
        return DeliveryDecision("rejected")
    except (Error, OriginalIntegrityError, UnicodeError):
        return DeliveryDecision("dependency_unavailable")


def assemble_travel_excerpts(
    connection: Connection, context: DeliveryContext, space_id: int, store: SyntheticOriginalStore,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    resolve: Callable[[Connection], tuple[tuple[UUID, int], ...]],
    seal: Callable[[Connection, DeliveryDecision], None],
) -> DeliveryDecision:
    if (context.operation, context.purpose, context.destination) != WIKI_INPUT_ACCESS:
        return DeliveryDecision("rejected")
    return authorize_travel_dependency_payload(
        connection, context, space_id, region=region, traveler_class=traveler_class,
        check_authority=check_authority, resolve=resolve, seal=seal, excerpt_store=store,
    )


def authorize_travel_dependency_payload(
    connection: Connection, context: DeliveryContext, space_id: int,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    resolve: Callable[[Connection], tuple[tuple[UUID, int], ...]],
    seal: Callable[[Connection, DeliveryDecision], None] | None = None,
    build_payload: Callable[[], bytes] | None = None,
    excerpt_store: SyntheticOriginalStore | None = None,
) -> DeliveryDecision:
    access = (context.operation, context.purpose, context.destination)
    if access not in WIKI_DERIVED_ACCESS or not _require_ingress(connection, context, *access):
        return DeliveryDecision("rejected")
    if (excerpt_store is not None) != (access == WIKI_INPUT_ACCESS) or (
        (build_payload is None) != (access == WIKI_INPUT_ACCESS)
    ):
        raise ValueError("Workspace authorization must bind the actual payload for its operation.")
    if excerpt_store is not None and not issuer_matches_admission(context.authority_issuer, store_admission(excerpt_store)):
        return DeliveryDecision("rejected")
    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            business_day = _request_day(connection, context)
            if business_day is None:
                return DeliveryDecision("rejected")
            selection = _TravelSelection(space_id, business_day, region, traveler_class, allow_pdf=True, allow_docx_tables=True)
            references = resolve(connection)
            if not 1 <= len(references) <= 20 or len({ref for ref, _ in references}) != len(references):
                return DeliveryDecision("rejected")
            passages = {}
            located_parts = {}
            for ref, revision in references:
                _check_deadline(context.deadline)
                if ref not in located_parts:
                    located = _passage_version(connection, context.org_id, space_id, ref)
                    if located is None:
                        return DeliveryDecision("rejected")
                    matches = _load_document(
                        connection, context.org_id, selection, located[0],
                        passage_ref=ref, include_csv_units=True, authority_issuer=context.authority_issuer,
                    )
                    located_parts.update((match.location.passage_ref, match) for match in matches)
                part = located_parts.get(ref)
                if part is None or part.location.revision != revision:
                    return DeliveryDecision("rejected")
                has_physical_location = isinstance(part.location, EXACT_LOCATIONS)
                if access == WIKI_READ_ACCESS:
                    fields = PASSAGE_FIELDS
                else:
                    fields = WORKSPACE_EVIDENCE_FIELDS if has_physical_location else frozenset({"excerpt"})
                scope = EvidenceScope(space_id, part.version.source_id, ref, fields, revision if has_physical_location else None)
                passages[scope] = part
            covered = _covered_csv_cells(passages)
            docx_cells = _covered_docx_cells(passages)
            if any(
                (part.csv_units and part.location not in covered)
                or (part.docx_unit is not None and part.location not in docx_cells)
                for part in passages.values()
            ):
                return DeliveryDecision("rejected")
        eligibility = _assess_passages(
            connection, context, selection, passages, _encode_json([[str(ref), rev] for ref, rev in references]),
            check_authority, record=False,
        )
        if eligibility.status != "succeeded":
            return DeliveryDecision(eligibility.status)
        if eligibility.valid_until is None:
            return DeliveryDecision("dependency_unavailable")
        if excerpt_store is not None:
            cells = _read_csv_passages(excerpt_store, passages, eligibility.valid_until)
            cells.update(
                (member.part.location, member)
                for unit in _read_docx_units(excerpt_store, passages, eligibility.valid_until)
                for member in unit.values()
            )
            pdf_transcripts = resolve_pdf_transcripts(connection, tuple(
                part.location for part in passages.values() if isinstance(part.location, ApprovedPdfPage)
            ))
            checked_pdf_assets = set()
            excerpts = []
            for part in passages.values():
                _check_deadline(eligibility.valid_until)
                location, asset = part.location, part.version.asset
                if hit := cells.get(location):
                    excerpts.append({
                        "source_type": "docx" if isinstance(location, ApprovedDocxCell) else "csv",
                        "location": _cell_location(location, hit.cell_header),
                        "excerpt": hit.excerpt,
                    })
                elif isinstance(location, ApprovedPdfPage):
                    if asset not in checked_pdf_assets:
                        excerpt_store.read(asset)
                        checked_pdf_assets.add(asset)
                    excerpts.append({
                        "source_type": "pdf", "location": {"page": location.page_number},
                        "excerpt": pdf_transcripts[location].decode("utf-8"),
                    })
                elif isinstance(location, ApprovedStructuredPassage):
                    excerpt = resolve_structured_excerpt(excerpt_store.read(asset), part.version.media_type, location)
                    excerpts.append({
                        "source_type": MEDIA_SOURCE_TYPE.get(part.version.media_type, location.kind),
                        "location": {
                            "kind": location.kind,
                            "locator": location.structured_locator,
                            "heading_path": location.heading_path,
                            "paragraph": location.paragraph,
                        },
                        "excerpt": excerpt.decode("utf-8"),
                    })
                else:
                    excerpt = _extract_excerpt(excerpt_store.read(asset), location)
                    excerpts.append(excerpt.decode("utf-8"))
            payload = _encode_json(excerpts)
        else:
            payload = build_payload()
        if len(payload) > 1048576:
            return DeliveryDecision("rejected")
        return _assess_passages(
            connection, context, selection, passages, payload, check_authority, record=True, seal=seal,
        )
    except _ExpiredDelivery:
        return DeliveryDecision("rejected")
    except (Error, OriginalIntegrityError, UnicodeError):
        return DeliveryDecision("dependency_unavailable")


def search_travel(
    connection: Connection,
    context: DeliveryContext,
    space_id: int,
    query: str,
    store: SyntheticOriginalStore,
    *,
    region: str,
    traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    top_k: int = 5,
    include_wiki: bool = False,
    source_refs: frozenset[UUID] | None = None,
    include_source_facets: bool = False,
    departments: frozenset[str] | None = None,
    include_department_facets: bool = False,
    seal: Callable[[Connection, DeliveryDecision], None] | None = None,
    seal_scope: Callable[[Connection, bool, bool], None] | None = None,
    embedding_provider: EmbeddingProviderPort | None = None,
) -> DeliveryDecision:
    """Search a bounded corpus without exposing the unfiltered projection."""
    started = monotonic()
    if not issuer_matches_admission(context.authority_issuer, store_admission(store)):
        return DeliveryDecision("rejected")
    if not _require_ingress(connection, context, "search"):
        return DeliveryDecision("rejected")
    if (
        not 1 <= len(query) <= 1000 or type(top_k) is not int or not 1 <= top_k <= 20
        or type(include_wiki) is not bool or type(include_source_facets) is not bool
        or type(include_department_facets) is not bool
    ):
        raise ValueError("Invalid synthetic search query or result limit.")
    terms = frozenset(SEARCH_TERM.findall(lexical.normalize_text(query)))
    if not terms:
        raise ValueError("A synthetic search requires at least one term.")

    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            business_day = _request_day(connection, context)
            if business_day is None:
                return DeliveryDecision("rejected")
            selection = _TravelSelection(
                space_id, business_day, region, traveler_class, allow_pdf=True, allow_docx=True, allow_docx_tables=True,
            )
            candidates = _search_candidates(connection, context, selection)
            visibility_limited = source_refs is not None or departments is not None or (
                seal_scope is not None and _scope_has_hold(connection, context.org_id, space_id)
            )
        if candidates:
            eligibility_payload = _encode_json([
                [str(scope.object_id), passage.location.revision] for scope, passage in candidates.items()
            ])
            eligibility = _assess_passages(
                connection, context, selection, candidates, eligibility_payload, check_authority, record=False,
            )
            if eligibility.status == "rejected" and eligibility.denied_scopes:
                visibility_limited = True
                candidates = _filter_search_candidates(candidates, eligibility.denied_scopes)
            elif eligibility.status != "succeeded":
                return DeliveryDecision(eligibility.status)
        if source_refs is not None and candidates:
            candidates = _filter_search_sources(connection, context.org_id, space_id, candidates, source_refs)
        if departments is not None and candidates:
            candidates = _filter_search_departments(connection, context.org_id, space_id, candidates, departments)

        def seal_observation(transaction, *, empty):
            if seal_scope is not None:
                seal_scope(transaction, visibility_limited or _scope_has_hold(transaction, context.org_id, space_id), empty)

        def seal_result(transaction, decision):
            seal_observation(transaction, empty=False)
            if seal is not None:
                seal(transaction, decision)

        text_passages = {scope: part for scope, part in candidates.items() if not part.csv_units and part.docx_unit is None}
        wiki_delivery_enabled, lexical_index_mode, vector_model_id = _current_space_release_flags(
            connection, context.org_id, space_id,
        )
        search_terms, search_query = glossary.expand_query_terms(
            connection, context.org_id, space_id, query, terms,
        )
        scores = (
            lexical.score_indexed_passages(
                connection, context.org_id, space_id, tuple(part.location for part in text_passages.values()), search_terms,
            )
            if lexical_index_mode in {"indexed", "hybrid_vector"}
            else {}
        )
        active_embedder = None
        if lexical_index_mode == "hybrid_vector":
            if embedding_provider is not None:
                if vector_model_id is not None and embedding_provider.model_id != vector_model_id:
                    raise EmbeddingPortUnavailable(
                        "Configured embedding provider model_id does not match space vector_model_id."
                    )
                active_embedder = embedding_provider
            else:
                active_embedder = vector.resolve_synthetic_embedding_provider(vector_model_id)
        vector_scores = (
            vector.score_vector_passages(
                connection,
                context.org_id,
                space_id,
                tuple(part.location for part in text_passages.values()),
                search_query,
                active_embedder,
            )
            if active_embedder is not None and text_passages
            else {}
        )
        pdf_transcripts = resolve_pdf_transcripts(
            connection,
            tuple(part.location for part in text_passages.values() if isinstance(part.location, ApprovedPdfPage)),
        )
        matches = _search_matches(
            store, candidates, text_passages, search_terms, scores, vector_scores, pdf_transcripts, context.deadline,
        )
        ranked = _rank_search_passages(matches, top_k)
        originals = {hit.scope: hit.part for hit in ranked}
        visible = frozenset(scope.object_id for scope in originals)
        facet_dependencies = {}
        view = {
            "request_id": str(context.request_id), "business_date": business_day.isoformat(),
            "status": "hits", "passages": [
                _passage_view(hit.part, hit.excerpt, cell_header=hit.cell_header) for hit in ranked
            ],
            "wiki": [],
        }
        if include_source_facets or include_department_facets:
            facet_dependencies = {hit.scope: hit.part for _, _, group in matches for hit in group}
        if include_source_facets:
            view["source_facets"] = _source_facets(connection, context.org_id, space_id, facet_dependencies)
        if include_department_facets:
            view["department_facets"] = _department_facets(connection, context.org_id, space_id, facet_dependencies)
        dependencies = originals | facet_dependencies
        wiki = (
            _search_wiki(connection, context, selection, candidates, search_terms, check_authority)
            if include_wiki and wiki_delivery_enabled
            else None
        )
        if wiki is not None:
            try:
                wiki_citations = frozenset(UUID(ref) for claim in wiki.view["claims"] for ref in claim["passage_ids"])
                released = _assess_passages(
                    connection, context, selection, dependencies | wiki.dependencies,
                    _encode_json(view | {"wiki": [wiki.view]}), check_authority, record=True,
                    wiki_publication=wiki.publication, seal=seal_result,
                    visible_citations=visible | wiki_citations, source_facets=(include_source_facets or include_department_facets),
                )
            except _PublicationChanged:
                released = DeliveryDecision("input_changed")
            if released.status in {"succeeded", "dependency_unavailable"}:
                return released
        if not dependencies:
            with connection.transaction():
                connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                connection.execute("SET LOCAL synchronous_commit = on")
                if _request_day(connection, context, lock=True) != business_day:
                    return DeliveryDecision("rejected")
                _check_deadline(context.deadline)
                if not finish_open_request(
                    connection, context.org_id, context.request_id, "no_evidence", int((monotonic() - started) * 1000),
                ):
                    return DeliveryDecision("rejected")
                if seal_scope is not None:
                    seal_observation(connection, empty=True)
                    _check_deadline(context.deadline)
            return DeliveryDecision("no_evidence")
        decision = _assess_passages(
            connection, context, selection, dependencies, _encode_json(view), check_authority, record=True,
            visible_citations=visible, seal=seal_result, source_facets=(include_source_facets or include_department_facets),
        )
        if (include_source_facets or include_department_facets) and decision.status == "rejected":
            return DeliveryDecision("dependency_unavailable")
        return decision
    except (
        Error,
        AuthorizationUnavailable,
        EmbeddingPortUnavailable,
        OriginalIntegrityError,
        UnicodeError,
        _ExpiredDelivery,
        _SearchLimitExceeded,
    ):
        return DeliveryDecision("dependency_unavailable")


def _check_deadline(deadline: datetime):
    if datetime.now(UTC) >= deadline:
        raise _ExpiredDelivery


def _scope_has_hold(connection: Connection, org_id: int, space_id: int) -> bool:
    return connection.execute(
        "SELECT 1 FROM thalion.current_version_hold WHERE (org_id, space_id) = (%s, %s) AND action = 'establish' LIMIT 1",
        (org_id, space_id),
    ).fetchone() is not None


def _search_candidates(connection, context, selection):
    documents = connection.execute(
        """
        SELECT identity.public_id
        FROM thalion.document AS document
        JOIN thalion.source AS source ON source.source_id = document.source_id
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (document.org_id, document.space_id, document.identity_type, document.document_id)
        WHERE document.org_id = %s AND document.space_id = %s
          AND source.lifecycle = 'active' AND source.local_policy_revision IS NOT NULL
        ORDER BY identity.public_id LIMIT %s
        """,
        (context.org_id, selection.space_id, MAX_SEARCH_DOCUMENTS + 1),
    ).fetchall()
    if len(documents) > MAX_SEARCH_DOCUMENTS:
        raise _SearchLimitExceeded
    candidates = {}
    for (ref,) in documents:
        _check_deadline(context.deadline)
        for passage in _load_document(
            connection, context.org_id, selection, ref, include_csv_units=True,
            authority_issuer=context.authority_issuer,
        ):
            location = passage.location
            scope = EvidenceScope(
                selection.space_id, passage.version.source_id, location.passage_ref, PASSAGE_FIELDS,
                revision=location.revision if isinstance(location, EXACT_LOCATIONS) else None,
            )
            candidates[scope] = passage
        if len(candidates) > MAX_SEARCH_PASSAGES:
            raise _SearchLimitExceeded
    return candidates


def _source_refs(connection, org_id, space_id, source_ids):
    return dict(connection.execute(
        """
        SELECT object_id, public_id FROM thalion.object_identity
        WHERE (org_id, space_id, object_type) = (%s, %s, 'source') AND object_id = ANY(%s)
        """,
        (org_id, space_id, sorted(source_ids)),
    ))


def _filter_search_sources(connection, org_id, space_id, candidates, source_refs):
    refs = _source_refs(connection, org_id, space_id, {scope.source_id for scope in candidates})
    selected = {source_id for source_id, public_id in refs.items() if public_id in source_refs}
    return {scope: part for scope, part in candidates.items() if scope.source_id in selected}


def _source_facets(connection, org_id, space_id, dependencies):
    documents = {}
    for part in dependencies.values():
        version = part.version
        documents.setdefault(version.source_id, {})[version.document_ref] = version.title
    refs = _source_refs(connection, org_id, space_id, documents.keys())
    if documents.keys() != refs.keys():
        raise AuthorizationUnavailable("The matched source identifiers could not be resolved.")
    return [
        {"source_id": str(refs[source_id]), "example_title": min(titles.values()), "document_count": len(titles)}
        for source_id, titles in sorted(documents.items(), key=lambda entry: refs[entry[0]])
    ]


def _filter_search_departments(connection, org_id, space_id, candidates, departments):
    doc_refs = {part.version.document_ref for part in candidates.values()}
    assigned = department_store.list_departments_for_documents(connection, org_id, space_id, doc_refs)
    return {
        scope: part for scope, part in candidates.items()
        if part.version.document_ref in assigned and assigned[part.version.document_ref][0] in departments
    }


def _department_facets(connection, org_id, space_id, dependencies):
    doc_refs = {part.version.document_ref for part in dependencies.values()}
    assigned = department_store.list_departments_for_documents(connection, org_id, space_id, doc_refs)
    buckets: dict[str, tuple[str, set[UUID]]] = {}
    for doc_ref, (code, name) in assigned.items():
        existing = buckets.get(code)
        if existing is None:
            buckets[code] = (name, {doc_ref})
        else:
            existing[1].add(doc_ref)
    return [
        {"department_code": code, "department_name": name, "document_count": len(docs)}
        for code, (name, docs) in sorted(buckets.items())
    ]


def list_employee_discovery(
    connection: Connection, context: DeliveryContext, space_id: int, *, region: str, traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    prefix: str | None = None, source_ref: UUID | None = None, departments_only: bool = False,
) -> DeliveryDecision:
    if departments_only:
        access = EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS
    else:
        access = EMPLOYEE_SOURCE_OPTIONS_ACCESS if prefix is None else EMPLOYEE_TITLE_SUGGESTIONS_ACCESS
    if not _require_ingress(connection, context, *access):
        return DeliveryDecision("rejected")
    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            business_day = _request_day(connection, context, scope_space_id=space_id)
            if business_day is None:
                return DeliveryDecision("rejected")
            selection = _TravelSelection(
                space_id, business_day, region, traveler_class, allow_pdf=True, allow_docx=True, allow_docx_tables=True,
            )
            candidates = _search_candidates(connection, context, selection)
        if not candidates:
            return DeliveryDecision("no_evidence")
        eligibility = _assess_passages(connection, context, selection, candidates, None, check_authority, record=False)
        if eligibility.status == "rejected" and eligibility.denied_scopes:
            candidates = _filter_search_candidates(candidates, eligibility.denied_scopes)
        elif eligibility.status != "succeeded":
            return eligibility
        if not candidates:
            return DeliveryDecision("no_evidence")

        if departments_only:
            key = "departments"
            options, dependencies = _employee_department_options(connection, context.org_id, space_id, candidates)
        elif prefix is None:
            key = "options"
            options, dependencies = _employee_source_options(connection, context.org_id, space_id, candidates)
        else:
            key = "suggestions"
            if source_ref is not None:
                candidates = _filter_search_sources(connection, context.org_id, space_id, candidates, frozenset({source_ref}))
            options, dependencies = _title_suggestions(candidates, lexical.normalize_text(prefix))
        if not options:
            return DeliveryDecision("no_evidence")
        payload = _encode_json({
            "request_id": str(context.request_id), "business_date": business_day.isoformat(), key: options,
        })
        decision = _assess_passages(connection, context, selection, dependencies, payload, check_authority, record=True)
        return decision if decision.status == "succeeded" else DeliveryDecision("dependency_unavailable")
    except (Error, AuthorizationUnavailable, _ExpiredDelivery, _SearchLimitExceeded):
        return DeliveryDecision("dependency_unavailable")


def _employee_source_options(connection, org_id, space_id, candidates):
    examples = {}
    for scope, part in sorted(candidates.items(), key=lambda item: (
        item[1].version.title, item[1].version.document_ref, item[0].object_id,
    )):
        examples.setdefault(scope.source_id, (scope, part))
    refs = _source_refs(connection, org_id, space_id, examples.keys())
    if examples.keys() != refs.keys():
        raise AuthorizationUnavailable("The discoverable source identifiers could not be resolved.")
    options = [
        {"source_id": str(refs[source_id]), "example_title": part.version.title}
        for source_id, (_, part) in examples.items()
    ]
    dependencies = dict(examples.values())
    if any(part.csv_units or part.docx_unit is not None for part in dependencies.values()):
        dependencies = candidates
    return options, dependencies


def _employee_department_options(connection, org_id, space_id, candidates):
    doc_representatives: dict[UUID, tuple[EvidenceScope, _CurrentPassage]] = {}
    for scope, part in sorted(candidates.items(), key=lambda item: (
        item[1].version.document_ref, item[0].object_id,
    )):
        doc_representatives.setdefault(part.version.document_ref, (scope, part))
    assigned = department_store.list_departments_for_documents(connection, org_id, space_id, doc_representatives.keys())
    if not assigned:
        return [], {}
    buckets: dict[str, tuple[str, set[UUID]]] = {}
    dependencies = {}
    for doc_ref, (code, name) in assigned.items():
        scope, part = doc_representatives[doc_ref]
        dependencies[scope] = part
        existing = buckets.get(code)
        if existing is None:
            buckets[code] = (name, {doc_ref})
        else:
            existing[1].add(doc_ref)
    options = [
        {"department_code": code, "department_name": name, "document_count": len(docs)}
        for code, (name, docs) in sorted(buckets.items())
    ]
    if any(part.csv_units or part.docx_unit is not None for part in dependencies.values()):
        dependencies = candidates
    return options, dependencies


def _title_suggestions(candidates, prefix):
    matching = {
        scope: part for scope, part in candidates.items()
        if lexical.normalize_text(part.version.title).startswith(prefix)
    }
    locations = {part.location: (scope, part) for scope, part in matching.items()}
    csv_support = {}
    for unit in sorted(_complete_csv_units(matching), key=lambda unit: unit.unit_ref):
        cells = _primary_csv_cells(unit)
        for cell in cells:
            csv_support.setdefault(cell, cells)
    suggestions = []
    documents = set()
    dependencies = {}
    for scope, part in sorted(matching.items(), key=lambda item: (
        lexical.normalize_text(item[1].version.title), item[1].version.document_ref, item[0].object_id,
    )):
        document = part.version
        if document.document_ref in documents:
            continue
        if part.csv_units:
            cells = csv_support.get(part.location)
            if cells is None:
                continue
            support = dict(locations[cell] for cell in cells)
            ref = cells[0].passage_ref
        elif part.docx_unit is not None:
            cells = tuple(member.cell for member in part.docx_unit.members)
            if not all(cell in locations for cell in cells):
                continue
            support = dict(locations[cell] for cell in cells)
            ref = scope.object_id
        else:
            support = {scope: part}
            ref = scope.object_id
        if len(dependencies) + len(support) > MAX_TITLE_SUGGESTION_DEPENDENCIES:
            continue
        documents.add(document.document_ref)
        dependencies.update(support)
        suggestions.append({"title": document.title, "passage_id": str(ref)})
        if len(suggestions) == MAX_TITLE_SUGGESTIONS:
            break
    return suggestions, dependencies


def _complete_csv_units(candidates):
    members = {part.location for part in candidates.values() if part.csv_units}
    units = {unit.unit_ref: unit for part in candidates.values() for unit in part.csv_units}
    complete = []
    for unit in units.values():
        available = tuple(member for member in unit.members if member.cell in members)
        if {member.role for member in available} == {member.role for member in unit.members}:
            complete.append(replace(unit, members=available))
    return tuple(complete)


def _primary_csv_cells(unit):
    by_role = {}
    for member in unit.members:
        by_role.setdefault(member.role, member.cell)
    return tuple(by_role.values())


def _covered_csv_cells(candidates):
    return {member.cell for unit in _complete_csv_units(candidates) for member in unit.members}


def _covered_docx_cells(candidates):
    cells = {part.location for part in candidates.values() if part.docx_unit is not None}
    return {
        part.location for part in candidates.values()
        if part.docx_unit is not None and all(member.cell in cells for member in part.docx_unit.members)
    }


def _filter_search_candidates(candidates, denied):
    allowed = {scope: part for scope, part in candidates.items() if scope not in denied}
    covered = _covered_csv_cells(allowed)
    docx_cells = _covered_docx_cells(allowed)
    return {
        scope: part for scope, part in allowed.items()
        if (not part.csv_units or part.location in covered)
        and (part.docx_unit is None or part.location in docx_cells)
    }


def _search_matches(store, candidates, text_passages, terms, scores, vector_scores, pdf_transcripts, deadline):
    text_hits = list(_matching_passages(store, text_passages, terms, scores, vector_scores, pdf_transcripts, deadline))
    csv_hits = [(-score, key, group, None) for score, key, group in _matching_csv_units(store, candidates, terms, deadline)]
    docx_hits = [(-score, key, group, None) for score, key, group in _matching_docx_units(store, candidates, terms, deadline)]
    combined = text_hits + csv_hits + docx_hits
    if not vector_scores:
        return sorted(((-lex, key, group) for lex, key, group, _ in combined), key=lambda hit: hit[:2])
    lex_ranked = {
        key: rank
        for rank, (_, key, _, _) in enumerate(
            sorted((item for item in combined if item[0] > 0), key=lambda item: (-item[0], item[1])),
            start=1,
        )
    }
    vec_ranked = {
        key: rank
        for rank, (_, key, _, _) in enumerate(
            sorted((item for item in combined if item[3] is not None), key=lambda item: (-item[3], item[1])),
            start=1,
        )
    }
    fused = []
    for lex_score, key, group, vec_score in combined:
        rrf = 0.0
        if key in lex_ranked:
            rrf += 1.0 / (60.0 + lex_ranked[key])
        if key in vec_ranked:
            rrf += 0.9 / (60.0 + vec_ranked[key])
        fused.append((-round(rrf, 12), key, group))
    return sorted(fused, key=lambda hit: hit[:2])


def _rank_search_passages(matches, top_k):
    selected = {}
    for _, _, members in matches:
        new_members = {hit.scope: hit for hit in members if hit.scope not in selected}
        if len(selected) + len(new_members) <= top_k:
            selected.update(new_members)
        if len(selected) == top_k:
            break
    return tuple(selected.values())


def _matching_passages(store, candidates, terms, scores, vector_scores, pdf_transcripts, deadline):
    for asset, group in groupby(candidates.items(), key=lambda item: item[1].version.asset):
        _check_deadline(deadline)
        body = store.read(asset)
        members = tuple(group)
        paragraphs = tuple(part.location for _, part in members if isinstance(part.location, ApprovedDocxParagraph))
        docx_excerpts = resolve_docx_paragraphs(body, paragraphs) if paragraphs else {}
        structured_locs = tuple(part.location for _, part in members if isinstance(part.location, ApprovedStructuredPassage))
        structured_excerpts = (
            resolve_structured_excerpts(body, members[0][1].version.media_type, structured_locs)
            if structured_locs else {}
        )
        for scope, part in members:
            _check_deadline(deadline)
            indexed_score = scores.get(scope.object_id)
            vec_score = vector_scores.get(scope.object_id)
            if indexed_score == 0 and vec_score is None:
                continue
            location = part.location
            if isinstance(location, ApprovedPdfPage):
                excerpt = pdf_transcripts[location]
            elif isinstance(location, ApprovedDocxParagraph):
                excerpt = docx_excerpts[location]
            elif isinstance(location, ApprovedStructuredPassage):
                excerpt = structured_excerpts[location]
            else:
                excerpt = _extract_excerpt(body, location)
            text = excerpt.decode("utf-8")
            searchable = lexical.normalize_text(text)
            score = sum(term in searchable for term in terms)
            if indexed_score is not None and indexed_score != score:
                raise OriginalIntegrityError("The indexed score does not match the approved original.")
            if score or vec_score is not None:
                yield score, scope.object_id, (_MatchedPassage(scope, part, text),), vec_score


def _read_csv_passages(store, candidates, deadline):
    assets = {}
    for scope, part in candidates.items():
        if part.csv_units:
            assets.setdefault(part.version.asset, []).append((scope, part))
    hits = {}
    for asset, members in assets.items():
        _check_deadline(deadline)
        materials = resolve_csv_cells(store.read(asset), tuple(part.location for _, part in members))
        for (scope, part), (header, excerpt) in zip(members, materials, strict=True):
            hits[part.location] = _MatchedPassage(scope, part, excerpt, header)
    for unit in _complete_csv_units(candidates):
        _check_deadline(deadline)
        roles = {member.role: hits[member.cell].excerpt for member in unit.members}
        if set(roles) == set(AMOUNT_ROLES + EXCEPTION_LINK_ROLES):
            if roles["exception_ref"] != roles["exception_key"]:
                raise OriginalIntegrityError("CSV exception evidence must match the exact approved note key.")
        elif set(roles) != set(AMOUNT_ROLES):
            raise OriginalIntegrityError("Delivery requires a complete approved CSV evidence unit.")
    return hits


def _matching_csv_units(store, candidates, terms, deadline):
    groups = []
    selected = set()
    for unit in _complete_csv_units(candidates):
        _check_deadline(deadline)
        group = _primary_csv_cells(unit)
        groups.append(group)
        selected.update(group)
    hits = _read_csv_passages(
        store, {scope: part for scope, part in candidates.items() if part.location in selected}, deadline,
    )
    for cells in groups:
        _check_deadline(deadline)
        group = tuple(hits[cell] for cell in cells)
        searchable = tuple(lexical.normalize_text(f"{member.cell_header}\n{member.excerpt}") for member in group)
        score = sum(any(term in text for text in searchable) for term in terms)
        if score:
            yield -score, group[0].scope.object_id, group


def _read_docx_units(store, candidates, deadline):
    assets = {}
    positions = {}
    for scope, part in candidates.items():
        unit = part.docx_unit
        if unit is not None:
            assets.setdefault((part.version.asset, unit.amount_columns), {})[unit.unit_ref] = unit
            positions[part.location] = (scope, part)
    for (asset, _), scoped_units in assets.items():
        _check_deadline(deadline)
        units = tuple(scoped_units.values())
        if any(member.cell not in positions for unit in units for member in unit.members):
            raise OriginalIntegrityError("Delivery requires the complete authorized DOCX row.")
        materials = resolve_docx_units(store.read(asset), units)
        for unit in units:
            _check_deadline(deadline)
            cells = {member.role: member.cell for member in unit.members}
            matches = {}
            for role in AMOUNT_ROLES:
                cell = cells[role]
                header, excerpt = materials[cell]
                matches[role] = _MatchedPassage(*positions[cell], excerpt, header)
            yield matches


def _matching_docx_units(store, candidates, terms, deadline):
    for matches in _read_docx_units(store, candidates, deadline):
        group = tuple(matches.values())
        searchable = tuple(lexical.normalize_text(f"{member.cell_header}\n{member.excerpt}") for member in group)
        score = sum(any(term in text for text in searchable) for term in terms)
        if score:
            yield -score, group[0].scope.object_id, group


def _search_wiki(connection, context, selection, candidates, terms, check_authority) -> _WikiHit | None:
    if not candidates:
        return None
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        available = {
            (scope.space_id, scope.source_id, scope.object_id, part.location.revision, part.version.policy_revision,
             part.version.epochs.organization, part.version.epochs.space, part.version.epochs.source): (scope, part)
            for scope, part in candidates.items()
            if not isinstance(part.location, ApprovedDocxParagraph)
        }
        publications = projection.list_search_publications(
            connection, context.org_id, selection.space_id, selection.business_date, MAX_SEARCH_DOCUMENTS + 1,
        )
        if len(publications) > MAX_SEARCH_DOCUMENTS:
            raise _SearchLimitExceeded
        eligible = []
        for publication in publications:
            _check_deadline(context.deadline)
            required = projection.search_publication_dependencies(connection, publication)
            if required and all(entry in available for entry in required):
                eligible.append((publication, dict(available[entry] for entry in required)))
    best = None
    for publication, dependencies in eligible:
        checked = _assess_passages(
            connection, context, selection, dependencies,
            _encode_json({"wiki_revision": str(publication.revision_ref)}), check_authority, record=False,
        )
        if checked.status == "dependency_unavailable":
            raise AuthorizationUnavailable()
        if checked.status != "succeeded":
            continue
        _check_deadline(checked.valid_until)
        view = projection.load_search_fields(connection, publication)
        text = "\n".join([view["title"], *(claim["text"] for claim in view["claims"])])
        searchable = lexical.normalize_text(text)
        score = sum(term in searchable for term in terms)
        if score and (best is None or score > best.score):
            best = _WikiHit(publication, dependencies, view, score)
    return best


def _encode_json(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _cell_location(location: ApprovedCsvCell | ApprovedDocxCell, header: str | None) -> dict:
    if header is None:
        raise RuntimeError("A cell location requires the verified header of its authorized column.")
    columns = [{"column": location.column_number, "header": header}]
    if isinstance(location, ApprovedDocxCell):
        return {"heading_path": location.heading_path, "table": location.table_number, "row_id": location.row_number,
                "columns": columns}
    return {"row_id": location.record_number, "columns": columns}


def _passage_view(part: _CurrentPassage, excerpt: str, *, cell_header: str | None = None) -> dict:
    version, location = part.version, part.location
    if isinstance(location, ApprovedCsvCell):
        source_type, locator = "csv", _cell_location(location, cell_header)
    elif isinstance(location, ApprovedDocxCell):
        source_type, locator = "docx", _cell_location(location, cell_header)
    elif isinstance(location, ApprovedPdfPage):
        source_type, locator = "pdf", {"page": location.page_number}
    elif isinstance(location, ApprovedStructuredPassage):
        source_type = MEDIA_SOURCE_TYPE.get(version.media_type, location.kind)
        locator = {
            "kind": location.kind,
            "locator": location.structured_locator,
            "heading_path": location.heading_path,
            "paragraph": location.paragraph,
        }
    else:
        source_type = "docx" if isinstance(location, ApprovedDocxParagraph) else "markdown"
        locator = {"heading_path": location.heading_path, "paragraph": location.paragraph}
    return {
        "passage_id": str(location.passage_ref), "excerpt_revision": location.revision, "source_type": source_type,
        "title": version.title, "version_id": str(version.rule.version_ref), "version_label": version.version_label,
        "valid_from": version.rule.valid_from.isoformat(),
        "valid_until": version.rule.valid_to.isoformat() if version.rule.valid_to else None,
        "location": locator, "excerpt": excerpt,
    }


def _assess_passages(
    connection: Connection, context: DeliveryContext, selection: _TravelSelection,
    passages: Mapping[EvidenceScope, _CurrentPassage], payload: bytes | None,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision], *, record: bool,
    seal: Callable[[Connection, DeliveryDecision], None] | None = None,
    wiki_publication: projection.SearchPublication | None = None,
    visible_citations: frozenset[UUID] = frozenset(),
    recheck: Callable[[Connection], bool] | None = None,
    source_facets: bool = False,
) -> DeliveryDecision:
    model_space_id = selection.space_id if context.operation == MODEL_RULE_OPERATION else None
    prerequisite = (
        replace(context, operation=EMPLOYEE_PASSAGE_ACCESS[0], purpose=EMPLOYEE_PASSAGE_ACCESS[1],
                destination=EMPLOYEE_PASSAGE_ACCESS[2]) if model_space_id is not None else None
    )
    epochs = {scope: part.version.epochs for scope, part in passages.items()}
    exact_allows = frozenset(
        scope for scope, part in passages.items() if isinstance(part.location, EXACT_LOCATIONS)
    )
    changed = False
    try:
        with ExitStack() as transaction:
            def load_local(check):
                nonlocal changed
                transaction.enter_context(connection.transaction())
                lock_request = record or recheck is not None
                if lock_request:
                    connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                else:
                    connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                if record:
                    connection.execute("SET LOCAL synchronous_commit = on")
                _check_deadline(context.deadline)
                scope_space_id = selection.space_id if context.operation in {
                    EMPLOYEE_SOURCE_OPTIONS_ACCESS[0], EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS[0], EMPLOYEE_TITLE_SUGGESTIONS_ACCESS[0],
                } else None
                if _request_day(
                    connection, context, lock=lock_request, model_space_id=model_space_id, scope_space_id=scope_space_id,
                ) != selection.business_date or (
                    recheck is not None and not recheck(connection)
                ):
                    return LocalAuthorization(epochs, (), frozenset(epochs))
                current_epochs = {}
                bindings = []
                loaded_policies = set()
                scoped_groups = {}
                blocked = set()
                documents = {}
                for scope, expected in sorted(passages.items(), key=lambda item: item[1].version.document_ref):
                    _check_deadline(context.deadline)
                    ref = expected.version.document_ref
                    include_csv_units = context.operation in EMPLOYEE_DISCOVERY_OPERATIONS or bool(expected.csv_units)
                    exact = scope.object_id
                    if include_csv_units:
                        exact = None
                    elif expected.docx_unit is not None:
                        exact = expected.docx_unit.members[0].cell.passage_ref
                    lookup = (ref, exact)
                    if lookup not in documents:
                        current = _load_document(
                            connection, context.org_id, selection, ref,
                            passage_ref=exact, lock=record,
                            include_csv_units=include_csv_units,
                            authority_issuer=context.authority_issuer,
                        )
                        documents[lookup] = {part.location.passage_ref: part for part in current}
                    actual = documents[lookup].get(scope.object_id)
                    if actual is None or (actual.location, actual.csv_units, actual.docx_unit) != (
                        expected.location, expected.csv_units, expected.docx_unit
                    ) or (
                        actual.version.rule, actual.version.asset, actual.version.title, actual.version.version_label
                    ) != (
                        expected.version.rule, expected.version.asset, expected.version.title, expected.version.version_label
                    ):
                        changed = True
                        blocked.add(scope)
                        current_epochs[scope] = epochs[scope]
                        continue
                    current_epochs[scope] = actual.version.epochs
                    policy = (scope.space_id, scope.source_id, actual.version.policy_revision)
                    if policy not in loaded_policies:
                        loaded_policies.add(policy)
                        bindings.extend(_read_bindings(connection, context, *policy, lock=record))
                        if prerequisite is not None:
                            bindings.extend(_read_bindings(connection, prerequisite, *policy, lock=record))
                    source_key = (scope.space_id, scope.source_id)
                    if (
                        model_space_id is None
                        and context.operation in SHARED_GROUP_OPERATIONS
                        and source_key not in scoped_groups
                    ):
                        scoped_groups[source_key] = _active_shared_groups(
                            connection, context.org_id, scope.space_id, scope.source_id,
                            context.principal_id, lock=record, authority_issuer=context.authority_issuer,
                        )
                if (record and model_space_id is not None
                        and _request_day(connection, context, model_space_id=model_space_id) != selection.business_date):
                    return LocalAuthorization(epochs, (), frozenset(epochs))
                return LocalAuthorization(
                    current_epochs, tuple(bindings), frozenset(blocked), exact_allows,
                    scoped_subject_expiries=scoped_groups,
                )

            decision = authorize_delivery(
                context, DeliveryCandidate(payload or b"", epochs), check_authority=check_authority, load_local=load_local,
                local_prerequisite=EMPLOYEE_PASSAGE_ACCESS if prerequisite is not None else None,
            )
            if changed and context.operation in EMPLOYEE_DISCOVERY_OPERATIONS and decision.status == "rejected":
                return DeliveryDecision("input_changed")
            if not record:
                return decision
            if decision.status != "succeeded":
                return DeliveryDecision(decision.status)
            if payload is None:
                return DeliveryDecision("dependency_unavailable")
            if wiki_publication is not None and not projection.is_available_publication(
                connection, context.org_id, selection.space_id, wiki_publication.topic_key, wiki_publication.publication_ref,
            ):
                raise _PublicationChanged
            if not _record_delivery(
                connection, context, passages, decision, wiki_publication, visible_citations, source_facets=source_facets,
            ):
                return DeliveryDecision("rejected")
            if seal is not None:
                seal(connection, decision)
            if decision.valid_until is None:
                raise RuntimeError("A successful delivery requires a validity window.")
            _check_deadline(decision.valid_until)
    except _ExpiredDelivery:
        return DeliveryDecision("rejected")
    except Error:
        return DeliveryDecision("dependency_unavailable")
    if datetime.now(UTC) >= decision.valid_until:
        return DeliveryDecision("rejected")
    return decision


def _read_bindings(connection, context, space_id, source_id, revision, *, lock) -> tuple[PermissionBinding, ...]:
    policy_operation = {
        "search": "read_passage",
        EMPLOYEE_SOURCE_OPTIONS_ACCESS[0]: "read_passage",
        EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS[0]: "read_passage",
        EMPLOYEE_TITLE_SUGGESTIONS_ACCESS[0]: "read_passage",
        WIKI_CANDIDATE_ACCESS[0]: WIKI_INPUT_ACCESS[0],
        WIKI_PREVIEW_ACCESS[0]: WIKI_REVIEW_ACCESS[0],
        WIKI_ROLLBACK_ACCESS[0]: WIKI_PUBLISH_ACCESS[0],
        WIKI_READ_ACCESS[0]: "read_passage",
    }.get(context.operation, context.operation)
    target = "version_ref" if context.operation == ORIGINAL_DOWNLOAD_ACCESS[0] else "passage_ref"
    rows = connection.execute(
        f"""
        SELECT binding.{target}, binding.subject_id, binding.effect, binding.purpose,
               binding.destination, binding.fields, binding.valid_from, binding.valid_until, subject.disabled
        FROM thalion.permission_binding AS binding
        JOIN thalion.principal AS subject ON (subject.org_id, subject.principal_id)
          = (binding.org_id, binding.subject_id)
        WHERE (binding.org_id, binding.space_id, binding.source_id, binding.revision) = (%s, %s, %s, %s)
          AND binding.operation = %s AND subject.authority_issuer = %s
        ORDER BY subject.principal_id
        """ + (" FOR SHARE OF subject" if lock else ""),
        (context.org_id, space_id, source_id, revision, policy_operation, context.authority_issuer),
    ).fetchall()
    return tuple(
        PermissionBinding(
            context.org_id, space_id, source_id, passage_ref, subject, context.operation, effect,
            frozenset({purpose}), frozenset({destination}), frozenset(fields), start, end,
        )
        for passage_ref, subject, effect, purpose, destination, fields, start, end, disabled in rows if not disabled
    )


def _current_space_release_flags(connection: Connection, org_id: int, space_id: int) -> tuple[bool, str, str | None]:
    if connection.execute("SELECT to_regclass('thalion.space_release_config') IS NOT NULL").fetchone()[0] is not True:
        return True, "indexed", None
    has_vector_col = connection.execute(
        """
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'thalion' AND table_name = 'space_release_config'
              AND column_name = 'vector_model_id'
        )
        """,
    ).fetchone()[0]
    if has_vector_col:
        row = connection.execute(
            """
            SELECT wiki_delivery_enabled, lexical_index_mode, vector_model_id
            FROM thalion.current_space_release_config
            WHERE (org_id, space_id) = (%s, %s)
            """,
            (org_id, space_id),
        ).fetchone()
        if row is None:
            return True, "indexed", None
        return bool(row[0]), str(row[1]), row[2]
    row = connection.execute(
        """
        SELECT wiki_delivery_enabled, lexical_index_mode
        FROM thalion.current_space_release_config
        WHERE (org_id, space_id) = (%s, %s)
        """,
        (org_id, space_id),
    ).fetchone()
    if row is None:
        return True, "indexed", None
    return bool(row[0]), str(row[1]), None


def _active_shared_groups(
    connection: Connection, org_id: int, space_id: int, source_id: int, principal_id: int,
    *, lock: bool, authority_issuer: str = SYNTHETIC_ISSUER,
) -> dict[int, datetime]:
    if connection.execute("SELECT to_regclass('thalion.shared_group') IS NOT NULL").fetchone()[0] is not True:
        return {}
    lock_clause = " FOR SHARE OF grp, member, owner_space, group_principal, employee" if lock else ""
    rows = connection.execute(
        f"""
        SELECT grp.group_principal_id, LEAST(grp.expires_at, member.expires_at) AS effective_expiry
        FROM thalion.shared_group AS grp
        JOIN thalion.shared_group_member AS member
          ON (member.org_id, member.owner_space_id, member.group_ref)
           = (grp.org_id, grp.owner_space_id, grp.group_ref)
        JOIN thalion.space AS owner_space
          ON (owner_space.org_id, owner_space.space_id) = (grp.org_id, grp.owner_space_id)
        JOIN thalion.principal AS group_principal
          ON (group_principal.org_id, group_principal.principal_id) = (grp.org_id, grp.group_principal_id)
        JOIN thalion.principal AS employee
          ON (employee.org_id, employee.principal_id) = (member.org_id, member.member_principal_id)
        WHERE grp.org_id = %s
          AND grp.target_space_id = %s
          AND grp.target_source_id = %s
          AND member.member_principal_id = %s
          AND owner_space.lifecycle = 'active'
          AND group_principal.principal_type = 'group'
          AND group_principal.authority_issuer = %s
          AND NOT group_principal.disabled
          AND employee.principal_type = 'employee'
          AND employee.authority_issuer = %s
          AND NOT employee.disabled
          AND grp.starts_at <= clock_timestamp()
          AND clock_timestamp() < grp.expires_at
          AND member.starts_at <= clock_timestamp()
          AND clock_timestamp() < member.expires_at
          AND NOT EXISTS (
              SELECT 1 FROM thalion.shared_group_revocation AS rev
              WHERE rev.group_ref = grp.group_ref
          )
          AND NOT EXISTS (
              SELECT 1 FROM thalion.shared_group_member_revocation AS mrev
              WHERE mrev.membership_ref = member.membership_ref
          )
        ORDER BY grp.group_principal_id, member.membership_ref{lock_clause}
        """,
        (org_id, space_id, source_id, principal_id, authority_issuer, authority_issuer),
    ).fetchall()
    expiries: dict[int, datetime] = {}
    for group_principal_id, expiry in rows:
        current = expiries.get(group_principal_id)
        if current is None or expiry > current:
            expiries[group_principal_id] = expiry
    return expiries


def _record_delivery(
    connection: Connection, context: DeliveryContext, passages: Mapping[EvidenceScope, _CurrentPassage],
    decision: DeliveryDecision, wiki_publication: projection.SearchPublication | None,
    visible_citations: frozenset[UUID],
    *, source_facets: bool = False,
) -> bool:
    if (
        decision.check is None or decision.check.scopes != passages.keys() or decision.payload_sha256 is None
        or decision.authority_proof_ref is None or decision.checked_at is None or decision.valid_until is None
    ):
        raise RuntimeError("A successful evidence decision requires complete audit metadata.")
    facet_column, facet_value = (", source_facets", ", true") if source_facets else ("", "")
    saved = connection.execute(
        f"""
        INSERT INTO thalion.delivery_record (
            check_id, org_id, request_id, dependency_count, payload_digest, proof_digest, checked_at, valid_until,
            wiki_publication_ref{facet_column}
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s{facet_value})
        ON CONFLICT (org_id, request_id) DO NOTHING RETURNING check_id
        """,
        (
            decision.check.check_id, context.org_id, context.request_id, len(passages),
            bytes.fromhex(decision.payload_sha256), sha256(decision.authority_proof_ref.encode()).digest(),
            decision.checked_at, decision.valid_until, wiki_publication.publication_ref if wiki_publication else None,
        ),
    ).fetchone()
    if saved is None:
        return False
    if not visible_citations <= {scope.object_id for scope in passages}:
        raise _PublicationChanged
    with connection.cursor() as cursor:
        cursor.executemany(
            """
            INSERT INTO thalion.delivery_dependency (
                check_id, org_id, position, space_id, source_id, passage_ref, excerpt_revision,
                policy_revision, organization_epoch, space_epoch, source_epoch, effectivity_ref
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            [
                (saved[0], context.org_id, position, scope.space_id, scope.source_id, scope.object_id,
                 part.location.revision, part.version.policy_revision, part.version.epochs.organization,
                 part.version.epochs.space, part.version.epochs.source, part.version.rule.decision_ref)
                for position, (scope, part) in enumerate(passages.items(), 1)
            ],
        )
    if visible_citations:
        connection.execute(
            """
            INSERT INTO thalion.delivery_citation (check_id, position)
            SELECT part.check_id, part.position FROM thalion.delivery_dependency AS part
            JOIN thalion.request_record AS request ON (request.org_id, request.scope_space_id) = (part.org_id, part.space_id)
            WHERE part.check_id = %s AND request.request_id = %s AND part.passage_ref = ANY(%s)
            """, (saved[0], context.request_id, list(visible_citations)),
        )
    return True
