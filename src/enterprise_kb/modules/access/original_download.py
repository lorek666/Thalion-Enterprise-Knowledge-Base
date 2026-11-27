from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from time import monotonic
from uuid import UUID

from psycopg import Error

from enterprise_kb.modules.evidence.docx_evidence import MEDIA_TYPE as DOCX_MEDIA_TYPE
from enterprise_kb.modules.evidence import multiformat_evidence
from enterprise_kb.modules.sources.effectivity import select_rule
from enterprise_kb.modules.sources.originals import OriginalAsset, OriginalIntegrityError
from enterprise_kb.modules.sources.registry import (
    admission_for_issuer, issuer_matches_admission, storage_kind_for_admission, store_admission,
)
from enterprise_kb.runtime.audit import finish_open_request

from .delivery import (
    AuthorizationUnavailable, DeliveryCandidate, DeliveryDecision, EvidenceScope, LocalAuthorization, SafetyEpochs,
    authorize_delivery,
)
from .policy import ORIGINAL_DOWNLOAD_ACCESS, ORIGINAL_FIELDS
from .travel import (
    EMPLOYEE_PASSAGE_ACCESS,
    _ExpiredDelivery,
    _active_shared_groups,
    _check_deadline,
    _read_bindings,
    _request_day,
    _require_ingress,
)


NAMES = {
    "text/markdown": "original.md",
    "text/csv": "original.csv",
    "application/pdf": "original.pdf",
    DOCX_MEDIA_TYPE: "original.docx",
    multiformat_evidence.XLSX_MEDIA_TYPE: "original.xlsx",
    multiformat_evidence.PPTX_MEDIA_TYPE: "original.pptx",
    multiformat_evidence.HTML_MEDIA_TYPE: "original.html",
    multiformat_evidence.PNG_MEDIA_TYPE: "original.png",
    multiformat_evidence.JPEG_MEDIA_TYPE: "original.jpg",
}
MAX_PASSAGES = 1024


@dataclass(frozen=True)
class _Original:
    version_id: int
    source_id: int
    policy_revision: int
    epochs: SafetyEpochs
    asset: OriginalAsset
    media_type: str
    run_ref: UUID
    effectivity_ref: UUID
    passages: frozenset[UUID]


def _load(connection, context, space_id, version_ref, region, traveler_class, *, lock):
    day = _request_day(connection, context, lock=lock, scope_space_id=space_id)
    if day is None:
        return None
    expected_admission = admission_for_issuer(context.authority_issuer)
    if expected_admission is None:
        return None
    expected_storage_kind = storage_kind_for_admission(expected_admission)
    row = connection.execute("""
        SELECT version.version_id, document_ref.public_id, source.source_id, source.local_policy_revision,
               organization.safety_epoch, space.safety_epoch, source.safety_epoch,
               source.contract_revision, asset.storage_key, asset.content_digest, asset.byte_length, asset.media_type
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.document AS document
          ON (document.org_id, document.space_id, document.source_id, document.document_id)
           = (version.org_id, version.space_id, version.source_id, version.document_id)
        JOIN thalion.object_identity AS document_ref
          ON (document_ref.org_id, document_ref.space_id, document_ref.object_type, document_ref.object_id)
           = (document.org_id, document.space_id, document.identity_type, document.document_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id) = (version.org_id, version.space_id, version.source_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (version.org_id, version.space_id)
        JOIN thalion.organization AS organization ON organization.org_id = version.org_id
        JOIN thalion.asset AS asset ON asset.asset_id = version.asset_id
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
          AND contract.admission = %s AND asset.storage_kind = %s
          AND source.lifecycle = 'active' AND space.lifecycle = 'active' AND source.local_policy_revision IS NOT NULL
        """ + (" FOR SHARE OF organization, space, source, document" if lock else ""),
        (context.org_id, space_id, version_ref, expected_admission, expected_storage_kind),
    ).fetchone()
    if row is None or row[11] not in NAMES:
        return None
    if lock and _request_day(connection, context, scope_space_id=space_id) != day:
        return None
    version_id, document_ref, source_id, revision = row[:4]
    rule = select_rule(
        connection, context.org_id, space_id, document_ref, day, region=region,
        traveler_class=traveler_class, retained_version=version_ref,
    )
    if rule.status != "applicable":
        return None
    run = connection.execute("""
        SELECT run.run_ref
        FROM (
            SELECT run_ref, contract_revision FROM thalion.processing_run WHERE version_id = %s
            ORDER BY configuration_revision DESC LIMIT 1
        ) AS run
        WHERE run.contract_revision = %s
          AND EXISTS (SELECT 1 FROM thalion.quality_decision WHERE run_ref = run.run_ref AND outcome = 'approved')
          AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision WHERE run_ref = run.run_ref AND outcome = 'quarantined')
          AND NOT EXISTS (
              SELECT 1 FROM thalion.current_version_hold WHERE version_id = %s AND action = 'establish'
          )
        """, (version_id, row[7], version_id),
    ).fetchone()
    if run is None:
        return None
    passages = frozenset(ref for (ref,) in connection.execute("""
        SELECT identity.public_id
        FROM thalion.passage AS passage
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
        WHERE passage.version_id = %s LIMIT %s
        """, (version_id, MAX_PASSAGES + 1),
    ))
    if len(passages) > MAX_PASSAGES:
        raise AuthorizationUnavailable("The original's restriction scope exceeds the review bound.")
    return _Original(
        version_id, source_id, revision, SafetyEpochs(*row[4:7]), OriginalAsset(*row[8:11]),
        row[11], run[0], rule.decision_ref, passages,
    )


def _bindings(connection, context, scope, original, *, lock):
    args = (scope.space_id, scope.source_id, original.policy_revision)
    exact = _read_bindings(connection, context, *args, lock=lock)
    read_context = replace(
        context, operation=EMPLOYEE_PASSAGE_ACCESS[0], purpose=EMPLOYEE_PASSAGE_ACCESS[1],
        destination=EMPLOYEE_PASSAGE_ACCESS[2],
    )
    restrictions = _read_bindings(connection, read_context, *args, lock=lock)
    return exact + tuple(
        replace(binding, object_id=scope.object_id, operation=context.operation, fields=scope.fields)
        for binding in restrictions
        if binding.effect == "deny" and (binding.object_id is None or binding.object_id in original.passages)
    )


def download_original(
    connection, context, space_id, version_ref, store, *, region, traveler_class, check_authority,
    check_final_authority,
):
    if not issuer_matches_admission(context.authority_issuer, store_admission(store)):
        return DeliveryDecision("rejected"), None
    if not _require_ingress(connection, context, *ORIGINAL_DOWNLOAD_ACCESS):
        return DeliveryDecision("rejected"), None
    started = monotonic()
    args = (connection, context, space_id, version_ref, region, traveler_class)
    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            original = _load(*args, lock=False)
        if original is None:
            return DeliveryDecision("rejected"), None
        scope = EvidenceScope(space_id, original.source_id, version_ref, ORIGINAL_FIELDS)
        passages = frozenset(
            EvidenceScope(space_id, original.source_id, ref, frozenset({"excerpt"})) for ref in original.passages
        )
        dependencies = {scope: original.epochs}

        def check_complete_scope(check, authorize_source):
            expanded = replace(check, scopes=check.scopes | passages)
            authority = authorize_source(expanded)
            if authority.permitted_fields.keys() != expanded.scopes:
                raise AuthorizationUnavailable("The source did not check the complete original's restriction scope.")
            allowed = all(part.fields <= authority.permitted_fields[part] for part in expanded.scopes)
            return replace(authority, permitted_fields={scope: scope.fields if allowed else frozenset()})

        def authorize(payload, *, seal):
            with connection.transaction():
                if seal:
                    connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    connection.execute("SET LOCAL synchronous_commit = on")
                else:
                    connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                _check_deadline(context.deadline)
                current = _load(*args, lock=seal)
                if current != original:
                    return DeliveryDecision("rejected")
                rules = _bindings(connection, context, scope, current, lock=seal)
                groups = _active_shared_groups(
                    connection, context.org_id, scope.space_id, scope.source_id, context.principal_id, lock=seal,
                    authority_issuer=context.authority_issuer,
                )
                local = LocalAuthorization(
                    dependencies, rules, exact_allow_scopes=frozenset({scope}),
                    scoped_subject_expiries={(scope.space_id, scope.source_id): groups},
                )
                decision = authorize_delivery(
                    context, DeliveryCandidate(payload, dependencies),
                    check_authority=lambda check: check_complete_scope(
                        check, check_final_authority if seal else check_authority,
                    ),
                    load_local=lambda _: local,
                )
                if seal and decision.status == "succeeded":
                    _check_deadline(decision.valid_until)
                    _record(connection, context, scope, original, decision)
                    if not finish_open_request(
                        connection, context.org_id, context.request_id, "succeeded", int((monotonic() - started) * 1000),
                    ):
                        raise AuthorizationUnavailable("The original download audit could not be finalized.")
                    _check_deadline(decision.valid_until)
                return decision

        initial = authorize(b"", seal=False)
        if initial.status != "succeeded":
            return initial, None
        _check_deadline(initial.valid_until)
        decision = authorize(store.read(original.asset), seal=True)
        return decision, NAMES[original.media_type] if decision.status == "succeeded" else None
    except _ExpiredDelivery:
        return DeliveryDecision("rejected"), None
    except (Error, OriginalIntegrityError, AuthorizationUnavailable):
        return DeliveryDecision("dependency_unavailable"), None


def _record(connection, context, scope, original, decision):
    connection.execute("""
        INSERT INTO thalion.original_download_receipt (
            org_id, space_id, source_id, version_id, request_id, check_id, run_ref, effectivity_ref, policy_revision,
            organization_epoch, space_epoch, source_epoch, payload_digest, proof_digest, checked_at, valid_until
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
        context.org_id, scope.space_id, scope.source_id, original.version_id, context.request_id,
        decision.check.check_id, original.run_ref, original.effectivity_ref, original.policy_revision,
        original.epochs.organization, original.epochs.space, original.epochs.source,
        bytes.fromhex(decision.payload_sha256), sha256(decision.authority_proof_ref.encode()).digest(),
        decision.checked_at, decision.valid_until,
    ))
