from dataclasses import dataclass
from datetime import date
from typing import Literal
from uuid import UUID

from psycopg import Connection, errors

from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event

from .registry import (
    SYNTHETIC_ISSUER, SourceNotAdmitted, SourceWrite, _command, _digest, _validate_keys, sql_admitted_admission, sql_issuer_matches_admission,
    has_source_delete_isolation,
)


StopKind = Literal["suspended", "withdrawn"]
ConflictOutcome = Literal["prefer_new_replace", "keep_existing", "narrow_scope", "withdraw_candidate"]
APPROVE = "approve_effectivity"
PREVIEW = "preview_effectivity"
PREVIEW_STOP = "preview_rule_stop"
STOP = "stop_rule_use"
RECORD_CONFLICT = "record_effectivity_conflict"
LIST_CONFLICTS = "list_effectivity_conflicts"
RESOLVE_CONFLICT = "resolve_effectivity_conflict"
WRITE_OPERATIONS = frozenset({APPROVE, STOP, RECORD_CONFLICT, RESOLVE_CONFLICT})
READ_OPERATIONS = frozenset({PREVIEW, PREVIEW_STOP, LIST_CONFLICTS})
OPERATIONS = WRITE_OPERATIONS | READ_OPERATIONS
CONFLICT_OUTCOMES = frozenset({"prefer_new_replace", "keep_existing", "narrow_scope", "withdraw_candidate"})
DESTINATION = "internal_sources"


class EffectivityConflict(Exception):
    pass


@dataclass(frozen=True)
class Approval:
    valid_from: date
    valid_to: date | None
    region: str | None
    traveler_class: str | None
    basis_ref: UUID
    replaces_ref: UUID | None = None


@dataclass(frozen=True)
class PreviewRequest:
    valid_from: date
    valid_to: date | None
    region: str | None
    traveler_class: str | None
    replaces_ref: UUID | None = None


@dataclass(frozen=True)
class StopRequest:
    kind: StopKind
    basis_ref: UUID
    reason: str


@dataclass(frozen=True)
class ConflictRegistration:
    existing_decision_ref: UUID
    valid_from: date
    valid_to: date | None
    region: str | None
    traveler_class: str | None
    basis_ref: UUID
    summary: str


@dataclass(frozen=True)
class ConflictResolution:
    outcome: ConflictOutcome
    basis_ref: UUID
    conclusion: str
    linked_decision_ref: UUID | None = None


@dataclass(frozen=True)
class RuleSelection:
    status: Literal["applicable", "not_applicable", "ambiguous", "suspended", "withdrawn", "deletion_blocked"]
    version_ref: UUID | None = None
    decision_ref: UUID | None = None
    valid_from: date | None = None
    valid_to: date | None = None


def _lock_policy(
    connection: Connection, context: SourceWrite, space_id: int, version_ref: UUID, operation: str,
    *, for_update: bool = True,
):
    if connection.execute("SHOW transaction_isolation").fetchone() != ("read committed",):
        raise RuntimeError("Effectivity decisions require READ COMMITTED.")
    require_open_request(
        connection, context.org_id, context.request_id, context.principal_id, None,
        operation=operation,
    )
    lock_clause = "FOR UPDATE OF document" if for_update else "FOR SHARE OF document"
    scope = connection.execute(
        f"""
        SELECT version.org_id, version.space_id, version.source_id, version.document_id,
               version.version_id, source.contract_revision
        FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.identity_type, version.version_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.document AS document
          ON (document.org_id, document.space_id, document.source_id, document.document_id)
           = (version.org_id, version.space_id, version.source_id, version.document_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id)
           = (version.org_id, version.space_id, version.source_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS approver
          ON (approver.org_id, approver.principal_id) = (contract.org_id, contract.approver_id)
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
          AND approver.principal_id = %s
          AND {sql_issuer_matches_admission('approver.authority_issuer', 'contract.admission')}
          AND approver.principal_type = 'employee' AND NOT approver.disabled
          AND {sql_admitted_admission('contract.admission')}
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
        FOR SHARE OF source, space, approver
        {lock_clause}
        """,
        (context.org_id, space_id, version_ref, context.principal_id),
    ).fetchone()
    if scope is None:
        raise SourceNotAdmitted("Only the current synthetic policy approver may record this decision.")
    return scope


def _lock_document_policy_actor(
    connection: Connection, context: SourceWrite, space_id: int, document_ref: UUID, operation: str,
    *, for_update: bool = False,
):
    if connection.execute("SHOW transaction_isolation").fetchone() != ("read committed",):
        raise RuntimeError("Effectivity conflict actions require READ COMMITTED.")
    require_open_request(
        connection, context.org_id, context.request_id, context.principal_id, None,
        operation=operation,
    )
    lock_clause = "FOR UPDATE OF document" if for_update else "FOR SHARE OF document"
    scope = connection.execute(
        f"""
        SELECT document.org_id, document.space_id, document.source_id, document.document_id,
               source.contract_revision
        FROM thalion.object_identity AS identity
        JOIN thalion.document AS document
          ON (document.org_id, document.space_id, document.identity_type, document.document_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id)
           = (document.org_id, document.space_id, document.source_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS actor
          ON (actor.org_id, actor.principal_id) = (document.org_id, %s)
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
          AND {sql_issuer_matches_admission('actor.authority_issuer', 'contract.admission')}
          AND actor.principal_type = 'employee' AND NOT actor.disabled
          AND {sql_admitted_admission('contract.admission')}
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND (
              contract.approver_id = actor.principal_id
              OR EXISTS (
                  SELECT 1 FROM (
                      SELECT responsible_id, expires_at
                      FROM thalion.responsibility_assignment
                      WHERE (org_id, space_id, source_id, document_id)
                          = (document.org_id, document.space_id, document.source_id, document.document_id)
                      ORDER BY generation DESC LIMIT 1
                  ) AS latest
                  WHERE latest.responsible_id = actor.principal_id
                    AND (latest.expires_at IS NULL OR latest.expires_at > clock_timestamp())
              )
          )
        FOR SHARE OF source, space, actor
        {lock_clause}
        """,
        (context.principal_id, context.org_id, space_id, document_ref),
    ).fetchone()
    if scope is None:
        raise SourceNotAdmitted("Only the current policy approver or document responsible person may handle conflicts.")
    return scope


def _has_stop_reason_column(connection: Connection) -> bool:
    return bool(
        connection.execute(
            """
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'thalion' AND table_name = 'rule_use_stop' AND column_name = 'reason'
            """,
        ).fetchone()
    )


def _validate_reason_text(value: str, label: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text.")
    cleaned = value.strip()
    if not 1 <= len(cleaned) <= max_length:
        raise ValueError(f"{label} must be between 1 and {max_length} characters.")
    return cleaned


def _decision_result(receipt) -> UUID:
    if receipt.result_ref is None:
        raise RuntimeError("The policy decision did not return a reference.")
    return receipt.result_ref


def approve_synthetic_rule(
    connection: Connection, context: SourceWrite, space_id: int, version_ref: UUID,
    approval: Approval,
) -> UUID:
    _validate_keys(*(value for value in (approval.region, approval.traveler_class) if value is not None))
    if approval.valid_to is not None and approval.valid_from >= approval.valid_to:
        raise ValueError("The business interval must be nonempty and half-open.")
    operation = APPROVE
    digest = _digest(
        space_id, str(version_ref), approval.valid_from.isoformat(),
        approval.valid_to.isoformat() if approval.valid_to else None,
        approval.region, approval.traveler_class, str(approval.basis_ref),
        str(approval.replaces_ref) if approval.replaces_ref else None,
    )
    with connection.transaction():
        scope = _lock_policy(connection, context, space_id, version_ref, operation)

        def apply(transaction):
            try:
                decision_ref = transaction.execute(
                    """
                    INSERT INTO thalion.rule_effectivity (
                        org_id, space_id, source_id, document_id, version_id, contract_revision,
                        approved_by, basis_ref, region, traveler_class, valid_from, valid_to, replaces_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING decision_ref
                    """,
                    (
                        *scope, context.principal_id, approval.basis_ref, approval.region,
                        approval.traveler_class, approval.valid_from, approval.valid_to,
                        approval.replaces_ref,
                    ),
                ).fetchone()[0]
            except errors.CheckViolation:
                raise EffectivityConflict("The policy approval conflicts with the current decisions.") from None
            append_event(transaction, context.org_id, "sources.rule.approved", version_ref, space_id=space_id)
            return decision_ref

        return _decision_result(execute_command(
            connection, _command(context, operation, scope[-1], digest), apply,
        ))


def stop_synthetic_rule(
    connection: Connection, context: SourceWrite, space_id: int, version_ref: UUID,
    kind: StopKind, basis_ref: UUID,
    *, reason: str | None = None,
) -> UUID:
    if kind not in ("suspended", "withdrawn"):
        raise ValueError("Unknown rule stop decision.")
    cleaned_reason = _validate_reason_text(reason, "reason", 500) if reason is not None else None
    operation = STOP
    digest = (
        _digest(space_id, str(version_ref), kind, str(basis_ref))
        if cleaned_reason is None
        else _digest(space_id, str(version_ref), kind, str(basis_ref), cleaned_reason)
    )
    with connection.transaction():
        scope = _lock_policy(connection, context, space_id, version_ref, operation)
        has_reason_column = _has_stop_reason_column(connection)

        def apply(transaction):
            if has_reason_column:
                recorded = transaction.execute(
                    """
                    INSERT INTO thalion.rule_use_stop (
                        org_id, space_id, source_id, document_id, version_id, contract_revision,
                        decided_by, kind, basis_ref, reason
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (version_id, kind) DO NOTHING
                    RETURNING decision_ref
                    """,
                    (*scope, context.principal_id, kind, basis_ref, cleaned_reason),
                ).fetchone()
            else:
                recorded = transaction.execute(
                    """
                    INSERT INTO thalion.rule_use_stop (
                        org_id, space_id, source_id, document_id, version_id, contract_revision,
                        decided_by, kind, basis_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (version_id, kind) DO NOTHING
                    RETURNING decision_ref
                    """,
                    (*scope, context.principal_id, kind, basis_ref),
                ).fetchone()
            if recorded is None:
                if has_reason_column:
                    existing_ref, existing_basis, existing_reason = transaction.execute(
                        """
                        SELECT decision_ref, basis_ref, reason FROM thalion.rule_use_stop
                        WHERE org_id = %s AND version_id = %s AND kind = %s
                        """,
                        (context.org_id, scope[4], kind),
                    ).fetchone()
                else:
                    existing_ref, existing_basis = transaction.execute(
                        """
                        SELECT decision_ref, basis_ref FROM thalion.rule_use_stop
                        WHERE org_id = %s AND version_id = %s AND kind = %s
                        """,
                        (context.org_id, scope[4], kind),
                    ).fetchone()
                    existing_reason = None
                if existing_basis != basis_ref or (
                    cleaned_reason is not None and existing_reason != cleaned_reason
                ):
                    raise EffectivityConflict("The recorded stop decision cannot be rebound.")
                return existing_ref
            append_event(transaction, context.org_id, "sources.rule.stopped", version_ref, space_id=space_id)
            return recorded[0]

        return _decision_result(execute_command(
            connection, _command(context, operation, scope[-1], digest), apply,
        ))


def preview_synthetic_rule(
    connection: Connection, context: SourceWrite, space_id: int, version_ref: UUID,
    preview: PreviewRequest,
) -> dict:
    _validate_keys(*(value for value in (preview.region, preview.traveler_class) if value is not None))
    if preview.valid_to is not None and preview.valid_from >= preview.valid_to:
        raise ValueError("The business interval must be nonempty and half-open.")
    with connection.transaction():
        org_id, resolved_space_id, source_id, document_id, version_id, _ = _lock_policy(
            connection, context, space_id, version_ref, PREVIEW, for_update=False,
        )
        document_ref, = connection.execute(
            """
            SELECT public_id FROM thalion.object_identity
            WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'document', %s)
            """,
            (org_id, resolved_space_id, document_id),
        ).fetchone()
        stopped_row = connection.execute(
            """
            SELECT kind FROM thalion.rule_use_stop
            WHERE org_id = %s AND version_id = %s
            ORDER BY (kind = 'withdrawn') DESC LIMIT 1
            """,
            (org_id, version_id),
        ).fetchone()
        source_deleted = bool(
            has_source_delete_isolation(connection)
            and connection.execute(
                "SELECT thalion.document_source_deleted(%s, %s, %s, %s)",
                (org_id, resolved_space_id, source_id, document_id),
            ).fetchone()[0]
        )
        latest_run = connection.execute(
            """
            SELECT run.outcome,
                   EXISTS (
                       SELECT 1 FROM thalion.quality_decision AS dec
                       WHERE dec.run_ref = run.run_ref AND dec.outcome = 'approved'
                   ) AS is_approved,
                   EXISTS (
                       SELECT 1 FROM thalion.quality_decision AS dec
                       WHERE dec.run_ref = run.run_ref AND dec.outcome = 'quarantined'
                   ) AS is_quarantined
            FROM thalion.processing_run AS run
            WHERE (run.org_id, run.space_id, run.version_id) = (%s, %s, %s)
            ORDER BY run.configuration_revision DESC LIMIT 1
            """,
            (org_id, resolved_space_id, version_id),
        ).fetchone()
        if stopped_row is not None or source_deleted:
            processing_readiness = "stopped"
            insufficient_notice = "目标版本已被撤回、暂停或源端删除，不可作为有效生效依据。"
        elif latest_run is not None and latest_run[0] == "pending_review" and latest_run[1] and not latest_run[2]:
            processing_readiness = "ready"
            insufficient_notice = None
        elif latest_run is not None and (latest_run[0] == "quarantined" or latest_run[2]):
            processing_readiness = "quarantined"
            insufficient_notice = "目标版本解析结果已隔离，新版开始适用时将提示可用依据不足，不会回落旧规定。"
        else:
            processing_readiness = "pending_processing"
            insufficient_notice = "目标版本尚未完成解析与质控批准；若新版开始适用时仍待解析，系统将提示可用依据不足，不会回落旧规定。"

        replacement_status = "none"
        if preview.replaces_ref is not None:
            valid_replacement = connection.execute(
                """
                SELECT 1 FROM thalion.rule_interval AS previous
                WHERE (previous.org_id, previous.space_id, previous.source_id, previous.document_id, previous.decision_ref)
                    = (%s, %s, %s, %s, %s)
                  AND previous.region IS NOT DISTINCT FROM %s
                  AND previous.traveler_class IS NOT DISTINCT FROM %s
                  AND previous.version_id <> %s
                  AND previous.valid_from < %s
                  AND NOT EXISTS (
                      SELECT 1 FROM thalion.rule_effectivity AS successor
                      WHERE successor.replaces_ref = %s
                  )
                """,
                (
                    org_id, resolved_space_id, source_id, document_id, preview.replaces_ref,
                    preview.region, preview.traveler_class, version_id, preview.valid_from,
                    preview.replaces_ref,
                ),
            ).fetchone()
            replacement_status = "valid_replacement" if valid_replacement is not None else "invalid_replacement"

        overlapping_rows = connection.execute(
            """
            SELECT existing.decision_ref, ver_id.public_id, existing.region, existing.traveler_class,
                   existing.valid_from, existing.effective_to,
                   (existing.region IS NOT DISTINCT FROM %s
                    AND existing.traveler_class IS NOT DISTINCT FROM %s) AS exact_scope_match
            FROM thalion.rule_interval AS existing
            JOIN thalion.object_identity AS ver_id
              ON (ver_id.org_id, ver_id.space_id, ver_id.object_type, ver_id.object_id)
               = (existing.org_id, existing.space_id, 'document_version', existing.version_id)
            WHERE (existing.org_id, existing.space_id, existing.source_id, existing.document_id)
                = (%s, %s, %s, %s)
              AND existing.decision_ref IS DISTINCT FROM %s
              AND (existing.region IS NULL OR %s::text IS NULL OR existing.region = %s::text)
              AND (existing.traveler_class IS NULL OR %s::text IS NULL OR existing.traveler_class = %s::text)
              AND daterange(existing.valid_from, existing.effective_to, '[)')
                  && daterange(%s::date, %s::date, '[)')
            ORDER BY existing.valid_from ASC, existing.decision_ref ASC
            """,
            (
                preview.region, preview.traveler_class,
                org_id, resolved_space_id, source_id, document_id,
                preview.replaces_ref,
                preview.region, preview.region,
                preview.traveler_class, preview.traveler_class,
                preview.valid_from, preview.valid_to,
            ),
        ).fetchall()
        overlapping_decisions = [
            {
                "decision_id": str(dec_ref),
                "version_id": str(ver_ref),
                "region": region,
                "traveler_class": traveler_class,
                "valid_from": valid_from.isoformat(),
                "effective_to": effective_to.isoformat() if effective_to is not None else None,
                "overlap_kind": "exact_scope" if exact_match else "partial_scope_overlap",
            }
            for dec_ref, ver_ref, region, traveler_class, valid_from, effective_to, exact_match in overlapping_rows
        ]

        wiki_rows = connection.execute(
            """
            SELECT DISTINCT pub.topic_key, pub.publication_ref, pub.generation,
                   CASE
                       WHEN %s::uuid IS NOT NULL AND input.effectivity_ref = %s::uuid
                            AND input.business_date >= %s::date THEN 'will_invalidate_on_replace'
                       ELSE 'same_document_reference'
                   END AS impact_kind
            FROM thalion.available_wiki_publication AS pub
            JOIN thalion.wiki_published_input AS input
              ON (input.org_id, input.space_id, input.publication_ref)
               = (pub.org_id, pub.space_id, pub.publication_ref)
            JOIN thalion.document_version AS dep_ver
              ON (dep_ver.org_id, dep_ver.space_id, dep_ver.version_id)
               = (input.org_id, input.space_id, input.version_id)
            WHERE (pub.org_id, pub.space_id) = (%s, %s)
              AND dep_ver.document_id = %s
            ORDER BY pub.topic_key ASC, pub.publication_ref ASC
            """,
            (
                preview.replaces_ref, preview.replaces_ref, preview.valid_from,
                org_id, resolved_space_id, document_id,
            ),
        ).fetchall()
        affected_by_topic: dict[str, dict] = {}
        for topic_key, pub_ref, generation, impact_kind in wiki_rows:
            existing = affected_by_topic.get(topic_key)
            if existing is None or (
                existing["impact_kind"] != "will_invalidate_on_replace"
                and impact_kind == "will_invalidate_on_replace"
            ):
                affected_by_topic[topic_key] = {
                    "topic_key": topic_key,
                    "publication_id": str(pub_ref),
                    "generation": generation,
                    "impact_kind": impact_kind,
                }

        open_conflicts, = connection.execute(
            """
            SELECT count(*) FROM thalion.rule_effectivity_conflict AS conflict
            WHERE (conflict.org_id, conflict.space_id, conflict.source_id, conflict.document_id)
                = (%s, %s, %s, %s)
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.rule_effectivity_conflict_resolution AS res
                  WHERE res.conflict_ref = conflict.conflict_ref
              )
            """,
            (org_id, resolved_space_id, source_id, document_id),
        ).fetchone()

    return {
        "version_id": str(version_ref),
        "document_id": str(document_ref),
        "switch_date": preview.valid_from.isoformat(),
        "valid_to": preview.valid_to.isoformat() if preview.valid_to is not None else None,
        "region": preview.region,
        "traveler_class": preview.traveler_class,
        "processing_readiness": processing_readiness,
        "insufficient_evidence_notice": insufficient_notice,
        "replacement_status": replacement_status,
        "overlapping_decisions": overlapping_decisions,
        "affected_wiki_topics": list(affected_by_topic.values()),
        "open_conflict_count": open_conflicts,
    }


def preview_synthetic_rule_stop(
    connection: Connection, context: SourceWrite, space_id: int, version_ref: UUID,
    kind: StopKind = "withdrawn",
) -> dict:
    if kind not in ("suspended", "withdrawn"):
        raise ValueError("Unknown rule stop decision.")
    with connection.transaction():
        org_id, resolved_space_id, source_id, document_id, version_id, _ = _lock_policy(
            connection, context, space_id, version_ref, PREVIEW_STOP, for_update=False,
        )
        document_ref, = connection.execute(
            """
            SELECT public_id FROM thalion.object_identity
            WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'document', %s)
            """,
            (org_id, resolved_space_id, document_id),
        ).fetchone()
        already_stopped = bool(
            connection.execute(
                "SELECT 1 FROM thalion.rule_use_stop WHERE org_id = %s AND version_id = %s AND kind = %s",
                (org_id, version_id, kind),
            ).fetchone()
        )
        active_decisions = [
            {
                "decision_id": str(dec_ref),
                "region": region,
                "traveler_class": traveler_class,
                "valid_from": valid_from.isoformat(),
                "effective_to": effective_to.isoformat() if effective_to is not None else None,
            }
            for dec_ref, region, traveler_class, valid_from, effective_to in connection.execute(
                """
                SELECT decision_ref, region, traveler_class, valid_from, effective_to
                FROM thalion.rule_interval
                WHERE (org_id, space_id, source_id, document_id, version_id) = (%s, %s, %s, %s, %s)
                ORDER BY valid_from ASC, decision_ref ASC
                """,
                (org_id, resolved_space_id, source_id, document_id, version_id),
            ).fetchall()
        ]
        affected_wiki_topics = [
            {
                "topic_key": topic_key,
                "publication_id": str(pub_ref),
                "generation": generation,
                "impact_kind": f"will_stop_on_{kind}",
            }
            for topic_key, pub_ref, generation in connection.execute(
                """
                SELECT DISTINCT pub.topic_key, pub.publication_ref, pub.generation
                FROM thalion.available_wiki_publication AS pub
                JOIN thalion.wiki_published_input AS input
                  ON (input.org_id, input.space_id, input.publication_ref)
                   = (pub.org_id, pub.space_id, pub.publication_ref)
                WHERE (pub.org_id, pub.space_id) = (%s, %s)
                  AND input.version_id = %s
                ORDER BY pub.topic_key ASC
                """,
                (org_id, resolved_space_id, version_id),
            ).fetchall()
        ]
    return {
        "version_id": str(version_ref),
        "document_id": str(document_ref),
        "kind": kind,
        "already_stopped": already_stopped,
        "stops_passage_retrieval": True,
        "active_decisions": active_decisions,
        "affected_wiki_topics": affected_wiki_topics,
    }


def read_stop_affected_wiki_topics(connection: Connection, org_id: int, space_id: int, decision_ref: UUID) -> list[dict]:
    return [
        {
            "topic_key": topic_key,
            "publication_id": str(pub_ref),
            "generation": generation,
            "reason": reason,
        }
        for topic_key, pub_ref, generation, reason in connection.execute(
            """
            SELECT pub.topic_key, pub.publication_ref, pub.generation, avail.reason
            FROM thalion.wiki_availability_event AS avail
            JOIN thalion.wiki_publication_event AS pub
              ON (pub.org_id, pub.space_id, pub.publication_ref)
               = (avail.org_id, avail.space_id, avail.publication_ref)
            WHERE (avail.org_id, avail.space_id, avail.cause_ref) = (%s, %s, %s)
            ORDER BY pub.topic_key ASC, pub.publication_ref ASC
            """,
            (org_id, space_id, decision_ref),
        ).fetchall()
    ]


def record_synthetic_effectivity_conflict(
    connection: Connection, context: SourceWrite, space_id: int, version_ref: UUID,
    conflict: ConflictRegistration,
) -> dict:
    _validate_keys(*(value for value in (conflict.region, conflict.traveler_class) if value is not None))
    if conflict.valid_to is not None and conflict.valid_from >= conflict.valid_to:
        raise ValueError("The business interval must be nonempty and half-open.")
    summary = _validate_reason_text(conflict.summary, "summary", 500)
    digest = _digest(
        space_id, str(version_ref), str(conflict.existing_decision_ref),
        conflict.valid_from.isoformat(),
        conflict.valid_to.isoformat() if conflict.valid_to else None,
        conflict.region, conflict.traveler_class, str(conflict.basis_ref), summary,
    )
    with connection.transaction():
        scope = _lock_policy(connection, context, space_id, version_ref, RECORD_CONFLICT)
        org_id, resolved_space_id, source_id, document_id, version_id, contract_revision = scope
        document_ref, = connection.execute(
            """
            SELECT public_id FROM thalion.object_identity
            WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'document', %s)
            """,
            (org_id, resolved_space_id, document_id),
        ).fetchone()

        def apply(transaction):
            try:
                conflict_ref, = transaction.execute(
                    """
                    INSERT INTO thalion.rule_effectivity_conflict (
                        org_id, space_id, source_id, document_id, candidate_version_id,
                        existing_decision_ref, contract_revision, reported_by, basis_ref,
                        candidate_region, candidate_traveler_class, candidate_valid_from,
                        candidate_valid_to, summary
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING conflict_ref
                    """,
                    (
                        org_id, resolved_space_id, source_id, document_id, version_id,
                        conflict.existing_decision_ref, contract_revision, context.principal_id,
                        conflict.basis_ref, conflict.region, conflict.traveler_class,
                        conflict.valid_from, conflict.valid_to, summary,
                    ),
                ).fetchone()
            except (errors.CheckViolation, errors.ForeignKeyViolation):
                raise EffectivityConflict("The reported scope does not overlap an existing decision of this document.") from None
            append_event(transaction, org_id, "sources.rule.conflict_recorded", version_ref, space_id=resolved_space_id)
            return conflict_ref

        conflict_ref = _decision_result(execute_command(
            connection, _command(context, RECORD_CONFLICT, contract_revision, digest), apply,
        ))
    return {
        "conflict_id": str(conflict_ref),
        "document_id": str(document_ref),
        "candidate_version_id": str(version_ref),
        "existing_decision_id": str(conflict.existing_decision_ref),
        "status": "open",
    }


def list_synthetic_effectivity_conflicts(
    connection: Connection, context: SourceWrite, space_id: int, document_ref: UUID,
) -> dict:
    with connection.transaction():
        org_id, resolved_space_id, source_id, document_id, _ = _lock_document_policy_actor(
            connection, context, space_id, document_ref, LIST_CONFLICTS, for_update=False,
        )
        rows = connection.execute(
            """
            SELECT conflict.conflict_ref, ver_id.public_id, conflict.existing_decision_ref,
                   conflict.candidate_region, conflict.candidate_traveler_class,
                   conflict.candidate_valid_from, conflict.candidate_valid_to,
                   conflict.summary, conflict.recorded_at,
                   res.resolution_ref, res.outcome, res.conclusion, res.linked_decision_ref,
                   res.recorded_at
            FROM thalion.rule_effectivity_conflict AS conflict
            JOIN thalion.object_identity AS ver_id
              ON (ver_id.org_id, ver_id.space_id, ver_id.object_type, ver_id.object_id)
               = (conflict.org_id, conflict.space_id, 'document_version', conflict.candidate_version_id)
            LEFT JOIN thalion.rule_effectivity_conflict_resolution AS res
              ON res.conflict_ref = conflict.conflict_ref
            WHERE (conflict.org_id, conflict.space_id, conflict.source_id, conflict.document_id)
                = (%s, %s, %s, %s)
            ORDER BY conflict.recorded_at DESC, conflict.conflict_ref ASC
            """,
            (org_id, resolved_space_id, source_id, document_id),
        ).fetchall()
    conflicts = []
    for (
        conflict_ref, ver_ref, existing_dec, region, traveler_class,
        valid_from, valid_to, summary, recorded_at,
        res_ref, outcome, conclusion, linked_dec, resolved_at,
    ) in rows:
        conflicts.append({
            "conflict_id": str(conflict_ref),
            "candidate_version_id": str(ver_ref),
            "existing_decision_id": str(existing_dec),
            "candidate_region": region,
            "candidate_traveler_class": traveler_class,
            "candidate_valid_from": valid_from.isoformat(),
            "candidate_valid_to": valid_to.isoformat() if valid_to is not None else None,
            "summary": summary,
            "recorded_at": recorded_at.isoformat(),
            "status": "resolved" if res_ref is not None else "open",
            "resolution": None if res_ref is None else {
                "resolution_id": str(res_ref),
                "outcome": outcome,
                "conclusion": conclusion,
                "linked_decision_id": str(linked_dec) if linked_dec is not None else None,
                "recorded_at": resolved_at.isoformat(),
            },
        })
    return {"document_id": str(document_ref), "conflicts": conflicts}


def resolve_synthetic_effectivity_conflict(
    connection: Connection, context: SourceWrite, space_id: int, conflict_ref: UUID,
    resolution: ConflictResolution,
) -> dict:
    if resolution.outcome not in CONFLICT_OUTCOMES:
        raise ValueError("Unsupported effectivity conflict resolution outcome.")
    conclusion = _validate_reason_text(resolution.conclusion, "conclusion", 1000)
    digest = _digest(
        space_id, str(conflict_ref), resolution.outcome, str(resolution.basis_ref),
        conclusion, str(resolution.linked_decision_ref) if resolution.linked_decision_ref else None,
    )
    with connection.transaction():
        doc_row = connection.execute(
            """
            SELECT doc_id.public_id
            FROM thalion.rule_effectivity_conflict AS conflict
            JOIN thalion.object_identity AS doc_id
              ON (doc_id.org_id, doc_id.space_id, doc_id.object_type, doc_id.object_id)
               = (conflict.org_id, conflict.space_id, 'document', conflict.document_id)
            WHERE (conflict.org_id, conflict.space_id, conflict.conflict_ref) = (%s, %s, %s)
            """,
            (context.org_id, space_id, conflict_ref),
        ).fetchone()
        if doc_row is None:
            raise SourceNotAdmitted("The referenced effectivity conflict is not available in this space.")
        document_ref, = doc_row
        org_id, resolved_space_id, source_id, document_id, contract_revision = _lock_document_policy_actor(
            connection, context, space_id, document_ref, RESOLVE_CONFLICT, for_update=True,
        )

        def apply(transaction):
            try:
                resolution_ref, = transaction.execute(
                    """
                    INSERT INTO thalion.rule_effectivity_conflict_resolution (
                        conflict_ref, org_id, space_id, source_id, document_id,
                        contract_revision, decided_by, basis_ref, outcome, conclusion, linked_decision_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING resolution_ref
                    """,
                    (
                        conflict_ref, org_id, resolved_space_id, source_id, document_id,
                        contract_revision, context.principal_id, resolution.basis_ref,
                        resolution.outcome, conclusion, resolution.linked_decision_ref,
                    ),
                ).fetchone()
            except (errors.UniqueViolation, errors.CheckViolation):
                raise EffectivityConflict("The effectivity conflict is already resolved or linked decision is invalid.") from None
            append_event(transaction, org_id, "sources.rule.conflict_resolved", document_ref, space_id=resolved_space_id)
            return resolution_ref

        resolution_ref = _decision_result(execute_command(
            connection, _command(context, RESOLVE_CONFLICT, contract_revision, digest), apply,
        ))
    return {
        "resolution_id": str(resolution_ref),
        "conflict_id": str(conflict_ref),
        "document_id": str(document_ref),
        "outcome": resolution.outcome,
        "status": "resolved",
    }


def select_rule(
    connection: Connection, org_id: int, space_id: int, document_ref: UUID, business_date: date,
    *, region: str, traveler_class: str, retained_version: UUID | None = None,
) -> RuleSelection:
    """Resolve the business date, or the unambiguous past interval of a fixed citation version."""
    _validate_keys(region, traveler_class)
    condition, values = (
        ("daterange(rule.valid_from, rule.effective_to, '[)') @> %s::date", (business_date,))
        if retained_version is None else
        ("version_ref.public_id = %s AND rule.valid_from <= %s", (retained_version, business_date))
    )
    delete_block = (
        """
                   CASE
                       WHEN thalion.document_source_deleted(
                           rule.org_id, rule.space_id, rule.source_id, rule.document_id
                       ) THEN 'deletion_blocked'
                   END,
        """
        if has_source_delete_isolation(connection)
        else ""
    )
    matches = connection.execute(
        f"""
        SELECT version_ref.public_id, rule.decision_ref, rule.valid_from, rule.effective_to,
               COALESCE(
                   {delete_block}
                   stopped.kind,
                   CASE
                   WHEN source.lifecycle <> 'active' OR space.lifecycle <> 'active'
                       THEN 'suspended'
                   END
               )
        FROM thalion.object_identity AS document
        JOIN thalion.rule_interval AS rule
          ON (rule.org_id, rule.space_id, rule.document_id)
           = (document.org_id, document.space_id, document.object_id)
        JOIN thalion.object_identity AS version_ref
          ON (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id)
           = (rule.org_id, rule.space_id, 'document_version', rule.version_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id)
           = (rule.org_id, rule.space_id, rule.source_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (rule.org_id, rule.space_id)
        LEFT JOIN LATERAL (
            SELECT kind FROM thalion.rule_use_stop WHERE version_id = rule.version_id
            ORDER BY (kind = 'deletion_blocked') DESC, (kind = 'withdrawn') DESC LIMIT 1
        ) AS stopped ON true
        WHERE document.org_id = %s AND document.space_id = %s
          AND document.object_type = 'document' AND document.public_id = %s
          AND (rule.region IS NULL OR rule.region = %s)
          AND (rule.traveler_class IS NULL OR rule.traveler_class = %s)
          AND
        """ + condition + " LIMIT 2",
        (org_id, space_id, document_ref, region, traveler_class, *values),
    ).fetchall()
    if not matches:
        return RuleSelection("not_applicable")
    if len(matches) > 1:
        return RuleSelection("ambiguous")
    version_ref, decision_ref, valid_from, valid_to, stop = matches[0]
    if stop is not None:
        return RuleSelection(stop)
    return RuleSelection("applicable", version_ref, decision_ref, valid_from, valid_to)
