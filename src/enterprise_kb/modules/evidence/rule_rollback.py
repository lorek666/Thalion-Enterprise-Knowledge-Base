from dataclasses import dataclass
from datetime import UTC, timedelta
import re
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus

from enterprise_kb.modules.evidence import docx_evidence, processing
from enterprise_kb.modules.sources.originals import ObjectStorageOriginalStore, SyntheticOriginalStore
from enterprise_kb.modules.sources.registry import (
    ADMITTED_ADMISSIONS, SourceWrite, _digest, has_source_delete_isolation,
    sql_admitted_admission, sql_admitted_issuer, sql_issuer_matches_admission,
    sql_issuers_same_mode, storage_matches_admission,
)
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import JobSpec, _require_read_committed, claim_job, enqueue_job


READ_IMPACT = "read_rule_impact"
PLAN_ROLLBACK = "plan_rule_rollback"
OPERATIONS = frozenset({READ_IMPACT, PLAN_ROLLBACK})
DESTINATION = "internal_management"
REASON_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
AUTO_ROLLBACK_MEDIA_TYPES = frozenset({"text/markdown", docx_evidence.MEDIA_TYPE})
MAX_IMPACT_ITEMS = 500
MAX_ROLLBACK_HISTORY = 50


class RuleRollbackNotAdmitted(Exception):
    pass


class RuleRollbackConflict(Exception):
    pass


@dataclass(frozen=True)
class _ScopeAccess:
    is_space_owner: bool
    reviewer_sources: frozenset[int]
    filter_source_id: int | None
    configuration_revision: int
    safety_epoch: int


@dataclass(frozen=True)
class RollbackExecutionItem:
    faulty_run_ref: UUID
    baseline_run_ref: UUID
    queued_job_id: UUID
    rollback_run_ref: UUID | None
    status: str


def _resolve_scope_access(
    connection: Connection, org_id: int, space_id: int, principal_id: int,
    *, source_ref: UUID | None = None, for_update: bool = False,
) -> _ScopeAccess:
    lock = "UPDATE" if for_update else "SHARE"
    row = connection.execute(
        f"""
        SELECT space.owner_principal_id = actor.principal_id, org.config_revision, space.safety_epoch
        FROM thalion.space AS space
        JOIN thalion.organization AS org USING (org_id)
        JOIN thalion.principal AS owner ON (owner.org_id, owner.principal_id) = (space.org_id, space.owner_principal_id)
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (space.org_id, %s)
        WHERE (space.org_id, space.space_id) = (%s, %s)
          AND space.lifecycle = 'active'
          AND actor.principal_type = 'employee'
          AND {sql_admitted_issuer('actor.authority_issuer')}
          AND {sql_issuers_same_mode('actor.authority_issuer', 'owner.authority_issuer')}
          AND NOT actor.disabled
        FOR SHARE OF org, actor
        FOR {lock} OF space
        """,
        (principal_id, org_id, space_id),
    ).fetchone()
    if row is None:
        raise RuleRollbackNotAdmitted("Active synthetic space principal is required.")
    is_space_owner, config_rev, safety_epoch = row
    reviewer_sources = frozenset(
        item[0]
        for item in connection.execute(
            f"""
            SELECT source.source_id
            FROM thalion.source AS source
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (source.org_id, source.space_id, source.source_id, source.contract_revision)
            JOIN thalion.principal AS reviewer
              ON (reviewer.org_id, reviewer.principal_id) = (contract.org_id, contract.quality_reviewer_id)
            WHERE (source.org_id, source.space_id) = (%s, %s)
              AND {sql_admitted_admission('contract.admission')}
              AND {sql_issuer_matches_admission('reviewer.authority_issuer', 'contract.admission')}
              AND contract.quality_reviewer_id = %s
              AND contract.processor_id IS DISTINCT FROM %s
            """,
            (org_id, space_id, principal_id, principal_id),
        ).fetchall()
    )
    if not is_space_owner and not reviewer_sources:
        raise RuleRollbackNotAdmitted("Caller is neither space owner nor a quality reviewer in this space.")
    filter_source_id: int | None = None
    if source_ref is not None:
        found = connection.execute(
            """
            SELECT source.source_id
            FROM thalion.object_identity AS identity
            JOIN thalion.source AS source
              ON (source.org_id, source.space_id, source.identity_type, source.source_id)
               = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
            WHERE identity.org_id = %s AND identity.space_id = %s
              AND identity.object_type = 'source' AND identity.public_id = %s
            """,
            (org_id, space_id, source_ref),
        ).fetchone()
        if found is None or (not is_space_owner and found[0] not in reviewer_sources):
            raise RuleRollbackNotAdmitted("Requested source is outside the caller's review scope.")
        filter_source_id = found[0]
    return _ScopeAccess(is_space_owner, reviewer_sources, filter_source_id, config_rev, safety_epoch)


def _find_baseline(connection: Connection, version_id: int, faulty_config: int, contract_rev: int, input_digest: bytes,
                   parser_version: str, profile: str, locator_revision: int) -> tuple[UUID, int] | None:
    row = connection.execute(
        """
        SELECT baseline.run_ref, baseline.configuration_revision
        FROM thalion.processing_run AS baseline
        JOIN thalion.processing_config_revision AS cfg USING (configuration_revision)
        WHERE baseline.version_id = %s
          AND baseline.configuration_revision < %s
          AND baseline.contract_revision = %s
          AND baseline.input_digest = %s
          AND baseline.outcome = 'pending_review'
          AND (cfg.parser_version, cfg.profile, cfg.locator_revision) = (%s, %s, %s)
          AND EXISTS (
              SELECT 1 FROM thalion.quality_decision
              WHERE run_ref = baseline.run_ref AND outcome = 'approved'
          )
          AND NOT EXISTS (
              SELECT 1 FROM thalion.quality_decision
              WHERE run_ref = baseline.run_ref AND outcome = 'quarantined'
          )
        ORDER BY baseline.configuration_revision DESC
        LIMIT 1
        """,
        (version_id, faulty_config, contract_rev, input_digest, parser_version, profile, locator_revision),
    ).fetchone()
    return (row[0], row[1]) if row is not None else None


def _query_rule_runs(
    connection: Connection, org_id: int, space_id: int, configuration_revision: int, access: _ScopeAccess,
    *, lock_versions: bool = False,
) -> tuple[dict | None, list[dict]]:
    rule_row = connection.execute(
        """
        SELECT configuration_revision, parser_version, profile, locator_revision
        FROM thalion.processing_config_revision
        WHERE configuration_revision = %s
        """,
        (configuration_revision,),
    ).fetchone()
    if rule_row is None:
        return None, []
    rule_rev, parser_version, profile, locator_revision = rule_row
    rule_meta = {
        "configuration_revision": rule_rev,
        "parser_version": parser_version,
        "profile": profile,
        "locator_revision": locator_revision,
    }
    delete_expr = (
        "thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
        if has_source_delete_isolation(connection)
        else "false"
    )
    source_filter = ""
    params: list = [org_id, space_id, configuration_revision]
    if access.filter_source_id is not None:
        source_filter = "AND version.source_id = %s"
        params.append(access.filter_source_id)
    elif not access.is_space_owner:
        source_filter = "AND version.source_id = ANY(%s)"
        params.append(sorted(access.reviewer_sources))
    lock_clause = "FOR UPDATE OF version" if lock_versions else ""
    rows = connection.execute(
        f"""
        SELECT run.run_ref, version.version_id, version.source_id, version.document_id,
               src_id.public_id AS source_ref, doc_id.public_id AS document_ref, ver_id.public_id AS version_ref,
               asset.media_type, asset.content_digest, run.outcome, run.contract_revision,
               source.contract_revision AS current_contract_revision,
               source.lifecycle, space.lifecycle, contract.admission, asset.storage_kind,
               contract.quality_reviewer_id, contract.processor_id,
               latest.run_ref AS latest_run_ref, latest.configuration_revision AS latest_config,
               EXISTS (
                   SELECT 1 FROM thalion.quality_decision q
                   WHERE q.run_ref = run.run_ref AND q.outcome = 'approved'
               ) AS has_approved,
               (
                   SELECT q.decision_ref FROM thalion.quality_decision q
                   WHERE q.run_ref = run.run_ref AND q.outcome = 'quarantined'
                   LIMIT 1
               ) AS quarantine_ref,
               EXISTS (
                   SELECT 1 FROM thalion.rule_effectivity eff
                   WHERE eff.version_id = version.version_id
               ) AS has_effectivity,
               EXISTS (
                   SELECT 1 FROM thalion.rule_use_stop stop
                   WHERE stop.version_id = version.version_id
               ) AS has_stop,
               {delete_expr} AS source_deleted,
               EXISTS (
                   SELECT 1 FROM thalion.current_version_hold hold
                   WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                       = (version.org_id, version.space_id, version.version_id, 'establish')
               ) AS has_hold,
               run.input_digest
        FROM thalion.processing_run AS run
        JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.object_identity AS src_id
          ON (src_id.org_id, src_id.space_id, src_id.object_type, src_id.object_id)
           = (source.org_id, source.space_id, 'source', source.source_id)
        JOIN thalion.object_identity AS doc_id
          ON (doc_id.org_id, doc_id.space_id, doc_id.object_type, doc_id.object_id)
           = (version.org_id, version.space_id, 'document', version.document_id)
        JOIN thalion.object_identity AS ver_id
          ON (ver_id.org_id, ver_id.space_id, ver_id.object_type, ver_id.object_id)
           = (version.org_id, version.space_id, 'document_version', version.version_id)
        CROSS JOIN LATERAL (
            SELECT r.run_ref, r.configuration_revision
            FROM thalion.processing_run AS r
            WHERE r.version_id = version.version_id
            ORDER BY r.configuration_revision DESC
            LIMIT 1
        ) AS latest
        WHERE (run.org_id, run.space_id, run.configuration_revision) = (%s, %s, %s)
          {source_filter}
        ORDER BY version.source_id, version.version_id, run.run_ref
        LIMIT %s
        {lock_clause}
        """,
        (*params, MAX_IMPACT_ITEMS),
    ).fetchall()

    run_refs = [row[0] for row in rows]
    wiki_by_run: dict[UUID, list[str]] = {ref: [] for ref in run_refs}
    if run_refs:
        wiki_rows = connection.execute(
            """
            SELECT DISTINCT wpi.run_ref, topic.wiki_ref
            FROM thalion.wiki_published_input AS wpi
            JOIN thalion.current_wiki_publication AS current
              USING (org_id, space_id, publication_ref)
            JOIN thalion.wiki AS topic
              ON (topic.org_id, topic.space_id, topic.topic_key)
               = (current.org_id, current.space_id, current.topic_key)
            WHERE (wpi.org_id, wpi.space_id) = (%s, %s)
              AND wpi.run_ref = ANY(%s)
            ORDER BY wpi.run_ref, topic.wiki_ref
            """,
            (org_id, space_id, run_refs),
        ).fetchall()
        for run_ref, wiki_ref in wiki_rows:
            wiki_by_run[run_ref].append(str(wiki_ref))

    rollback_by_run: dict[UUID, tuple[UUID | None, UUID | None]] = {}
    if run_refs:
        rb_rows = connection.execute(
            """
            SELECT DISTINCT ON (item.faulty_run_ref)
                   item.faulty_run_ref, item.queued_job_id, completed.run_ref
            FROM thalion.processing_rule_rollback_item AS item
            JOIN thalion.processing_rule_rollback AS rb USING (org_id, space_id, rollback_ref)
            LEFT JOIN thalion.processing_run AS completed
              ON (completed.org_id, completed.space_id, completed.version_id, completed.replaces_run_ref)
               = (item.org_id, item.space_id, item.version_id, item.faulty_run_ref)
             AND completed.rollback_run_ref = item.baseline_run_ref
            WHERE (item.org_id, item.space_id) = (%s, %s)
              AND item.faulty_run_ref = ANY(%s)
              AND item.action = 'queued_rollback'
            ORDER BY item.faulty_run_ref, rb.recorded_at DESC
            """,
            (org_id, space_id, run_refs),
        ).fetchall()
        for faulty_ref, job_id, completed_run in rb_rows:
            rollback_by_run[faulty_ref] = (job_id, completed_run)

    items = []
    for row in rows:
        (
            run_ref, version_id, source_id, document_id, source_ref, doc_ref, ver_ref,
            media_type, asset_digest, run_outcome, run_contract, current_contract,
            source_lifecycle, space_lifecycle, admission, storage_kind,
            quality_reviewer_id, processor_id, latest_run_ref, latest_config,
            has_approved, quarantine_ref, has_effectivity, has_stop, source_deleted,
            has_hold, input_digest,
        ) = row
        is_latest = latest_run_ref == run_ref
        if run_outcome == "quarantined":
            quality_status = "parse_quarantined"
        elif quarantine_ref is not None:
            quality_status = "quarantined"
        elif has_approved:
            quality_status = "approved"
        else:
            quality_status = "pending_review"

        baseline = _find_baseline(
            connection, version_id, configuration_revision, run_contract, input_digest,
            parser_version, profile, locator_revision,
        )
        reasons: list[str] = []
        if not is_latest:
            reasons.append("not_latest_run")
        if source_deleted:
            reasons.append("source_deleted")
        if has_stop:
            reasons.append("version_stopped")
        if has_hold:
            reasons.append("custody_hold")
        if (
            source_lifecycle != "active" or space_lifecycle != "active"
            or admission not in ADMITTED_ADMISSIONS or not storage_matches_admission(storage_kind, admission)
            or run_contract != current_contract or input_digest != asset_digest
            or run_outcome != "pending_review"
        ):
            reasons.append("scope_or_contract_changed")
        if media_type not in AUTO_ROLLBACK_MEDIA_TYPES:
            reasons.append("unsupported_media_type")
        if baseline is None:
            reasons.append("no_approved_baseline")
        if quarantine_ref is None and source_id not in access.reviewer_sources:
            reasons.append("requires_reviewer_quarantine")

        rb_job, rb_run = rollback_by_run.get(run_ref, (None, None))
        items.append({
            "_internal": {
                "version_id": version_id,
                "source_id": source_id,
                "document_id": document_id,
                "version_ref": ver_ref,
                "run_ref": run_ref,
                "input_digest": input_digest,
                "latest_config": latest_config,
                "quarantine_ref": quarantine_ref,
                "baseline_ref": baseline[0] if baseline is not None else None,
                "quality_reviewer_id": quality_reviewer_id,
                "processor_id": processor_id,
                "is_latest": is_latest,
                "source_deleted": source_deleted,
                "has_stop": has_stop,
                "has_hold": has_hold,
                "run_outcome": run_outcome,
                "scope_active": (
                    source_lifecycle == "active" and space_lifecycle == "active"
                    and admission in ADMITTED_ADMISSIONS and storage_matches_admission(storage_kind, admission)
                    and run_contract == current_contract and input_digest == asset_digest
                ),
            },
            "source_id": str(source_ref),
            "document_id": str(doc_ref),
            "version_id": str(ver_ref),
            "run_id": str(run_ref),
            "media_type": media_type,
            "run_outcome": run_outcome,
            "quality_status": quality_status,
            "is_latest_run": is_latest,
            "latest_configuration_revision": latest_config,
            "has_active_effectivity": has_effectivity,
            "stopped": has_stop,
            "source_deleted": source_deleted,
            "held": has_hold,
            "rollback_eligible": len(reasons) == 0,
            "baseline_run_id": str(baseline[0]) if baseline is not None else None,
            "baseline_configuration_revision": baseline[1] if baseline is not None else None,
            "ineligible_reasons": reasons,
            "affected_wiki_ids": wiki_by_run[run_ref],
            "rollback_job_id": str(rb_job) if rb_job is not None else None,
            "rollback_run_id": str(rb_run) if rb_run is not None else None,
        })
    return rule_meta, items


def list_rule_revisions(connection: Connection, org_id: int, space_id: int, principal_id: int) -> dict:
    access = _resolve_scope_access(connection, org_id, space_id, principal_id)
    source_filter = ""
    params: list = [org_id, space_id]
    if not access.is_space_owner:
        source_filter = "AND version.source_id = ANY(%s)"
        params.append(sorted(access.reviewer_sources))
    rows = connection.execute(
        f"""
        SELECT cfg.configuration_revision, cfg.parser_version, cfg.profile, cfg.locator_revision,
               count(*) AS run_count,
               count(*) FILTER (WHERE latest.run_ref = run.run_ref) AS latest_run_count,
               count(*) FILTER (
                   WHERE run.outcome = 'quarantined' OR EXISTS (
                       SELECT 1 FROM thalion.quality_decision q
                       WHERE q.run_ref = run.run_ref AND q.outcome = 'quarantined'
                   )
               ) AS quarantined_count
        FROM thalion.processing_run AS run
        JOIN thalion.processing_config_revision AS cfg USING (configuration_revision)
        JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
        CROSS JOIN LATERAL (
            SELECT r.run_ref FROM thalion.processing_run AS r
            WHERE r.version_id = run.version_id
            ORDER BY r.configuration_revision DESC LIMIT 1
        ) AS latest
        WHERE (run.org_id, run.space_id) = (%s, %s)
          {source_filter}
        GROUP BY cfg.configuration_revision, cfg.parser_version, cfg.profile, cfg.locator_revision
        ORDER BY cfg.configuration_revision DESC
        """,
        params,
    ).fetchall()
    revisions = [
        {
            "configuration_revision": rev,
            "parser_version": parser_ver,
            "profile": profile,
            "locator_revision": loc_rev,
            "run_count": run_count,
            "latest_run_count": latest_count,
            "quarantined_count": quarantined_count,
        }
        for rev, parser_ver, profile, loc_rev, run_count, latest_count, quarantined_count in rows
    ]
    rb_filter = ""
    rb_params: list = [org_id, space_id]
    if not access.is_space_owner:
        rb_filter = """
            AND EXISTS (
                SELECT 1 FROM thalion.processing_rule_rollback_item item
                WHERE item.rollback_ref = rb.rollback_ref AND item.source_id = ANY(%s)
            )
        """
        rb_params.append(sorted(access.reviewer_sources))
    rb_rows = connection.execute(
        f"""
        SELECT rb.rollback_ref, rb.faulty_configuration_revision, rb.target_configuration_revision,
               rb.reason_code, rb.quarantined_count, rb.queued_count, rb.skipped_count, rb.recorded_at
        FROM thalion.processing_rule_rollback AS rb
        WHERE (rb.org_id, rb.space_id) = (%s, %s)
          {rb_filter}
        ORDER BY rb.recorded_at DESC, rb.rollback_ref DESC
        LIMIT %s
        """,
        (*rb_params, MAX_ROLLBACK_HISTORY),
    ).fetchall()
    rollbacks = [
        {
            "rollback_id": str(rb_ref),
            "faulty_configuration_revision": faulty_cfg,
            "target_configuration_revision": target_cfg,
            "reason_code": reason_code,
            "quarantined_count": q_cnt,
            "queued_count": queue_cnt,
            "skipped_count": skip_cnt,
            "recorded_at": recorded_at.astimezone(UTC).isoformat(),
        }
        for rb_ref, faulty_cfg, target_cfg, reason_code, q_cnt, queue_cnt, skip_cnt, recorded_at in rb_rows
    ]
    return {"role": "owner" if access.is_space_owner else "reviewer", "revisions": revisions, "rollbacks": rollbacks}


def read_rule_impact(
    connection: Connection, org_id: int, space_id: int, principal_id: int, configuration_revision: int,
    *, source_ref: UUID | None = None,
) -> dict:
    if type(configuration_revision) is not int or configuration_revision < 1:
        raise ValueError("Configuration revision must be a positive integer.")
    access = _resolve_scope_access(connection, org_id, space_id, principal_id, source_ref=source_ref)
    rule_meta, raw_items = _query_rule_runs(connection, org_id, space_id, configuration_revision, access)
    if rule_meta is None:
        raise RuleRollbackConflict("The requested processing configuration revision does not exist.")
    public_items = [{k: v for k, v in item.items() if k != "_internal"} for item in raw_items]
    affected_wikis = sorted({wiki for item in public_items for wiki in item["affected_wiki_ids"]})
    summary = {
        "total_runs": len(public_items),
        "latest_runs": sum(1 for item in public_items if item["is_latest_run"]),
        "rollback_eligible": sum(1 for item in public_items if item["rollback_eligible"]),
        "stopped_or_deleted": sum(1 for item in public_items if item["stopped"] or item["source_deleted"]),
        "held": sum(1 for item in public_items if item["held"]),
        "affected_wikis": affected_wikis,
    }
    return {"rule": rule_meta, "summary": summary, "items": public_items}


def _load_rollback_receipt(connection: Connection, org_id: int, space_id: int, rollback_ref: UUID) -> dict:
    header = connection.execute(
        """
        SELECT rollback_ref, faulty_configuration_revision, target_configuration_revision,
               reason_code, basis_ref, quarantined_count, queued_count, skipped_count, recorded_at
        FROM thalion.processing_rule_rollback
        WHERE (org_id, space_id, rollback_ref) = (%s, %s, %s)
        """,
        (org_id, space_id, rollback_ref),
    ).fetchone()
    if header is None:
        raise RuntimeError("Rollback receipt could not be reloaded.")
    rb_ref, faulty_cfg, target_cfg, reason_code, basis_ref, q_cnt, queue_cnt, skip_cnt, recorded_at = header
    item_rows = connection.execute(
        """
        SELECT src_id.public_id, ver_id.public_id, item.faulty_run_ref, item.baseline_run_ref,
               item.action, item.skip_reason, item.quarantine_decision_ref, item.queued_job_id
        FROM thalion.processing_rule_rollback_item AS item
        JOIN thalion.object_identity AS src_id
          ON (src_id.org_id, src_id.space_id, src_id.object_type, src_id.object_id)
           = (item.org_id, item.space_id, 'source', item.source_id)
        JOIN thalion.object_identity AS ver_id
          ON (ver_id.org_id, ver_id.space_id, ver_id.object_type, ver_id.object_id)
           = (item.org_id, item.space_id, 'document_version', item.version_id)
        WHERE (item.org_id, item.space_id, item.rollback_ref) = (%s, %s, %s)
        ORDER BY item.source_id, item.version_id, item.faulty_run_ref
        """,
        (org_id, space_id, rollback_ref),
    ).fetchall()
    return {
        "rollback_id": str(rb_ref),
        "faulty_configuration_revision": faulty_cfg,
        "target_configuration_revision": target_cfg,
        "reason_code": reason_code,
        "basis_id": str(basis_ref),
        "quarantined_count": q_cnt,
        "queued_count": queue_cnt,
        "skipped_count": skip_cnt,
        "recorded_at": recorded_at.astimezone(UTC).isoformat(),
        "items": [
            {
                "source_id": str(src_ref),
                "version_id": str(ver_ref),
                "faulty_run_id": str(faulty_ref),
                "baseline_run_id": str(base_ref) if base_ref is not None else None,
                "action": action,
                "skip_reason": skip_reason,
                "quarantine_decision_id": str(q_ref) if q_ref is not None else None,
                "queued_job_id": str(job_id) if job_id is not None else None,
            }
            for src_ref, ver_ref, faulty_ref, base_ref, action, skip_reason, q_ref, job_id in item_rows
        ],
    }


def plan_rule_rollback(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    faulty_configuration_revision: int,
    reason_code: str,
    basis_ref: UUID,
    *,
    source_ref: UUID | None = None,
    target_configuration_revision: int | None = None,
    quarantine_ineligible: bool = True,
) -> dict:
    if (
        type(faulty_configuration_revision) is not int or faulty_configuration_revision < 1
        or not isinstance(reason_code, str) or REASON_PATTERN.fullmatch(reason_code) is None
        or (target_configuration_revision is not None
            and (type(target_configuration_revision) is not int or target_configuration_revision <= faulty_configuration_revision))
    ):
        raise ValueError("Invalid rule rollback arguments.")
    with connection.transaction():
        _require_read_committed(connection)
        require_open_request(
            connection, context.org_id, context.request_id, context.principal_id, None, operation=PLAN_ROLLBACK,
        )
        access = _resolve_scope_access(
            connection, context.org_id, space_id, context.principal_id, source_ref=source_ref, for_update=True,
        )
        space_ref = connection.execute(
            """
            SELECT public_id FROM thalion.object_identity
            WHERE org_id = %s AND space_id = %s AND object_type = 'space' AND object_id = %s
            """,
            (context.org_id, space_id, space_id),
        ).fetchone()[0]
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, PLAN_ROLLBACK,
            context.idempotency_key, _digest(
                space_id, faulty_configuration_revision, target_configuration_revision,
                str(source_ref) if source_ref is not None else None,
                reason_code, str(basis_ref), bool(quarantine_ineligible),
            ), access.configuration_revision, access.safety_epoch,
        )

        def apply(transaction):
            rule_meta, raw_items = _query_rule_runs(
                transaction, context.org_id, space_id, faulty_configuration_revision, access, lock_versions=True,
            )
            if rule_meta is None:
                raise RuleRollbackConflict("The faulty processing configuration revision does not exist.")
            if not raw_items:
                raise RuleRollbackConflict("No processing runs match this configuration revision in scope.")

            eligible_items = [item for item in raw_items if item["rollback_eligible"]]
            chosen_target: int | None = None
            if eligible_items:
                max_latest = max(item["_internal"]["latest_config"] for item in eligible_items)
                if target_configuration_revision is not None:
                    existing_target = transaction.execute(
                        """
                        SELECT parser_version, profile, locator_revision
                        FROM thalion.processing_config_revision
                        WHERE configuration_revision = %s
                        """,
                        (target_configuration_revision,),
                    ).fetchone()
                    if (
                        existing_target is None
                        or target_configuration_revision <= max_latest
                        or existing_target != (
                            rule_meta["parser_version"], rule_meta["profile"], rule_meta["locator_revision"],
                        )
                    ):
                        raise RuleRollbackConflict("Requested target configuration revision is incompatible or not newer.")
                    chosen_target = target_configuration_revision
                else:
                    transaction.execute("LOCK TABLE thalion.processing_config_revision IN EXCLUSIVE MODE")
                    next_rev = transaction.execute(
                        "SELECT coalesce(max(configuration_revision), 0) + 1 FROM thalion.processing_config_revision"
                    ).fetchone()[0]
                    chosen_target = max(next_rev, max_latest + 1)
                    transaction.execute(
                        """
                        INSERT INTO thalion.processing_config_revision
                            (configuration_revision, parser_version, profile, locator_revision)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            chosen_target, rule_meta["parser_version"], rule_meta["profile"],
                            rule_meta["locator_revision"],
                        ),
                    )

            planned_rows = []
            quarantined_now = 0
            queued_count = 0
            skipped_count = 0

            for item in raw_items:
                meta = item["_internal"]
                quarantine_ref = meta["quarantine_ref"]
                can_reviewer_quarantine = (
                    quarantine_ref is None
                    and meta["is_latest"]
                    and meta["scope_active"]
                    and meta["run_outcome"] == "pending_review"
                    and not meta["source_deleted"]
                    and not meta["has_stop"]
                    and not meta["has_hold"]
                    and meta["source_id"] in access.reviewer_sources
                )
                if item["rollback_eligible"]:
                    if quarantine_ref is None:
                        quarantine_ref = transaction.execute(
                            """
                            INSERT INTO thalion.quality_decision (
                                org_id, space_id, version_id, run_ref, reviewer_id, request_id, basis_ref, outcome
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'quarantined')
                            RETURNING decision_ref
                            """,
                            (
                                context.org_id, space_id, meta["version_id"], meta["run_ref"],
                                context.principal_id, context.request_id, basis_ref,
                            ),
                        ).fetchone()[0]
                        append_event(
                            transaction, context.org_id, "evidence.quality.decided",
                            meta["version_ref"], space_id=space_id,
                        )
                        quarantined_now += 1
                    job_id = enqueue_job(
                        transaction,
                        JobSpec(
                            context.org_id, space_id, meta["version_ref"], "parse",
                            meta["input_digest"], chosen_target,
                        ),
                        request_id=context.request_id,
                    )
                    queued_count += 1
                    planned_rows.append((
                        meta["source_id"], meta["version_id"], meta["run_ref"], meta["baseline_ref"],
                        "queued_rollback", None, quarantine_ref, job_id,
                    ))
                else:
                    if quarantine_ineligible and can_reviewer_quarantine:
                        quarantine_ref = transaction.execute(
                            """
                            INSERT INTO thalion.quality_decision (
                                org_id, space_id, version_id, run_ref, reviewer_id, request_id, basis_ref, outcome
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'quarantined')
                            RETURNING decision_ref
                            """,
                            (
                                context.org_id, space_id, meta["version_id"], meta["run_ref"],
                                context.principal_id, context.request_id, basis_ref,
                            ),
                        ).fetchone()[0]
                        append_event(
                            transaction, context.org_id, "evidence.quality.decided",
                            meta["version_ref"], space_id=space_id,
                        )
                        quarantined_now += 1
                    skipped_count += 1
                    planned_rows.append((
                        meta["source_id"], meta["version_id"], meta["run_ref"], meta["baseline_ref"],
                        "skipped", item["ineligible_reasons"][0], quarantine_ref, None,
                    ))

            rollback_ref = transaction.execute(
                """
                INSERT INTO thalion.processing_rule_rollback (
                    org_id, space_id, faulty_configuration_revision, target_configuration_revision,
                    actor_id, request_id, basis_ref, reason_code,
                    quarantined_count, queued_count, skipped_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING rollback_ref
                """,
                (
                    context.org_id, space_id, faulty_configuration_revision, chosen_target,
                    context.principal_id, context.request_id, basis_ref, reason_code,
                    quarantined_now, queued_count, skipped_count,
                ),
            ).fetchone()[0]
            for src_id, ver_id, f_ref, b_ref, act, skip_r, q_ref, j_id in planned_rows:
                transaction.execute(
                    """
                    INSERT INTO thalion.processing_rule_rollback_item (
                        rollback_ref, org_id, space_id, source_id, version_id,
                        faulty_run_ref, baseline_run_ref, action, skip_reason,
                        quarantine_decision_ref, queued_job_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (rollback_ref, context.org_id, space_id, src_id, ver_id, f_ref, b_ref, act, skip_r, q_ref, j_id),
                )
            append_event(
                transaction, context.org_id, "evidence.rule_rollback.planned", space_ref, space_id=space_id,
            )
            return rollback_ref

        receipt = execute_command(connection, command, apply)
        if receipt.result_ref is None:
            raise RuntimeError("Rule rollback did not produce a receipt.")
        return _load_rollback_receipt(connection, context.org_id, space_id, receipt.result_ref)


def execute_rule_rollback(
    connection: Connection, org_id: int, space_id: int, rollback_ref: UUID, store: SyntheticOriginalStore,
    *, lease_duration: timedelta = timedelta(minutes=5),
) -> list[RollbackExecutionItem]:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Rule rollback execution must start outside an open transaction.")
    with connection.transaction():
        rows = connection.execute(
            """
            SELECT item.faulty_run_ref, item.baseline_run_ref, item.queued_job_id,
                   rb.basis_ref, asset.media_type, contract.processor_id,
                   thalion.docx_run_has_cells(item.faulty_run_ref)
                       OR thalion.docx_run_has_cells(item.baseline_run_ref) AS has_docx_cells
            FROM thalion.processing_rule_rollback_item AS item
            JOIN thalion.processing_rule_rollback AS rb USING (org_id, space_id, rollback_ref)
            JOIN thalion.document_version AS version
              ON (version.org_id, version.space_id, version.version_id)
               = (item.org_id, item.space_id, item.version_id)
            JOIN thalion.asset AS asset
              ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
               = (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
            JOIN thalion.source AS source
              ON (source.org_id, source.space_id, source.source_id)
               = (version.org_id, version.space_id, version.source_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (source.org_id, source.space_id, source.source_id, source.contract_revision)
            WHERE (item.org_id, item.space_id, item.rollback_ref) = (%s, %s, %s)
              AND item.action = 'queued_rollback'
            ORDER BY item.source_id, item.version_id, item.faulty_run_ref
            """,
            (org_id, space_id, rollback_ref),
        ).fetchall()
    results: list[RollbackExecutionItem] = []
    for faulty_ref, baseline_ref, job_id, basis_ref, media_type, processor_id, has_docx_cells in rows:
        if processor_id is None:
            results.append(RollbackExecutionItem(faulty_ref, baseline_ref, job_id, None, "no_processor"))
            continue
        lease = claim_job(connection, org_id, "parse", processor_id, lease_duration, job_id=job_id)
        if lease is None:
            existing = connection.execute(
                """
                SELECT result_ref, state FROM thalion.job
                WHERE (org_id, space_id, job_id) = (%s, %s, %s)
                """,
                (org_id, space_id, job_id),
            ).fetchone()
            if existing is not None and existing[1] == "succeeded":
                results.append(RollbackExecutionItem(faulty_ref, baseline_ref, job_id, existing[0], "already_completed"))
            else:
                results.append(RollbackExecutionItem(faulty_ref, baseline_ref, job_id, None, "not_claimable"))
            continue
        if media_type == docx_evidence.MEDIA_TYPE:
            res = processing.repair_docx_job(
                connection, lease, store, replaces=faulty_ref, rollback_to=baseline_ref,
                basis_ref=basis_ref, allow_tables=bool(has_docx_cells),
            )
        elif media_type == "text/markdown":
            res = processing.repair_markdown_job(
                connection, lease, store, replaces=faulty_ref, rollback_to=baseline_ref, basis_ref=basis_ref,
            )
        else:
            results.append(RollbackExecutionItem(faulty_ref, baseline_ref, job_id, None, "unsupported_media_type"))
            continue
        results.append(RollbackExecutionItem(faulty_ref, baseline_ref, job_id, res.run_ref, "pending_review"))
    return results
