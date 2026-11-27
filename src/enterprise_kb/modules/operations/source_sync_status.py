from datetime import UTC
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.sources.registry import (
    has_source_delete_isolation, sql_admitted_admission, sql_issuer_matches_admission,
    storage_kind_for_admission,
)
from enterprise_kb.runtime.job_backlog import read_job_backlog

from .context import OperationsCall, OperationsNotAdmitted, require_current_scope, require_scope


READ = "read_source_sync_status"
DESTINATION = "internal_management"
VISIBLE_STAGES = ("parse", "synthetic_model_excerpts")


def require_source_owner(
    connection: Connection, call: OperationsCall, source_ref: UUID, space_owner: int,
) -> tuple[int, str, int, str]:
    if space_owner != call.principal_id:
        raise OperationsNotAdmitted("Source sync status requires the current space owner.")
    source = connection.execute(
        f"""
        SELECT source.source_id, source.lifecycle, source.contract_revision, contract.admission
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS owner
          ON (owner.org_id, owner.principal_id) = (source.org_id, source.owner_principal_id)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
          AND source.owner_principal_id = %s
          AND {sql_admitted_admission('contract.admission')}
          AND {sql_issuer_matches_admission('owner.authority_issuer', 'contract.admission')}
        FOR SHARE OF source
        """,
        (call.org_id, call.space_id, source_ref, call.principal_id),
    ).fetchone()
    if source is None:
        raise OperationsNotAdmitted("Source sync status requires the current synthetic source owner.")
    return source


def pin_release_scope(connection: Connection, call: OperationsCall, source_ref: UUID) -> int:
    return require_source_owner(
        connection, call, source_ref, require_current_scope(connection, call, READ, destination=DESTINATION),
    )[0]


def observe(connection: Connection, call: OperationsCall, source_ref: UUID) -> dict:
    source_id, lifecycle, contract_revision, admission = require_source_owner(
        connection, call, source_ref, require_scope(connection, call, READ, destination=DESTINATION),
    )
    observed_at, = connection.execute("SELECT statement_timestamp()").fetchone()
    contract_scope = (call.org_id, call.space_id, source_id, contract_revision)
    source_scope = (call.org_id, call.space_id, source_id)

    content_row = connection.execute(
        """
        SELECT sequence, through_cursor, item_count, committed_at
        FROM thalion.source_sync_page
        WHERE (org_id, space_id, source_id, contract_revision) = (%s, %s, %s, %s)
        ORDER BY sequence DESC LIMIT 1
        """,
        contract_scope,
    ).fetchone()
    content_sync = None if content_row is None else {
        "sequence": content_row[0],
        "through_cursor": str(content_row[1]),
        "item_count": content_row[2],
        "committed_at": content_row[3].astimezone(UTC).isoformat(),
    }

    inventory_row = connection.execute(
        """
        SELECT sequence, snapshot_ref, content_position, entry_count, matched_count, differences, committed_at
        FROM thalion.source_inventory_receipt
        WHERE (org_id, space_id, source_id, contract_revision) = (%s, %s, %s, %s)
        ORDER BY sequence DESC LIMIT 1
        """,
        contract_scope,
    ).fetchone()
    if inventory_row is None:
        inventory_reconciliation = None
    else:
        difference_counts = {
            "version_not_registered": 0,
            "digest_mismatch": 0,
            "not_enumerated": 0,
        }
        for detail in inventory_row[5]:
            kind = detail[3]
            if kind in difference_counts:
                difference_counts[kind] += 1
        inventory_reconciliation = {
            "sequence": inventory_row[0],
            "snapshot_ref": str(inventory_row[1]),
            "content_position": str(inventory_row[2]) if inventory_row[2] is not None else None,
            "entry_count": inventory_row[3],
            "matched_count": inventory_row[4],
            "difference_counts": difference_counts,
            "committed_at": inventory_row[6].astimezone(UTC).isoformat(),
        }

    checkpoint_row = connection.execute(
        """
        SELECT sequence, checkpoint_ref, contract_revision, authority_ref, authority_stream_ref,
               authority_generation, acknowledged_count, last_acknowledged_generation, committed_at
        FROM thalion.source_permission_checkpoint
        WHERE (org_id, space_id, source_id) = (%s, %s, %s)
        ORDER BY sequence DESC LIMIT 1
        """,
        source_scope,
    ).fetchone()
    permission_checkpoint = None if checkpoint_row is None else {
        "sequence": checkpoint_row[0],
        "checkpoint_ref": str(checkpoint_row[1]),
        "contract_revision": checkpoint_row[2],
        "authority_ref": str(checkpoint_row[3]),
        "authority_stream_ref": str(checkpoint_row[4]),
        "authority_generation": checkpoint_row[5],
        "acknowledged_count": checkpoint_row[6],
        "last_acknowledged_generation": checkpoint_row[7],
        "committed_at": checkpoint_row[8].astimezone(UTC).isoformat(),
    }

    restriction_row = connection.execute(
        """
        SELECT count(*)::integer,
               count(*) FILTER (WHERE kind = 'withdrawn')::integer,
               count(*) FILTER (WHERE kind = 'deleted')::integer,
               count(*) FILTER (WHERE kind = 'permission_revoked')::integer,
               max(committed_at),
               max(authority_generation) FILTER (WHERE kind = 'permission_revoked')
        FROM thalion.source_restriction_receipt
        WHERE (org_id, space_id, source_id) = (%s, %s, %s)
        """,
        source_scope,
    ).fetchone()
    restriction_receipts = {
        "total": restriction_row[0],
        "by_kind": {
            "withdrawn": restriction_row[1],
            "deleted": restriction_row[2],
            "permission_revoked": restriction_row[3],
        },
        "latest_committed_at": restriction_row[4].astimezone(UTC).isoformat() if restriction_row[4] is not None else None,
        "latest_authority_generation": restriction_row[5],
    }

    delete_clause = (
        "OR thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
        if has_source_delete_isolation(connection)
        else ""
    )
    processing_row = connection.execute(
        f"""
        WITH versions AS MATERIALIZED (
            SELECT version.org_id, version.space_id, version.version_id, version.contract_revision,
                   asset.storage_kind,
                   (
                       EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = version.version_id)
                      {delete_clause}
                       OR EXISTS (
                           SELECT 1 FROM thalion.current_version_hold AS hold
                           WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                               = (version.org_id, version.space_id, version.version_id, 'establish')
                       )
                   ) AS is_blocked
            FROM thalion.document_version AS version
            JOIN thalion.asset AS asset
              ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
               = (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
            WHERE (version.org_id, version.space_id, version.source_id) = (%s, %s, %s)
        ), current_runs AS MATERIALIZED (
            SELECT version.org_id, version.space_id, version.version_id, current.run_ref, current.outcome
            FROM versions AS version
            CROSS JOIN LATERAL (
                SELECT run_ref, contract_revision, outcome
                FROM thalion.processing_run
                WHERE version_id = version.version_id
                ORDER BY configuration_revision DESC LIMIT 1
            ) AS current
            WHERE NOT version.is_blocked
              AND version.storage_kind = %s
              AND current.contract_revision = %s
        ), ingest_counts AS (
            SELECT count(*) FILTER (WHERE item.status = 'rejected')::integer AS rejected_items,
                   count(*) FILTER (WHERE item.status = 'needs_confirmation')::integer AS confirmation_items
            FROM thalion.source_ingest_batch AS batch
            JOIN thalion.source_ingest_item AS item USING (org_id, space_id, batch_ref)
            WHERE (batch.org_id, batch.space_id, batch.source_id) = (%s, %s, %s)
        )
        SELECT (
            SELECT count(*)::integer FROM thalion.document
            WHERE (org_id, space_id, source_id) = (%s, %s, %s)
        ), (
            SELECT count(*)::integer FROM versions
        ), (
            SELECT count(*) FILTER (WHERE contract_revision = %s)::integer FROM versions
        ), (
            SELECT count(*) FILTER (WHERE is_blocked)::integer FROM versions
        ), (
            SELECT count(*)::integer FROM current_runs AS current
            WHERE current.outcome = 'pending_review'
              AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision WHERE run_ref = current.run_ref)
        ), (
            SELECT count(DISTINCT (correction.run_ref, correction.page_number))::integer
            FROM current_runs
            JOIN thalion.pdf_ocr_correction AS correction USING (org_id, space_id, run_ref)
            WHERE NOT EXISTS (
                SELECT 1 FROM thalion.pdf_ocr_review_decision WHERE correction_ref = correction.correction_ref
            ) AND NOT EXISTS (
                SELECT 1 FROM thalion.pdf_ocr_review_decision AS approved
                WHERE (approved.run_ref, approved.page_number, approved.outcome)
                    = (correction.run_ref, correction.page_number, 'approved')
            )
        ), (
            SELECT count(*)::integer FROM current_runs AS current
            WHERE current.outcome = 'quarantined'
               OR EXISTS (
                   SELECT 1 FROM thalion.quality_decision
                   WHERE run_ref = current.run_ref AND outcome = 'quarantined'
               )
        ), ingest_counts.rejected_items, ingest_counts.confirmation_items
        FROM ingest_counts
        """,
        (*source_scope, storage_kind_for_admission(admission), contract_revision, *source_scope, *source_scope, contract_revision),
    ).fetchone()
    processing_and_review = {
        "registered_documents": processing_row[0],
        "registered_versions": processing_row[1],
        "current_contract_versions": processing_row[2],
        "blocked_versions": processing_row[3],
        "pending_quality_reviews": processing_row[4],
        "pending_ocr_review_pages": processing_row[5],
        "quarantined_versions": processing_row[6],
        "rejected_ingest_items": processing_row[7],
        "needs_confirmation_ingest_items": processing_row[8],
    }

    jobs = read_job_backlog(
        connection, call.org_id, call.space_id, observed_at,
        visible_stages=VISIBLE_STAGES, include_estimate=False, source_id=source_id,
    )
    return {
        "observed_at": observed_at.astimezone(UTC).isoformat(),
        "source_id": str(source_ref),
        "lifecycle": lifecycle,
        "contract_revision": contract_revision,
        "admission": admission,
        "content_sync": content_sync,
        "inventory_reconciliation": inventory_reconciliation,
        "permission_checkpoint": permission_checkpoint,
        "restriction_receipts": restriction_receipts,
        "processing_and_review": processing_and_review,
        "job_backlog_by_stage": jobs["job_backlog_by_stage"],
        "job_throughput_by_stage": jobs["job_throughput_by_stage"],
    }
