CREATE OR REPLACE FUNCTION thalion.current_export_transcript(scope_org bigint, scope_space bigint, target_version bigint)
RETURNS TABLE (run_ref uuid, configuration_revision bigint, manifest_digest bytea, passage_count integer)
LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT latest.run_ref, latest.configuration_revision, latest.manifest_digest, latest.passage_count
    FROM thalion.document_version AS version
    JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    CROSS JOIN LATERAL (
        SELECT run.run_ref, run.configuration_revision, run.manifest_digest, run.passage_count,
               run.contract_revision, run.outcome, run.replaces_run_ref, run.rollback_run_ref, run.pdf_page_count
        FROM thalion.processing_run AS run
        WHERE (run.org_id, run.space_id, run.version_id) = (version.org_id, version.space_id, version.version_id)
        ORDER BY run.configuration_revision DESC LIMIT 1
    ) AS latest
    WHERE (version.org_id, version.space_id, version.version_id) = (scope_org, scope_space, target_version)
      AND latest.contract_revision = source.contract_revision AND latest.outcome = 'pending_review'
      AND latest.passage_count BETWEEN 1 AND 128
      AND (asset.media_type = 'text/markdown' OR (asset.media_type = 'application/pdf' AND latest.pdf_page_count > 0))
      AND EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality
          WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'approved'
            AND (latest.replaces_run_ref IS NULL OR (
                latest.pdf_page_count IS NULL
                AND quality.repair_preview_ref IS NOT NULL AND thalion.markdown_repair_admitted(
                    target_version, latest.configuration_revision, latest.replaces_run_ref, latest.rollback_run_ref, latest.run_ref
                )
            ))
      ) AND NOT EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'quarantined'
      );
$$;

CREATE FUNCTION thalion.pdf_export_scope_admitted(candidate thalion.synthetic_export_request)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, thalion AS $$
    SELECT candidate.wiki_publication_ref IS NULL AND candidate.rebuild_metadata_digest IS NULL
       AND candidate.wiki_rebuild_digest IS NULL AND candidate.repair_history_digest IS NULL;
$$;

CREATE OR REPLACE FUNCTION thalion.guard_synthetic_export() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    candidate thalion.synthetic_export_request%ROWTYPE;
    target thalion.synthetic_original_export_target%ROWTYPE;
    recipient bigint := NEW.requester_id;
    result_actor bigint := NEW.requester_id;
    operation_name text := 'request_original_export';
BEGIN
    IF TG_TABLE_NAME = 'synthetic_export_request' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO STRICT candidate FROM thalion.synthetic_export_request AS request
        WHERE (request.org_id, request.space_id, request.export_ref, request.requester_id) =
              (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
        IF TG_TABLE_NAME = 'synthetic_export_approval' THEN
            result_actor := NEW.approver_id;
            operation_name := 'approve_original_export';
        ELSE
            operation_name := 'export_original_archive';
        END IF;
    END IF;
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, result_actor, operation_name
    ) THEN
        RAISE EXCEPTION 'original archive requires a matching open request' USING ERRCODE = '23514';
    END IF;
    PERFORM thalion.lock_synthetic_export_target(NEW.org_id, NEW.space_id, candidate.version_id);
    SELECT * INTO target FROM thalion.synthetic_original_export_target
    WHERE (org_id, space_id, version_id) = (NEW.org_id, NEW.space_id, candidate.version_id);
    IF NOT FOUND OR target.blocked OR target.snapshot <> candidate.snapshot
        OR target.owner_id <> recipient OR target.space_owner_id <> recipient
        OR (operation_name = 'approve_original_export' AND target.approver_id IS DISTINCT FROM result_actor)
        OR (target.media_type = 'application/pdf' AND NOT thalion.pdf_export_scope_admitted(candidate))
    THEN
        RAISE EXCEPTION 'original archive requires a current scoped version and independent authorization' USING ERRCODE = '23514';
    END IF;
    IF operation_name = 'export_original_archive' THEN
        IF NOT EXISTS (
            SELECT 1 FROM thalion.synthetic_export_approval AS approval
            JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (approval.org_id, approval.approver_id)
            WHERE approval.approval_ref = NEW.approval_ref AND approval.approver_id = target.approver_id
              AND NOT actor.disabled AND actor.principal_type = 'employee' AND actor.authority_issuer = 'https://synthetic.invalid'
              AND clock_timestamp() < least(approval.expires_at, NEW.authority_valid_until)
            FOR SHARE OF actor
        ) THEN
            RAISE EXCEPTION 'archive sealing requires live independent approval and authority' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
