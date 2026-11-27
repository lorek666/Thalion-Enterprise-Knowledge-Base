ALTER TABLE thalion.synthetic_export_request
    ADD COLUMN repair_history_digest bytea,
    ADD CHECK (repair_history_digest IS NULL OR (
        octet_length(repair_history_digest) = 32 AND transcript_run_ref IS NOT NULL
        AND rebuild_metadata_digest IS NULL AND wiki_publication_ref IS NULL AND wiki_rebuild_digest IS NULL
    ));

CREATE OR REPLACE FUNCTION thalion.current_export_transcript(scope_org bigint, scope_space bigint, target_version bigint)
RETURNS TABLE (run_ref uuid, configuration_revision bigint, manifest_digest bytea, passage_count integer)
LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT latest.run_ref, latest.configuration_revision, latest.manifest_digest, latest.passage_count
    FROM thalion.document_version AS version
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    CROSS JOIN LATERAL (
        SELECT run.run_ref, run.configuration_revision, run.manifest_digest, run.passage_count,
               run.contract_revision, run.outcome, run.replaces_run_ref, run.rollback_run_ref
        FROM thalion.processing_run AS run
        WHERE (run.org_id, run.space_id, run.version_id) = (version.org_id, version.space_id, version.version_id)
        ORDER BY run.configuration_revision DESC LIMIT 1
    ) AS latest
    WHERE (version.org_id, version.space_id, version.version_id) = (scope_org, scope_space, target_version)
      AND latest.contract_revision = source.contract_revision AND latest.outcome = 'pending_review'
      AND latest.passage_count BETWEEN 1 AND 128
      AND EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality
          WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'approved'
            AND (latest.replaces_run_ref IS NULL OR (
                quality.repair_preview_ref IS NOT NULL AND thalion.markdown_repair_admitted(
                    target_version, latest.configuration_revision, latest.replaces_run_ref, latest.rollback_run_ref, latest.run_ref
                )
            ))
      ) AND NOT EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'quarantined'
      );
$$;

CREATE OR REPLACE FUNCTION thalion.guard_export_transcript_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    candidate thalion.synthetic_export_request%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'synthetic_export_request' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO STRICT candidate FROM thalion.synthetic_export_request AS request
        WHERE (request.org_id, request.space_id, request.export_ref, request.requester_id) =
              (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
    END IF;
    IF candidate.transcript_run_ref IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM thalion.current_export_transcript(candidate.org_id, candidate.space_id, candidate.version_id) AS current_run
        JOIN thalion.processing_run AS run USING (run_ref)
        WHERE current_run.run_ref = candidate.transcript_run_ref
          AND (run.replaces_run_ref IS NULL) = (candidate.repair_history_digest IS NULL)
    ) THEN
        RAISE EXCEPTION 'archive transcript must remain approved with its enrolled repair history' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
