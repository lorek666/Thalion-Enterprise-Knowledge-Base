ALTER TABLE thalion.synthetic_export_request
    ADD COLUMN transcript_run_ref uuid,
    ADD FOREIGN KEY (org_id, space_id, version_id, transcript_run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref);

CREATE FUNCTION thalion.current_export_transcript(scope_org bigint, scope_space bigint, target_version bigint)
RETURNS TABLE (run_ref uuid, configuration_revision bigint, manifest_digest bytea, passage_count integer)
LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT latest.run_ref, latest.configuration_revision, latest.manifest_digest, latest.passage_count
    FROM thalion.document_version AS version
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    CROSS JOIN LATERAL (
        SELECT run_ref, configuration_revision, manifest_digest, passage_count, contract_revision, outcome
        FROM thalion.processing_run AS run
        WHERE (run.org_id, run.space_id, run.version_id) = (version.org_id, version.space_id, version.version_id)
        ORDER BY run.configuration_revision DESC LIMIT 1
    ) AS latest
    WHERE (version.org_id, version.space_id, version.version_id) = (scope_org, scope_space, target_version)
      AND latest.contract_revision = source.contract_revision AND latest.outcome = 'pending_review'
      AND latest.passage_count BETWEEN 1 AND 128
      AND EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'approved'
      ) AND NOT EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'quarantined'
      );
$$;

CREATE FUNCTION thalion.guard_export_transcript_scope() RETURNS trigger
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
        WHERE current_run.run_ref = candidate.transcript_run_ref
    ) THEN
        RAISE EXCEPTION 'archive transcript must remain the current approved processing run' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_export_request_transcript_scope BEFORE INSERT ON thalion.synthetic_export_request
FOR EACH ROW EXECUTE FUNCTION thalion.guard_export_transcript_scope();
CREATE TRIGGER synthetic_export_approval_transcript_scope BEFORE INSERT ON thalion.synthetic_export_approval
FOR EACH ROW EXECUTE FUNCTION thalion.guard_export_transcript_scope();
CREATE TRIGGER synthetic_export_package_transcript_scope BEFORE INSERT ON thalion.synthetic_export_package
FOR EACH ROW EXECUTE FUNCTION thalion.guard_export_transcript_scope();
