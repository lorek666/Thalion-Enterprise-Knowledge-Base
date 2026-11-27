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

ALTER TABLE thalion.archive_docx_rebuild
    ADD COLUMN repair_history jsonb,
    ADD CONSTRAINT archive_docx_repair_history_shape CHECK (
        repair_history IS NULL OR (
            repair_history ->> 'run_id' IS NOT DISTINCT FROM run_ref::text
            AND jsonb_typeof(repair_history -> 'runs') IS NOT DISTINCT FROM 'array'
            AND jsonb_array_length(repair_history -> 'runs') BETWEEN 2 AND 16
        )
    );
