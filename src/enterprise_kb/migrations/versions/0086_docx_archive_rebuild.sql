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
        JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        WHERE current_run.run_ref = candidate.transcript_run_ref
          AND (run.replaces_run_ref IS NULL) = (candidate.repair_history_digest IS NULL)
          AND (candidate.rebuild_metadata_digest IS NULL OR run.replaces_run_ref IS NULL
               OR asset.media_type <> 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    ) THEN
        RAISE EXCEPTION 'archive transcript must remain approved with its enrolled repair history' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE thalion.archive_docx_rebuild (
    version_ref uuid PRIMARY KEY REFERENCES thalion.archive_rebuild_rule_check (version_ref),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    amount_columns text[],
    transcription jsonb NOT NULL,
    transcript_bytes bytea[] NOT NULL,
    rebuilt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    CHECK (transcription ->> 'run_id' IS NOT DISTINCT FROM run_ref::text),
    CHECK (jsonb_typeof(transcription -> 'paragraphs') IS NOT DISTINCT FROM 'array'
           AND jsonb_typeof(transcription -> 'tables') IS NOT DISTINCT FROM 'array'),
    CHECK (array_ndims(transcript_bytes) = 1 AND cardinality(transcript_bytes) BETWEEN 1 AND 128
           AND array_position(transcript_bytes, NULL) IS NULL
           AND cardinality(transcript_bytes) = jsonb_array_length(transcription -> 'paragraphs')
               + jsonb_array_length(jsonb_path_query_array(transcription, '$.tables[*].rows[*].cells[*]')))
);

CREATE TRIGGER archive_docx_rebuild_fenced BEFORE INSERT ON thalion.archive_docx_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.guard_repair_rebuild_rehearsal();

CREATE TRIGGER archive_docx_rebuild_immutable BEFORE UPDATE OR DELETE ON thalion.archive_docx_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER archive_docx_rebuild_no_truncate BEFORE TRUNCATE ON thalion.archive_docx_rebuild
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
