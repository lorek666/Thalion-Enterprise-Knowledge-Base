CREATE OR REPLACE FUNCTION thalion.pdf_export_scope_admitted(candidate thalion.synthetic_export_request)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, thalion AS $$
    SELECT candidate.wiki_publication_ref IS NULL AND candidate.wiki_rebuild_digest IS NULL
       AND (candidate.rebuild_metadata_digest IS NULL OR candidate.repair_history_digest IS NULL);
$$;

CREATE TABLE thalion.archive_pdf_rebuild (
    version_ref uuid PRIMARY KEY REFERENCES thalion.archive_rebuild_rule_check (version_ref),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    transcription jsonb NOT NULL,
    page_transcripts bytea[] NOT NULL,
    rebuilt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    CHECK (transcription ->> 'run_id' IS NOT DISTINCT FROM run_ref::text),
    CHECK (jsonb_typeof(transcription -> 'pages') IS NOT DISTINCT FROM 'array'),
    CHECK (array_ndims(page_transcripts) = 1 AND cardinality(page_transcripts) BETWEEN 1 AND 128
           AND cardinality(page_transcripts) = jsonb_array_length(transcription -> 'pages'))
);

CREATE TRIGGER archive_pdf_rebuild_fenced BEFORE INSERT ON thalion.archive_pdf_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.guard_repair_rebuild_rehearsal();

CREATE TRIGGER archive_pdf_rebuild_immutable BEFORE UPDATE OR DELETE ON thalion.archive_pdf_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER archive_pdf_rebuild_no_truncate BEFORE TRUNCATE ON thalion.archive_pdf_rebuild
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
