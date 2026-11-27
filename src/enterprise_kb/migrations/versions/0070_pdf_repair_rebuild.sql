CREATE OR REPLACE FUNCTION thalion.pdf_export_scope_admitted(candidate thalion.synthetic_export_request)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, thalion AS $$
    SELECT candidate.wiki_publication_ref IS NULL AND candidate.wiki_rebuild_digest IS NULL;
$$;

ALTER TABLE thalion.archive_pdf_rebuild
    ADD COLUMN repair_history jsonb,
    ADD CONSTRAINT archive_pdf_repair_history_shape CHECK (
        repair_history IS NULL OR (
            repair_history ->> 'run_id' IS NOT DISTINCT FROM run_ref::text
            AND jsonb_typeof(repair_history -> 'runs') IS NOT DISTINCT FROM 'array'
            AND jsonb_array_length(repair_history -> 'runs') BETWEEN 2 AND 16
        )
    );
