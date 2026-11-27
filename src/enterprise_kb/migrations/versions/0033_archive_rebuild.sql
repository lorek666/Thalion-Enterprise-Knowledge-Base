ALTER TABLE thalion.synthetic_export_request
    ADD COLUMN rebuild_metadata_digest bytea,
    ADD CHECK (rebuild_metadata_digest IS NULL OR (
        octet_length(rebuild_metadata_digest) = 32 AND transcript_run_ref IS NOT NULL AND wiki_publication_ref IS NULL
    ));
