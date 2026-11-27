ALTER TABLE thalion.synthetic_export_request
    ADD COLUMN wiki_rebuild_digest bytea,
    ADD CHECK (wiki_rebuild_digest IS NULL OR (
        octet_length(wiki_rebuild_digest) = 32 AND wiki_publication_ref IS NOT NULL
    ));
