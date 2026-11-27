CREATE TABLE thalion.synthetic_lexical_index (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    profile text NOT NULL CHECK (length(profile) BETWEEN 1 AND 80),
    index_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    entries jsonb NOT NULL CHECK (jsonb_typeof(entries) = 'object'
                                  AND octet_length(entries::text) BETWEEN 3 AND 8388608),
    content_digest bytea NOT NULL CHECK (content_digest = sha256(convert_to(entries::text, 'UTF8'))),
    indexed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (run_ref, profile),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref)
);

CREATE INDEX synthetic_lexical_index_version ON thalion.synthetic_lexical_index (org_id, space_id, version_id);

CREATE TRIGGER synthetic_lexical_index_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_lexical_index
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER synthetic_lexical_index_no_truncate BEFORE TRUNCATE ON thalion.synthetic_lexical_index
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
