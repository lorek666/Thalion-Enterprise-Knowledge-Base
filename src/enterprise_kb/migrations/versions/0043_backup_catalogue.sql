CREATE TABLE thalion.synthetic_backup_manifest (
    space_ref uuid NOT NULL,
    version_ref uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    manifest_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    byte_length bigint NOT NULL CHECK (byte_length > 0),
    stores bytea[] NOT NULL CHECK (cardinality(stores) BETWEEN 1 AND 8 AND array_position(stores, NULL) IS NULL),
    backup_refs uuid[] NOT NULL CHECK (cardinality(backup_refs) <= 500 AND array_position(backup_refs, NULL) IS NULL),
    copy_stores bytea[] NOT NULL CHECK (cardinality(copy_stores) = cardinality(backup_refs)
                                      AND copy_stores <@ stores AND array_position(copy_stores, NULL) IS NULL),
    recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)
                                          AND expires_at > recorded_at AND expires_at <= recorded_at + interval '24 hours'),
    PRIMARY KEY (space_ref, version_ref, generation)
);

CREATE TRIGGER synthetic_backup_manifest_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_backup_manifest
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER synthetic_backup_manifest_no_truncate BEFORE TRUNCATE ON thalion.synthetic_backup_manifest
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
