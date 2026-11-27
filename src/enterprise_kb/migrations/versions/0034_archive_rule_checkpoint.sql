CREATE TABLE thalion.archive_rebuild_rule_check (
    version_ref uuid PRIMARY KEY REFERENCES thalion.object_identity (public_id),
    archive_digest bytea NOT NULL CHECK (octet_length(archive_digest) = 32),
    origin_org_id bigint NOT NULL CHECK (origin_org_id > 0),
    origin_space_id bigint NOT NULL CHECK (origin_space_id > 0),
    export_ref uuid NOT NULL,
    authority_ref uuid NOT NULL,
    log_ref uuid NOT NULL CHECK (log_ref <> authority_ref),
    stream_ref uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER archive_rebuild_rule_check_immutable
BEFORE UPDATE OR DELETE ON thalion.archive_rebuild_rule_check
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
