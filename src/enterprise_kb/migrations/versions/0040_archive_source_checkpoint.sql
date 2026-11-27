ALTER TABLE thalion.archive_rebuild_rule_check
    ADD COLUMN source_authority_ref uuid,
    ADD COLUMN source_space_ref uuid,
    ADD COLUMN source_stream_ref uuid,
    ADD COLUMN source_generation bigint,
    ADD COLUMN source_requester_ref uuid,
    ADD CONSTRAINT archive_rebuild_source_checkpoint_required CHECK (
        quality_stream_ref IS NOT NULL
        AND num_nonnulls(source_authority_ref, source_space_ref, source_stream_ref, source_generation, source_requester_ref) = 5
        AND source_authority_ref NOT IN (authority_ref, log_ref)
        AND source_generation >= 0
    ) NOT VALID;

CREATE TRIGGER archive_rebuild_rule_check_no_truncate BEFORE TRUNCATE ON thalion.archive_rebuild_rule_check
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
