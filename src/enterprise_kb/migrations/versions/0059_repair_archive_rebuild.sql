DO $$
DECLARE
    old_check name;
BEGIN
    SELECT conname INTO STRICT old_check FROM pg_constraint
    WHERE conrelid = 'thalion.synthetic_export_request'::regclass AND contype = 'c'
      AND (SELECT attnum FROM pg_attribute WHERE attrelid = conrelid AND attname = 'repair_history_digest') = ANY(conkey);
    EXECUTE format('ALTER TABLE thalion.synthetic_export_request DROP CONSTRAINT %I', old_check);
END;
$$;

ALTER TABLE thalion.synthetic_export_request
    ADD CONSTRAINT repair_export_scope CHECK (repair_history_digest IS NULL OR (
        octet_length(repair_history_digest) = 32 AND transcript_run_ref IS NOT NULL
        AND wiki_publication_ref IS NULL AND wiki_rebuild_digest IS NULL
    ));

CREATE TABLE thalion.archive_repair_rebuild (
    version_ref uuid PRIMARY KEY REFERENCES thalion.archive_rebuild_rule_check (version_ref),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    history jsonb NOT NULL,
    rebuilt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    CHECK (history ->> 'run_id' IS NOT DISTINCT FROM run_ref::text),
    CHECK (jsonb_typeof(history -> 'runs') IS NOT DISTINCT FROM 'array')
);

CREATE FUNCTION thalion.guard_repair_rebuild_rehearsal() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_db_role_setting AS setting
        JOIN pg_database AS db ON db.oid = setting.setdatabase
        WHERE db.datname = current_database() AND setting.setrole = 0
          AND ('thalion.restore_rehearsal=' || current_database()) = ANY(setting.setconfig)
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.space AS space
        JOIN thalion.object_identity AS identity USING (org_id, space_id)
        JOIN thalion.archive_rebuild_rule_check AS checkpoint ON checkpoint.version_ref = identity.public_id
        WHERE (space.org_id, space.space_id, space.lifecycle) = (NEW.org_id, NEW.space_id, 'archived')
          AND (identity.public_id, identity.object_type) = (NEW.version_ref, 'document_version')
          AND checkpoint.quality_stream_ref IS NOT NULL AND checkpoint.source_authority_ref IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'repair reconstruction requires a fenced scope and current safety checkpoint'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER archive_repair_rebuild_fenced BEFORE INSERT ON thalion.archive_repair_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.guard_repair_rebuild_rehearsal();

CREATE TRIGGER archive_repair_rebuild_immutable BEFORE UPDATE OR DELETE ON thalion.archive_repair_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER archive_repair_rebuild_no_truncate BEFORE TRUNCATE ON thalion.archive_repair_rebuild
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
