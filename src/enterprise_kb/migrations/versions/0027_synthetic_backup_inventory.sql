CREATE TABLE thalion.synthetic_backup_copy (
    backup_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    asset_id uuid NOT NULL REFERENCES thalion.asset (asset_id),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    byte_length bigint NOT NULL CHECK (byte_length > 0),
    recorded_by bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id) REFERENCES thalion.document_version (org_id, space_id, version_id),
    FOREIGN KEY (org_id, recorded_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE INDEX synthetic_backup_copy_version ON thalion.synthetic_backup_copy (org_id, space_id, version_id);

CREATE FUNCTION thalion.verify_local_backup_copy_registration() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.recorded_by, 'register_synthetic_backup_copy'
    ) OR NOT thalion.lock_local_hold_target(NEW.org_id, NEW.space_id, NEW.version_id, NEW.recorded_by) OR NOT EXISTS (
        SELECT 1 FROM thalion.document_version AS version
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        WHERE (version.org_id, version.space_id, version.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id)
          AND asset.storage_kind = 'synthetic_file'
          AND (asset.asset_id, asset.content_digest, asset.byte_length) = (NEW.asset_id, NEW.content_digest, NEW.byte_length)
    ) THEN
        RAISE EXCEPTION 'backup enrollment requires a current independent custodian, matching request and exact asset'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_backup_copy_requires_scope BEFORE INSERT ON thalion.synthetic_backup_copy
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_backup_copy_registration();

CREATE TRIGGER synthetic_backup_copy_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_backup_copy
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
