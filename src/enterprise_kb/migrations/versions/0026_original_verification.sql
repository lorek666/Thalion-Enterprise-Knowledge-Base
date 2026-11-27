CREATE TABLE thalion.disposition_original_observation (
    observation_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    case_ref uuid NOT NULL,
    submitted_by bigint NOT NULL,
    inventory_snapshot bytea NOT NULL,
    asset_id uuid NOT NULL REFERENCES thalion.asset (asset_id),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    byte_length bigint NOT NULL CHECK (byte_length > 0),
    observed_by bigint NOT NULL CHECK (observed_by <> submitted_by),
    request_id uuid NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, case_ref, submitted_by, inventory_snapshot)
        REFERENCES thalion.disposition_case (org_id, space_id, case_ref, submitted_by, inventory_snapshot),
    FOREIGN KEY (org_id, observed_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE FUNCTION thalion.verify_local_disposition_original_observation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.observed_by, 'verify_disposition_original'
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.lock_local_disposition_review(NEW.org_id, NEW.space_id, NEW.case_ref, NEW.observed_by) AS target
        JOIN thalion.document_version AS version ON (version.org_id, version.space_id, version.version_id) =
                                                   (NEW.org_id, NEW.space_id, target.version_id)
        JOIN thalion.asset AS asset
          ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id) =
             (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
        WHERE asset.storage_kind = 'synthetic_file'
          AND (asset.asset_id, asset.content_digest, asset.byte_length) = (NEW.asset_id, NEW.content_digest, NEW.byte_length)
    ) OR EXISTS (
        SELECT 1 FROM thalion.disposition_rejection AS rejection
        WHERE (rejection.org_id, rejection.space_id, rejection.case_ref) = (NEW.org_id, NEW.space_id, NEW.case_ref)
    ) THEN
        RAISE EXCEPTION 'original verification requires a matching open request, eligible case and registered asset'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER disposition_original_observation_requires_scope BEFORE INSERT ON thalion.disposition_original_observation
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_disposition_original_observation();

CREATE TRIGGER disposition_original_observation_immutable BEFORE UPDATE OR DELETE ON thalion.disposition_original_observation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
