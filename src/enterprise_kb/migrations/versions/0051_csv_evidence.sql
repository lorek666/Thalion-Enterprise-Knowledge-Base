ALTER TABLE thalion.asset DROP CONSTRAINT asset_media_type_check,
    ADD CHECK (media_type IN ('text/markdown', 'text/csv'));

INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
SELECT greatest(max(configuration_revision), 2) + 1, '1', 'utf8_csv_literal_v1', 1
FROM thalion.processing_config_revision;

ALTER TABLE thalion.passage
    ALTER COLUMN byte_start DROP NOT NULL,
    ALTER COLUMN byte_end DROP NOT NULL,
    ALTER COLUMN heading_path DROP NOT NULL,
    ALTER COLUMN paragraph DROP NOT NULL,
    ADD COLUMN csv_record integer CHECK (csv_record >= 2),
    ADD COLUMN csv_column integer CHECK (csv_column > 0),
    DROP CONSTRAINT passage_kind_check,
    ADD CONSTRAINT passage_locator_shape CHECK (
        (kind IN ('paragraph', 'table', 'blockquote', 'list', 'code')
            AND heading_path IS NOT NULL AND paragraph IS NOT NULL AND byte_start IS NOT NULL AND byte_end IS NOT NULL
            AND csv_record IS NULL AND csv_column IS NULL)
        OR
        (kind = 'csv_cell' AND csv_record IS NOT NULL AND csv_column IS NOT NULL
            AND heading_path IS NULL AND paragraph IS NULL AND byte_start IS NULL AND byte_end IS NULL)
    );

CREATE UNIQUE INDEX passage_csv_location
    ON thalion.passage (version_id, locator_revision, csv_record, csv_column) WHERE kind = 'csv_cell';

CREATE FUNCTION thalion.verify_evidence_format() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    actual_media_type text;
    csv_format boolean;
BEGIN
    SELECT asset.media_type INTO STRICT actual_media_type
    FROM thalion.document_version AS version
    JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id);
    IF TG_TABLE_NAME = 'passage' THEN
        csv_format := NEW.kind = 'csv_cell';
    ELSE
        SELECT profile = 'utf8_csv_literal_v1' INTO STRICT csv_format
        FROM thalion.processing_config_revision WHERE configuration_revision = NEW.configuration_revision;
    END IF;
    IF csv_format IS DISTINCT FROM (actual_media_type = 'text/csv') THEN
        RAISE EXCEPTION 'the evidence format does not match the original asset' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER passage_media_type BEFORE INSERT ON thalion.passage
FOR EACH ROW EXECUTE FUNCTION thalion.verify_evidence_format();
CREATE TRIGGER run_media_type BEFORE INSERT ON thalion.processing_run
FOR EACH ROW EXECUTE FUNCTION thalion.verify_evidence_format();

CREATE OR REPLACE VIEW thalion.synthetic_export_target AS
SELECT version.org_id, version.space_id, version.version_id, source.source_id, identity.public_id AS version_ref,
       source.owner_principal_id AS owner_id, space.owner_principal_id AS space_owner_id, contract.approver_id,
       ARRAY[organization.safety_epoch, space.safety_epoch, source.safety_epoch, source.contract_revision, organization.config_revision,
             coalesce(hold.generation, 0)] AS snapshot,
       asset.storage_key, asset.content_digest, asset.byte_length,
       coalesce(hold.action = 'establish', false) OR EXISTS (
           SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = version.version_id
       ) AS blocked
FROM thalion.document_version AS version
JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
JOIN thalion.source AS source USING (org_id, space_id, source_id)
JOIN thalion.organization AS organization USING (org_id)
JOIN thalion.space AS space USING (org_id, space_id)
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
     (source.org_id, source.space_id, source.source_id, source.contract_revision)
JOIN thalion.object_identity AS identity
  ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
     (version.org_id, version.space_id, 'document_version', version.version_id)
LEFT JOIN thalion.current_version_hold AS hold
  ON (hold.org_id, hold.space_id, hold.version_id) = (version.org_id, version.space_id, version.version_id)
WHERE source.lifecycle = 'active' AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
  AND asset.storage_kind = 'synthetic_file' AND asset.media_type = 'text/markdown';
