CREATE OR REPLACE VIEW thalion.synthetic_original_export_target AS
SELECT version.org_id, version.space_id, version.version_id, source.source_id, identity.public_id AS version_ref,
       source.owner_principal_id AS owner_id, space.owner_principal_id AS space_owner_id, contract.approver_id,
       ARRAY[organization.safety_epoch, space.safety_epoch, source.safety_epoch, source.contract_revision, organization.config_revision,
             coalesce(hold.generation, 0)] AS snapshot,
       asset.storage_key, asset.content_digest, asset.byte_length,
       coalesce(hold.action = 'establish', false) OR EXISTS (
           SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = version.version_id
       ) AS blocked,
       asset.media_type
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
  AND asset.storage_kind = 'synthetic_file' AND asset.media_type IN (
      'text/markdown', 'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  );

CREATE OR REPLACE VIEW thalion.synthetic_export_target AS
SELECT * FROM thalion.synthetic_original_export_target WHERE media_type IN ('text/markdown', 'application/pdf');
