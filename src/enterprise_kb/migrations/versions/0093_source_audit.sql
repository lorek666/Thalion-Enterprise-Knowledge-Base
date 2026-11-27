CREATE TABLE thalion.source_audit_access (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    request_id uuid NOT NULL,
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, space_id, source_id) REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TRIGGER source_audit_access_immutable BEFORE UPDATE OR DELETE ON thalion.source_audit_access
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_audit_access_no_truncate BEFORE TRUNCATE ON thalion.source_audit_access
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.source_ingest_attempt (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    batch_ref uuid NOT NULL,
    upload_request_id uuid NOT NULL,
    collector_request_id uuid NOT NULL,
    PRIMARY KEY (org_id, upload_request_id),
    UNIQUE (org_id, collector_request_id),
    FOREIGN KEY (org_id, space_id, batch_ref) REFERENCES thalion.source_ingest_batch (org_id, space_id, batch_ref),
    FOREIGN KEY (org_id, space_id, upload_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, collector_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CHECK (upload_request_id <> collector_request_id)
);

CREATE TRIGGER source_ingest_attempt_immutable BEFORE UPDATE OR DELETE ON thalion.source_ingest_attempt
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_ingest_attempt_no_truncate BEFORE TRUNCATE ON thalion.source_ingest_attempt
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE INDEX delivery_dependency_by_source
ON thalion.delivery_dependency (org_id, space_id, source_id, check_id);

CREATE INDEX original_download_by_source
ON thalion.original_download_receipt (org_id, space_id, source_id, request_id);

CREATE INDEX source_audit_access_by_source
ON thalion.source_audit_access (org_id, space_id, source_id, request_id);

CREATE INDEX source_ingest_attempt_by_batch
ON thalion.source_ingest_attempt (org_id, space_id, batch_ref);

CREATE INDEX disposition_case_by_source
ON thalion.disposition_case (org_id, space_id, source_id, case_ref);

CREATE INDEX command_receipt_by_origin
ON thalion.command_receipt (org_id, request_id) WHERE result_ref IS NOT NULL;

CREATE INDEX request_command_by_receipt
ON thalion.request_command (org_id, receipt_id, request_id);

CREATE VIEW thalion.source_audit_lifecycle_request AS
SELECT org_id, space_id, source_id, request_id FROM thalion.retention_policy_revision
UNION ALL
SELECT version.org_id, version.space_id, version.source_id, hold.request_id
FROM thalion.version_hold_decision AS hold JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
UNION ALL
SELECT org_id, space_id, source_id, request_id FROM thalion.disposition_case
UNION ALL
SELECT candidate.org_id, candidate.space_id, candidate.source_id, decision.request_id
FROM thalion.disposition_decision AS decision JOIN thalion.disposition_case AS candidate USING (org_id, space_id, case_ref)
UNION ALL
SELECT candidate.org_id, candidate.space_id, candidate.source_id, observation.request_id
FROM thalion.disposition_original_observation AS observation
JOIN thalion.disposition_case AS candidate USING (org_id, space_id, case_ref)
UNION ALL
SELECT org_id, space_id, source_id, disposition_request_id FROM thalion.rule_use_stop
WHERE disposition_request_id IS NOT NULL
UNION ALL
SELECT candidate.org_id, candidate.space_id, candidate.source_id, receipt.request_id
FROM thalion.disposition_copy_receipt AS receipt JOIN thalion.disposition_case AS candidate USING (org_id, space_id, case_ref)
UNION ALL
SELECT version.org_id, version.space_id, version.source_id, copy.request_id
FROM thalion.synthetic_backup_copy AS copy JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
UNION ALL
SELECT version.org_id, version.space_id, version.source_id, plan.request_id
FROM thalion.synthetic_backup_expiry_plan AS plan JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
UNION ALL
SELECT version.org_id, version.space_id, version.source_id, observation.request_id
FROM thalion.synthetic_backup_expiry_observation AS observation
JOIN thalion.synthetic_backup_expiry_plan AS plan USING (org_id, space_id, backup_ref, schedule_ref)
JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
UNION ALL
SELECT version.org_id, version.space_id, version.source_id, export.request_id
FROM thalion.synthetic_export_request AS export JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
UNION ALL
SELECT version.org_id, version.space_id, version.source_id, approval.request_id
FROM thalion.synthetic_export_approval AS approval
JOIN thalion.synthetic_export_request AS export USING (org_id, space_id, export_ref)
JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
UNION ALL
SELECT version.org_id, version.space_id, version.source_id, package.request_id
FROM thalion.synthetic_export_package AS package
JOIN thalion.synthetic_export_request AS export USING (org_id, space_id, export_ref)
JOIN thalion.document_version AS version USING (org_id, space_id, version_id);

CREATE VIEW thalion.source_audit_request AS
SELECT dependency.org_id, dependency.space_id, dependency.source_id, delivery.request_id
FROM thalion.delivery_dependency AS dependency
JOIN thalion.delivery_record AS delivery USING (org_id, check_id)
UNION ALL
SELECT org_id, space_id, source_id, request_id FROM thalion.original_download_receipt
UNION ALL
SELECT org_id, space_id, source_id, request_id FROM thalion.source_ingest_batch
UNION ALL
SELECT batch.org_id, batch.space_id, batch.source_id, ids.request_id
FROM thalion.source_ingest_batch AS batch JOIN thalion.source_ingest_attempt AS attempt USING (org_id, space_id, batch_ref)
CROSS JOIN LATERAL (VALUES (attempt.upload_request_id), (attempt.collector_request_id)) AS ids(request_id)
UNION ALL
SELECT org_id, space_id, source_id, request_id FROM thalion.source_audit_lifecycle_request
UNION ALL
SELECT origin.org_id, origin.space_id, origin.source_id, replay.request_id
FROM thalion.source_audit_lifecycle_request AS origin
JOIN thalion.command_receipt AS command USING (org_id, request_id)
JOIN thalion.request_command AS link USING (org_id, receipt_id)
JOIN thalion.request_record AS replay
  ON (replay.org_id, replay.scope_space_id, replay.request_id) = (origin.org_id, origin.space_id, link.request_id)
WHERE command.result_ref IS NOT NULL AND link.request_id <> origin.request_id
  AND replay.operation = command.operation AND replay.destination = 'internal_lifecycle'
  AND replay.principal_id = command.principal_id
  AND replay.delegated_principal_id IS NOT DISTINCT FROM command.delegated_principal_id
  AND replay.configuration_revision = command.configuration_revision
UNION ALL
SELECT org_id, space_id, source_id, request_id FROM thalion.source_audit_access;
