ALTER TABLE thalion.permission_binding DROP CONSTRAINT permission_binding_use,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation, purpose, destination) = ('read_passage', 'employee_evidence', 'employee')
        OR (destination = 'local_workspace'
            AND fields IN (ARRAY['excerpt'], ARRAY['location'], ARRAY['excerpt', 'location'])
            AND (operation, purpose) IN (
                ('assemble_wiki_inputs', 'wiki_compilation'), ('review_wiki_revision', 'wiki_review'),
                ('publish_wiki_revision', 'wiki_publication'), ('preview_evidence_repair', 'evidence_quality_review'),
                ('preview_docx_quality', 'evidence_quality_review')
            ))
        OR ((operation, purpose, destination)
                = ('preview_pdf_original_page', 'evidence_quality_review', 'local_workspace')
            AND fields = ARRAY['original_page'] AND passage_ref IS NULL)
    );

CREATE TABLE thalion.docx_quality_preview (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 1),
    safety_epochs bigint[] NOT NULL CHECK (cardinality(safety_epochs) = 3 AND array_position(safety_epochs, NULL) IS NULL),
    batch_digest bytea NOT NULL CHECK (octet_length(batch_digest) = 32),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    checked_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > checked_at AND expires_at <= checked_at + interval '5 minutes'),
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref)
);

CREATE TRIGGER docx_quality_preview_immutable BEFORE UPDATE OR DELETE ON thalion.docx_quality_preview
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER docx_quality_preview_no_truncate BEFORE TRUNCATE ON thalion.docx_quality_preview
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

ALTER TABLE thalion.quality_decision ADD COLUMN docx_preview_request uuid,
    ADD UNIQUE (org_id, docx_preview_request),
    ADD FOREIGN KEY (org_id, docx_preview_request) REFERENCES thalion.docx_quality_preview (org_id, request_id),
    ADD CHECK (docx_preview_request IS NULL OR (repair_preview_ref IS NULL AND pdf_repair_page_requests IS NULL));

CREATE FUNCTION thalion.guard_docx_quality_preview() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE request_operation text;
BEGIN
    SELECT operation INTO request_operation FROM thalion.request_record
    WHERE (org_id, request_id) = (NEW.org_id, NEW.request_id);
    IF (NEW.docx_preview_request IS NOT NULL) <> (request_operation IS NOT DISTINCT FROM 'decide_docx_quality') THEN
        RAISE EXCEPTION 'managed DOCX decisions require a sealed preview' USING ERRCODE = '23514';
    END IF;
    IF NEW.docx_preview_request IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM thalion.docx_quality_preview AS preview
        JOIN thalion.processing_run AS run USING (org_id, space_id, version_id, run_ref)
        JOIN thalion.processing_config_revision AS config USING (configuration_revision)
        JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.organization AS org USING (org_id)
        JOIN thalion.request_record AS viewed USING (org_id, request_id)
        JOIN thalion.request_record AS deciding ON (deciding.org_id, deciding.scope_space_id, deciding.request_id)
            = (preview.org_id, preview.space_id, NEW.request_id)
        WHERE (preview.org_id, preview.space_id, preview.version_id, preview.run_ref, preview.request_id)
            = (NEW.org_id, NEW.space_id, NEW.version_id, NEW.run_ref, NEW.docx_preview_request)
          AND config.profile = 'docx_literal_paragraphs_v1' AND run.outcome = 'pending_review'
          AND run.contract_revision = source.contract_revision AND preview.policy_revision = source.local_policy_revision
          AND preview.safety_epochs = ARRAY[org.safety_epoch, space.safety_epoch, source.safety_epoch]
          AND preview.expires_at > clock_timestamp()
          AND (viewed.principal_id, viewed.client_id, viewed.operation, viewed.destination, viewed.outcome)
            = (NEW.reviewer_id, deciding.client_id, 'preview_docx_quality', 'local_workspace', 'succeeded')
          AND viewed.delegated_principal_id IS NULL AND viewed.configuration_revision = org.config_revision
          AND deciding.principal_id = NEW.reviewer_id AND deciding.configuration_revision = org.config_revision
          AND deciding.destination = 'local_workspace' AND deciding.outcome IS NULL AND deciding.delegated_principal_id IS NULL
          AND NOT EXISTS (SELECT 1 FROM thalion.processing_run AS newer WHERE newer.version_id = run.version_id
                          AND newer.configuration_revision > run.configuration_revision)
          AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision AS existing WHERE existing.run_ref = run.run_ref)
    ) THEN
        RAISE EXCEPTION 'the DOCX review receipt is not current or admitted' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quality_decision_docx_preview BEFORE INSERT ON thalion.quality_decision
FOR EACH ROW EXECUTE FUNCTION thalion.guard_docx_quality_preview();
