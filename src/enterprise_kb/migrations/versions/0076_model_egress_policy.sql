ALTER TABLE thalion.source_contract_revision ADD COLUMN model_policy_approver_id bigint,
    ADD FOREIGN KEY (org_id, model_policy_approver_id) REFERENCES thalion.principal (org_id, principal_id);

ALTER TABLE thalion.policy_revision DROP CONSTRAINT policy_revision_binding_count_check,
    ADD CONSTRAINT policy_revision_binding_count_check CHECK (binding_count BETWEEN 0 AND 1000);

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
        OR (operation = 'send_model_evidence' AND destination = 'synthetic-gateway'
            AND purpose IN ('model_answer', 'wiki_compilation', 'model_review')
            AND passage_ref IS NOT NULL AND isfinite(valid_from) AND valid_until IS NOT NULL AND isfinite(valid_until)
            AND fields <@ ARRAY['excerpt', 'citation', 'title', 'location', 'version'])
    );
