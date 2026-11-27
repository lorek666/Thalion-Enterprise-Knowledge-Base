ALTER TABLE thalion.permission_binding
    DROP CONSTRAINT permission_binding_fields_check,
    ADD CONSTRAINT permission_binding_fields_check CHECK (
        CASE WHEN operation = 'preview_pdf_original_page' THEN fields = ARRAY['original_page']
        ELSE cardinality(fields) BETWEEN 1 AND 5 AND array_position(fields, NULL) IS NULL
             AND fields <@ ARRAY['excerpt', 'citation', 'title', 'location', 'version'] END
    ),
    DROP CONSTRAINT permission_binding_use,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation, purpose, destination) = ('read_passage', 'employee_evidence', 'employee')
        OR (destination = 'local_workspace'
            AND fields IN (ARRAY['excerpt'], ARRAY['location'], ARRAY['excerpt', 'location'])
            AND (operation, purpose) IN (
                ('assemble_wiki_inputs', 'wiki_compilation'), ('review_wiki_revision', 'wiki_review'),
                ('publish_wiki_revision', 'wiki_publication'), ('preview_evidence_repair', 'evidence_quality_review')
            ))
        OR ((operation, purpose, destination)
                = ('preview_pdf_original_page', 'evidence_quality_review', 'local_workspace')
            AND fields = ARRAY['original_page'] AND passage_ref IS NULL)
    );

CREATE TABLE thalion.pdf_page_preview (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    page_number integer NOT NULL,
    request_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    checked_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > checked_at),
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    FOREIGN KEY (run_ref, page_number) REFERENCES thalion.pdf_page_observation (run_ref, page_number)
);

CREATE TRIGGER pdf_page_preview_immutable BEFORE UPDATE OR DELETE ON thalion.pdf_page_preview
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER pdf_page_preview_no_truncate BEFORE TRUNCATE ON thalion.pdf_page_preview
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
