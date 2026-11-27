ALTER TABLE thalion.permission_binding
    ADD COLUMN version_ref uuid,
    ADD FOREIGN KEY (org_id, space_id, version_ref) REFERENCES thalion.object_identity (org_id, space_id, public_id),
    ADD CONSTRAINT permission_binding_version_scope CHECK (
        (operation = 'download_original') = (version_ref IS NOT NULL)
        AND (version_ref IS NULL OR passage_ref IS NULL)
    ),
    DROP CONSTRAINT permission_binding_fields_check,
    ADD CONSTRAINT permission_binding_fields_check CHECK (
        CASE operation
            WHEN 'preview_pdf_original_page' THEN fields = ARRAY['original_page']
            WHEN 'download_original' THEN fields = ARRAY['original']
            ELSE cardinality(fields) BETWEEN 1 AND 5 AND array_position(fields, NULL) IS NULL
                 AND fields <@ ARRAY['excerpt', 'citation', 'title', 'location', 'version']
        END
    ),
    DROP CONSTRAINT permission_binding_use,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation IN ('read_passage', 'download_original') AND (purpose, destination) = ('employee_evidence', 'employee'))
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

CREATE FUNCTION thalion.guard_permission_binding_version() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.object_identity AS identity
        JOIN thalion.document_version AS version
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (version.org_id, version.space_id, version.identity_type, version.version_id)
        WHERE (identity.org_id, identity.space_id, identity.public_id, version.source_id)
            = (NEW.org_id, NEW.space_id, NEW.version_ref, NEW.source_id)
    ) THEN
        RAISE EXCEPTION 'original download bindings require a version in the same source' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER permission_binding_version_guard BEFORE INSERT ON thalion.permission_binding
FOR EACH ROW WHEN (NEW.version_ref IS NOT NULL)
EXECUTE FUNCTION thalion.guard_permission_binding_version();

ALTER TABLE thalion.rule_effectivity ADD UNIQUE (org_id, space_id, source_id, version_id, decision_ref);

CREATE TABLE thalion.original_download_receipt (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    version_id bigint NOT NULL,
    request_id uuid NOT NULL,
    check_id uuid NOT NULL UNIQUE,
    run_ref uuid NOT NULL,
    effectivity_ref uuid NOT NULL,
    policy_revision bigint NOT NULL,
    organization_epoch bigint NOT NULL CHECK (organization_epoch > 0),
    space_epoch bigint NOT NULL CHECK (space_epoch > 0),
    source_epoch bigint NOT NULL CHECK (source_epoch >= policy_revision),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    checked_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > checked_at),
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref) REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    FOREIGN KEY (org_id, space_id, source_id, version_id, effectivity_ref)
        REFERENCES thalion.rule_effectivity (org_id, space_id, source_id, version_id, decision_ref),
    FOREIGN KEY (org_id, space_id, source_id, policy_revision)
        REFERENCES thalion.policy_revision (org_id, space_id, source_id, revision)
);

CREATE TRIGGER original_download_receipt_immutable BEFORE UPDATE OR DELETE ON thalion.original_download_receipt
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER original_download_receipt_no_truncate BEFORE TRUNCATE ON thalion.original_download_receipt
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
