ALTER TABLE thalion.permission_binding DROP CONSTRAINT permission_binding_use,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation, purpose, destination) = ('read_passage', 'employee_evidence', 'employee')
        OR (destination = 'local_workspace'
            AND fields IN (ARRAY['excerpt'], ARRAY['location'], ARRAY['excerpt', 'location'])
            AND (operation, purpose) IN (
                ('assemble_wiki_inputs', 'wiki_compilation'), ('review_wiki_revision', 'wiki_review'),
                ('publish_wiki_revision', 'wiki_publication'), ('preview_evidence_repair', 'evidence_quality_review')
            ))
    );

CREATE TABLE thalion.repair_review_preview (
    preview_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    replaces_run_ref uuid NOT NULL,
    reviewer_id bigint NOT NULL,
    request_id uuid NOT NULL,
    difference_digest bytea NOT NULL CHECK (octet_length(difference_digest) = 32),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    expires_at timestamptz NOT NULL,
    UNIQUE (org_id, request_id),
    UNIQUE (org_id, space_id, version_id, run_ref, reviewer_id, preview_ref),
    FOREIGN KEY (org_id, reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    FOREIGN KEY (org_id, space_id, version_id, replaces_run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    CHECK (run_ref <> replaces_run_ref)
);

CREATE TRIGGER repair_review_preview_immutable BEFORE UPDATE OR DELETE ON thalion.repair_review_preview
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

ALTER TABLE thalion.quality_decision
    ADD COLUMN repair_preview_ref uuid,
    ADD UNIQUE (repair_preview_ref),
    ADD FOREIGN KEY (org_id, space_id, version_id, run_ref, reviewer_id, repair_preview_ref)
        REFERENCES thalion.repair_review_preview (org_id, space_id, version_id, run_ref, reviewer_id, preview_ref);

CREATE FUNCTION thalion.guard_repair_quality_preview() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE replaced uuid;
BEGIN
    SELECT replaces_run_ref INTO replaced FROM thalion.processing_run WHERE run_ref = NEW.run_ref;
    IF NEW.repair_preview_ref IS NULL THEN
        IF replaced IS NOT NULL AND NEW.outcome = 'approved' THEN
            RAISE EXCEPTION 'approval of a repair requires a sealed difference preview' USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM thalion.repair_review_preview AS preview
        JOIN thalion.request_record AS request USING (org_id, request_id)
        WHERE preview.preview_ref = NEW.repair_preview_ref AND preview.replaces_run_ref = replaced
          AND preview.expires_at > clock_timestamp()
          AND (request.scope_space_id, request.principal_id, request.operation, request.destination, request.outcome)
            = (NEW.space_id, NEW.reviewer_id, 'preview_evidence_repair', 'local_workspace', 'succeeded')
          AND request.delegated_principal_id IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.request_record AS submit
        WHERE (submit.org_id, submit.scope_space_id, submit.request_id, submit.principal_id) =
              (NEW.org_id, NEW.space_id, NEW.request_id, NEW.reviewer_id)
          AND submit.operation = 'decide_evidence_quality' AND submit.destination = 'local_workspace'
          AND submit.outcome IS NULL AND submit.delegated_principal_id IS NULL
    ) THEN
        RAISE EXCEPTION 'the repair difference preview is not current or admitted' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quality_decision_repair_preview BEFORE INSERT ON thalion.quality_decision
FOR EACH ROW EXECUTE FUNCTION thalion.guard_repair_quality_preview();
