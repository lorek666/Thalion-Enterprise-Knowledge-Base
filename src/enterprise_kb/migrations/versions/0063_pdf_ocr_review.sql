ALTER TABLE thalion.pdf_ocr_correction ADD UNIQUE (correction_ref, org_id, space_id, version_id, run_ref, page_number);

ALTER TABLE thalion.pdf_page_preview ADD COLUMN correction_ref uuid,
    ADD FOREIGN KEY (correction_ref, org_id, space_id, version_id, run_ref, page_number)
        REFERENCES thalion.pdf_ocr_correction (correction_ref, org_id, space_id, version_id, run_ref, page_number);

CREATE TABLE thalion.pdf_ocr_review_decision (
    decision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    correction_ref uuid NOT NULL UNIQUE,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    page_number integer NOT NULL,
    reviewer_id bigint NOT NULL,
    preview_request_id uuid NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('approved', 'rejected')),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (correction_ref, org_id, space_id, version_id, run_ref, page_number)
        REFERENCES thalion.pdf_ocr_correction (correction_ref, org_id, space_id, version_id, run_ref, page_number),
    FOREIGN KEY (org_id, reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, preview_request_id) REFERENCES thalion.pdf_page_preview (org_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE UNIQUE INDEX pdf_ocr_one_approval_per_page
    ON thalion.pdf_ocr_review_decision (run_ref, page_number) WHERE outcome = 'approved';

CREATE FUNCTION thalion.guard_pdf_ocr_review_decision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM run.run_ref
    FROM thalion.pdf_ocr_correction AS correction
    JOIN thalion.processing_run AS run USING (org_id, space_id, version_id, run_ref)
    JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
    JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.source_contract_revision AS contract
        ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
         = (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS reviewer ON (reviewer.org_id, reviewer.principal_id) = (run.org_id, NEW.reviewer_id)
    JOIN thalion.pdf_page_preview AS preview
        ON (preview.org_id, preview.correction_ref, preview.request_id)
         = (run.org_id, correction.correction_ref, NEW.preview_request_id)
    JOIN thalion.request_record AS read_request
        ON (read_request.org_id, read_request.request_id) = (preview.org_id, preview.request_id)
    JOIN thalion.request_record AS decide
        ON (decide.org_id, decide.scope_space_id, decide.request_id) = (run.org_id, run.space_id, NEW.request_id)
    WHERE (correction.correction_ref, correction.org_id, correction.space_id, correction.version_id,
           correction.run_ref, correction.page_number)
        = (NEW.correction_ref, NEW.org_id, NEW.space_id, NEW.version_id, NEW.run_ref, NEW.page_number)
      AND run.contract_revision = source.contract_revision AND source.lifecycle = 'active' AND space.lifecycle = 'active'
      AND contract.admission = 'synthetic_only' AND reviewer.authority_issuer = 'https://synthetic.invalid'
      AND reviewer.principal_type = 'employee' AND NOT reviewer.disabled
      AND reviewer.principal_id = contract.quality_reviewer_id AND reviewer.principal_id <> correction.author_id
      AND (read_request.principal_id, read_request.operation, read_request.destination, read_request.outcome)
          = (reviewer.principal_id, 'preview_pdf_ocr_correction', 'local_workspace', 'succeeded')
      AND (decide.principal_id, decide.operation, decide.destination, decide.client_id)
          = (reviewer.principal_id, 'decide_pdf_ocr_correction', 'local_workspace', read_request.client_id)
      AND read_request.delegated_principal_id IS NULL AND decide.delegated_principal_id IS NULL AND decide.outcome IS NULL
      AND preview.policy_revision = source.local_policy_revision
      AND preview.checked_at > clock_timestamp() - interval '5 minutes'
      AND NOT EXISTS (
          SELECT 1 FROM thalion.processing_run AS newer
          WHERE newer.version_id = run.version_id AND newer.configuration_revision > run.configuration_revision
      )
      AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = run.version_id)
      AND NOT EXISTS (
          SELECT 1 FROM thalion.current_version_hold AS hold
          WHERE hold.version_id = run.version_id AND hold.action = 'establish'
      )
    FOR SHARE OF source, space, reviewer FOR UPDATE OF document;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'a current correction and a recent preview by its independent reviewer are required'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER pdf_ocr_review_decision_guard BEFORE INSERT ON thalion.pdf_ocr_review_decision
FOR EACH ROW EXECUTE FUNCTION thalion.guard_pdf_ocr_review_decision();
CREATE TRIGGER pdf_ocr_review_decision_immutable BEFORE UPDATE OR DELETE ON thalion.pdf_ocr_review_decision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER pdf_ocr_review_decision_no_truncate BEFORE TRUNCATE ON thalion.pdf_ocr_review_decision
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
