CREATE TABLE thalion.pdf_ocr_correction (
    correction_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    page_number integer NOT NULL,
    author_id bigint NOT NULL,
    preview_request_id uuid NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    proposed_transcript bytea NOT NULL CHECK (
        octet_length(proposed_transcript) BETWEEN 1 AND 32768
        AND btrim(convert_from(proposed_transcript, 'UTF8'), E' \n\r\t') <> ''
    ),
    proposed_digest bytea GENERATED ALWAYS AS (sha256(proposed_transcript)) STORED,
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, author_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, preview_request_id) REFERENCES thalion.pdf_page_preview (org_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    FOREIGN KEY (run_ref, page_number) REFERENCES thalion.pdf_page_observation (run_ref, page_number)
);

CREATE FUNCTION thalion.guard_pdf_ocr_correction() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM run.run_ref
    FROM thalion.processing_run AS run
    JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
    JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.source_contract_revision AS contract
        ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
         = (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS author ON (author.org_id, author.principal_id) = (run.org_id, NEW.author_id)
    JOIN thalion.pdf_page_observation AS page ON (page.run_ref, page.page_number) = (run.run_ref, NEW.page_number)
    JOIN thalion.pdf_page_preview AS preview
        ON (preview.org_id, preview.space_id, preview.version_id, preview.run_ref, preview.page_number, preview.request_id)
         = (run.org_id, run.space_id, run.version_id, run.run_ref, page.page_number, NEW.preview_request_id)
    JOIN thalion.request_record AS read_request
        ON (read_request.org_id, read_request.request_id) = (preview.org_id, preview.request_id)
    JOIN thalion.request_record AS submit
        ON (submit.org_id, submit.scope_space_id, submit.request_id) = (run.org_id, run.space_id, NEW.request_id)
    WHERE (run.org_id, run.space_id, run.version_id, run.run_ref) = (NEW.org_id, NEW.space_id, NEW.version_id, NEW.run_ref)
      AND run.contract_revision = source.contract_revision AND source.lifecycle = 'active' AND space.lifecycle = 'active'
      AND contract.admission = 'synthetic_only' AND author.authority_issuer = 'https://synthetic.invalid'
      AND author.principal_type = 'employee' AND NOT author.disabled AND author.principal_id <> contract.quality_reviewer_id
      AND (read_request.principal_id, read_request.operation, read_request.destination, read_request.outcome)
          = (author.principal_id, 'preview_pdf_original_page', 'local_workspace', 'succeeded')
      AND (submit.principal_id, submit.operation, submit.destination, submit.client_id)
          = (author.principal_id, 'submit_pdf_ocr_correction', 'local_workspace', read_request.client_id)
      AND read_request.delegated_principal_id IS NULL AND submit.delegated_principal_id IS NULL AND submit.outcome IS NULL
      AND preview.policy_revision = source.local_policy_revision
      AND preview.checked_at > clock_timestamp() - interval '5 minutes'
      AND page.method = 'ocr' AND page.ocr_profile_digest IS NOT NULL
      AND page.transcript IS DISTINCT FROM NEW.proposed_transcript
      AND (run.outcome = 'quarantined' OR EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality WHERE (quality.run_ref, quality.outcome) = (run.run_ref, 'quarantined')
      ))
      AND NOT EXISTS (
          SELECT 1 FROM thalion.processing_run AS newer
          WHERE newer.version_id = run.version_id AND newer.configuration_revision > run.configuration_revision
      )
      AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = run.version_id)
      AND NOT EXISTS (
          SELECT 1 FROM thalion.current_version_hold AS hold
          WHERE hold.version_id = run.version_id AND hold.action = 'establish'
      )
    FOR SHARE OF source, space, author FOR UPDATE OF document;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'a current quarantined OCR page and a recent preview by an independent author are required'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER pdf_ocr_correction_guard BEFORE INSERT ON thalion.pdf_ocr_correction
FOR EACH ROW EXECUTE FUNCTION thalion.guard_pdf_ocr_correction();
CREATE TRIGGER pdf_ocr_correction_immutable BEFORE UPDATE OR DELETE ON thalion.pdf_ocr_correction
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER pdf_ocr_correction_no_truncate BEFORE TRUNCATE ON thalion.pdf_ocr_correction
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
