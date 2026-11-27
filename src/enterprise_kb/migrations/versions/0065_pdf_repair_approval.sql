ALTER TABLE thalion.pdf_page_preview ADD COLUMN repair_safety_epochs bigint[],
    ADD CHECK (repair_safety_epochs IS NULL OR (
        correction_ref IS NULL AND cardinality(repair_safety_epochs) = 3
        AND array_position(repair_safety_epochs, NULL) IS NULL
    ));

ALTER TABLE thalion.quality_decision
    ADD COLUMN pdf_repair_page_requests uuid[],
    ADD COLUMN pdf_repair_proof_digest bytea,
    ADD CHECK (
        (pdf_repair_page_requests IS NULL AND pdf_repair_proof_digest IS NULL)
        OR (pdf_repair_page_requests IS NOT NULL AND pdf_repair_proof_digest IS NOT NULL
            AND octet_length(pdf_repair_proof_digest) = 32 AND outcome = 'approved'
            AND repair_preview_ref IS NULL AND cardinality(pdf_repair_page_requests) BETWEEN 1 AND 16)
    );

CREATE FUNCTION thalion.pdf_repair_review_until(target_run uuid, approval_request uuid, page_requests uuid[])
RETURNS timestamptz LANGUAGE sql VOLATILE SET search_path = pg_catalog, thalion AS $$
    SELECT min(preview.checked_at) + interval '30 minutes'
    FROM thalion.processing_run AS run
    JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.organization AS organization USING (org_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.request_record AS approval
      ON (approval.org_id, approval.scope_space_id, approval.request_id) = (run.org_id, run.space_id, approval_request)
    JOIN thalion.principal AS reviewer
      ON (reviewer.org_id, reviewer.principal_id) = (approval.org_id, approval.principal_id)
    CROSS JOIN unnest(page_requests) WITH ORDINALITY AS requested(request_id, page_number)
    JOIN thalion.pdf_page_preview AS preview
      ON (preview.org_id, preview.space_id, preview.version_id, preview.run_ref, preview.page_number, preview.request_id)
       = (run.org_id, run.space_id, run.version_id, run.run_ref, requested.page_number, requested.request_id)
    JOIN thalion.request_record AS viewed ON (viewed.org_id, viewed.request_id) = (preview.org_id, preview.request_id)
    WHERE run.run_ref = target_run AND run.replaces_run_ref IS NOT NULL AND run.outcome = 'pending_review'
      AND run.pdf_page_count = cardinality(page_requests) AND run.pdf_page_count = run.passage_count
      AND run.contract_revision = source.contract_revision AND source.lifecycle = 'active' AND space.lifecycle = 'active'
      AND contract.admission = 'synthetic_only' AND reviewer.principal_id = contract.quality_reviewer_id
      AND reviewer.principal_type = 'employee' AND reviewer.authority_issuer = 'https://synthetic.invalid'
      AND NOT reviewer.disabled AND approval.delegated_principal_id IS NULL AND approval.outcome IS NULL
      AND approval.configuration_revision = organization.config_revision
      AND (approval.operation, approval.destination) = ('approve_pdf_repair', 'local_workspace')
      AND (viewed.principal_id, viewed.client_id, viewed.operation, viewed.destination, viewed.outcome)
        = (reviewer.principal_id, approval.client_id, 'preview_pdf_repair_page', 'local_workspace', 'succeeded')
      AND viewed.delegated_principal_id IS NULL AND viewed.configuration_revision = approval.configuration_revision
      AND preview.policy_revision = source.local_policy_revision AND preview.correction_ref IS NULL
      AND preview.repair_safety_epochs = ARRAY[organization.safety_epoch, space.safety_epoch, source.safety_epoch]
      AND preview.checked_at > clock_timestamp() - interval '30 minutes'
      AND NOT EXISTS (
          SELECT 1 FROM thalion.processing_run AS newer
          WHERE newer.version_id = run.version_id AND newer.configuration_revision > run.configuration_revision
      )
      AND NOT EXISTS (
          SELECT 1 FROM thalion.pdf_page_observation AS page
          JOIN thalion.pdf_ocr_review_decision AS decision ON decision.decision_ref = page.repair_decision_ref
          JOIN thalion.pdf_ocr_correction AS correction USING (correction_ref)
          WHERE page.run_ref = run.run_ref AND correction.author_id = reviewer.principal_id
      )
      AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = run.version_id)
      AND NOT EXISTS (
          SELECT 1 FROM thalion.current_version_hold WHERE version_id = run.version_id AND action = 'establish'
      )
      AND NOT EXISTS (
          SELECT 1 FROM thalion.quality_decision WHERE run_ref = run.run_ref AND outcome = 'quarantined'
      )
    HAVING count(*) = cardinality(page_requests);
$$;

CREATE OR REPLACE FUNCTION thalion.guard_pdf_repair_quality() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE is_pdf_repair boolean;
BEGIN
    SELECT run.pdf_page_count IS NOT NULL AND run.replaces_run_ref IS NOT NULL INTO is_pdf_repair
    FROM thalion.processing_run AS run
    WHERE (run.org_id, run.space_id, run.version_id, run.run_ref) = (NEW.org_id, NEW.space_id, NEW.version_id, NEW.run_ref);
    IF is_pdf_repair IS DISTINCT FROM (NEW.pdf_repair_page_requests IS NOT NULL) THEN
        RAISE EXCEPTION 'PDF repairs require independent whole-batch review' USING ERRCODE = '23514';
    END IF;
    IF is_pdf_repair THEN
        PERFORM document.document_id FROM thalion.document_version AS version
        JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
        WHERE (version.org_id, version.space_id, version.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id)
        FOR UPDATE OF document;
        IF NOT EXISTS (
            SELECT 1 FROM thalion.request_record
            WHERE (org_id, request_id, principal_id) = (NEW.org_id, NEW.request_id, NEW.reviewer_id)
        ) OR thalion.pdf_repair_review_until(NEW.run_ref, NEW.request_id, NEW.pdf_repair_page_requests) IS NULL THEN
            RAISE EXCEPTION 'PDF repairs require every recent page receipt from the current reviewer' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION thalion.guard_repair_quality_preview() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE replaced uuid;
BEGIN
    SELECT replaces_run_ref INTO replaced FROM thalion.processing_run WHERE run_ref = NEW.run_ref AND pdf_page_count IS NULL;
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
