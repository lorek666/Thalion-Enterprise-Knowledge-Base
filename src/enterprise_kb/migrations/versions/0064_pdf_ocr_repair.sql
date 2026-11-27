ALTER TABLE thalion.pdf_page_observation ADD COLUMN repair_decision_ref uuid
    REFERENCES thalion.pdf_ocr_review_decision (decision_ref),
    ADD CHECK (repair_decision_ref IS NULL OR (method = 'ocr' AND transcript IS NOT NULL));

CREATE FUNCTION thalion.pdf_repair_admitted(
    target_version bigint, target_configuration bigint, replaced_ref uuid, submitted_ref uuid DEFAULT NULL
) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.document_version AS version
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        CROSS JOIN LATERAL (
            SELECT run_ref, configuration_revision, contract_revision, input_digest, outcome, pdf_page_count
            FROM thalion.processing_run
            WHERE version_id = version.version_id AND run_ref IS DISTINCT FROM submitted_ref
            ORDER BY configuration_revision DESC LIMIT 1
        ) AS latest
        JOIN thalion.processing_config_revision AS prior ON prior.configuration_revision = latest.configuration_revision
        JOIN thalion.processing_config_revision AS target ON target.configuration_revision = target_configuration
        WHERE version.version_id = target_version AND asset.media_type = 'application/pdf'
          AND source.lifecycle = 'active' AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
          AND latest.run_ref = replaced_ref AND latest.configuration_revision < target_configuration
          AND latest.contract_revision = source.contract_revision AND latest.input_digest = asset.content_digest
          AND latest.pdf_page_count > 0
          AND prior.profile = 'pdf_pages_v1'
          AND (prior.parser_version, prior.profile, prior.locator_revision)
            = (target.parser_version, target.profile, target.locator_revision)
          AND (latest.outcome = 'quarantined' OR EXISTS (
              SELECT 1 FROM thalion.quality_decision WHERE (run_ref, outcome) = (latest.run_ref, 'quarantined')
          ))
          AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = target_version)
          AND NOT EXISTS (
              SELECT 1 FROM thalion.current_version_hold WHERE version_id = target_version AND action = 'establish'
          )
    );
$$;

CREATE FUNCTION thalion.pdf_repair_pages(replaced_ref uuid)
RETURNS TABLE (
    page_number integer, method text, transcript bytea, reason text, ocr_profile_digest bytea,
    repair_decision_ref uuid, changed boolean
) LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT prior.page_number, prior.method, coalesce(correction.proposed_transcript, prior.transcript),
           CASE WHEN decision.decision_ref IS NULL THEN prior.reason END,
           prior.ocr_profile_digest, coalesce(decision.decision_ref, prior.repair_decision_ref),
           decision.decision_ref IS NOT NULL
    FROM thalion.pdf_page_observation AS prior
    LEFT JOIN thalion.pdf_ocr_review_decision AS decision
      ON (decision.run_ref, decision.page_number, decision.outcome) = (prior.run_ref, prior.page_number, 'approved')
    LEFT JOIN thalion.pdf_ocr_correction AS correction USING (correction_ref)
    WHERE prior.run_ref = replaced_ref;
$$;

DROP TRIGGER processing_run_repair_sealed ON thalion.processing_run;
CREATE CONSTRAINT TRIGGER processing_run_repair_sealed AFTER INSERT ON thalion.processing_run
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
WHEN (NEW.replaces_run_ref IS NOT NULL AND NEW.pdf_page_count IS NULL)
EXECUTE FUNCTION thalion.check_markdown_repair();

CREATE FUNCTION thalion.check_pdf_repair() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NEW.replaces_run_ref IS NULL THEN
        IF EXISTS (
            SELECT 1 FROM thalion.pdf_page_observation
            WHERE run_ref = NEW.run_ref AND repair_decision_ref IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'an ordinary PDF parse cannot carry OCR repair decisions' USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;
    IF NEW.rollback_run_ref IS NOT NULL OR NOT thalion.pdf_repair_admitted(
        NEW.version_id, NEW.configuration_revision, NEW.replaces_run_ref, NEW.run_ref
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.processing_run WHERE run_ref = NEW.replaces_run_ref
          AND (pdf_page_count, input_digest, contract_revision) = (NEW.pdf_page_count, NEW.input_digest, NEW.contract_revision)
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.pdf_repair_pages(NEW.replaces_run_ref) WHERE changed
    ) OR EXISTS (
        SELECT 1 FROM thalion.pdf_repair_pages(NEW.replaces_run_ref) AS expected
        LEFT JOIN thalion.pdf_page_observation AS actual
          ON (actual.run_ref, actual.page_number) = (NEW.run_ref, expected.page_number)
        WHERE expected.transcript IS NULL OR (
            actual.method, actual.transcript, actual.reason, actual.ocr_profile_digest, actual.repair_decision_ref
        ) IS DISTINCT FROM (
            expected.method, expected.transcript, expected.reason, expected.ocr_profile_digest, expected.repair_decision_ref
        )
    ) THEN
        RAISE EXCEPTION 'a PDF repair needs the current quarantine and all exact approved pages' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER processing_run_pdf_repair_sealed AFTER INSERT ON thalion.processing_run
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.pdf_page_count IS NOT NULL)
EXECUTE FUNCTION thalion.check_pdf_repair();

CREATE FUNCTION thalion.guard_pdf_repair_quality() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM thalion.processing_run
        WHERE run_ref = NEW.run_ref AND pdf_page_count IS NOT NULL AND replaces_run_ref IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'PDF repairs require independent whole-batch review' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quality_decision_pdf_repair BEFORE INSERT ON thalion.quality_decision
FOR EACH ROW WHEN (NEW.outcome = 'approved') EXECUTE FUNCTION thalion.guard_pdf_repair_quality();
