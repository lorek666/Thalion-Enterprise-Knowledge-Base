CREATE FUNCTION thalion.docx_run_has_cells(target_run uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.passage_excerpt AS excerpt JOIN thalion.passage AS passage USING (passage_id)
        WHERE excerpt.run_ref = target_run AND passage.kind = 'docx_cell'
    );
$$;

CREATE OR REPLACE FUNCTION thalion.docx_repair_admitted(
    target_version bigint, target_configuration bigint, replaced_ref uuid, baseline_ref uuid,
    submitted_ref uuid DEFAULT NULL
) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.document_version AS version
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        CROSS JOIN LATERAL (
            SELECT run_ref, configuration_revision, contract_revision, input_digest, outcome
            FROM thalion.processing_run
            WHERE version_id = version.version_id AND run_ref IS DISTINCT FROM submitted_ref
            ORDER BY configuration_revision DESC LIMIT 1
        ) AS latest
        JOIN thalion.processing_config_revision AS prior ON prior.configuration_revision = latest.configuration_revision
        JOIN thalion.processing_config_revision AS target ON target.configuration_revision = target_configuration
        WHERE version.version_id = target_version
          AND source.lifecycle = 'active' AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
          AND asset.storage_kind = 'synthetic_file'
          AND asset.media_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
          AND latest.run_ref = replaced_ref AND latest.configuration_revision < target_configuration
          AND (latest.contract_revision, latest.input_digest) = (source.contract_revision, asset.content_digest)
          AND latest.outcome = 'pending_review'
          AND prior.profile = 'docx_literal_paragraphs_v1'
          AND (prior.parser_version, prior.profile, prior.locator_revision) =
              (target.parser_version, target.profile, target.locator_revision)
          AND EXISTS (
              SELECT 1 FROM thalion.quality_decision WHERE (run_ref, outcome) = (latest.run_ref, 'quarantined')
          )
          AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = target_version)
          AND NOT EXISTS (
              SELECT 1 FROM thalion.current_version_hold WHERE version_id = target_version AND action = 'establish'
          )
          AND NOT EXISTS (
              SELECT 1 FROM thalion.passage_excerpt AS excerpt JOIN thalion.passage AS passage USING (passage_id)
              WHERE excerpt.run_ref IN (replaced_ref, baseline_ref, submitted_ref)
                AND passage.kind NOT IN ('docx_paragraph', 'docx_cell')
          )
          AND (submitted_ref IS NULL OR thalion.docx_run_has_cells(submitted_ref) OR NOT (
              thalion.docx_run_has_cells(replaced_ref) OR thalion.docx_run_has_cells(baseline_ref)
          ))
          AND (baseline_ref IS NULL OR EXISTS (
              SELECT 1 FROM thalion.processing_run AS baseline
              JOIN thalion.processing_config_revision AS config USING (configuration_revision)
              WHERE baseline.run_ref = baseline_ref AND baseline.version_id = target_version
                AND baseline.configuration_revision < latest.configuration_revision
                AND (baseline.contract_revision, baseline.input_digest) = (latest.contract_revision, latest.input_digest)
                AND baseline.outcome = 'pending_review'
                AND (config.parser_version, config.profile, config.locator_revision) =
                    (target.parser_version, target.profile, target.locator_revision)
                AND EXISTS (
                    SELECT 1 FROM thalion.quality_decision WHERE (run_ref, outcome) = (baseline_ref, 'approved')
                )
                AND NOT EXISTS (
                    SELECT 1 FROM thalion.quality_decision WHERE (run_ref, outcome) = (baseline_ref, 'quarantined')
                )
          ))
    );
$$;

CREATE FUNCTION thalion.docx_runs_match(first_run uuid, second_run uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    WITH evidence AS (
        SELECT excerpt.run_ref, excerpt.passage_id, excerpt.docx_header_digest, excerpt.content_digest,
               member.role, unit.reason
        FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (passage_id)
        LEFT JOIN thalion.evidence_unit AS unit ON (unit.run_ref, unit.docx_table, unit.record_number) =
            (excerpt.run_ref, passage.docx_table, passage.docx_row)
        LEFT JOIN thalion.evidence_unit_member AS member ON (member.unit_ref, member.passage_id, member.excerpt_revision) =
            (unit.unit_ref, excerpt.passage_id, excerpt.excerpt_revision)
        WHERE excerpt.run_ref IN (first_run, second_run)
    ), first_evidence AS (
        SELECT passage_id, docx_header_digest, content_digest, role, reason FROM evidence WHERE run_ref = first_run
    ), second_evidence AS (
        SELECT passage_id, docx_header_digest, content_digest, role, reason FROM evidence WHERE run_ref = second_run
    )
    SELECT NOT EXISTS (SELECT * FROM first_evidence EXCEPT SELECT * FROM second_evidence)
       AND NOT EXISTS (SELECT * FROM second_evidence EXCEPT SELECT * FROM first_evidence);
$$;

CREATE OR REPLACE FUNCTION thalion.check_markdown_repair() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE is_docx boolean;
BEGIN
    is_docx := thalion.docx_repair_admitted(
        NEW.version_id, NEW.configuration_revision, NEW.replaces_run_ref, NEW.rollback_run_ref, NEW.run_ref
    );
    IF NOT (is_docx OR thalion.markdown_repair_admitted(
        NEW.version_id, NEW.configuration_revision, NEW.replaces_run_ref, NEW.rollback_run_ref, NEW.run_ref
    )) OR NOT EXISTS (
        SELECT 1 FROM thalion.processing_run
        WHERE run_ref = NEW.replaces_run_ref
          AND (input_digest, contract_revision) = (NEW.input_digest, NEW.contract_revision)
    ) THEN
        RAISE EXCEPTION 'a repair needs the current quarantine and an eligible baseline'
            USING ERRCODE = '23514';
    END IF;
    IF (CASE WHEN is_docx THEN thalion.docx_runs_match(NEW.replaces_run_ref, NEW.run_ref)
             ELSE thalion.markdown_runs_match(NEW.replaces_run_ref, NEW.run_ref) END) THEN
        RAISE EXCEPTION 'the repair must change an exact evidence location, digest or group'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.rollback_run_ref IS NOT NULL AND NOT (
        CASE WHEN is_docx THEN thalion.docx_runs_match(NEW.rollback_run_ref, NEW.run_ref)
             ELSE thalion.markdown_runs_match(NEW.rollback_run_ref, NEW.run_ref) END
    ) THEN
        RAISE EXCEPTION 'the rollback must match the complete approved baseline evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION thalion.guard_repair_quality_preview() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE repaired thalion.processing_run%ROWTYPE;
BEGIN
    SELECT * INTO repaired FROM thalion.processing_run WHERE run_ref = NEW.run_ref AND pdf_page_count IS NULL;
    IF repaired.replaces_run_ref IS NOT NULL AND thalion.docx_run_has_cells(NEW.run_ref) THEN
        IF NEW.repair_preview_ref IS NOT NULL OR (NEW.outcome = 'approved' AND (
            NEW.docx_preview_request IS NULL OR NOT thalion.docx_repair_admitted(
                repaired.version_id, repaired.configuration_revision, repaired.replaces_run_ref,
                repaired.rollback_run_ref, repaired.run_ref
            )
        )) THEN
            RAISE EXCEPTION 'a DOCX table repair requires a current whole-batch preview' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.repair_preview_ref IS NULL THEN
        IF repaired.replaces_run_ref IS NOT NULL AND NEW.outcome = 'approved' THEN
            RAISE EXCEPTION 'approval of a repair requires a sealed difference preview' USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM thalion.repair_review_preview AS preview
        JOIN thalion.request_record AS request USING (org_id, request_id)
        WHERE preview.preview_ref = NEW.repair_preview_ref AND preview.replaces_run_ref = repaired.replaces_run_ref
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
