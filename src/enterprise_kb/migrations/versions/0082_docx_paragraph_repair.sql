CREATE FUNCTION thalion.docx_repair_admitted(
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
              WHERE excerpt.run_ref IN (replaced_ref, baseline_ref, submitted_ref) AND passage.kind <> 'docx_paragraph'
          )
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

CREATE OR REPLACE FUNCTION thalion.check_markdown_repair() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT (thalion.markdown_repair_admitted(
        NEW.version_id, NEW.configuration_revision, NEW.replaces_run_ref, NEW.rollback_run_ref, NEW.run_ref
    ) OR thalion.docx_repair_admitted(
        NEW.version_id, NEW.configuration_revision, NEW.replaces_run_ref, NEW.rollback_run_ref, NEW.run_ref
    )) OR NOT EXISTS (
        SELECT 1 FROM thalion.processing_run
        WHERE run_ref = NEW.replaces_run_ref
          AND (input_digest, contract_revision) = (NEW.input_digest, NEW.contract_revision)
    ) THEN
        RAISE EXCEPTION 'a repair needs the current quarantine and an eligible baseline'
            USING ERRCODE = '23514';
    END IF;
    IF thalion.markdown_runs_match(NEW.replaces_run_ref, NEW.run_ref) THEN
        RAISE EXCEPTION 'the repair must change an exact evidence location or digest'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.rollback_run_ref IS NOT NULL AND NOT thalion.markdown_runs_match(NEW.rollback_run_ref, NEW.run_ref) THEN
        RAISE EXCEPTION 'the rollback must match the complete approved baseline evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;
