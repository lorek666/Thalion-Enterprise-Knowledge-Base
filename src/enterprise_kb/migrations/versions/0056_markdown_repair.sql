ALTER TABLE thalion.processing_run
    ADD COLUMN replaces_run_ref uuid,
    ADD COLUMN rollback_run_ref uuid,
    ADD COLUMN repair_basis_ref uuid,
    ADD FOREIGN KEY (org_id, space_id, version_id, replaces_run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    ADD FOREIGN KEY (org_id, space_id, version_id, rollback_run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    ADD CHECK (
        (replaces_run_ref IS NULL AND rollback_run_ref IS NULL AND repair_basis_ref IS NULL)
        OR (replaces_run_ref IS NOT NULL AND repair_basis_ref IS NOT NULL AND outcome = 'pending_review')
    );

CREATE FUNCTION thalion.markdown_repair_admitted(
    target_version bigint, target_configuration bigint, replaced_ref uuid, baseline_ref uuid,
    submitted_ref uuid DEFAULT NULL
) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.document_version AS version
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        CROSS JOIN LATERAL (
            SELECT run_ref, configuration_revision, contract_revision, input_digest
            FROM thalion.processing_run
            WHERE version_id = version.version_id AND run_ref IS DISTINCT FROM submitted_ref
            ORDER BY configuration_revision DESC LIMIT 1
        ) AS latest
        WHERE version.version_id = target_version AND asset.media_type = 'text/markdown'
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND latest.run_ref = replaced_ref AND latest.configuration_revision < target_configuration
          AND latest.contract_revision = source.contract_revision AND latest.input_digest = asset.content_digest
          AND EXISTS (
              SELECT 1 FROM thalion.quality_decision
              WHERE run_ref = latest.run_ref AND outcome = 'quarantined'
          )
          AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = target_version)
          AND NOT EXISTS (
              SELECT 1 FROM thalion.current_version_hold
              WHERE version_id = target_version AND action = 'establish'
          )
          AND (baseline_ref IS NULL OR EXISTS (
              SELECT 1 FROM thalion.processing_run AS baseline
              JOIN thalion.processing_config_revision AS baseline_config USING (configuration_revision)
              JOIN thalion.processing_config_revision AS target_config
                ON target_config.configuration_revision = target_configuration
              WHERE baseline.run_ref = baseline_ref AND baseline.version_id = target_version
                AND baseline.configuration_revision < latest.configuration_revision
                AND baseline.contract_revision = latest.contract_revision AND baseline.input_digest = latest.input_digest
                AND baseline.outcome = 'pending_review'
                AND (baseline_config.parser_version, baseline_config.profile, baseline_config.locator_revision) =
                    (target_config.parser_version, target_config.profile, target_config.locator_revision)
                AND EXISTS (
                    SELECT 1 FROM thalion.quality_decision WHERE run_ref = baseline_ref AND outcome = 'approved'
                )
                AND NOT EXISTS (
                    SELECT 1 FROM thalion.quality_decision WHERE run_ref = baseline_ref AND outcome = 'quarantined'
                )
          ))
    );
$$;

CREATE FUNCTION thalion.markdown_runs_match(first_run uuid, second_run uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    WITH prior AS (
        SELECT passage_id, content_digest FROM thalion.passage_excerpt WHERE run_ref = first_run
    ), proposed AS (
        SELECT passage_id, content_digest FROM thalion.passage_excerpt WHERE run_ref = second_run
    )
    SELECT NOT EXISTS (
        SELECT 1 FROM prior FULL JOIN proposed USING (passage_id)
        WHERE prior.content_digest IS DISTINCT FROM proposed.content_digest
    );
$$;

CREATE FUNCTION thalion.check_markdown_repair() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT thalion.markdown_repair_admitted(
        NEW.version_id, NEW.configuration_revision, NEW.replaces_run_ref, NEW.rollback_run_ref, NEW.run_ref
    ) OR NOT EXISTS (
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

CREATE CONSTRAINT TRIGGER processing_run_repair_sealed AFTER INSERT ON thalion.processing_run
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.replaces_run_ref IS NOT NULL)
EXECUTE FUNCTION thalion.check_markdown_repair();

CREATE OR REPLACE FUNCTION thalion.current_export_transcript(scope_org bigint, scope_space bigint, target_version bigint)
RETURNS TABLE (run_ref uuid, configuration_revision bigint, manifest_digest bytea, passage_count integer)
LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT latest.run_ref, latest.configuration_revision, latest.manifest_digest, latest.passage_count
    FROM thalion.document_version AS version
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    CROSS JOIN LATERAL (
        SELECT run_ref, configuration_revision, manifest_digest, passage_count, contract_revision, outcome, replaces_run_ref
        FROM thalion.processing_run AS run
        WHERE (run.org_id, run.space_id, run.version_id) = (version.org_id, version.space_id, version.version_id)
        ORDER BY run.configuration_revision DESC LIMIT 1
    ) AS latest
    WHERE (version.org_id, version.space_id, version.version_id) = (scope_org, scope_space, target_version)
      AND latest.contract_revision = source.contract_revision AND latest.outcome = 'pending_review'
      AND latest.passage_count BETWEEN 1 AND 128 AND latest.replaces_run_ref IS NULL
      AND EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'approved'
      ) AND NOT EXISTS (
          SELECT 1 FROM thalion.quality_decision AS quality WHERE quality.run_ref = latest.run_ref AND quality.outcome = 'quarantined'
      );
$$;
