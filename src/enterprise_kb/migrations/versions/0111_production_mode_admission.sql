-- 1. Bidirectional deployment-mode isolation helpers
CREATE OR REPLACE FUNCTION thalion.is_admitted_authority_issuer(issuer text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, thalion AS $$
    SELECT issuer IS NOT NULL
       AND issuer LIKE 'https://%'
       AND char_length(btrim(issuer)) > 8;
$$;

CREATE OR REPLACE FUNCTION thalion.is_production_issuer(issuer text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, thalion AS $$
    SELECT thalion.is_admitted_authority_issuer(issuer)
       AND issuer <> 'https://synthetic.invalid';
$$;

CREATE OR REPLACE FUNCTION thalion.admission_for_issuer(issuer text)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, thalion AS $$
    SELECT CASE
        WHEN issuer = 'https://synthetic.invalid' THEN 'synthetic_only'
        WHEN thalion.is_production_issuer(issuer) THEN 'production_approved'
        ELSE NULL
    END;
$$;

CREATE OR REPLACE FUNCTION thalion.issuer_matches_admission(issuer text, admission text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, thalion AS $$
    SELECT COALESCE(
        admission IN ('synthetic_only', 'production_approved')
        AND thalion.admission_for_issuer(issuer) = admission,
        FALSE
    );
$$;

CREATE OR REPLACE FUNCTION thalion.storage_matches_admission(storage_kind text, admission text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, thalion AS $$
    SELECT COALESCE(
        (admission = 'synthetic_only' AND storage_kind = 'synthetic_file')
        OR (admission = 'production_approved' AND storage_kind = 'https_object_store'),
        FALSE
    );
$$;

CREATE OR REPLACE FUNCTION thalion.issuers_same_mode(issuer_a text, issuer_b text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, thalion AS $$
    SELECT COALESCE(
        thalion.admission_for_issuer(issuer_a) IS NOT NULL
        AND thalion.admission_for_issuer(issuer_a) = thalion.admission_for_issuer(issuer_b),
        FALSE
    );
$$;

-- 2. Upgrade table CHECK constraints for dual-mode admission & storage
ALTER TABLE thalion.source_contract_revision
    DROP CONSTRAINT IF EXISTS source_contract_revision_admission_check,
    ADD CONSTRAINT source_contract_revision_admission_check
        CHECK (admission IN ('synthetic_only', 'production_approved'));

ALTER TABLE thalion.source_contract_revision
    DROP CONSTRAINT IF EXISTS source_contract_revision_check4,
    ADD CONSTRAINT source_contract_revision_check4
        CHECK (
            docx_amount_columns IS NULL
            OR (
                admission IN ('synthetic_only', 'production_approved')
                AND processor_id IS NOT NULL
                AND quality_reviewer_id IS NOT NULL
                AND thalion.valid_csv_amount_columns(docx_amount_columns)
            ) IS TRUE
        );

ALTER TABLE thalion.asset
    DROP CONSTRAINT IF EXISTS asset_storage_kind_check,
    ADD CONSTRAINT asset_storage_kind_check
        CHECK (storage_kind IN ('synthetic_file', 'https_object_store'));

ALTER TABLE thalion.permission_binding
    DROP CONSTRAINT IF EXISTS permission_binding_use,
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
        OR (operation = 'send_model_evidence'
            AND destination ~ '^[a-z0-9][a-z0-9._:-]{1,127}$'
            AND purpose IN ('model_answer', 'wiki_compilation', 'model_review')
            AND passage_ref IS NOT NULL AND isfinite(valid_from) AND valid_until IS NOT NULL AND isfinite(valid_until)
            AND fields <@ ARRAY['excerpt', 'citation', 'title', 'location', 'version'])
    );

ALTER TABLE thalion.compile_template_revision
    DROP CONSTRAINT IF EXISTS compile_template_revision_model_profile_check,
    ADD CONSTRAINT compile_template_revision_model_profile_check
        CHECK (model_profile ~ '^[a-z0-9][a-z0-9._:-]{1,127}$');

-- 3. Database-level bidirectional isolation triggers (no cross-mode mixing)
CREATE OR REPLACE FUNCTION thalion.guard_source_contract_isolation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, thalion AS $$
DECLARE
    prior_admission text;
    mismatch_count integer;
BEGIN
    IF NEW.admission NOT IN ('synthetic_only', 'production_approved') THEN
        RAISE EXCEPTION 'unsupported source contract admission mode: %', NEW.admission
            USING ERRCODE = '23514';
    END IF;

    SELECT scr.admission INTO prior_admission
    FROM thalion.source_contract_revision AS scr
    WHERE (scr.org_id, scr.space_id, scr.source_id) = (NEW.org_id, NEW.space_id, NEW.source_id)
      AND scr.revision <> NEW.revision
    LIMIT 1;
    IF prior_admission IS NOT NULL AND prior_admission <> NEW.admission THEN
        RAISE EXCEPTION 'source contract admission mode cannot change across revisions'
            USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM thalion.source AS src
    JOIN thalion.space AS sp ON (sp.org_id, sp.space_id) = (src.org_id, src.space_id)
    JOIN thalion.principal AS src_owner
      ON (src_owner.org_id, src_owner.principal_id) = (src.org_id, src.owner_principal_id)
    JOIN thalion.principal AS sp_owner
      ON (sp_owner.org_id, sp_owner.principal_id) = (sp.org_id, sp.owner_principal_id)
    WHERE (src.org_id, src.space_id, src.source_id) = (NEW.org_id, NEW.space_id, NEW.source_id)
      AND thalion.issuer_matches_admission(src_owner.authority_issuer, NEW.admission)
      AND thalion.issuer_matches_admission(sp_owner.authority_issuer, NEW.admission);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source and space owners must match source contract admission mode'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO mismatch_count
    FROM thalion.principal AS p
    WHERE p.org_id = NEW.org_id
      AND p.principal_id IN (
          NEW.collector_id,
          COALESCE(NEW.approver_id, NEW.collector_id),
          COALESCE(NEW.processor_id, NEW.collector_id),
          COALESCE(NEW.quality_reviewer_id, NEW.collector_id)
      )
      AND NOT thalion.issuer_matches_admission(p.authority_issuer, NEW.admission);
    IF mismatch_count > 0 THEN
        RAISE EXCEPTION 'all source contract principals must match contract admission mode'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS source_contract_isolation_guard ON thalion.source_contract_revision;
CREATE TRIGGER source_contract_isolation_guard
BEFORE INSERT OR UPDATE ON thalion.source_contract_revision
FOR EACH ROW EXECUTE FUNCTION thalion.guard_source_contract_isolation();

CREATE OR REPLACE FUNCTION thalion.guard_asset_storage_isolation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, thalion AS $$
DECLARE
    src_admission text;
BEGIN
    SELECT contract.admission INTO src_admission
    FROM thalion.source AS src
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (src.org_id, src.space_id, src.source_id, src.contract_revision)
    WHERE (src.org_id, src.space_id, src.source_id) = (NEW.org_id, NEW.space_id, NEW.source_id);

    IF src_admission IS NULL THEN
        RAISE EXCEPTION 'asset requires an admitted source contract' USING ERRCODE = '23514';
    END IF;
    IF NOT thalion.storage_matches_admission(NEW.storage_kind, src_admission) THEN
        RAISE EXCEPTION 'asset storage_kind (%) violates source admission mode (%)', NEW.storage_kind, src_admission
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS asset_storage_isolation_guard ON thalion.asset;
CREATE TRIGGER asset_storage_isolation_guard
BEFORE INSERT OR UPDATE ON thalion.asset
FOR EACH ROW EXECUTE FUNCTION thalion.guard_asset_storage_isolation();

CREATE OR REPLACE FUNCTION thalion.guard_document_version_isolation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, thalion AS $$
DECLARE
    contract_admission text;
    asset_storage text;
BEGIN
    SELECT contract.admission INTO contract_admission
    FROM thalion.source_contract_revision AS contract
    WHERE (contract.org_id, contract.space_id, contract.source_id, contract.revision)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision);
    SELECT asset.storage_kind INTO asset_storage
    FROM thalion.asset AS asset
    WHERE (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id, NEW.asset_id);

    IF contract_admission IS NULL OR asset_storage IS NULL
       OR NOT thalion.storage_matches_admission(asset_storage, contract_admission) THEN
        RAISE EXCEPTION 'document version asset storage_kind does not match contract admission mode'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS document_version_isolation_guard ON thalion.document_version;
CREATE TRIGGER document_version_isolation_guard
BEFORE INSERT OR UPDATE ON thalion.document_version
FOR EACH ROW EXECUTE FUNCTION thalion.guard_document_version_isolation();

CREATE OR REPLACE FUNCTION thalion.guard_permission_binding_isolation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, thalion AS $$
DECLARE
    src_admission text;
    subject_issuer text;
BEGIN
    SELECT contract.admission INTO src_admission
    FROM thalion.source AS src
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (src.org_id, src.space_id, src.source_id, src.contract_revision)
    WHERE (src.org_id, src.space_id, src.source_id) = (NEW.org_id, NEW.space_id, NEW.source_id);

    SELECT p.authority_issuer INTO subject_issuer
    FROM thalion.principal AS p
    WHERE (p.org_id, p.principal_id) = (NEW.org_id, NEW.subject_id);

    IF src_admission IS NULL
       OR subject_issuer IS NULL
       OR NOT thalion.issuer_matches_admission(subject_issuer, src_admission) THEN
        RAISE EXCEPTION 'permission binding subject must match source contract admission mode'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.operation = 'send_model_evidence' THEN
        IF src_admission = 'synthetic_only' AND NEW.destination <> 'synthetic-gateway' THEN
            RAISE EXCEPTION 'synthetic source model egress destination must be synthetic-gateway'
                USING ERRCODE = '23514';
        END IF;
        IF src_admission = 'production_approved' AND NEW.destination = 'synthetic-gateway' THEN
            RAISE EXCEPTION 'production source model egress destination cannot be synthetic-gateway'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS permission_binding_isolation_guard ON thalion.permission_binding;
CREATE TRIGGER permission_binding_isolation_guard
BEFORE INSERT OR UPDATE ON thalion.permission_binding
FOR EACH ROW EXECUTE FUNCTION thalion.guard_permission_binding_isolation();

CREATE OR REPLACE FUNCTION thalion.guard_compile_template_isolation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, thalion AS $$
DECLARE
    owner_issuer text;
    author_issuer text;
    reviewer_issuer text;
    space_mode text;
BEGIN
    SELECT owner.authority_issuer, author.authority_issuer, reviewer.authority_issuer
    INTO owner_issuer, author_issuer, reviewer_issuer
    FROM thalion.space AS sp
    JOIN thalion.principal AS owner ON (owner.org_id, owner.principal_id) = (sp.org_id, sp.owner_principal_id)
    JOIN thalion.principal AS author ON (author.org_id, author.principal_id) = (NEW.org_id, NEW.author_id)
    JOIN thalion.principal AS reviewer ON (reviewer.org_id, reviewer.principal_id) = (NEW.org_id, NEW.reviewer_id)
    WHERE (sp.org_id, sp.space_id) = (NEW.org_id, NEW.space_id);

    space_mode := thalion.admission_for_issuer(owner_issuer);
    IF space_mode IS NULL
       OR NOT thalion.issuers_same_mode(owner_issuer, author_issuer)
       OR NOT thalion.issuers_same_mode(owner_issuer, reviewer_issuer) THEN
        RAISE EXCEPTION 'compile template principals must match space deployment mode'
            USING ERRCODE = '23514';
    END IF;

    IF space_mode = 'synthetic_only' AND NEW.model_profile <> 'synthetic-local' THEN
        RAISE EXCEPTION 'synthetic compile template must use synthetic-local model_profile'
            USING ERRCODE = '23514';
    END IF;
    IF space_mode = 'production_approved' AND NEW.model_profile = 'synthetic-local' THEN
        RAISE EXCEPTION 'production compile template cannot use synthetic-local model_profile'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS compile_template_isolation_guard ON thalion.compile_template_revision;
CREATE TRIGGER compile_template_isolation_guard
BEFORE INSERT OR UPDATE ON thalion.compile_template_revision
FOR EACH ROW EXECUTE FUNCTION thalion.guard_compile_template_isolation();

-- 4. Upgrade all 4 views for dual-mode with bidirectional matching
CREATE OR REPLACE VIEW thalion.active_compile_template AS
SELECT latest.org_id,
    latest.space_id,
    latest.template_key,
    latest.revision_ref,
    latest.generation
FROM (
    SELECT DISTINCT ON (org_id, space_id, template_key)
        org_id, space_id, template_key, revision_ref, generation, activated_by
    FROM thalion.compile_template_activation
    ORDER BY org_id, space_id, template_key, generation DESC
) AS latest
JOIN thalion.space AS space USING (org_id, space_id)
JOIN thalion.compile_template_admission AS admission USING (org_id, space_id, template_key, revision_ref)
JOIN thalion.principal AS owner ON (owner.org_id, owner.principal_id) = (latest.org_id, latest.activated_by)
JOIN thalion.principal AS reviewer ON (reviewer.org_id, reviewer.principal_id) = (latest.org_id, admission.reviewer_id)
WHERE space.lifecycle = 'active'
  AND space.owner_principal_id = owner.principal_id
  AND owner.principal_id <> reviewer.principal_id
  AND owner.principal_type = 'employee' AND NOT owner.disabled
  AND reviewer.principal_type = 'employee' AND NOT reviewer.disabled
  AND thalion.issuers_same_mode(owner.authority_issuer, reviewer.authority_issuer);

CREATE OR REPLACE VIEW thalion.pdf_processing_restriction_material AS
SELECT run.org_id,
    run.run_ref,
    space.public_id AS space_ref,
    version_ref.public_id AS version_ref,
    run.configuration_revision,
    run.manifest_digest,
    run.recorded_at,
    run.reason,
    run.pdf_page_count
FROM thalion.processing_run AS run
JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
   = (version.org_id, version.space_id, version.source_id, run.contract_revision)
JOIN thalion.object_identity AS space
  ON (space.org_id, space.space_id, space.object_type, space.object_id)
   = (run.org_id, run.space_id, 'space', run.space_id)
JOIN thalion.object_identity AS version_ref
  ON (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id)
   = (run.org_id, run.space_id, 'document_version', run.version_id)
WHERE run.outcome = 'quarantined'
  AND run.pdf_page_count IS NOT NULL
  AND contract.admission IN ('synthetic_only', 'production_approved');

CREATE OR REPLACE VIEW thalion.quality_restriction_material AS
SELECT decision.org_id,
    decision.decision_ref,
    space.public_id AS space_ref,
    version_ref.public_id AS version_ref,
    reviewer.public_id AS reviewer_ref,
    run.run_ref,
    run.configuration_revision,
    run.manifest_digest,
    decision.basis_ref,
    decision.recorded_at
FROM thalion.quality_decision AS decision
JOIN thalion.processing_run AS run USING (org_id, space_id, version_id, run_ref)
JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
   = (version.org_id, version.space_id, version.source_id, run.contract_revision)
JOIN thalion.object_identity AS space
  ON (space.org_id, space.space_id, space.object_type, space.object_id)
   = (decision.org_id, decision.space_id, 'space', decision.space_id)
JOIN thalion.object_identity AS version_ref
  ON (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id)
   = (decision.org_id, decision.space_id, 'document_version', decision.version_id)
JOIN thalion.object_identity AS reviewer
  ON (reviewer.org_id, reviewer.object_type, reviewer.object_id)
   = (decision.org_id, 'principal', decision.reviewer_id)
WHERE decision.outcome = 'quarantined'
  AND contract.admission IN ('synthetic_only', 'production_approved');

CREATE OR REPLACE VIEW thalion.synthetic_original_export_target AS
SELECT version.org_id,
    version.space_id,
    version.version_id,
    source.source_id,
    identity.public_id AS version_ref,
    source.owner_principal_id AS owner_id,
    space.owner_principal_id AS space_owner_id,
    contract.approver_id,
    ARRAY[
        organization.safety_epoch, space.safety_epoch, source.safety_epoch,
        source.contract_revision, organization.config_revision, COALESCE(hold.generation, (0)::bigint)
    ] AS snapshot,
    asset.storage_key,
    asset.content_digest,
    asset.byte_length,
    (COALESCE((hold.action = 'establish'::text), false) OR EXISTS (
        SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = version.version_id
    )) AS blocked,
    asset.media_type
FROM thalion.document_version AS version
JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
JOIN thalion.source AS source USING (org_id, space_id, source_id)
JOIN thalion.organization AS organization USING (org_id)
JOIN thalion.space AS space USING (org_id, space_id)
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
   = (source.org_id, source.space_id, source.source_id, source.contract_revision)
JOIN thalion.object_identity AS identity
  ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
   = (version.org_id, version.space_id, 'document_version', version.version_id)
LEFT JOIN thalion.current_version_hold AS hold
  ON (hold.org_id, hold.space_id, hold.version_id) = (version.org_id, version.space_id, version.version_id)
WHERE source.lifecycle = 'active'
  AND space.lifecycle = 'active'
  AND contract.admission IN ('synthetic_only', 'production_approved')
  AND thalion.storage_matches_admission(asset.storage_kind, contract.admission)
  AND asset.media_type = ANY (ARRAY[
      'text/markdown'::text,
      'application/pdf'::text,
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'::text
  ]);

-- 5. Upgrade all 24 existing functions for dual-mode + bidirectional isolation
CREATE OR REPLACE FUNCTION thalion.docx_repair_admitted(target_version bigint, target_configuration bigint, replaced_ref uuid, baseline_ref uuid, submitted_ref uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
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
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND contract.admission IN ('synthetic_only', 'production_approved')
          AND thalion.storage_matches_admission(asset.storage_kind, contract.admission)
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
$function$;

CREATE OR REPLACE FUNCTION thalion.enqueue_rule_restriction()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
DECLARE
    next_generation bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.source_contract_revision AS contract
        WHERE (contract.org_id, contract.space_id, contract.source_id, contract.revision)
            = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision)
          AND contract.admission IN ('synthetic_only', 'production_approved')
    ) THEN
        RETURN NULL;
    END IF;
    INSERT INTO thalion.rule_restriction_stream AS stream (org_id, generation)
    VALUES (NEW.org_id, 1)
    ON CONFLICT (org_id) DO UPDATE SET generation = stream.generation + 1
    RETURNING generation INTO next_generation;
    INSERT INTO thalion.rule_restriction_item (decision_ref, org_id, generation)
    VALUES (NEW.decision_ref, NEW.org_id, next_generation);
    RETURN NULL;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_document_responsibility()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    PERFORM 1 FROM thalion.document AS document
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.organization AS organization USING (org_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (document.org_id, NEW.approved_by)
    JOIN thalion.request_record AS request
      ON (request.org_id, request.scope_space_id, request.request_id) = (document.org_id, document.space_id, NEW.request_id)
    WHERE (document.org_id, document.space_id, document.source_id, document.document_id)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
      AND source.lifecycle = 'active' AND space.lifecycle = 'active'
      AND actor.principal_type = 'employee' AND NOT actor.disabled
      AND thalion.issuer_matches_admission(actor.authority_issuer, contract.admission)
      AND (
          source.owner_principal_id = NEW.approved_by
          OR thalion.has_active_space_delegation(NEW.org_id, NEW.space_id, NEW.approved_by, 'responsibility_management')
          OR (request.operation = 'record_transition_handoff' AND space.owner_principal_id = NEW.approved_by)
      )
      AND request.principal_id = NEW.approved_by AND request.delegated_principal_id IS NULL AND request.outcome IS NULL
      AND request.configuration_revision = organization.config_revision
      AND (
          (request.operation = 'set_document_responsibility' AND request.destination = 'internal_sources')
          OR (request.operation = 'record_transition_handoff' AND request.destination = 'internal_governance')
      )
    FOR SHARE OF source, space, organization, actor, request
    FOR UPDATE OF document;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'an open request from the current source owner or active delegate is required' USING ERRCODE = '23514';
    END IF;
    IF NEW.responsible_id IS NOT NULL THEN
        PERFORM 1 FROM thalion.principal AS resp
        JOIN thalion.principal AS approver ON (approver.org_id, approver.principal_id) = (NEW.org_id, NEW.approved_by)
        WHERE (resp.org_id, resp.principal_id) = (NEW.org_id, NEW.responsible_id)
          AND resp.principal_type = 'employee' AND NOT resp.disabled
          AND thalion.issuers_same_mode(resp.authority_issuer, approver.authority_issuer)
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'responsibility requires an active employee of this organization' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.generation <> 1 + COALESCE((
        SELECT max(generation) FROM thalion.responsibility_assignment
        WHERE (org_id, space_id, source_id, document_id) = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
    ), 0) THEN
        RAISE EXCEPTION 'responsibility generation must follow the current decision' USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_pdf_ocr_correction()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
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
      AND thalion.issuer_matches_admission(author.authority_issuer, contract.admission)
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
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_pdf_ocr_review_decision()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
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
      AND thalion.issuer_matches_admission(reviewer.authority_issuer, contract.admission)
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
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_shared_group_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    PERFORM 1
    FROM thalion.space AS owner_space
    JOIN thalion.space AS target_space
      ON (target_space.org_id, target_space.space_id) = (NEW.org_id, NEW.target_space_id)
    JOIN thalion.source AS target_source
      ON (target_source.org_id, target_source.space_id, target_source.source_id)
       = (NEW.org_id, NEW.target_space_id, NEW.target_source_id)
    JOIN thalion.principal AS grp
      ON (grp.org_id, grp.principal_id) = (NEW.org_id, NEW.group_principal_id)
    JOIN thalion.principal AS creator
      ON (creator.org_id, creator.principal_id) = (NEW.org_id, NEW.created_by)
    WHERE (owner_space.org_id, owner_space.space_id) = (NEW.org_id, NEW.owner_space_id)
      AND owner_space.lifecycle = 'active'
      AND target_space.lifecycle = 'active'
      AND target_source.lifecycle = 'active'
      AND grp.principal_type = 'group'
      AND NOT grp.disabled
      AND creator.principal_type = 'employee'
      AND thalion.issuers_same_mode(grp.authority_issuer, creator.authority_issuer)
      AND NOT creator.disabled
    FOR SHARE OF owner_space, target_space, target_source, grp, creator;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'shared group requires active spaces, source, group principal, and employee creator'
            USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_shared_group_member_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
DECLARE
    grp thalion.shared_group%ROWTYPE;
BEGIN
    SELECT * INTO STRICT grp
    FROM thalion.shared_group
    WHERE (org_id, owner_space_id, group_ref) = (NEW.org_id, NEW.owner_space_id, NEW.group_ref)
    FOR SHARE;
    IF EXISTS (SELECT 1 FROM thalion.shared_group_revocation WHERE group_ref = NEW.group_ref) THEN
        RAISE EXCEPTION 'cannot add members to a revoked shared group' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM thalion.space AS owner_space
        JOIN thalion.space AS target_space
          ON (target_space.org_id, target_space.space_id) = (grp.org_id, grp.target_space_id)
        WHERE (owner_space.org_id, owner_space.space_id) = (grp.org_id, grp.owner_space_id)
          AND owner_space.lifecycle = 'active' AND target_space.lifecycle = 'active'
    ) THEN
        RAISE EXCEPTION 'cannot add members to a shared group in an archived space' USING ERRCODE = '23514';
    END IF;
    PERFORM 1 FROM thalion.principal AS member_p
    JOIN thalion.principal AS grp_p ON (grp_p.org_id, grp_p.principal_id) = (grp.org_id, grp.group_principal_id)
    WHERE (member_p.org_id, member_p.principal_id) = (NEW.org_id, NEW.member_principal_id)
      AND member_p.principal_type = 'employee' AND NOT member_p.disabled
      AND thalion.issuers_same_mode(member_p.authority_issuer, grp_p.authority_issuer)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'shared group member must be an active employee of this organization' USING ERRCODE = '23514';
    END IF;
    IF NEW.starts_at < grp.starts_at OR NEW.expires_at > grp.expires_at THEN
        RAISE EXCEPTION 'shared group membership window must fit inside the shared group window' USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_space_archive_approval_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
DECLARE
    req_sources bigint[];
    approved_sources integer;
BEGIN
    SELECT source_ids INTO req_sources
    FROM thalion.space_archive_request
    WHERE (org_id, space_id, export_ref, requester_id)
        = (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
    IF req_sources IS NULL THEN
        RAISE EXCEPTION 'space archive request not found for approval' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.approver_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id <> NEW.approver_id
      AND actor.principal_type = 'employee'
      AND thalion.is_admitted_authority_issuer(actor.authority_issuer)
      AND EXISTS (
          SELECT 1 FROM thalion.principal AS sp_owner
          WHERE (sp_owner.org_id, sp_owner.principal_id) = (space.org_id, space.owner_principal_id)
            AND thalion.issuers_same_mode(actor.authority_issuer, sp_owner.authority_issuer)
      )
      AND NOT actor.disabled
      AND req.principal_id = NEW.approver_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'approve_space_archive'
      AND req.destination = 'internal_lifecycle'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF space, org, actor, req;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space archive approval requires an independent active employee with an open request'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO approved_sources
    FROM thalion.source AS src
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (src.org_id, src.space_id, src.source_id, src.contract_revision)
    WHERE (src.org_id, src.space_id) = (NEW.org_id, NEW.space_id)
      AND src.source_id = ANY(req_sources)
      AND contract.approver_id = NEW.approver_id
      AND src.owner_principal_id <> NEW.approver_id;
    IF approved_sources <> cardinality(req_sources) THEN
        RAISE EXCEPTION 'approver must hold independent approval authority across every archived source'
            USING ERRCODE = '23514';
    END IF;

    NEW.approved_at := clock_timestamp();
    IF NEW.expires_at <= NEW.approved_at OR NEW.expires_at > NEW.approved_at + interval '15 minutes' THEN
        RAISE EXCEPTION 'space archive approval expiry must be within fifteen minutes' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_space_archive_package_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.requester_id)
    JOIN thalion.space_archive_approval AS approval
      ON (approval.org_id, approval.space_id, approval.export_ref, approval.approval_ref)
       = (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.approval_ref)
    JOIN thalion.principal AS approver
      ON (approver.org_id, approver.principal_id) = (approval.org_id, approval.approver_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.requester_id
      AND actor.principal_type = 'employee'
      AND NOT actor.disabled
      AND approver.principal_type = 'employee'
      AND thalion.issuers_same_mode(actor.authority_issuer, approver.authority_issuer)
      AND NOT approver.disabled
      AND approval.expires_at > clock_timestamp()
      AND NEW.authority_valid_until > clock_timestamp()
      AND req.principal_id = NEW.requester_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'seal_space_archive'
      AND req.destination = 'internal_lifecycle'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF space, org, actor, approver, approval, req;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'sealing a space archive requires a live independent approval and open requester session'
            USING ERRCODE = '23514';
    END IF;
    NEW.sealed_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_space_archive_request_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
DECLARE
    distinct_sources integer;
    matching_sources integer;
    distinct_versions integer;
    matching_versions integer;
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.requester_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.requester_id
      AND actor.principal_type = 'employee'
      AND thalion.is_admitted_authority_issuer(actor.authority_issuer)
      AND NOT actor.disabled
      AND req.principal_id = NEW.requester_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'request_space_archive'
      AND req.destination = 'internal_lifecycle'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF org, actor, req
    FOR UPDATE OF space;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space archive request requires an open request from the active space owner'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(DISTINCT s) INTO distinct_sources FROM unnest(NEW.source_ids) AS s;
    IF distinct_sources <> cardinality(NEW.source_ids) THEN
        RAISE EXCEPTION 'space archive source list must not contain duplicates' USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO matching_sources
    FROM thalion.source AS src
    WHERE (src.org_id, src.space_id) = (NEW.org_id, NEW.space_id)
      AND src.source_id = ANY(NEW.source_ids)
      AND src.owner_principal_id = NEW.requester_id;
    IF matching_sources <> distinct_sources THEN
        RAISE EXCEPTION 'all archived sources must belong to this space and be owned by the requester'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(DISTINCT v) INTO distinct_versions FROM unnest(NEW.version_ids) AS v;
    IF distinct_versions <> cardinality(NEW.version_ids) THEN
        RAISE EXCEPTION 'space archive version list must not contain duplicates' USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO matching_versions
    FROM thalion.document_version AS ver
    WHERE (ver.org_id, ver.space_id) = (NEW.org_id, NEW.space_id)
      AND ver.source_id = ANY(NEW.source_ids)
      AND ver.version_id = ANY(NEW.version_ids);
    IF matching_versions <> distinct_versions THEN
        RAISE EXCEPTION 'all archived versions must belong to the selected space and sources'
            USING ERRCODE = '23514';
    END IF;

    NEW.requested_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_space_delegation_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.principal AS delegator
      ON (delegator.org_id, delegator.principal_id) = (space.org_id, NEW.delegator_id)
    JOIN thalion.principal AS delegate
      ON (delegate.org_id, delegate.principal_id) = (space.org_id, NEW.delegate_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.delegator_id
      AND delegator.principal_type = 'employee'
      AND NOT delegator.disabled
      AND delegate.principal_type = 'employee'
      AND thalion.issuers_same_mode(delegator.authority_issuer, delegate.authority_issuer)
      AND NOT delegate.disabled
    FOR SHARE OF space, delegator, delegate;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space delegation requires an active space owner delegating to another active employee'
            USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_space_release_config_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
DECLARE
    target_gen bigint;
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.actor_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.actor_id
      AND actor.principal_type = 'employee'
      AND thalion.is_admitted_authority_issuer(actor.authority_issuer)
      AND NOT actor.disabled
      AND req.principal_id = NEW.actor_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'switch_space_release'
      AND req.destination = 'internal_release'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF org, actor, req
    FOR UPDATE OF space;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space release change requires an open request from the active space owner'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.generation <> 1 + COALESCE((
        SELECT max(generation) FROM thalion.space_release_config
        WHERE (org_id, space_id) = (NEW.org_id, NEW.space_id)
    ), 0) THEN
        RAISE EXCEPTION 'space release generation must increment monotonically' USING ERRCODE = '23514';
    END IF;
    IF NEW.target_release_ref IS NOT NULL THEN
        SELECT generation INTO target_gen
        FROM thalion.space_release_config
        WHERE (org_id, space_id, release_ref) = (NEW.org_id, NEW.space_id, NEW.target_release_ref);
        IF target_gen IS NULL OR target_gen >= NEW.generation THEN
            RAISE EXCEPTION 'rollback target release must be an earlier release in the same space'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.template_revision_ref IS NOT NULL THEN
        PERFORM 1
        FROM thalion.compile_template_admission AS admission
        JOIN thalion.principal AS reviewer
          ON (reviewer.org_id, reviewer.principal_id) = (admission.org_id, admission.reviewer_id)
        WHERE (admission.org_id, admission.space_id, admission.template_key, admission.revision_ref)
            = (NEW.org_id, NEW.space_id, NEW.template_key, NEW.template_revision_ref)
          AND admission.decision = 'approved'
          AND admission.reviewer_id <> NEW.actor_id
          AND reviewer.principal_type = 'employee'
          AND EXISTS (
              SELECT 1 FROM thalion.principal AS actor_p
              WHERE (actor_p.org_id, actor_p.principal_id) = (NEW.org_id, NEW.actor_id)
                AND thalion.issuers_same_mode(reviewer.authority_issuer, actor_p.authority_issuer)
          )
          AND NOT reviewer.disabled
        FOR SHARE OF reviewer;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'release template must have an active independent approval in this space'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_synthetic_export()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
DECLARE
    candidate thalion.synthetic_export_request%ROWTYPE;
    target thalion.synthetic_original_export_target%ROWTYPE;
    recipient bigint := NEW.requester_id;
    result_actor bigint := NEW.requester_id;
    operation_name text := 'request_original_export';
BEGIN
    IF TG_TABLE_NAME = 'synthetic_export_request' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO STRICT candidate FROM thalion.synthetic_export_request AS request
        WHERE (request.org_id, request.space_id, request.export_ref, request.requester_id) =
              (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
        IF TG_TABLE_NAME = 'synthetic_export_approval' THEN
            result_actor := NEW.approver_id;
            operation_name := 'approve_original_export';
        ELSE
            operation_name := 'export_original_archive';
        END IF;
    END IF;
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, result_actor, operation_name
    ) THEN
        RAISE EXCEPTION 'original archive requires a matching open request' USING ERRCODE = '23514';
    END IF;
    PERFORM thalion.lock_synthetic_export_target(NEW.org_id, NEW.space_id, candidate.version_id);
    SELECT * INTO target FROM thalion.synthetic_original_export_target
    WHERE (org_id, space_id, version_id) = (NEW.org_id, NEW.space_id, candidate.version_id);
    IF NOT FOUND OR target.blocked OR target.snapshot <> candidate.snapshot
        OR target.owner_id <> recipient OR target.space_owner_id <> recipient
        OR (operation_name = 'approve_original_export' AND target.approver_id IS DISTINCT FROM result_actor)
        OR (target.media_type = 'application/pdf' AND NOT thalion.pdf_export_scope_admitted(candidate))
    THEN
        RAISE EXCEPTION 'original archive requires a current scoped version and independent authorization' USING ERRCODE = '23514';
    END IF;
    IF operation_name = 'export_original_archive' THEN
        IF NOT EXISTS (
            SELECT 1 FROM thalion.synthetic_export_approval AS approval
            JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (approval.org_id, approval.approver_id)
            WHERE approval.approval_ref = NEW.approval_ref AND approval.approver_id = target.approver_id
              AND NOT actor.disabled AND actor.principal_type = 'employee'
              AND EXISTS (
                  SELECT 1 FROM thalion.principal AS req_p
                  WHERE (req_p.org_id, req_p.principal_id) = (NEW.org_id, NEW.requester_id)
                    AND thalion.issuers_same_mode(actor.authority_issuer, req_p.authority_issuer)
              )
              AND clock_timestamp() < least(approval.expires_at, NEW.authority_valid_until)
            FOR SHARE OF actor
        ) THEN
            RAISE EXCEPTION 'archive sealing requires live independent approval and authority' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.guard_wiki_topic_rollback_insert()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
DECLARE
    current_pub thalion.wiki_publication_event%ROWTYPE;
    target_pub thalion.wiki_publication_event%ROWTYPE;
    effective_pub uuid;
    target_author bigint;
    target_digest bytea;
    target_business_date date;
BEGIN
    PERFORM 1 FROM thalion.wiki
    WHERE (org_id, space_id, topic_key) = (NEW.org_id, NEW.space_id, NEW.topic_key)
    FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Wiki topic does not exist in this space' USING ERRCODE = '23514';
    END IF;

    SELECT * INTO current_pub
    FROM thalion.current_wiki_publication
    WHERE (org_id, space_id, topic_key) = (NEW.org_id, NEW.space_id, NEW.topic_key);
    IF current_pub.publication_ref IS NULL OR current_pub.publication_ref <> NEW.from_publication_ref THEN
        RAISE EXCEPTION 'Wiki rollback must reference the current published head of the topic' USING ERRCODE = '23514';
    END IF;

    SELECT * INTO target_pub
    FROM thalion.wiki_publication_event
    WHERE (org_id, space_id, topic_key, publication_ref)
        = (NEW.org_id, NEW.space_id, NEW.topic_key, NEW.target_publication_ref);
    IF target_pub.publication_ref IS NULL OR target_pub.revision_ref <> NEW.target_revision_ref THEN
        RAISE EXCEPTION 'Wiki rollback target must match an existing publication of the same topic' USING ERRCODE = '23514';
    END IF;

    SELECT target_publication_ref INTO effective_pub
    FROM thalion.wiki_topic_rollback
    WHERE (org_id, space_id, topic_key, from_publication_ref)
        = (NEW.org_id, NEW.space_id, NEW.topic_key, NEW.from_publication_ref)
    ORDER BY rollback_seq DESC LIMIT 1;
    effective_pub := COALESCE(effective_pub, current_pub.publication_ref);
    IF effective_pub = NEW.target_publication_ref THEN
        RAISE EXCEPTION 'Wiki topic is already serving the requested target publication' USING ERRCODE = '23514';
    END IF;

    IF NEW.rollback_seq <> 1 + COALESCE((
        SELECT max(rollback_seq) FROM thalion.wiki_topic_rollback
        WHERE (org_id, space_id, topic_key) = (NEW.org_id, NEW.space_id, NEW.topic_key)
    ), 0) THEN
        RAISE EXCEPTION 'Wiki rollback sequence must increment monotonically' USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1 FROM thalion.wiki_availability_event
        WHERE publication_ref = NEW.target_publication_ref
    ) THEN
        RAISE EXCEPTION 'Cannot roll back to a Wiki publication invalidated by current revocations, holds, or deletions'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM thalion.wiki_published_input AS inp
        JOIN thalion.document_version AS ver
          ON (ver.org_id, ver.space_id, ver.version_id) = (inp.org_id, inp.space_id, inp.version_id)
        WHERE inp.publication_ref = NEW.target_publication_ref
          AND (
              thalion.document_source_deleted(ver.org_id, ver.space_id, ver.source_id, ver.document_id)
              OR EXISTS (SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = ver.version_id)
              OR EXISTS (
                  SELECT 1 FROM thalion.current_version_hold AS hold
                  WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                      = (ver.org_id, ver.space_id, ver.version_id, 'establish')
              )
          )
    ) THEN
        RAISE EXCEPTION 'Cannot roll back to a Wiki publication whose inputs are currently stopped, held, or source-deleted'
            USING ERRCODE = '23514';
    END IF;

    SELECT rev.author_id, sha256(rev.content), req.business_date
    INTO STRICT target_author, target_digest, target_business_date
    FROM thalion.wiki_revision AS rev
    JOIN thalion.delivery_record AS d ON (d.org_id, d.check_id) = (target_pub.org_id, target_pub.check_id)
    JOIN thalion.request_record AS req ON (req.org_id, req.request_id) = (d.org_id, d.request_id)
    WHERE (rev.org_id, rev.space_id, rev.topic_key, rev.revision_ref)
        = (NEW.org_id, NEW.space_id, NEW.topic_key, NEW.target_revision_ref);

    IF NEW.actor_id = target_author THEN
        RAISE EXCEPTION 'Wiki author cannot self-rollback their own revision' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.actor_id)
    JOIN thalion.principal AS orig_pub ON (orig_pub.org_id, orig_pub.principal_id) = (space.org_id, target_pub.publisher_id)
    JOIN thalion.delivery_record AS delivery ON (delivery.org_id, delivery.check_id) = (NEW.org_id, NEW.check_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.request_id) = (delivery.org_id, delivery.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND actor.principal_type = 'employee'
      AND NOT actor.disabled
      AND orig_pub.principal_type = 'employee'
      AND thalion.issuers_same_mode(actor.authority_issuer, orig_pub.authority_issuer)
      AND NOT orig_pub.disabled
      AND req.request_id = NEW.request_id
      AND req.principal_id = NEW.actor_id
      AND req.delegated_principal_id IS NULL
      AND req.operation = 'rollback_wiki_topic'
      AND req.destination = 'local_workspace'
      AND req.business_date = target_business_date
      AND delivery.payload_digest = target_digest
      AND delivery.valid_until > clock_timestamp()
      AND thalion.same_wiki_dependency_snapshot(target_pub.check_id, NEW.check_id)
    FOR SHARE OF space, actor, orig_pub;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Wiki rollback does not match current authority receipt or dependency snapshot'
            USING ERRCODE = '23514';
    END IF;

    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.has_active_space_delegation(p_org_id bigint, p_space_id bigint, p_principal_id bigint, p_scope text)
 RETURNS boolean
 LANGUAGE sql
 STABLE
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM thalion.space_delegation AS delegation
        JOIN thalion.space AS space
          ON (space.org_id, space.space_id) = (delegation.org_id, delegation.space_id)
        JOIN thalion.principal AS delegator
          ON (delegator.org_id, delegator.principal_id) = (delegation.org_id, delegation.delegator_id)
        JOIN thalion.principal AS delegate
          ON (delegate.org_id, delegate.principal_id) = (delegation.org_id, delegation.delegate_id)
        WHERE delegation.org_id = p_org_id
          AND delegation.space_id = p_space_id
          AND delegation.delegate_id = p_principal_id
          AND p_scope = ANY(delegation.scopes)
          AND space.lifecycle = 'active'
          AND space.owner_principal_id = delegation.delegator_id
          AND delegator.principal_type = 'employee'
          AND NOT delegator.disabled
          AND delegate.principal_type = 'employee'
          AND thalion.issuers_same_mode(delegator.authority_issuer, delegate.authority_issuer)
          AND NOT delegate.disabled
          AND delegation.starts_at <= clock_timestamp()
          AND clock_timestamp() < delegation.expires_at
          AND NOT EXISTS (
              SELECT 1 FROM thalion.space_delegation_revocation AS rev
              WHERE rev.delegation_ref = delegation.delegation_ref
          )
    );
$function$;

CREATE OR REPLACE FUNCTION thalion.local_disposition_request_is_open(scope_org bigint, scope_space bigint, target_request uuid, actor_id bigint, target_operation text)
 RETURNS boolean
 LANGUAGE sql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        JOIN thalion.organization AS organization USING (org_id)
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (request.org_id, request.principal_id)
        WHERE (request.org_id, request.scope_space_id, request.request_id, request.principal_id) =
              (scope_org, scope_space, target_request, actor_id)
          AND request.destination = 'internal_lifecycle' AND request.operation = target_operation
          AND request.configuration_revision = organization.config_revision
          AND request.outcome IS NULL AND request.delegated_principal_id IS NULL
          AND actor.principal_type = 'employee' AND thalion.is_admitted_authority_issuer(actor.authority_issuer) AND NOT actor.disabled
        FOR SHARE OF request, organization, actor
    );
$function$;

CREATE OR REPLACE FUNCTION thalion.lock_local_disposition_review(scope_org bigint, scope_space bigint, target_case uuid, actor_id bigint)
 RETURNS TABLE(version_ref uuid, source_id bigint, contract_revision bigint, version_id bigint, action text, reason text, inventory_snapshot bytea, submitted_by bigint)
 LANGUAGE sql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
    SELECT identity.public_id, source.source_id, source.contract_revision, candidate.version_id,
           candidate.action, candidate.reason, candidate.inventory_snapshot, candidate.submitted_by
    FROM thalion.disposition_case AS candidate
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.object_identity AS identity
      ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
         (candidate.org_id, candidate.space_id, 'document_version', candidate.version_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
         (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (contract.org_id, contract.approver_id)
    WHERE (candidate.org_id, candidate.space_id, candidate.case_ref) = (scope_org, scope_space, target_case)
      AND actor.principal_id = actor_id
      AND actor.principal_id NOT IN (candidate.submitted_by, source.owner_principal_id, space.owner_principal_id)
      AND actor.principal_type = 'employee' AND NOT actor.disabled
      AND space.lifecycle = 'active'
      AND thalion.issuer_matches_admission(actor.authority_issuer, contract.admission)
    FOR SHARE OF source, space, actor FOR NO KEY UPDATE OF candidate;
$function$;

CREATE OR REPLACE FUNCTION thalion.lock_local_hold_target(scope_org bigint, scope_space bigint, target_version bigint, actor_id bigint)
 RETURNS boolean
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    PERFORM document.document_id
    FROM thalion.document_version AS version
    JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
         (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (contract.org_id, contract.approver_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (scope_org, scope_space, target_version)
      AND actor.principal_id = actor_id AND actor.principal_id NOT IN (source.owner_principal_id, space.owner_principal_id)
      AND actor.principal_type = 'employee' AND NOT actor.disabled
      AND space.lifecycle = 'active'
      AND thalion.issuer_matches_admission(actor.authority_issuer, contract.admission)
    FOR SHARE OF source, space, actor FOR UPDATE OF document;
    RETURN FOUND;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.pdf_repair_admitted(target_version bigint, target_configuration bigint, replaced_ref uuid, submitted_ref uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
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
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND contract.admission IN ('synthetic_only', 'production_approved')
          AND thalion.storage_matches_admission(asset.storage_kind, contract.admission)
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
$function$;

CREATE OR REPLACE FUNCTION thalion.pdf_repair_review_until(target_run uuid, approval_request uuid, page_requests uuid[])
 RETURNS timestamp with time zone
 LANGUAGE sql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
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
      AND reviewer.principal_id = contract.quality_reviewer_id
      AND reviewer.principal_type = 'employee'
      AND thalion.issuer_matches_admission(reviewer.authority_issuer, contract.admission)
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
$function$;

CREATE OR REPLACE FUNCTION thalion.verify_local_backup_copy_registration()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.recorded_by, 'register_synthetic_backup_copy'
    ) OR NOT thalion.lock_local_hold_target(NEW.org_id, NEW.space_id, NEW.version_id, NEW.recorded_by) OR NOT EXISTS (
        SELECT 1 FROM thalion.document_version AS version
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        WHERE (version.org_id, version.space_id, version.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id)
          AND asset.storage_kind IN ('synthetic_file', 'https_object_store')
          AND (asset.asset_id, asset.content_digest, asset.byte_length) = (NEW.asset_id, NEW.content_digest, NEW.byte_length)
    ) THEN
        RAISE EXCEPTION 'backup enrollment requires a current independent custodian, matching request and exact asset'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.verify_local_disposition_case()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.submitted_by, 'submit_disposition_case'
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.document_version AS version
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE (version.org_id, version.space_id, version.source_id, version.version_id, source.contract_revision) =
              (NEW.org_id, NEW.space_id, NEW.source_id, NEW.version_id, NEW.contract_revision)
          AND NEW.submitted_by = source.owner_principal_id AND NEW.submitted_by = space.owner_principal_id
          AND space.lifecycle = 'active'
          AND EXISTS (
              SELECT 1 FROM thalion.principal AS sub_p
              WHERE (sub_p.org_id, sub_p.principal_id) = (NEW.org_id, NEW.submitted_by)
                AND thalion.issuer_matches_admission(sub_p.authority_issuer, contract.admission)
          )
        FOR SHARE OF source, space
    ) THEN
        RAISE EXCEPTION 'disposition case requires current scoped synthetic ownership and matching request' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.verify_local_disposition_original_observation()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.observed_by, 'verify_disposition_original'
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.lock_local_disposition_review(NEW.org_id, NEW.space_id, NEW.case_ref, NEW.observed_by) AS target
        JOIN thalion.document_version AS version ON (version.org_id, version.space_id, version.version_id) =
                                                   (NEW.org_id, NEW.space_id, target.version_id)
        JOIN thalion.asset AS asset
          ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id) =
             (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
        WHERE asset.storage_kind IN ('synthetic_file', 'https_object_store')
          AND (asset.asset_id, asset.content_digest, asset.byte_length) = (NEW.asset_id, NEW.content_digest, NEW.byte_length)
    ) OR EXISTS (
        SELECT 1 FROM thalion.disposition_rejection AS rejection
        WHERE (rejection.org_id, rejection.space_id, rejection.case_ref) = (NEW.org_id, NEW.space_id, NEW.case_ref)
    ) THEN
        RAISE EXCEPTION 'original verification requires a matching open request, eligible case and registered asset'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION thalion.verify_local_retention_policy()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'thalion'
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.source AS source
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.request_record AS request ON (request.org_id, request.scope_space_id) = (space.org_id, space.space_id)
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (request.org_id, request.principal_id)
        WHERE (source.org_id, source.space_id, source.source_id, source.contract_revision) =
              (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision)
          AND source.owner_principal_id = NEW.decided_by AND space.owner_principal_id = NEW.decided_by
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND (request.request_id, request.principal_id, request.operation, request.destination) =
              (NEW.request_id, NEW.decided_by, 'register_retention_policy', 'internal_lifecycle')
          AND request.outcome IS NULL AND request.delegated_principal_id IS NULL
          AND actor.principal_type = 'employee' AND NOT actor.disabled
          AND thalion.issuer_matches_admission(actor.authority_issuer, contract.admission)
    ) THEN
        RAISE EXCEPTION 'retention policy requires current scoped synthetic ownership' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;
