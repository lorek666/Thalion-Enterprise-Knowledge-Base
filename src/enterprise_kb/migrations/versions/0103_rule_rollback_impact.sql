CREATE INDEX processing_run_by_space_config
    ON thalion.processing_run (org_id, space_id, configuration_revision, run_ref);

CREATE TABLE thalion.processing_rule_rollback (
    rollback_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    faulty_configuration_revision bigint NOT NULL REFERENCES thalion.processing_config_revision (configuration_revision),
    target_configuration_revision bigint REFERENCES thalion.processing_config_revision (configuration_revision),
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    quarantined_count integer NOT NULL CHECK (quarantined_count >= 0),
    queued_count integer NOT NULL CHECK (queued_count >= 0),
    skipped_count integer NOT NULL CHECK (skipped_count >= 0),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, rollback_ref),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    CHECK (queued_count + skipped_count > 0),
    CHECK (
        (queued_count = 0 AND target_configuration_revision IS NULL)
        OR (queued_count > 0 AND target_configuration_revision IS NOT NULL
            AND target_configuration_revision > faulty_configuration_revision)
    )
);

CREATE INDEX processing_rule_rollback_by_space
    ON thalion.processing_rule_rollback (org_id, space_id, recorded_at DESC, rollback_ref DESC);

CREATE TABLE thalion.processing_rule_rollback_item (
    rollback_ref uuid NOT NULL,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    version_id bigint NOT NULL,
    faulty_run_ref uuid NOT NULL,
    baseline_run_ref uuid,
    action text NOT NULL CHECK (action IN ('queued_rollback', 'skipped')),
    skip_reason text CHECK (skip_reason IN (
        'not_latest_run',
        'version_stopped',
        'source_deleted',
        'custody_hold',
        'scope_or_contract_changed',
        'unsupported_media_type',
        'no_approved_baseline',
        'requires_reviewer_quarantine'
    )),
    quarantine_decision_ref uuid REFERENCES thalion.quality_decision (decision_ref),
    queued_job_id uuid,
    PRIMARY KEY (rollback_ref, faulty_run_ref),
    FOREIGN KEY (org_id, space_id, rollback_ref)
        REFERENCES thalion.processing_rule_rollback (org_id, space_id, rollback_ref),
    FOREIGN KEY (org_id, space_id, source_id)
        REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, space_id, version_id, faulty_run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    FOREIGN KEY (org_id, space_id, version_id, baseline_run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref),
    FOREIGN KEY (org_id, queued_job_id)
        REFERENCES thalion.job (org_id, job_id),
    CHECK (
        (action = 'queued_rollback'
         AND baseline_run_ref IS NOT NULL
         AND quarantine_decision_ref IS NOT NULL
         AND queued_job_id IS NOT NULL
         AND skip_reason IS NULL)
        OR (action = 'skipped'
            AND skip_reason IS NOT NULL
            AND queued_job_id IS NULL)
    )
);

CREATE INDEX processing_rule_rollback_item_by_run
    ON thalion.processing_rule_rollback_item (org_id, space_id, faulty_run_ref);

CREATE FUNCTION thalion.guard_rule_rollback_compat() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NEW.target_configuration_revision IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM thalion.processing_config_revision AS faulty
        JOIN thalion.processing_config_revision AS target
          ON target.configuration_revision = NEW.target_configuration_revision
        WHERE faulty.configuration_revision = NEW.faulty_configuration_revision
          AND (faulty.parser_version, faulty.profile, faulty.locator_revision)
            = (target.parser_version, target.profile, target.locator_revision)
    ) THEN
        RAISE EXCEPTION 'rule rollback target configuration must keep parser, profile, and locator revision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER processing_rule_rollback_compat
BEFORE INSERT ON thalion.processing_rule_rollback
FOR EACH ROW EXECUTE FUNCTION thalion.guard_rule_rollback_compat();

CREATE FUNCTION thalion.guard_rule_rollback_item() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    rb thalion.processing_rule_rollback%ROWTYPE;
    faulty thalion.processing_run%ROWTYPE;
    baseline thalion.processing_run%ROWTYPE;
    doc_id bigint;
BEGIN
    SELECT * INTO STRICT rb
    FROM thalion.processing_rule_rollback
    WHERE (org_id, space_id, rollback_ref) = (NEW.org_id, NEW.space_id, NEW.rollback_ref);

    SELECT * INTO STRICT faulty
    FROM thalion.processing_run
    WHERE (org_id, space_id, version_id, run_ref)
        = (NEW.org_id, NEW.space_id, NEW.version_id, NEW.faulty_run_ref);

    IF faulty.configuration_revision <> rb.faulty_configuration_revision THEN
        RAISE EXCEPTION 'rollback item run does not belong to the faulty configuration revision'
            USING ERRCODE = '23514';
    END IF;

    SELECT version.document_id INTO STRICT doc_id
    FROM thalion.document_version AS version
    WHERE (version.org_id, version.space_id, version.source_id, version.version_id)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.version_id);

    IF NEW.quarantine_decision_ref IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM thalion.quality_decision AS qd
        WHERE (qd.org_id, qd.space_id, qd.version_id, qd.run_ref, qd.decision_ref, qd.outcome)
            = (NEW.org_id, NEW.space_id, NEW.version_id, NEW.faulty_run_ref, NEW.quarantine_decision_ref, 'quarantined')
    ) THEN
        RAISE EXCEPTION 'rollback item quarantine reference must match a quarantined quality decision'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.action = 'queued_rollback' THEN
        IF rb.target_configuration_revision IS NULL THEN
            RAISE EXCEPTION 'queued rollback item requires a target configuration revision'
                USING ERRCODE = '23514';
        END IF;
        IF EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = NEW.version_id)
           OR thalion.document_source_deleted(NEW.org_id, NEW.space_id, NEW.source_id, doc_id)
           OR EXISTS (
               SELECT 1 FROM thalion.current_version_hold
               WHERE (org_id, space_id, version_id, action)
                   = (NEW.org_id, NEW.space_id, NEW.version_id, 'establish')
           ) THEN
            RAISE EXCEPTION 'stopped, deleted, or held versions cannot be queued for rule rollback'
                USING ERRCODE = '23514';
        END IF;

        SELECT * INTO STRICT baseline
        FROM thalion.processing_run
        WHERE (org_id, space_id, version_id, run_ref)
            = (NEW.org_id, NEW.space_id, NEW.version_id, NEW.baseline_run_ref);

        IF baseline.configuration_revision >= faulty.configuration_revision
           OR (baseline.contract_revision, baseline.input_digest)
               IS DISTINCT FROM (faulty.contract_revision, faulty.input_digest)
           OR NOT EXISTS (
               SELECT 1 FROM thalion.quality_decision
               WHERE run_ref = baseline.run_ref AND outcome = 'approved'
           )
           OR EXISTS (
               SELECT 1 FROM thalion.quality_decision
               WHERE run_ref = baseline.run_ref AND outcome = 'quarantined'
           ) THEN
            RAISE EXCEPTION 'rollback baseline must be an earlier approved non-quarantined run'
                USING ERRCODE = '23514';
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM thalion.job AS job
            WHERE (job.org_id, job.space_id, job.job_id, job.stage, job.configuration_revision)
                = (NEW.org_id, NEW.space_id, NEW.queued_job_id, 'parse', rb.target_configuration_revision)
        ) THEN
            RAISE EXCEPTION 'rollback item queued job must target the rollback configuration revision'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER processing_rule_rollback_item_guard
BEFORE INSERT ON thalion.processing_rule_rollback_item
FOR EACH ROW EXECUTE FUNCTION thalion.guard_rule_rollback_item();

CREATE TRIGGER processing_rule_rollback_immutable
BEFORE UPDATE OR DELETE ON thalion.processing_rule_rollback
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER processing_rule_rollback_item_immutable
BEFORE UPDATE OR DELETE ON thalion.processing_rule_rollback_item
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
