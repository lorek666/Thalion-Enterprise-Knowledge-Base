ALTER TABLE thalion.rule_use_stop
    DROP CONSTRAINT rule_use_stop_kind_check,
    ADD COLUMN disposition_case_ref uuid REFERENCES thalion.disposition_decision (case_ref),
    ADD COLUMN disposition_request_id uuid,
    ADD COLUMN replay_log_ref uuid,
    ADD UNIQUE (disposition_case_ref),
    ADD UNIQUE (org_id, disposition_request_id),
    ADD FOREIGN KEY (org_id, space_id, disposition_request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    ADD CONSTRAINT rule_use_stop_provenance CHECK (
        (kind IN ('suspended', 'withdrawn') AND disposition_case_ref IS NULL
         AND disposition_request_id IS NULL AND replay_log_ref IS NULL)
        OR (kind = 'deletion_blocked' AND (
            (disposition_case_ref IS NOT NULL AND disposition_request_id IS NOT NULL AND replay_log_ref IS NULL)
            OR (disposition_case_ref IS NULL AND disposition_request_id IS NULL AND replay_log_ref IS NOT NULL)
        ))
    );

ALTER TABLE thalion.wiki_availability_event DROP CONSTRAINT wiki_availability_event_reason_check,
    ADD CONSTRAINT wiki_availability_event_reason_check CHECK (reason IN (
        'suspended', 'withdrawn', 'quarantined', 'reprocessed', 'policy_changed', 'rule_replaced', 'custody_hold',
        'deletion_blocked'
    ));

CREATE FUNCTION thalion.guard_deletion_tombstone() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NEW.replay_log_ref IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_db_role_setting AS setting
            JOIN pg_database AS database ON database.oid = setting.setdatabase
            WHERE database.datname = current_database() AND setting.setrole = 0
              AND ('thalion.restore_rehearsal=' || current_database()) = ANY(setting.setconfig)
        ) OR NOT EXISTS (
            SELECT 1 FROM thalion.rule_log_endpoint AS endpoint
            WHERE endpoint.singleton AND endpoint.log_ref <> NEW.replay_log_ref
        ) THEN
            RAISE EXCEPTION 'deletion replay requires a fenced database and distinct log' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.disposition_request_id, NEW.decided_by, 'register_deletion_tombstone'
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.lock_local_disposition_review(
            NEW.org_id, NEW.space_id, NEW.disposition_case_ref, NEW.decided_by
        ) AS target
        WHERE (target.source_id, target.contract_revision, target.version_id, target.action) =
              (NEW.source_id, NEW.contract_revision, NEW.version_id, 'destroy')
    ) THEN
        RAISE EXCEPTION 'deletion tombstone requires a current independent reviewer and matching request' USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    IF NOT EXISTS (
        SELECT 1 FROM thalion.disposition_decision AS approval
        JOIN thalion.disposition_case AS candidate USING (org_id, space_id, case_ref)
        WHERE (approval.org_id, approval.space_id, approval.case_ref, approval.decided_by, approval.basis_ref) =
              (NEW.org_id, NEW.space_id, NEW.disposition_case_ref, NEW.decided_by, NEW.basis_ref)
          AND approval.outcome = 'approved' AND approval.expires_at > NEW.recorded_at
          AND (candidate.source_id, candidate.contract_revision, candidate.version_id) =
              (NEW.source_id, NEW.contract_revision, NEW.version_id)
          AND candidate.policy_revision = (
              SELECT max(revision) FROM thalion.retention_policy_revision
              WHERE (org_id, space_id, source_id) = (NEW.org_id, NEW.space_id, NEW.source_id)
          )
    ) OR EXISTS (
        SELECT 1 FROM thalion.current_version_hold AS hold
        WHERE (hold.org_id, hold.space_id, hold.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id)
          AND hold.action = 'establish'
    ) OR EXISTS (
        SELECT 1 FROM thalion.lifecycle_version_manifest AS input
        WHERE (input.org_id, input.space_id, input.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id)
    ) THEN
        RAISE EXCEPTION 'deletion tombstone requires a live approval and unprotected version' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER rule_use_stop_tombstone BEFORE INSERT ON thalion.rule_use_stop
FOR EACH ROW WHEN (NEW.kind = 'deletion_blocked') EXECUTE FUNCTION thalion.guard_deletion_tombstone();
CREATE TRIGGER rule_use_stop_no_truncate BEFORE TRUNCATE ON thalion.rule_use_stop
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
