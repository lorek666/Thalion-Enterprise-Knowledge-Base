ALTER TABLE thalion.synthetic_backup_copy
    ADD UNIQUE (org_id, space_id, version_id, backup_ref),
    ADD COLUMN store_identity bytea,
    ADD CONSTRAINT synthetic_backup_requires_store_identity
        CHECK (store_identity IS NOT NULL AND octet_length(store_identity) = 32) NOT VALID;

CREATE TABLE thalion.synthetic_backup_expiry_plan (
    schedule_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    backup_ref uuid NOT NULL UNIQUE,
    withdrawal_ref uuid NOT NULL REFERENCES thalion.rule_use_stop (decision_ref),
    expected_expiry_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    recorded_by bigint NOT NULL,
    request_id uuid NOT NULL,
    UNIQUE (org_id, space_id, backup_ref, schedule_ref),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id, backup_ref)
        REFERENCES thalion.synthetic_backup_copy (org_id, space_id, version_id, backup_ref),
    FOREIGN KEY (org_id, recorded_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TABLE thalion.synthetic_backup_expiry_observation (
    observation_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    backup_ref uuid NOT NULL UNIQUE,
    schedule_ref uuid NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    recorded_by bigint NOT NULL,
    request_id uuid NOT NULL,
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, backup_ref, schedule_ref)
        REFERENCES thalion.synthetic_backup_expiry_plan (org_id, space_id, backup_ref, schedule_ref),
    FOREIGN KEY (org_id, recorded_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE FUNCTION thalion.guard_synthetic_backup_expiry() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    schedule thalion.synthetic_backup_expiry_plan%ROWTYPE;
    operation_name text;
    checked_at timestamptz;
BEGIN
    IF TG_TABLE_NAME = 'synthetic_backup_expiry_plan' THEN
        schedule := NEW;
        operation_name := 'schedule_synthetic_backup_expiry';
    ELSE
        SELECT * INTO STRICT schedule FROM thalion.synthetic_backup_expiry_plan AS plan
        WHERE (plan.org_id, plan.space_id, plan.backup_ref, plan.schedule_ref) =
              (NEW.org_id, NEW.space_id, NEW.backup_ref, NEW.schedule_ref);
        operation_name := 'observe_synthetic_backup_expiry';
    END IF;
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.recorded_by, operation_name
    ) OR NOT thalion.lock_local_hold_target(NEW.org_id, NEW.space_id, schedule.version_id, NEW.recorded_by) THEN
        RAISE EXCEPTION 'backup expiry requires current independent custody and a matching request' USING ERRCODE = '23514';
    END IF;
    checked_at := clock_timestamp();
    IF EXISTS (
        SELECT 1 FROM thalion.current_version_hold AS hold
        WHERE (hold.org_id, hold.space_id, hold.version_id) = (NEW.org_id, NEW.space_id, schedule.version_id)
          AND hold.action = 'establish'
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.rule_use_stop AS stop
        WHERE (stop.org_id, stop.space_id, stop.version_id, stop.decision_ref) =
              (NEW.org_id, NEW.space_id, schedule.version_id, schedule.withdrawal_ref)
          AND stop.kind = 'withdrawn' AND stop.recorded_at <= schedule.expected_expiry_at
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.synthetic_backup_copy AS copy
        WHERE (copy.org_id, copy.space_id, copy.version_id, copy.backup_ref) =
              (NEW.org_id, NEW.space_id, schedule.version_id, NEW.backup_ref)
          AND copy.store_identity IS NOT NULL
    ) OR schedule.expected_expiry_at > checked_at + interval '8784 hours' THEN
        RAISE EXCEPTION 'backup expiry requires exact withdrawal, a bounded date and no active hold' USING ERRCODE = '23514';
    END IF;
    IF operation_name = 'observe_synthetic_backup_expiry' THEN
        IF checked_at < schedule.expected_expiry_at THEN
            RAISE EXCEPTION 'backup expiry observation is not yet due' USING ERRCODE = '23514';
        END IF;
        NEW.observed_at := checked_at;
    ELSE
        NEW.recorded_at := checked_at;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_backup_expiry_plan_scope BEFORE INSERT ON thalion.synthetic_backup_expiry_plan
FOR EACH ROW EXECUTE FUNCTION thalion.guard_synthetic_backup_expiry();
CREATE TRIGGER synthetic_backup_expiry_observation_scope BEFORE INSERT ON thalion.synthetic_backup_expiry_observation
FOR EACH ROW EXECUTE FUNCTION thalion.guard_synthetic_backup_expiry();
CREATE TRIGGER synthetic_backup_expiry_plan_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_backup_expiry_plan
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER synthetic_backup_expiry_observation_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_backup_expiry_observation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
