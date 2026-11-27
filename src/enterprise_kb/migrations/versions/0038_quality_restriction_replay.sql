ALTER TABLE thalion.quality_decision
    ALTER COLUMN request_id DROP NOT NULL,
    ADD COLUMN replay_log_ref uuid,
    ADD CONSTRAINT quality_decision_provenance CHECK (
        (request_id IS NOT NULL AND replay_log_ref IS NULL)
        OR (request_id IS NULL AND replay_log_ref IS NOT NULL AND outcome = 'quarantined')
    );

CREATE FUNCTION thalion.guard_replayed_quality_decision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_db_role_setting AS setting
        JOIN pg_database AS db ON db.oid = setting.setdatabase
        WHERE db.datname = current_database() AND setting.setrole = 0
          AND ('thalion.restore_rehearsal=' || current_database()) = ANY(setting.setconfig)
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.rule_log_endpoint AS endpoint
        WHERE endpoint.singleton AND endpoint.log_ref <> NEW.replay_log_ref
    ) THEN
        RAISE EXCEPTION 'quality restriction replay requires a fenced database and distinct log'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quality_decision_rehearsal BEFORE INSERT ON thalion.quality_decision
FOR EACH ROW WHEN (NEW.replay_log_ref IS NOT NULL) EXECUTE FUNCTION thalion.guard_replayed_quality_decision();
