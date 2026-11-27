CREATE TABLE thalion.source_revocation_stream (
    space_ref uuid PRIMARY KEY,
    stream_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0)
);

CREATE TABLE thalion.source_revocation_event (
    decision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    space_ref uuid NOT NULL REFERENCES thalion.source_revocation_stream (space_ref),
    generation bigint NOT NULL CHECK (generation > 0),
    employee_ref uuid NOT NULL,
    object_ref uuid NOT NULL,
    access_use text NOT NULL CHECK (access_use IN ('evidence', 'archive')),
    basis_ref uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (space_ref, generation),
    UNIQUE (space_ref, employee_ref, object_ref, access_use)
);

CREATE TRIGGER source_revocation_event_immutable BEFORE UPDATE OR DELETE ON thalion.source_revocation_event
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_revocation_stream_identity
BEFORE UPDATE OF space_ref, stream_ref OR DELETE ON thalion.source_revocation_stream
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_revocation_event_no_truncate BEFORE TRUNCATE ON thalion.source_revocation_event
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_revocation_stream_no_truncate BEFORE TRUNCATE ON thalion.source_revocation_stream
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE FUNCTION thalion.guard_source_revocation_head() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM thalion.organization) OR EXISTS (
        SELECT 1 FROM pg_db_role_setting AS setting
        JOIN pg_database AS db ON db.oid = setting.setdatabase
        CROSS JOIN LATERAL unnest(setting.setconfig) AS entry(value)
        WHERE db.datname = current_database() AND setting.setrole = 0
          AND split_part(entry.value, '=', 1) = 'thalion.restore_rehearsal'
    ) THEN
        RAISE EXCEPTION 'source revocations require a separate active authority database' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.generation <> 0 THEN
            RAISE EXCEPTION 'source revocation streams must start at zero' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.generation <> OLD.generation + 1 OR NOT EXISTS (
        SELECT 1 FROM thalion.source_revocation_event AS event
        WHERE (event.space_ref, event.generation) = (NEW.space_ref, NEW.generation)
    ) THEN
        RAISE EXCEPTION 'source revocation generation requires the exact new event' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_revocation_head_guard BEFORE INSERT OR UPDATE OF generation ON thalion.source_revocation_stream
FOR EACH ROW EXECUTE FUNCTION thalion.guard_source_revocation_head();

CREATE FUNCTION thalion.advance_source_revocation_head() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    UPDATE thalion.source_revocation_stream SET generation = NEW.generation WHERE space_ref = NEW.space_ref;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source revocation stream is unavailable' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER source_revocation_add AFTER INSERT ON thalion.source_revocation_event
FOR EACH ROW EXECUTE FUNCTION thalion.advance_source_revocation_head();
