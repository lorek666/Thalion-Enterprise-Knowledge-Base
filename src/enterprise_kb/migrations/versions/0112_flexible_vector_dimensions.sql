DROP INDEX IF EXISTS thalion.synthetic_vector_entry_cosine_hnsw;

DO $$
DECLARE
    constraint_row record;
BEGIN
    FOR constraint_row IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'thalion.synthetic_vector_index'::regclass
          AND contype = 'c'
          AND (
              pg_get_constraintdef(oid) LIKE '%dimension%'
              OR pg_get_constraintdef(oid) LIKE '%model_id%'
          )
    LOOP
        EXECUTE format('ALTER TABLE thalion.synthetic_vector_index DROP CONSTRAINT %I', constraint_row.conname);
    END LOOP;

    FOR constraint_row IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'thalion.space_release_config'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%vector_model_id%'
          AND conname <> 'space_release_config_vector_model_check'
    LOOP
        EXECUTE format('ALTER TABLE thalion.space_release_config DROP CONSTRAINT %I', constraint_row.conname);
    END LOOP;
END;
$$;

ALTER TABLE thalion.synthetic_vector_index
    ADD CONSTRAINT synthetic_vector_index_dimension_check
        CHECK (dimension BETWEEN 1 AND 4096),
    ADD CONSTRAINT synthetic_vector_index_model_id_check
        CHECK (model_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$' AND model_id !~ '\.\.');

ALTER TABLE thalion.space_release_config
    ADD CONSTRAINT space_release_config_vector_model_id_check
        CHECK (
            vector_model_id IS NULL
            OR (vector_model_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$' AND vector_model_id !~ '\.\.')
        );

ALTER TABLE thalion.synthetic_vector_entry
    ALTER COLUMN embedding TYPE vector USING embedding::vector;

CREATE FUNCTION thalion.guard_vector_entry_dimension() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion, public AS $$
DECLARE
    expected_dim integer;
BEGIN
    SELECT dimension INTO expected_dim
    FROM thalion.synthetic_vector_index
    WHERE index_ref = NEW.index_ref;
    IF expected_dim IS NULL OR vector_dims(NEW.embedding) <> expected_dim THEN
        RAISE EXCEPTION 'vector entry dimension does not match vector index dimension'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_vector_entry_dimension_guard
BEFORE INSERT ON thalion.synthetic_vector_entry
FOR EACH ROW EXECUTE FUNCTION thalion.guard_vector_entry_dimension();
