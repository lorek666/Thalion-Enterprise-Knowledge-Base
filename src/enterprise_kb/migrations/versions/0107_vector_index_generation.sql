CREATE TABLE thalion.synthetic_vector_index (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    model_id text NOT NULL CHECK (model_id ~ '^[a-z0-9][a-z0-9._:-]{1,79}$'),
    dimension integer NOT NULL CHECK (dimension = 64),
    distance_metric text NOT NULL CHECK (distance_metric = 'cosine'),
    generation bigint NOT NULL CHECK (generation >= 1),
    index_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    entry_count integer NOT NULL CHECK (entry_count BETWEEN 1 AND 512),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    indexed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (run_ref, model_id),
    UNIQUE (org_id, space_id, version_id, run_ref, index_ref),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref)
);

CREATE INDEX synthetic_vector_index_version
    ON thalion.synthetic_vector_index (org_id, space_id, version_id, model_id);

CREATE FUNCTION thalion.guard_vector_index_stopped() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    version_source bigint;
    version_document bigint;
BEGIN
    SELECT source_id, document_id INTO version_source, version_document
    FROM thalion.document_version
    WHERE (org_id, space_id, version_id) = (NEW.org_id, NEW.space_id, NEW.version_id);
    IF EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = NEW.version_id)
       OR EXISTS (
           SELECT 1 FROM thalion.current_version_hold AS hold
           WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
               = (NEW.org_id, NEW.space_id, NEW.version_id, 'establish')
       )
       OR (version_document IS NOT NULL
           AND thalion.document_source_deleted(NEW.org_id, NEW.space_id, version_source, version_document)) THEN
        RAISE EXCEPTION 'held, stopped, or source-deleted versions cannot be vector indexed'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_vector_index_stop_guard
BEFORE INSERT ON thalion.synthetic_vector_index
FOR EACH ROW EXECUTE FUNCTION thalion.guard_vector_index_stopped();

CREATE TRIGGER synthetic_vector_index_immutable
BEFORE UPDATE OR DELETE ON thalion.synthetic_vector_index
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER synthetic_vector_index_no_truncate
BEFORE TRUNCATE ON thalion.synthetic_vector_index
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.synthetic_vector_entry (
    index_ref uuid NOT NULL,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    passage_id bigint NOT NULL,
    excerpt_revision bigint NOT NULL,
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    embedding vector(64) NOT NULL,
    PRIMARY KEY (index_ref, passage_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref, index_ref)
        REFERENCES thalion.synthetic_vector_index (org_id, space_id, version_id, run_ref, index_ref),
    FOREIGN KEY (org_id, space_id, version_id, passage_id)
        REFERENCES thalion.passage (org_id, space_id, version_id, passage_id),
    FOREIGN KEY (passage_id, excerpt_revision)
        REFERENCES thalion.passage_excerpt (passage_id, excerpt_revision),
    FOREIGN KEY (passage_id, run_ref)
        REFERENCES thalion.passage_excerpt (passage_id, run_ref)
);

CREATE INDEX synthetic_vector_entry_passage
    ON thalion.synthetic_vector_entry (org_id, space_id, passage_id, excerpt_revision);

CREATE INDEX synthetic_vector_entry_cosine_hnsw
    ON thalion.synthetic_vector_entry USING hnsw (embedding vector_cosine_ops);

CREATE TRIGGER synthetic_vector_entry_immutable
BEFORE UPDATE OR DELETE ON thalion.synthetic_vector_entry
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER synthetic_vector_entry_no_truncate
BEFORE TRUNCATE ON thalion.synthetic_vector_entry
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

DO $$
DECLARE
    constraint_row record;
BEGIN
    FOR constraint_row IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'thalion.space_release_config'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%lexical_index_mode%'
    LOOP
        EXECUTE format('ALTER TABLE thalion.space_release_config DROP CONSTRAINT %I', constraint_row.conname);
    END LOOP;

    FOR constraint_row IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'thalion.space_archive_rebuild'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%lexical_index_mode%'
    LOOP
        EXECUTE format('ALTER TABLE thalion.space_archive_rebuild DROP CONSTRAINT %I', constraint_row.conname);
    END LOOP;
END;
$$;

ALTER TABLE thalion.space_release_config
    ADD COLUMN vector_model_id text CHECK (
        vector_model_id IS NULL OR vector_model_id ~ '^[a-z0-9][a-z0-9._:-]{1,79}$'
    ),
    ADD CONSTRAINT space_release_config_lexical_mode_check
        CHECK (lexical_index_mode IN ('indexed', 'direct_scan', 'hybrid_vector')),
    ADD CONSTRAINT space_release_config_vector_model_check
        CHECK ((lexical_index_mode = 'hybrid_vector') = (vector_model_id IS NOT NULL));

ALTER TABLE thalion.space_archive_rebuild
    ADD CONSTRAINT space_archive_rebuild_lexical_mode_check
        CHECK (lexical_index_mode IN ('indexed', 'direct_scan', 'hybrid_vector'));

CREATE OR REPLACE VIEW thalion.current_space_release_config AS
SELECT DISTINCT ON (org_id, space_id)
    release_ref, org_id, space_id, generation, prior_generation, action,
    wiki_delivery_enabled, lexical_index_mode, target_release_ref,
    template_key, template_revision_ref, observation_window_minutes,
    min_sample_requests, rollback_trigger_summary, reason_code,
    basis_ref, actor_id, request_id, recorded_at, vector_model_id
FROM thalion.space_release_config
ORDER BY org_id, space_id, generation DESC;
