ALTER TABLE thalion.source_contract_revision
    ADD COLUMN processor_id bigint,
    ADD COLUMN quality_reviewer_id bigint,
    ADD FOREIGN KEY (org_id, processor_id) REFERENCES thalion.principal (org_id, principal_id),
    ADD FOREIGN KEY (org_id, quality_reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    ADD CHECK (processor_id <> quality_reviewer_id);

ALTER TABLE thalion.document_version
    ADD UNIQUE (org_id, space_id, version_id);

CREATE TABLE thalion.processing_config_revision (
    configuration_revision bigint PRIMARY KEY CHECK (configuration_revision > 0),
    parser_version text NOT NULL,
    profile text NOT NULL,
    locator_revision integer NOT NULL CHECK (locator_revision > 0)
);

INSERT INTO thalion.processing_config_revision
    (configuration_revision, parser_version, profile, locator_revision)
VALUES (1, '4.3.0', 'commonmark_table_v1', 1);

CREATE TABLE thalion.processing_run (
    run_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    contract_revision bigint NOT NULL CHECK (contract_revision > 0),
    job_id uuid NOT NULL,
    generation bigint NOT NULL,
    configuration_revision bigint NOT NULL REFERENCES thalion.processing_config_revision,
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
    outcome text NOT NULL CHECK (outcome IN ('pending_review', 'quarantined')),
    reason text CHECK (reason IN ('empty', 'invalid_encoding', 'unsupported_structure', 'size_limit')),
    passage_count integer NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, version_id, run_ref),
    UNIQUE (version_id, configuration_revision),
    UNIQUE (org_id, job_id, generation),
    FOREIGN KEY (org_id, space_id, version_id)
        REFERENCES thalion.document_version (org_id, space_id, version_id),
    FOREIGN KEY (org_id, job_id, generation)
        REFERENCES thalion.job_attempt (org_id, job_id, generation),
    CHECK (
        (outcome = 'pending_review' AND reason IS NULL AND passage_count > 0)
        OR (outcome = 'quarantined' AND reason IS NOT NULL AND passage_count = 0)
    )
);

CREATE FUNCTION thalion.verify_processing_run_job() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.job AS job
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.public_id)
           = (job.org_id, job.space_id, job.target_ref)
        WHERE (job.org_id, job.space_id, job.job_id, job.generation)
            = (NEW.org_id, NEW.space_id, NEW.job_id, NEW.generation)
          AND (identity.object_type, identity.object_id) = ('document_version', NEW.version_id)
          AND job.stage = 'parse' AND job.state = 'running'
          AND job.input_digest = NEW.input_digest
          AND job.configuration_revision = NEW.configuration_revision
    ) THEN
        RAISE EXCEPTION 'processing run does not match its current job' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER processing_run_matches_job BEFORE INSERT ON thalion.processing_run
FOR EACH ROW EXECUTE FUNCTION thalion.verify_processing_run_job();

ALTER TABLE thalion.object_identity
    DROP CONSTRAINT object_identity_shape,
    ADD CONSTRAINT object_identity_shape CHECK (
        (object_type = 'principal' AND space_id IS NULL)
        OR (object_type = 'space' AND space_id IS NOT NULL AND object_id = space_id)
        OR (object_type IN ('source', 'document', 'document_version', 'passage') AND space_id IS NOT NULL)
    );

CREATE TABLE thalion.passage (
    passage_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    identity_type text GENERATED ALWAYS AS ('passage'::text) STORED,
    locator_revision integer NOT NULL CHECK (locator_revision > 0),
    heading_path text[] NOT NULL CHECK (cardinality(heading_path) <= 6),
    paragraph integer NOT NULL CHECK (paragraph > 0),
    kind text NOT NULL CHECK (kind IN ('paragraph', 'table', 'blockquote', 'list', 'code')),
    byte_start bigint NOT NULL CHECK (byte_start >= 0),
    byte_end bigint NOT NULL CHECK (byte_end > byte_start),
    UNIQUE (org_id, space_id, version_id, passage_id),
    UNIQUE (version_id, locator_revision, byte_start, byte_end),
    FOREIGN KEY (org_id, space_id, version_id)
        REFERENCES thalion.document_version (org_id, space_id, version_id),
    FOREIGN KEY (org_id, space_id, identity_type, passage_id)
        REFERENCES thalion.object_identity (org_id, space_id, object_type, object_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE thalion.passage_excerpt (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    passage_id bigint NOT NULL,
    excerpt_revision bigint NOT NULL CHECK (excerpt_revision > 0),
    run_ref uuid NOT NULL,
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    PRIMARY KEY (passage_id, excerpt_revision),
    UNIQUE (passage_id, run_ref),
    FOREIGN KEY (org_id, space_id, version_id, passage_id)
        REFERENCES thalion.passage (org_id, space_id, version_id, passage_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref)
);

CREATE INDEX passage_excerpt_by_run ON thalion.passage_excerpt (run_ref);

CREATE FUNCTION thalion.require_open_processing_run() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM job.job_id FROM thalion.processing_run AS run
    JOIN thalion.job AS job ON (job.org_id, job.job_id) = (run.org_id, run.job_id)
    WHERE run.run_ref = NEW.run_ref AND run.outcome = 'pending_review'
      AND job.state = 'running' AND job.generation = run.generation
    FOR UPDATE OF job;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the processing manifest is not open for excerpts' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER passage_excerpt_open_run BEFORE INSERT ON thalion.passage_excerpt
FOR EACH ROW EXECUTE FUNCTION thalion.require_open_processing_run();

CREATE FUNCTION thalion.verify_sealed_processing_run() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.job AS job
        JOIN thalion.job_attempt AS attempt
          ON (attempt.org_id, attempt.job_id, attempt.generation) = (job.org_id, job.job_id, job.generation)
        WHERE (job.org_id, job.job_id, job.generation) = (NEW.org_id, NEW.job_id, NEW.generation)
          AND job.state = 'succeeded' AND job.result_ref = NEW.run_ref AND attempt.outcome = 'succeeded'
    ) OR NEW.passage_count <> (
        SELECT count(*) FROM thalion.passage_excerpt WHERE run_ref = NEW.run_ref
    ) THEN
        RAISE EXCEPTION 'the processing manifest and completed job must commit together'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER processing_run_sealed AFTER INSERT ON thalion.processing_run
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.verify_sealed_processing_run();

CREATE TABLE thalion.quality_decision (
    decision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    run_ref uuid NOT NULL,
    reviewer_id bigint NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('approved', 'quarantined')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (run_ref, outcome),
    FOREIGN KEY (org_id, reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id, run_ref)
        REFERENCES thalion.processing_run (org_id, space_id, version_id, run_ref)
);

CREATE TRIGGER processing_config_immutable BEFORE UPDATE OR DELETE ON thalion.processing_config_revision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER processing_run_immutable BEFORE UPDATE OR DELETE ON thalion.processing_run
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER passage_immutable BEFORE UPDATE OR DELETE ON thalion.passage
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER passage_excerpt_immutable BEFORE UPDATE OR DELETE ON thalion.passage_excerpt
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER quality_decision_immutable BEFORE UPDATE OR DELETE ON thalion.quality_decision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE OR REPLACE FUNCTION thalion.verify_identity_entity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    target thalion.object_identity%ROWTYPE;
    entity_exists boolean;
BEGIN
    IF TG_TABLE_NAME = 'object_identity' THEN
        target := NEW;
    ELSE
        SELECT * INTO target FROM thalion.object_identity
        WHERE object_type = TG_TABLE_NAME
          AND object_id = (to_jsonb(OLD) ->> TG_ARGV[0])::bigint AND org_id = OLD.org_id;
        IF NOT FOUND THEN
            RETURN NULL;
        END IF;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM thalion.principal WHERE target.object_type = 'principal'
          AND principal_id = target.object_id AND org_id = target.org_id
        UNION ALL SELECT 1 FROM thalion.space WHERE target.object_type = 'space'
          AND space_id = target.object_id AND org_id = target.org_id
        UNION ALL SELECT 1 FROM thalion.source WHERE target.object_type = 'source'
          AND source_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
        UNION ALL SELECT 1 FROM thalion.document WHERE target.object_type = 'document'
          AND document_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
        UNION ALL SELECT 1 FROM thalion.document_version WHERE target.object_type = 'document_version'
          AND version_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
        UNION ALL SELECT 1 FROM thalion.passage WHERE target.object_type = 'passage'
          AND passage_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
    ) INTO entity_exists;
    IF NOT entity_exists THEN
        RAISE EXCEPTION 'registered identity requires matching entity in its scope'
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END;
$$;
