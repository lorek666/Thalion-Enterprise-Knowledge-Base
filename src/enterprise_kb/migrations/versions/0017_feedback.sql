ALTER TABLE thalion.request_record
    ADD COLUMN scope_space_id bigint,
    ADD FOREIGN KEY (org_id, scope_space_id) REFERENCES thalion.space (org_id, space_id),
    ADD UNIQUE (org_id, scope_space_id, request_id);

CREATE TRIGGER request_space_immutable BEFORE UPDATE OF scope_space_id ON thalion.request_record
FOR EACH ROW WHEN (OLD.scope_space_id IS DISTINCT FROM NEW.scope_space_id) EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.delivery_citation (
    check_id uuid NOT NULL,
    position integer NOT NULL,
    PRIMARY KEY (check_id, position),
    FOREIGN KEY (check_id, position) REFERENCES thalion.delivery_dependency (check_id, position)
);

CREATE FUNCTION thalion.require_open_citation_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.delivery_record AS delivery
        JOIN thalion.request_record AS request USING (org_id, request_id)
        JOIN thalion.delivery_dependency AS part USING (org_id, check_id)
        WHERE (part.check_id, part.position, part.space_id) = (NEW.check_id, NEW.position, request.scope_space_id)
          AND request.operation IN ('read_passage', 'search') AND request.destination = 'employee'
          AND request.outcome IS NULL
    ) THEN
        RAISE EXCEPTION 'a displayed citation must belong to an open scoped evidence response' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_citation_open BEFORE INSERT ON thalion.delivery_citation
FOR EACH ROW EXECUTE FUNCTION thalion.require_open_citation_receipt();
CREATE TRIGGER delivery_citation_immutable BEFORE UPDATE OR DELETE ON thalion.delivery_citation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

ALTER TABLE thalion.delivery_record ADD UNIQUE (org_id, request_id, check_id);
ALTER TABLE thalion.object_identity
    DROP CONSTRAINT object_identity_shape,
    ADD CONSTRAINT object_identity_shape CHECK (
        (object_type = 'principal' AND space_id IS NULL)
        OR (object_type = 'space' AND space_id IS NOT NULL AND space_id = object_id)
        OR (object_type IN ('source', 'document', 'document_version', 'passage', 'feedback') AND space_id IS NOT NULL)
    );

CREATE TABLE thalion.feedback (
    feedback_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identity_type text GENERATED ALWAYS AS ('feedback'::text) STORED,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    reporter_id bigint NOT NULL,
    created_request_id uuid NOT NULL,
    origin_request_id uuid NOT NULL,
    origin_check_id uuid,
    citation_position integer,
    category text NOT NULL CHECK (category IN ('incorrect_evidence', 'missing_evidence')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, feedback_id),
    FOREIGN KEY (org_id, space_id, identity_type, feedback_id)
        REFERENCES thalion.object_identity (org_id, space_id, object_type, object_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (org_id, reporter_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, created_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, origin_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, origin_request_id, origin_check_id) REFERENCES thalion.delivery_record (org_id, request_id, check_id),
    FOREIGN KEY (origin_check_id, citation_position) REFERENCES thalion.delivery_citation (check_id, position) MATCH FULL,
    CHECK (created_request_id <> origin_request_id),
    CHECK ((category = 'incorrect_evidence') = (origin_check_id IS NOT NULL))
);

CREATE TABLE thalion.feedback_note (
    feedback_id bigint PRIMARY KEY REFERENCES thalion.feedback (feedback_id),
    note text NOT NULL CHECK (btrim(note) <> '' AND octet_length(note) <= 2048)
);

CREATE TABLE thalion.feedback_decision (
    decision_ref uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    feedback_id bigint NOT NULL,
    generation bigint NOT NULL CHECK (generation > 1),
    prior_generation bigint GENERATED ALWAYS AS (nullif(generation - 1, 1)) STORED,
    action text NOT NULL CHECK (action IN ('assign', 'mark_corrected', 'explain', 'verify_correction')),
    actor_id bigint NOT NULL,
    assignee_id bigint NOT NULL,
    request_id uuid NOT NULL,
    basis_request_id uuid,
    retest_request_id uuid,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (feedback_id, generation),
    FOREIGN KEY (org_id, space_id, feedback_id) REFERENCES thalion.feedback (org_id, space_id, feedback_id),
    FOREIGN KEY (feedback_id, prior_generation) REFERENCES thalion.feedback_decision (feedback_id, generation),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, assignee_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, basis_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, retest_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CHECK ((action = 'explain') = (basis_request_id IS NOT NULL)),
    CHECK ((action = 'verify_correction') = (retest_request_id IS NOT NULL)),
    CHECK ((actor_id = assignee_id) = (action IN ('mark_corrected', 'explain')))
);

CREATE TRIGGER feedback_immutable BEFORE UPDATE OR DELETE ON thalion.feedback
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER feedback_note_immutable BEFORE UPDATE OR DELETE ON thalion.feedback_note
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER feedback_decision_immutable BEFORE UPDATE OR DELETE ON thalion.feedback_decision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE VIEW thalion.current_feedback AS
SELECT report.*, identity.public_id AS feedback_ref, part.passage_ref, part.excerpt_revision,
       coalesce(latest.generation, 1) AS generation, latest.assignee_id, latest.recorded_at AS decided_at,
       CASE latest.action
           WHEN 'mark_corrected' THEN 'awaiting_retest'
           WHEN 'explain' THEN 'explained'
           WHEN 'verify_correction' THEN 'closed'
           ELSE 'pending'
       END AS state
FROM thalion.feedback AS report
JOIN thalion.object_identity AS identity
  ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
     (report.org_id, report.space_id, report.identity_type, report.feedback_id)
LEFT JOIN thalion.delivery_dependency AS part
  ON (part.check_id, part.position) = (report.origin_check_id, report.citation_position)
LEFT JOIN LATERAL (
    SELECT decision.generation, decision.action, decision.assignee_id, decision.recorded_at
    FROM thalion.feedback_decision AS decision WHERE decision.feedback_id = report.feedback_id
    ORDER BY decision.generation DESC LIMIT 1
) AS latest ON true;

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
        UNION ALL SELECT 1 FROM thalion.feedback WHERE target.object_type = 'feedback'
          AND feedback_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
    ) INTO entity_exists;
    IF NOT entity_exists THEN
        RAISE EXCEPTION 'registered identity requires matching entity in its scope'
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END;
$$;
