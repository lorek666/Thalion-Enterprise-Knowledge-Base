CREATE TABLE thalion.feedback_handoff (
    handoff_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    authorizer_id bigint NOT NULL,
    incumbent_id bigint NOT NULL,
    successor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    item_count integer NOT NULL CHECK (item_count BETWEEN 1 AND 20),
    UNIQUE (org_id, space_id, handoff_ref),
    UNIQUE (org_id, space_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, authorizer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, incumbent_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, successor_id) REFERENCES thalion.principal (org_id, principal_id),
    CHECK (successor_id NOT IN (authorizer_id, incumbent_id)),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '15 minutes')
);

CREATE TABLE thalion.feedback_handoff_item (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    handoff_ref uuid NOT NULL,
    feedback_id bigint NOT NULL,
    expected_generation bigint NOT NULL,
    PRIMARY KEY (handoff_ref, feedback_id),
    UNIQUE (handoff_ref, feedback_id, expected_generation),
    FOREIGN KEY (org_id, space_id, handoff_ref) REFERENCES thalion.feedback_handoff (org_id, space_id, handoff_ref),
    FOREIGN KEY (org_id, space_id, feedback_id) REFERENCES thalion.feedback (org_id, space_id, feedback_id),
    FOREIGN KEY (feedback_id, expected_generation) REFERENCES thalion.feedback_decision (feedback_id, generation)
);

CREATE TABLE thalion.feedback_handoff_resolution (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    handoff_ref uuid PRIMARY KEY,
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('accepted', 'revoked')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, handoff_ref) REFERENCES thalion.feedback_handoff (org_id, space_id, handoff_ref),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id)
);

ALTER TABLE thalion.feedback_decision
    DROP CONSTRAINT feedback_decision_action_check,
    DROP CONSTRAINT feedback_decision_check2,
    ADD COLUMN handoff_ref uuid,
    ADD CHECK (action IN ('assign', 'mark_corrected', 'explain', 'verify_correction', 'accept_handoff')),
    ADD CHECK ((actor_id = assignee_id) = (action IN ('mark_corrected', 'explain', 'accept_handoff'))),
    ADD CHECK ((handoff_ref IS NOT NULL) = (action = 'accept_handoff')),
    ADD CHECK (handoff_ref IS NULL OR generation > 2),
    ADD FOREIGN KEY (handoff_ref, feedback_id, prior_generation)
        REFERENCES thalion.feedback_handoff_item (handoff_ref, feedback_id, expected_generation);

CREATE INDEX feedback_decision_by_handoff ON thalion.feedback_decision (handoff_ref) WHERE handoff_ref IS NOT NULL;

CREATE FUNCTION thalion.require_open_feedback_handoff() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    expected_count integer;
BEGIN
    SELECT grant_row.item_count INTO expected_count
    FROM thalion.feedback_handoff AS grant_row
    JOIN thalion.request_record AS request ON (request.org_id, request.scope_space_id, request.request_id) =
                                              (grant_row.org_id, grant_row.space_id, grant_row.request_id)
    JOIN thalion.feedback_decision AS decision ON (decision.feedback_id, decision.generation, decision.assignee_id) =
                                                  (NEW.feedback_id, NEW.expected_generation, grant_row.incumbent_id)
    WHERE (grant_row.org_id, grant_row.space_id, grant_row.handoff_ref) = (NEW.org_id, NEW.space_id, NEW.handoff_ref)
      AND request.operation = 'authorize_feedback_handoff' AND request.destination = 'internal_feedback'
      AND request.principal_id = grant_row.authorizer_id AND request.outcome IS NULL
      AND decision.action IN ('assign', 'accept_handoff')
    FOR UPDATE OF grant_row;
    IF NOT FOUND OR expected_count <= (
        SELECT count(*) FROM thalion.feedback_handoff_item WHERE handoff_ref = NEW.handoff_ref
    ) THEN
        RAISE EXCEPTION 'handoff items must belong to the open, bounded authorization' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER feedback_handoff_item_open BEFORE INSERT ON thalion.feedback_handoff_item
FOR EACH ROW EXECUTE FUNCTION thalion.require_open_feedback_handoff();

CREATE FUNCTION thalion.require_feedback_handoff_acceptance() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.feedback_handoff_resolution AS resolution
        JOIN thalion.feedback_handoff AS grant_row USING (org_id, space_id, handoff_ref)
        WHERE (resolution.org_id, resolution.space_id, resolution.handoff_ref, resolution.request_id, resolution.actor_id) =
              (NEW.org_id, NEW.space_id, NEW.handoff_ref, NEW.request_id, NEW.actor_id)
          AND resolution.outcome = 'accepted' AND resolution.recorded_at < grant_row.expires_at
          AND resolution.actor_id = grant_row.successor_id
    ) THEN
        RAISE EXCEPTION 'handoff assignment requires the scoped successor acceptance' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER feedback_handoff_decision BEFORE INSERT ON thalion.feedback_decision
FOR EACH ROW WHEN (NEW.action = 'accept_handoff') EXECUTE FUNCTION thalion.require_feedback_handoff_acceptance();

CREATE FUNCTION thalion.verify_feedback_handoff_coverage() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    expected_count integer;
    actual_count integer;
BEGIN
    IF TG_TABLE_NAME = 'feedback_handoff' THEN
        expected_count := NEW.item_count;
        SELECT count(*) INTO actual_count FROM thalion.feedback_handoff_item WHERE handoff_ref = NEW.handoff_ref;
    ELSE
        SELECT item_count INTO expected_count FROM thalion.feedback_handoff WHERE handoff_ref = NEW.handoff_ref;
        SELECT count(*) INTO actual_count FROM thalion.feedback_decision WHERE handoff_ref = NEW.handoff_ref;
    END IF;
    IF expected_count IS DISTINCT FROM actual_count THEN
        RAISE EXCEPTION 'handoff coverage must equal the sealed item count' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER feedback_handoff_scope_complete AFTER INSERT ON thalion.feedback_handoff
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.verify_feedback_handoff_coverage();
CREATE CONSTRAINT TRIGGER feedback_handoff_accepted_complete AFTER INSERT ON thalion.feedback_handoff_resolution
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.outcome = 'accepted')
EXECUTE FUNCTION thalion.verify_feedback_handoff_coverage();

CREATE TRIGGER feedback_handoff_immutable BEFORE UPDATE OR DELETE ON thalion.feedback_handoff
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER feedback_handoff_item_immutable BEFORE UPDATE OR DELETE ON thalion.feedback_handoff_item
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER feedback_handoff_resolution_immutable BEFORE UPDATE OR DELETE ON thalion.feedback_handoff_resolution
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER feedback_handoff_no_truncate BEFORE TRUNCATE ON thalion.feedback_handoff
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER feedback_handoff_item_no_truncate BEFORE TRUNCATE ON thalion.feedback_handoff_item
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER feedback_handoff_resolution_no_truncate BEFORE TRUNCATE ON thalion.feedback_handoff_resolution
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
