CREATE TABLE thalion.search_scope_observation (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    request_id uuid NOT NULL,
    visibility_limited boolean NOT NULL,
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TABLE thalion.gap_event (
    gap_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    origin_request_id uuid NOT NULL,
    recorded_request_id uuid NOT NULL,
    feedback_id bigint,
    observation text NOT NULL CHECK (observation IN (
        'reported_missing', 'no_visible_match', 'visibility_limited', 'scope_unverified',
        'dependency_unavailable', 'input_changed'
    )),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, origin_request_id),
    UNIQUE (org_id, space_id, gap_ref),
    FOREIGN KEY (org_id, space_id, origin_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, recorded_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, feedback_id) REFERENCES thalion.feedback (org_id, space_id, feedback_id),
    CHECK (origin_request_id <> recorded_request_id),
    CHECK (observation <> 'reported_missing' OR feedback_id IS NOT NULL)
);

CREATE TABLE thalion.gap_review (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    gap_ref uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation >= 2),
    classification text NOT NULL CHECK (classification IN ('permission_review', 'conditions_missing')),
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (gap_ref, generation),
    FOREIGN KEY (org_id, space_id, gap_ref) REFERENCES thalion.gap_event (org_id, space_id, gap_ref),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TRIGGER search_scope_observation_immutable BEFORE UPDATE OR DELETE ON thalion.search_scope_observation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER gap_event_immutable BEFORE UPDATE OR DELETE ON thalion.gap_event
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER gap_review_immutable BEFORE UPDATE OR DELETE ON thalion.gap_review
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE VIEW thalion.current_gap AS
SELECT event.*, coalesce(review.generation, 1) AS generation,
       coalesce(review.classification, event.observation) AS classification
FROM thalion.gap_event AS event
LEFT JOIN LATERAL (
    SELECT generation, classification FROM thalion.gap_review WHERE gap_ref = event.gap_ref
    ORDER BY generation DESC LIMIT 1
) AS review ON true;
