ALTER TABLE thalion.permission_binding DROP CONSTRAINT permission_binding_use,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation, purpose, destination) = ('read_passage', 'employee_evidence', 'employee')
        OR (destination = 'local_workspace' AND fields = ARRAY['excerpt'] AND (operation, purpose) IN (
            ('assemble_wiki_inputs', 'wiki_compilation'), ('review_wiki_revision', 'wiki_review'),
            ('publish_wiki_revision', 'wiki_publication')
        ))
    );

ALTER TABLE thalion.wiki_review_material
    ADD COLUMN expected_generation bigint CHECK (expected_generation >= 0);
ALTER TABLE thalion.wiki_revision ADD UNIQUE (org_id, space_id, topic_key, revision_ref);
ALTER TABLE thalion.wiki_review ADD UNIQUE (org_id, space_id, revision_ref, review_ref, reviewer_id, decision);

CREATE TABLE thalion.wiki_publication_event (
    publication_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    topic_key text NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    prior_generation bigint GENERATED ALWAYS AS (nullif(generation - 1, 0)) STORED,
    revision_ref uuid NOT NULL UNIQUE,
    review_ref uuid NOT NULL,
    publisher_id bigint NOT NULL,
    approved_decision text GENERATED ALWAYS AS ('approved'::text) STORED,
    check_id uuid NOT NULL UNIQUE,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, topic_key, generation),
    FOREIGN KEY (org_id, space_id, topic_key, revision_ref)
        REFERENCES thalion.wiki_revision (org_id, space_id, topic_key, revision_ref),
    FOREIGN KEY (org_id, space_id, topic_key, prior_generation)
        REFERENCES thalion.wiki_publication_event (org_id, space_id, topic_key, generation),
    FOREIGN KEY (org_id, space_id, revision_ref, review_ref, publisher_id, approved_decision)
        REFERENCES thalion.wiki_review (org_id, space_id, revision_ref, review_ref, reviewer_id, decision),
    FOREIGN KEY (check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id)
);

CREATE VIEW thalion.current_wiki_publication AS
SELECT DISTINCT ON (org_id, space_id, topic_key) * FROM thalion.wiki_publication_event
ORDER BY org_id, space_id, topic_key, generation DESC;

CREATE FUNCTION thalion.same_wiki_dependency_snapshot(first_check uuid, second_check uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT first_snapshot IS NOT NULL AND first_snapshot = second_snapshot
    FROM (
        SELECT jsonb_agg(to_jsonb(dependency) - 'check_id' ORDER BY position)
                   FILTER (WHERE check_id = first_check) AS first_snapshot,
               jsonb_agg(to_jsonb(dependency) - 'check_id' ORDER BY position)
                   FILTER (WHERE check_id = second_check) AS second_snapshot
        FROM thalion.delivery_dependency AS dependency WHERE check_id IN (first_check, second_check)
    ) AS snapshots;
$$;

CREATE FUNCTION thalion.verify_wiki_publication() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.wiki_review AS review
        JOIN thalion.wiki_review_material AS material ON material.check_id = review.material_check_id
        JOIN thalion.delivery_record AS delivery ON delivery.check_id = NEW.check_id
        JOIN thalion.request_record AS request ON (request.org_id, request.request_id) = (delivery.org_id, delivery.request_id)
        JOIN thalion.delivery_record AS reviewed ON reviewed.check_id = review.check_id
        JOIN thalion.request_record AS review_request
          ON (review_request.org_id, review_request.request_id) = (reviewed.org_id, reviewed.request_id)
        WHERE review.review_ref = NEW.review_ref AND material.expected_generation = NEW.generation - 1
          AND (request.org_id, request.principal_id) = (NEW.org_id, NEW.publisher_id)
          AND request.operation = 'publish_wiki_revision' AND request.destination = 'local_workspace'
          AND request.delegated_principal_id IS NULL AND request.business_date = review_request.business_date
          AND delivery.payload_digest = review.content_digest AND delivery.valid_until > clock_timestamp()
          AND thalion.same_wiki_dependency_snapshot(review.check_id, NEW.check_id)
    ) THEN
        RAISE EXCEPTION 'Wiki publication does not match its review and current delivery receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER verify_wiki_publication BEFORE INSERT ON thalion.wiki_publication_event
FOR EACH ROW EXECUTE FUNCTION thalion.verify_wiki_publication();
CREATE TRIGGER wiki_publication_immutable BEFORE UPDATE OR DELETE ON thalion.wiki_publication_event
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
