ALTER TABLE thalion.permission_binding DROP CONSTRAINT permission_binding_use,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation, purpose, destination) = ('read_passage', 'employee_evidence', 'employee')
        OR (destination = 'local_workspace' AND fields = ARRAY['excerpt'] AND (operation, purpose) IN (
            ('assemble_wiki_inputs', 'wiki_compilation'), ('review_wiki_revision', 'wiki_review')
        ))
    );

ALTER TABLE thalion.input_manifest
    ADD UNIQUE (org_id, space_id, author_id, manifest_ref, expanded_digest);

CREATE TABLE thalion.wiki (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    topic_key text NOT NULL CHECK (topic_key ~ '^[a-z][a-z0-9_-]{0,63}$'),
    PRIMARY KEY (org_id, space_id, topic_key),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id)
);

CREATE TABLE thalion.wiki_revision (
    revision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    topic_key text NOT NULL,
    author_id bigint NOT NULL,
    reviewer_id bigint NOT NULL CHECK (reviewer_id <> author_id),
    basis_ref uuid NOT NULL,
    authorship text NOT NULL DEFAULT 'manual' CHECK (authorship = 'manual'),
    manifest_ref uuid NOT NULL,
    input_digest bytea NOT NULL,
    content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 131072),
    content_digest bytea GENERATED ALWAYS AS (sha256(content)) STORED,
    check_id uuid NOT NULL UNIQUE,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, revision_ref, reviewer_id, content_digest, input_digest),
    FOREIGN KEY (org_id, space_id, topic_key) REFERENCES thalion.wiki (org_id, space_id, topic_key),
    FOREIGN KEY (org_id, space_id, author_id, manifest_ref, input_digest)
        REFERENCES thalion.input_manifest (org_id, space_id, author_id, manifest_ref, expanded_digest),
    FOREIGN KEY (org_id, reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id)
);

CREATE TABLE thalion.wiki_review_material (
    check_id uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    revision_ref uuid NOT NULL,
    reviewer_id bigint NOT NULL,
    content_digest bytea NOT NULL,
    input_digest bytea NOT NULL,
    UNIQUE (org_id, space_id, revision_ref, reviewer_id, check_id),
    FOREIGN KEY (org_id, space_id, revision_ref, reviewer_id, content_digest, input_digest)
        REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref, reviewer_id, content_digest, input_digest),
    FOREIGN KEY (check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id)
);

CREATE TABLE thalion.wiki_review (
    review_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    revision_ref uuid NOT NULL UNIQUE,
    reviewer_id bigint NOT NULL,
    content_digest bytea NOT NULL,
    input_digest bytea NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    basis_ref uuid NOT NULL,
    check_id uuid NOT NULL UNIQUE,
    material_check_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, revision_ref, reviewer_id, content_digest, input_digest)
        REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref, reviewer_id, content_digest, input_digest),
    FOREIGN KEY (org_id, space_id, revision_ref, reviewer_id, material_check_id)
        REFERENCES thalion.wiki_review_material (org_id, space_id, revision_ref, reviewer_id, check_id),
    FOREIGN KEY (check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id)
);

CREATE FUNCTION thalion.guard_wiki_write_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    manuscript thalion.wiki_revision%ROWTYPE;
    expected_actor bigint;
    expected_operation text;
    expected_payload bytea;
    citations jsonb;
BEGIN
    IF TG_TABLE_NAME = 'wiki_revision' THEN
        manuscript := NEW;
        expected_actor := manuscript.author_id;
        expected_operation := 'create_wiki_candidate';
        citations := convert_from(manuscript.content, 'UTF8')::jsonb -> 'citations';
        IF jsonb_typeof(citations) IS DISTINCT FROM 'array' OR jsonb_array_length(citations) NOT BETWEEN 1 AND 20
           OR EXISTS (
               SELECT jsonb_array_elements(citations)
               EXCEPT
               SELECT jsonb_build_array(passage_ref, excerpt_revision)
               FROM thalion.input_manifest_entry WHERE manifest_ref = manuscript.manifest_ref
           ) THEN
            RAISE EXCEPTION 'Wiki citations must refer to exact entries in the sealed manifest' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT * INTO STRICT manuscript FROM thalion.wiki_revision WHERE revision_ref = NEW.revision_ref;
        expected_actor := NEW.reviewer_id;
        expected_operation := CASE WHEN TG_TABLE_NAME = 'wiki_review_material'
                                   THEN 'read_wiki_candidate' ELSE 'review_wiki_revision' END;
    END IF;
    expected_payload := sha256(manuscript.content);
    IF NOT EXISTS (
        SELECT 1 FROM thalion.delivery_record AS delivery
        JOIN thalion.request_record AS request USING (org_id, request_id)
        JOIN thalion.input_manifest AS origin ON origin.manifest_ref = manuscript.manifest_ref
        JOIN thalion.delivery_record AS origin_delivery ON origin_delivery.check_id = origin.check_id
        JOIN thalion.request_record AS origin_request
          ON (origin_request.org_id, origin_request.request_id) = (origin_delivery.org_id, origin_delivery.request_id)
        WHERE (delivery.org_id, delivery.check_id) = (NEW.org_id, NEW.check_id)
          AND request.principal_id = expected_actor AND request.operation = expected_operation
          AND request.destination = 'local_workspace' AND request.delegated_principal_id IS NULL
          AND request.business_date = origin_request.business_date
          AND delivery.payload_digest = expected_payload AND delivery.valid_until > clock_timestamp()
    ) OR EXISTS (
        (SELECT space_id, source_id, passage_ref, excerpt_revision
         FROM thalion.input_manifest_entry WHERE manifest_ref = manuscript.manifest_ref)
        EXCEPT
        (SELECT space_id, source_id, passage_ref, excerpt_revision
         FROM thalion.delivery_dependency WHERE check_id = NEW.check_id)
    ) OR EXISTS (
        (SELECT space_id, source_id, passage_ref, excerpt_revision
         FROM thalion.delivery_dependency WHERE check_id = NEW.check_id)
        EXCEPT
        (SELECT space_id, source_id, passage_ref, excerpt_revision
         FROM thalion.input_manifest_entry WHERE manifest_ref = manuscript.manifest_ref)
    ) THEN
        RAISE EXCEPTION 'Wiki writes require a fresh scoped receipt for the exact content and complete inputs'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER wiki_revision_receipt BEFORE INSERT ON thalion.wiki_revision
FOR EACH ROW EXECUTE FUNCTION thalion.guard_wiki_write_receipt();
CREATE TRIGGER wiki_review_receipt BEFORE INSERT ON thalion.wiki_review
FOR EACH ROW EXECUTE FUNCTION thalion.guard_wiki_write_receipt();
CREATE TRIGGER wiki_review_material_receipt BEFORE INSERT ON thalion.wiki_review_material
FOR EACH ROW EXECUTE FUNCTION thalion.guard_wiki_write_receipt();
CREATE TRIGGER wiki_topic_immutable BEFORE UPDATE OR DELETE ON thalion.wiki
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER wiki_revision_immutable BEFORE UPDATE OR DELETE ON thalion.wiki_revision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER wiki_review_immutable BEFORE UPDATE OR DELETE ON thalion.wiki_review
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER wiki_review_material_immutable BEFORE UPDATE OR DELETE ON thalion.wiki_review_material
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
