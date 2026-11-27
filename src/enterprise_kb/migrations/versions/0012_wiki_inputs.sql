ALTER TABLE thalion.permission_binding
    DROP CONSTRAINT permission_binding_operation_check,
    DROP CONSTRAINT permission_binding_purpose_check,
    DROP CONSTRAINT permission_binding_destination_check,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation, purpose, destination) = ('read_passage', 'employee_evidence', 'employee')
        OR ((operation, purpose, destination) = ('assemble_wiki_inputs', 'wiki_compilation', 'local_workspace')
            AND fields = ARRAY['excerpt'])
    );

CREATE TABLE thalion.input_manifest (
    manifest_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    author_id bigint NOT NULL,
    check_id uuid NOT NULL UNIQUE,
    format_revision integer NOT NULL DEFAULT 1 CHECK (format_revision = 1),
    purpose text NOT NULL DEFAULT 'wiki_compilation' CHECK (purpose = 'wiki_compilation'),
    destination text NOT NULL DEFAULT 'local_workspace' CHECK (destination = 'local_workspace'),
    direct_count integer NOT NULL CHECK (direct_count BETWEEN 0 AND 20),
    parent_refs uuid[] NOT NULL CHECK (cardinality(parent_refs) <= 8 AND array_position(parent_refs, NULL) IS NULL),
    direct_digest bytea NOT NULL CHECK (octet_length(direct_digest) = 32),
    expanded_digest bytea NOT NULL CHECK (octet_length(expanded_digest) = 32),
    sealed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, author_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id),
    CHECK (direct_count > 0 OR cardinality(parent_refs) > 0)
);

CREATE VIEW thalion.input_manifest_entry AS
SELECT manifest.manifest_ref, dependency.*
FROM thalion.input_manifest AS manifest
JOIN thalion.delivery_dependency AS dependency USING (check_id, org_id);

CREATE INDEX input_manifest_parents ON thalion.input_manifest USING gin (parent_refs);
CREATE INDEX delivery_dependency_passage ON thalion.delivery_dependency (org_id, space_id, passage_ref, excerpt_revision);

CREATE FUNCTION thalion.verify_local_input_manifest() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    NEW.sealed_at := clock_timestamp();
    IF NOT EXISTS (
        SELECT 1 FROM thalion.delivery_record AS delivery
        JOIN thalion.request_record AS request USING (org_id, request_id)
        JOIN thalion.delivery_dependency AS entry USING (check_id, org_id)
        WHERE (delivery.org_id, delivery.check_id) = (NEW.org_id, NEW.check_id)
          AND request.principal_id = NEW.author_id AND request.delegated_principal_id IS NULL
          AND request.operation = 'assemble_wiki_inputs' AND request.destination = NEW.destination
        GROUP BY delivery.dependency_count, delivery.valid_until
        HAVING count(*) = delivery.dependency_count AND bool_and(entry.space_id = NEW.space_id)
           AND NEW.direct_count <= delivery.dependency_count AND NEW.sealed_at < delivery.valid_until
    ) OR cardinality(NEW.parent_refs) <> (
        SELECT count(*) FROM thalion.input_manifest AS parent
        WHERE parent.manifest_ref = ANY(NEW.parent_refs)
          AND (parent.org_id, parent.space_id, parent.author_id) = (NEW.org_id, NEW.space_id, NEW.author_id)
          AND (parent.purpose, parent.destination, parent.format_revision) =
              (NEW.purpose, NEW.destination, NEW.format_revision)
    ) OR EXISTS (
        SELECT parent.passage_ref, parent.excerpt_revision
        FROM thalion.input_manifest_entry AS parent WHERE parent.manifest_ref = ANY(NEW.parent_refs)
        EXCEPT
        SELECT entry.passage_ref, entry.excerpt_revision
        FROM thalion.delivery_dependency AS entry WHERE entry.check_id = NEW.check_id
    ) OR EXISTS (
        SELECT entry.passage_ref, entry.excerpt_revision
        FROM thalion.delivery_dependency AS entry WHERE entry.check_id = NEW.check_id AND entry.position > NEW.direct_count
        EXCEPT
        SELECT parent.passage_ref, parent.excerpt_revision
        FROM thalion.input_manifest_entry AS parent WHERE parent.manifest_ref = ANY(NEW.parent_refs)
    ) THEN
        RAISE EXCEPTION 'incomplete, expired, or out-of-scope Wiki input seal' USING ERRCODE = '23514';
    END IF;
    SELECT sha256(convert_to(jsonb_build_array(
               coalesce(jsonb_agg(exact_ref ORDER BY position) FILTER (WHERE position <= NEW.direct_count), '[]'),
               to_jsonb(NEW.parent_refs)
           )::text, 'UTF8')),
           sha256(convert_to(jsonb_agg(exact_ref ORDER BY position)::text, 'UTF8'))
      INTO NEW.direct_digest, NEW.expanded_digest
      FROM (
          SELECT position, jsonb_build_array(passage_ref, excerpt_revision) AS exact_ref
          FROM thalion.delivery_dependency WHERE check_id = NEW.check_id
      ) AS ordered;
    RETURN NEW;
END;
$$;

CREATE TRIGGER input_manifest_verified BEFORE INSERT ON thalion.input_manifest
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_input_manifest();

CREATE TRIGGER input_manifest_immutable BEFORE UPDATE OR DELETE ON thalion.input_manifest
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
