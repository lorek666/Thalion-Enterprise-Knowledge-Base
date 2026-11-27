ALTER TABLE thalion.permission_binding DROP CONSTRAINT permission_binding_use,
    ADD CONSTRAINT permission_binding_use CHECK (
        (operation, purpose, destination) = ('read_passage', 'employee_evidence', 'employee')
        OR (destination = 'local_workspace'
            AND fields IN (ARRAY['excerpt'], ARRAY['location'], ARRAY['excerpt', 'location'])
            AND (operation, purpose) IN (
                ('assemble_wiki_inputs', 'wiki_compilation'), ('review_wiki_revision', 'wiki_review'),
                ('publish_wiki_revision', 'wiki_publication')
            ))
    );

CREATE INDEX evidence_unit_member_exact_passage
    ON thalion.evidence_unit_member (passage_id, excerpt_revision);

CREATE FUNCTION thalion.wiki_csv_groups_complete(scope_org bigint, scope_space bigint, refs jsonb)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    WITH included AS (
        SELECT passage.passage_id, (exact_ref ->> 1)::bigint AS excerpt_revision
        FROM jsonb_array_elements(refs) AS exact_ref
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.public_id)
           = (scope_org, scope_space, 'passage', (exact_ref ->> 0)::uuid)
        JOIN thalion.passage AS passage
          ON passage.passage_id = identity.object_id AND passage.kind = 'csv_cell'
    )
    SELECT NOT EXISTS (
        SELECT 1 FROM included
        LEFT JOIN thalion.evidence_unit_member AS member USING (passage_id, excerpt_revision)
        WHERE member.unit_ref IS NULL OR EXISTS (
            SELECT 1 FROM thalion.evidence_unit_member AS required
            WHERE required.unit_ref = member.unit_ref AND NOT EXISTS (
                SELECT 1 FROM included AS supplied
                WHERE (supplied.passage_id, supplied.excerpt_revision) =
                      (required.passage_id, required.excerpt_revision)
            )
        )
    );
$$;

CREATE FUNCTION thalion.verify_wiki_csv_groups() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    content jsonb;
    refs jsonb;
    supports jsonb;
BEGIN
    IF TG_TABLE_NAME = 'input_manifest' THEN
        SELECT jsonb_agg(jsonb_build_array(passage_ref, excerpt_revision)) INTO refs
        FROM thalion.delivery_dependency WHERE (org_id, check_id) = (NEW.org_id, NEW.check_id);
    ELSE
        content := convert_from(NEW.content, 'UTF8')::jsonb;
        refs := content -> 'citations';
    END IF;
    IF NOT thalion.wiki_csv_groups_complete(NEW.org_id, NEW.space_id, refs) THEN
        RAISE EXCEPTION 'Wiki inputs and citations must keep approved CSV groups complete' USING ERRCODE = '23514';
    END IF;
    FOR supports IN
        SELECT support.value
        FROM jsonb_array_elements(content -> 'statements') AS statement(value)
        CROSS JOIN LATERAL jsonb_array_elements(statement.value -> 'support_groups') AS support(value)
    LOOP
        IF NOT thalion.wiki_csv_groups_complete(NEW.org_id, NEW.space_id, supports) THEN
            RAISE EXCEPTION 'each Wiki support set must keep its CSV groups complete' USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE TRIGGER input_manifest_csv_groups AFTER INSERT ON thalion.input_manifest
FOR EACH ROW EXECUTE FUNCTION thalion.verify_wiki_csv_groups();

CREATE TRIGGER wiki_revision_csv_groups AFTER INSERT ON thalion.wiki_revision
FOR EACH ROW EXECUTE FUNCTION thalion.verify_wiki_csv_groups();
