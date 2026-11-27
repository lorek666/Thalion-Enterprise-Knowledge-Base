ALTER FUNCTION thalion.wiki_csv_groups_complete(bigint, bigint, jsonb) RENAME TO wiki_evidence_groups_complete;

CREATE OR REPLACE FUNCTION thalion.wiki_evidence_groups_complete(scope_org bigint, scope_space bigint, refs jsonb)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    WITH included AS (
        SELECT passage.passage_id, (exact_ref ->> 1)::bigint AS excerpt_revision
        FROM jsonb_array_elements(refs) AS exact_ref
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.public_id)
           = (scope_org, scope_space, 'passage', (exact_ref ->> 0)::uuid)
        JOIN thalion.passage AS passage
          ON passage.passage_id = identity.object_id AND passage.kind IN ('csv_cell', 'docx_cell')
    )
    SELECT NOT EXISTS (
        SELECT 1 FROM included
        WHERE NOT EXISTS (
            SELECT 1 FROM thalion.evidence_unit_member AS member
            WHERE (member.passage_id, member.excerpt_revision) = (included.passage_id, included.excerpt_revision)
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.evidence_unit_member AS required
                  WHERE required.unit_ref = member.unit_ref AND NOT required.is_alternative AND NOT EXISTS (
                      SELECT 1 FROM thalion.evidence_unit_member AS choice
                      JOIN included AS supplied USING (passage_id, excerpt_revision)
                      WHERE (choice.unit_ref, choice.role) = (required.unit_ref, required.role)
                  )
              )
        )
    );
$$;

ALTER FUNCTION thalion.verify_wiki_csv_groups() RENAME TO verify_wiki_evidence_groups;
ALTER TRIGGER input_manifest_csv_groups ON thalion.input_manifest RENAME TO input_manifest_evidence_groups;
ALTER TRIGGER wiki_revision_csv_groups ON thalion.wiki_revision RENAME TO wiki_revision_evidence_groups;

CREATE OR REPLACE FUNCTION thalion.verify_wiki_evidence_groups() RETURNS trigger
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
    IF NOT thalion.wiki_evidence_groups_complete(NEW.org_id, NEW.space_id, refs) THEN
        RAISE EXCEPTION 'Wiki inputs and citations must keep approved evidence groups complete' USING ERRCODE = '23514';
    END IF;
    FOR supports IN
        SELECT support.value
        FROM jsonb_array_elements(content -> 'statements') AS statement(value)
        CROSS JOIN LATERAL jsonb_array_elements(statement.value -> 'support_groups') AS support(value)
    LOOP
        IF NOT thalion.wiki_evidence_groups_complete(NEW.org_id, NEW.space_id, supports) THEN
            RAISE EXCEPTION 'each Wiki support set must keep its evidence groups complete' USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;
