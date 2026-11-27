CREATE FUNCTION thalion.valid_csv_alternate_columns(
    primary_headers text[], link_headers text[], alternate_headers text[]
) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    WITH headers AS (
        SELECT primary_headers || coalesce(link_headers, '{}'::text[])
            || array_remove(alternate_headers, NULL) AS declared
    )
    SELECT primary_headers IS NOT NULL
       AND array_ndims(alternate_headers) = 1 AND array_lower(alternate_headers, 1) = 1
       AND cardinality(alternate_headers) = 4 AND cardinality(array_remove(alternate_headers, NULL)) > 0
       AND (SELECT count(DISTINCT header COLLATE "C") FROM unnest(declared) AS header
            WHERE char_length(header) BETWEEN 1 AND 128
              AND btrim(header) <> '' AND header !~ '[[:cntrl:]]') = cardinality(declared)
    FROM headers;
$$;

ALTER TABLE thalion.source_contract_revision ADD COLUMN csv_alternate_columns text[]
    CHECK (csv_alternate_columns IS NULL OR thalion.valid_csv_alternate_columns(
        csv_amount_columns, csv_exception_link_columns, csv_alternate_columns
    ) IS TRUE);

ALTER TABLE thalion.passage_excerpt
    ADD COLUMN csv_header_digest bytea,
    ADD COLUMN csv_value_digest bytea,
    ADD CONSTRAINT csv_equivalence_digest_pair CHECK (
        (csv_header_digest IS NULL AND csv_value_digest IS NULL) OR
        (octet_length(csv_header_digest) = 32 AND octet_length(csv_value_digest) = 32) IS TRUE
    );

ALTER TABLE thalion.evidence_unit_member
    ADD COLUMN is_alternative boolean NOT NULL DEFAULT false,
    DROP CONSTRAINT evidence_unit_member_pkey,
    ADD PRIMARY KEY (unit_ref, role, is_alternative),
    ADD CHECK (NOT is_alternative OR role IN ('amount', 'unit', 'condition', 'exception'));

CREATE OR REPLACE FUNCTION thalion.verify_sealed_csv_unit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    primary_count integer;
    contract thalion.source_contract_revision%ROWTYPE;
BEGIN
    SELECT count(*) INTO primary_count FROM thalion.evidence_unit_member
    WHERE unit_ref = NEW.unit_ref AND NOT is_alternative;
    SELECT admitted.* INTO contract
    FROM thalion.processing_run AS run
    JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
    JOIN thalion.source_contract_revision AS admitted
      ON (admitted.org_id, admitted.space_id, admitted.source_id, admitted.revision) =
         (run.org_id, run.space_id, version.source_id, run.contract_revision)
    WHERE run.run_ref = NEW.run_ref;

    IF NEW.exception_record_number IS NOT NULL THEN
        IF primary_count <> 6 OR contract.csv_exception_link_columns IS NULL THEN
            RAISE EXCEPTION 'a complete CSV exception requires a declared link and all six linked members'
                USING ERRCODE = '23514';
        END IF;
    ELSIF primary_count <> (CASE WHEN NEW.reason IS NULL THEN 4 ELSE 0 END) THEN
        RAISE EXCEPTION 'a complete CSV unit must seal all four required members together'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1 FROM thalion.evidence_unit_member AS alternative
        JOIN thalion.passage_excerpt AS alternate_excerpt
          ON (alternate_excerpt.passage_id, alternate_excerpt.excerpt_revision) =
             (alternative.passage_id, alternative.excerpt_revision)
        CROSS JOIN LATERAL (
            SELECT array_position(ARRAY['amount', 'unit', 'condition', 'exception'], alternative.role) AS slot
        ) AS declared
        WHERE alternative.unit_ref = NEW.unit_ref AND alternative.is_alternative
          AND NOT EXISTS (
              SELECT 1 FROM thalion.evidence_unit_member AS original
              JOIN thalion.passage_excerpt AS original_excerpt
                ON (original_excerpt.passage_id, original_excerpt.excerpt_revision) =
                   (original.passage_id, original.excerpt_revision)
              WHERE (original.unit_ref, original.role) = (alternative.unit_ref, alternative.role)
                AND NOT original.is_alternative
                AND original_excerpt.csv_header_digest = sha256(convert_to(contract.csv_amount_columns[declared.slot], 'UTF8'))
                AND alternate_excerpt.csv_header_digest = sha256(convert_to(contract.csv_alternate_columns[declared.slot], 'UTF8'))
                AND alternate_excerpt.csv_value_digest = original_excerpt.csv_value_digest
          )
    ) THEN
        RAISE EXCEPTION 'a CSV alternate must be a declared, exact equivalent of its primary member'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION thalion.wiki_csv_groups_complete(scope_org bigint, scope_space bigint, refs jsonb)
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
