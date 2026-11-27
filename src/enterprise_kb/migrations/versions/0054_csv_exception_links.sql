ALTER TABLE thalion.source_contract_revision ADD COLUMN csv_exception_link_columns text[]
    CHECK (csv_exception_link_columns IS NULL OR (
        csv_amount_columns IS NOT NULL
        AND array_ndims(csv_exception_link_columns) = 1 AND array_lower(csv_exception_link_columns, 1) = 1
        AND cardinality(csv_exception_link_columns) = 2
        AND NOT csv_exception_link_columns && csv_amount_columns
        AND thalion.valid_csv_amount_columns(ARRAY[
            csv_amount_columns[1], csv_amount_columns[2],
            csv_exception_link_columns[1], csv_exception_link_columns[2]
        ])
    ) IS TRUE);

ALTER TABLE thalion.evidence_unit DROP CONSTRAINT evidence_unit_reason_check,
    ADD CONSTRAINT evidence_unit_reason_check
        CHECK (reason IN ('missing_column', 'missing_value', 'invalid_amount', 'invalid_exception_link')),
    ADD COLUMN exception_record_number integer CHECK (exception_record_number IS NULL OR (
        reason IS NULL AND exception_record_number >= 2 AND exception_record_number <> record_number
    ));

ALTER TABLE thalion.evidence_unit_member DROP CONSTRAINT evidence_unit_member_role_check,
    ADD CONSTRAINT evidence_unit_member_role_check
        CHECK (role IN ('amount', 'unit', 'condition', 'exception', 'exception_ref', 'exception_key'));

CREATE OR REPLACE FUNCTION thalion.verify_csv_unit_member() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.evidence_unit AS unit
        JOIN thalion.passage_excerpt AS excerpt ON excerpt.run_ref = unit.run_ref
        JOIN thalion.passage AS passage ON passage.passage_id = excerpt.passage_id
        WHERE (unit.unit_ref, unit.run_ref) = (NEW.unit_ref, NEW.run_ref)
          AND (excerpt.passage_id, excerpt.excerpt_revision) = (NEW.passage_id, NEW.excerpt_revision)
          AND passage.kind = 'csv_cell' AND unit.reason IS NULL
          AND (NEW.role NOT IN ('exception_ref', 'exception_key') OR unit.exception_record_number IS NOT NULL)
          AND passage.csv_record = CASE
              WHEN NEW.role IN ('exception', 'exception_key') THEN coalesce(unit.exception_record_number, unit.record_number)
              ELSE unit.record_number
          END
    ) THEN
        RAISE EXCEPTION 'the CSV unit member must belong to its exact declared row and processing revision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION thalion.verify_sealed_csv_unit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE member_count integer;
BEGIN
    SELECT count(*) INTO member_count FROM thalion.evidence_unit_member WHERE unit_ref = NEW.unit_ref;
    IF NEW.exception_record_number IS NOT NULL THEN
        IF member_count <> 6 OR NOT EXISTS (
            SELECT 1 FROM thalion.processing_run AS run
            JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
                 (run.org_id, run.space_id, version.source_id, run.contract_revision)
            WHERE run.run_ref = NEW.run_ref AND contract.csv_exception_link_columns IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'a complete CSV exception requires a declared link and all six linked members'
                USING ERRCODE = '23514';
        END IF;
    ELSIF member_count <> (CASE WHEN NEW.reason IS NULL THEN 4 ELSE 0 END) THEN
        RAISE EXCEPTION 'a complete CSV unit must seal all four required members together'
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
                  WHERE required.unit_ref = member.unit_ref AND NOT EXISTS (
                      SELECT 1 FROM included AS supplied
                      WHERE (supplied.passage_id, supplied.excerpt_revision) =
                            (required.passage_id, required.excerpt_revision)
                  )
              )
        )
    );
$$;
