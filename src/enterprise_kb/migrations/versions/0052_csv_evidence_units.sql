CREATE FUNCTION thalion.valid_csv_amount_columns(headers text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT array_ndims(headers) = 1 AND array_lower(headers, 1) = 1
       AND cardinality(headers) = 4
       AND (SELECT count(DISTINCT header) FROM unnest(headers) AS header
            WHERE char_length(header) BETWEEN 1 AND 128
              AND btrim(header) <> '' AND header !~ '[[:cntrl:]]') = 4;
$$;

ALTER TABLE thalion.source_contract_revision ADD COLUMN csv_amount_columns text[]
    CHECK (csv_amount_columns IS NULL OR thalion.valid_csv_amount_columns(csv_amount_columns) IS TRUE);

CREATE TABLE thalion.evidence_unit (
    unit_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_ref uuid NOT NULL REFERENCES thalion.processing_run,
    record_number integer NOT NULL CHECK (record_number >= 2),
    reason text CHECK (reason IN ('missing_column', 'missing_value', 'invalid_amount')),
    UNIQUE (run_ref, record_number),
    UNIQUE (unit_ref, run_ref)
);

CREATE TABLE thalion.evidence_unit_member (
    unit_ref uuid NOT NULL,
    run_ref uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('amount', 'unit', 'condition', 'exception')),
    passage_id bigint NOT NULL,
    excerpt_revision bigint NOT NULL,
    PRIMARY KEY (unit_ref, role),
    UNIQUE (unit_ref, passage_id),
    FOREIGN KEY (unit_ref, run_ref) REFERENCES thalion.evidence_unit (unit_ref, run_ref),
    FOREIGN KEY (passage_id, excerpt_revision) REFERENCES thalion.passage_excerpt (passage_id, excerpt_revision)
);

CREATE FUNCTION thalion.verify_csv_unit_member() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.evidence_unit AS unit
        JOIN thalion.passage_excerpt AS excerpt ON excerpt.run_ref = unit.run_ref
        JOIN thalion.passage AS passage ON passage.passage_id = excerpt.passage_id
        WHERE (unit.unit_ref, unit.run_ref) = (NEW.unit_ref, NEW.run_ref)
          AND (excerpt.passage_id, excerpt.excerpt_revision) = (NEW.passage_id, NEW.excerpt_revision)
          AND passage.kind = 'csv_cell' AND passage.csv_record = unit.record_number
          AND unit.reason IS NULL
    ) THEN
        RAISE EXCEPTION 'the CSV unit member must belong to its exact row and processing revision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION thalion.verify_sealed_csv_unit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF (SELECT count(*) FROM thalion.evidence_unit_member WHERE unit_ref = NEW.unit_ref)
        <> (CASE WHEN NEW.reason IS NULL THEN 4 ELSE 0 END) THEN
        RAISE EXCEPTION 'a complete CSV unit must seal all four required members together'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER evidence_unit_open_run BEFORE INSERT ON thalion.evidence_unit
FOR EACH ROW EXECUTE FUNCTION thalion.require_open_processing_run();
CREATE TRIGGER evidence_unit_member_open_run BEFORE INSERT ON thalion.evidence_unit_member
FOR EACH ROW EXECUTE FUNCTION thalion.require_open_processing_run();
CREATE TRIGGER evidence_unit_member_matches_row BEFORE INSERT ON thalion.evidence_unit_member
FOR EACH ROW EXECUTE FUNCTION thalion.verify_csv_unit_member();
CREATE CONSTRAINT TRIGGER evidence_unit_sealed AFTER INSERT ON thalion.evidence_unit
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.verify_sealed_csv_unit();

CREATE TRIGGER evidence_unit_immutable BEFORE UPDATE OR DELETE ON thalion.evidence_unit
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER evidence_unit_member_immutable BEFORE UPDATE OR DELETE ON thalion.evidence_unit_member
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
