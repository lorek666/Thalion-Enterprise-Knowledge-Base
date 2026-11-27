ALTER TABLE thalion.source_contract_revision ADD COLUMN docx_amount_columns text[]
    CHECK (docx_amount_columns IS NULL OR (
        admission = 'synthetic_only' AND processor_id IS NOT NULL AND quality_reviewer_id IS NOT NULL
        AND thalion.valid_csv_amount_columns(docx_amount_columns)
    ) IS TRUE);

ALTER TABLE thalion.passage
    ADD COLUMN docx_table integer CHECK (docx_table BETWEEN 1 AND 16),
    ADD COLUMN docx_row integer CHECK (docx_row BETWEEN 2 AND 128),
    ADD COLUMN docx_column integer CHECK (docx_column BETWEEN 1 AND 16),
    ADD CONSTRAINT passage_docx_cell_coordinates CHECK (
        num_nonnulls(docx_table, docx_row, docx_column) = CASE WHEN kind = 'docx_cell' THEN 3 ELSE 0 END
    ),
    DROP CONSTRAINT passage_locator_shape,
    ADD CONSTRAINT passage_locator_shape CHECK (
        (kind IN ('paragraph', 'table', 'blockquote', 'list', 'code')
            AND heading_path IS NOT NULL AND paragraph IS NOT NULL AND byte_start IS NOT NULL AND byte_end IS NOT NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL AND docx_paragraph IS NULL)
        OR
        (kind = 'csv_cell' AND csv_record IS NOT NULL AND csv_column IS NOT NULL AND pdf_page IS NULL
            AND heading_path IS NULL AND paragraph IS NULL AND byte_start IS NULL AND byte_end IS NULL AND docx_paragraph IS NULL)
        OR
        (kind = 'pdf_page' AND pdf_page IS NOT NULL AND csv_record IS NULL AND csv_column IS NULL
            AND heading_path IS NULL AND paragraph IS NULL AND byte_start IS NULL AND byte_end IS NULL AND docx_paragraph IS NULL)
        OR
        (kind = 'docx_paragraph' AND docx_paragraph IS NOT NULL AND heading_path IS NOT NULL
            AND paragraph BETWEEN 1 AND docx_paragraph AND paragraph IS NOT NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL AND byte_start IS NULL AND byte_end IS NULL)
        OR
        (kind = 'docx_cell' AND heading_path IS NOT NULL AND paragraph IS NULL AND docx_paragraph IS NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL AND byte_start IS NULL AND byte_end IS NULL)
    );

CREATE UNIQUE INDEX passage_docx_cell_location
    ON thalion.passage (version_id, locator_revision, docx_table, docx_row, docx_column) WHERE kind = 'docx_cell';

CREATE OR REPLACE FUNCTION thalion.verify_evidence_format() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    actual_media_type text;
    expected_media_type text;
    docx_media_type constant text := 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
BEGIN
    SELECT asset.media_type INTO STRICT actual_media_type
    FROM thalion.document_version AS version
    JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id);
    IF TG_TABLE_NAME = 'passage' THEN
        expected_media_type := CASE
            WHEN NEW.kind IN ('docx_paragraph', 'docx_cell') THEN docx_media_type
            WHEN NEW.kind = 'csv_cell' THEN 'text/csv'
            WHEN NEW.kind = 'pdf_page' THEN 'application/pdf'
            ELSE 'text/markdown' END;
    ELSE
        SELECT CASE profile WHEN 'utf8_csv_literal_v1' THEN 'text/csv' WHEN 'pdf_pages_v1' THEN 'application/pdf'
               WHEN 'docx_literal_paragraphs_v1' THEN docx_media_type ELSE 'text/markdown' END INTO STRICT expected_media_type
        FROM thalion.processing_config_revision WHERE configuration_revision = NEW.configuration_revision;
        IF (NEW.pdf_page_count IS NOT NULL) IS DISTINCT FROM (expected_media_type = 'application/pdf') THEN
            RAISE EXCEPTION 'PDF processing runs require a bounded page count' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF actual_media_type IS DISTINCT FROM expected_media_type THEN
        RAISE EXCEPTION 'the evidence format does not match the original asset' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE thalion.passage_excerpt ADD COLUMN docx_header_digest bytea
    CHECK (docx_header_digest IS NULL OR (
        octet_length(docx_header_digest) = 32 AND csv_header_digest IS NULL AND csv_value_digest IS NULL
    ));

CREATE FUNCTION thalion.verify_docx_cell_excerpt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE is_docx_cell boolean;
BEGIN
    SELECT kind = 'docx_cell' INTO STRICT is_docx_cell FROM thalion.passage WHERE passage_id = NEW.passage_id;
    IF is_docx_cell <> (NEW.docx_header_digest IS NOT NULL) OR (is_docx_cell AND NOT EXISTS (
        SELECT 1 FROM thalion.processing_run AS run
        JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (run.org_id, run.space_id, version.source_id, run.contract_revision)
        WHERE run.run_ref = NEW.run_ref AND contract.docx_amount_columns IS NOT NULL
    )) THEN
        RAISE EXCEPTION 'DOCX cells require a header digest and an admitted table contract' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER passage_excerpt_docx_cell BEFORE INSERT ON thalion.passage_excerpt
FOR EACH ROW EXECUTE FUNCTION thalion.verify_docx_cell_excerpt();

ALTER TABLE thalion.evidence_unit
    ADD COLUMN docx_table integer CHECK (docx_table IS NULL OR (
        docx_table BETWEEN 1 AND 16 AND record_number <= 128 AND exception_record_number IS NULL
        AND reason IS DISTINCT FROM 'invalid_exception_link'
    )),
    DROP CONSTRAINT evidence_unit_run_ref_record_number_key;

CREATE UNIQUE INDEX evidence_unit_csv_row ON thalion.evidence_unit (run_ref, record_number) WHERE docx_table IS NULL;
CREATE UNIQUE INDEX evidence_unit_docx_row ON thalion.evidence_unit (run_ref, docx_table, record_number);

CREATE OR REPLACE FUNCTION thalion.verify_csv_unit_member() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.evidence_unit AS unit
        JOIN thalion.passage_excerpt AS excerpt ON excerpt.run_ref = unit.run_ref
        JOIN thalion.passage AS passage ON passage.passage_id = excerpt.passage_id
        WHERE (unit.unit_ref, unit.run_ref) = (NEW.unit_ref, NEW.run_ref)
          AND (excerpt.passage_id, excerpt.excerpt_revision) = (NEW.passage_id, NEW.excerpt_revision)
          AND unit.reason IS NULL
          AND (
              (unit.docx_table IS NULL AND passage.kind = 'csv_cell'
               AND (NEW.role NOT IN ('exception_ref', 'exception_key') OR unit.exception_record_number IS NOT NULL)
               AND passage.csv_record = CASE
                   WHEN NEW.role IN ('exception', 'exception_key') THEN coalesce(unit.exception_record_number, unit.record_number)
                   ELSE unit.record_number END)
              OR
              (passage.kind = 'docx_cell' AND NOT NEW.is_alternative
               AND (passage.docx_table, passage.docx_row) = (unit.docx_table, unit.record_number)
               AND EXISTS (
                   SELECT 1 FROM thalion.processing_run AS run
                   JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
                   JOIN thalion.source_contract_revision AS contract
                     ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
                        (run.org_id, run.space_id, version.source_id, run.contract_revision)
                   WHERE run.run_ref = unit.run_ref AND excerpt.docx_header_digest = sha256(convert_to(
                       contract.docx_amount_columns[array_position(ARRAY['amount','unit','condition','exception'], NEW.role)], 'UTF8'
                   ))
               ))
          )
    ) THEN
        RAISE EXCEPTION 'an evidence member must match its exact declared row, role and processing revision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION thalion.verify_sealed_docx_unit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (passage_id)
        WHERE excerpt.run_ref = NEW.run_ref AND passage.kind = 'docx_cell'
          AND (passage.docx_table, passage.docx_row) = (NEW.docx_table, NEW.record_number)
    ) OR (SELECT count(*) FROM thalion.evidence_unit_member WHERE unit_ref = NEW.unit_ref)
        <> (CASE WHEN NEW.reason IS NULL THEN 4 ELSE 0 END) THEN
        RAISE EXCEPTION 'a DOCX row must seal all four required members together or record its rejection'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER evidence_unit_sealed ON thalion.evidence_unit;
CREATE CONSTRAINT TRIGGER evidence_unit_sealed AFTER INSERT ON thalion.evidence_unit
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.docx_table IS NULL)
EXECUTE FUNCTION thalion.verify_sealed_csv_unit();
CREATE CONSTRAINT TRIGGER evidence_unit_docx_sealed AFTER INSERT ON thalion.evidence_unit
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.docx_table IS NOT NULL)
EXECUTE FUNCTION thalion.verify_sealed_docx_unit();

CREATE FUNCTION thalion.verify_docx_rows_sealed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (passage_id)
        WHERE excerpt.run_ref = NEW.run_ref AND passage.kind = 'docx_cell' AND NOT EXISTS (
            SELECT 1 FROM thalion.evidence_unit AS unit
            WHERE (unit.run_ref, unit.docx_table, unit.record_number) = (excerpt.run_ref, passage.docx_table, passage.docx_row)
        )
    ) THEN
        RAISE EXCEPTION 'each DOCX row requires a sealed evidence unit or a rejection' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER processing_run_docx_sealed AFTER INSERT ON thalion.processing_run
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.verify_docx_rows_sealed();

CREATE FUNCTION thalion.require_docx_table_preview() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (passage_id)
        WHERE excerpt.run_ref = NEW.run_ref AND passage.kind = 'docx_cell'
    ) THEN
        RAISE EXCEPTION 'approving DOCX tables requires a current whole-batch preview' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quality_decision_docx_tables BEFORE INSERT ON thalion.quality_decision
FOR EACH ROW WHEN (NEW.outcome = 'approved' AND NEW.docx_preview_request IS NULL)
EXECUTE FUNCTION thalion.require_docx_table_preview();
