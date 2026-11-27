ALTER TABLE thalion.asset DROP CONSTRAINT asset_media_type_check,
    ADD CHECK (media_type IN ('text/markdown', 'text/csv', 'application/pdf'));

INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
SELECT greatest(max(configuration_revision), 100) + 1, 'pdfium2:5.15.2;tesseract:5.5.3', 'pdf_pages_v1', 1
FROM thalion.processing_config_revision;

ALTER TABLE thalion.processing_run ADD COLUMN pdf_page_count integer CHECK (pdf_page_count BETWEEN 0 AND 16);
ALTER TABLE thalion.passage
    ADD COLUMN pdf_page integer CHECK (pdf_page BETWEEN 1 AND 16),
    DROP CONSTRAINT passage_locator_shape,
    ADD CONSTRAINT passage_locator_shape CHECK (
        (kind IN ('paragraph', 'table', 'blockquote', 'list', 'code')
            AND heading_path IS NOT NULL AND paragraph IS NOT NULL AND byte_start IS NOT NULL AND byte_end IS NOT NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL)
        OR
        (kind = 'csv_cell' AND csv_record IS NOT NULL AND csv_column IS NOT NULL AND pdf_page IS NULL
            AND heading_path IS NULL AND paragraph IS NULL AND byte_start IS NULL AND byte_end IS NULL)
        OR
        (kind = 'pdf_page' AND pdf_page IS NOT NULL AND csv_record IS NULL AND csv_column IS NULL
            AND heading_path IS NULL AND paragraph IS NULL AND byte_start IS NULL AND byte_end IS NULL)
    );

CREATE UNIQUE INDEX passage_pdf_location
    ON thalion.passage (version_id, locator_revision, pdf_page) WHERE kind = 'pdf_page';

CREATE OR REPLACE FUNCTION thalion.verify_evidence_format() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    actual_media_type text;
    expected_media_type text;
BEGIN
    SELECT asset.media_type INTO STRICT actual_media_type
    FROM thalion.document_version AS version
    JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id);
    IF TG_TABLE_NAME = 'passage' THEN
        expected_media_type := CASE NEW.kind WHEN 'csv_cell' THEN 'text/csv' WHEN 'pdf_page' THEN 'application/pdf'
                               ELSE 'text/markdown' END;
    ELSE
        SELECT CASE profile WHEN 'utf8_csv_literal_v1' THEN 'text/csv' WHEN 'pdf_pages_v1' THEN 'application/pdf'
               ELSE 'text/markdown' END INTO STRICT expected_media_type
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

CREATE TABLE thalion.pdf_page_observation (
    run_ref uuid NOT NULL REFERENCES thalion.processing_run (run_ref),
    page_number integer NOT NULL CHECK (page_number BETWEEN 1 AND 16),
    method text NOT NULL CHECK (method IN ('text_layer', 'ocr')),
    transcript bytea CHECK (octet_length(transcript) BETWEEN 1 AND 32768),
    reason text CHECK (reason IN ('empty', 'low_confidence', 'size_limit', 'unsupported_structure')),
    ocr_profile_digest bytea CHECK (octet_length(ocr_profile_digest) = 32),
    PRIMARY KEY (run_ref, page_number),
    CHECK ((transcript IS NULL) = (reason IS NOT NULL)),
    CHECK (CASE WHEN method = 'text_layer' THEN ocr_profile_digest IS NULL
                ELSE ocr_profile_digest IS NOT NULL OR reason IS NOT DISTINCT FROM 'size_limit' END)
);

CREATE FUNCTION thalion.require_open_pdf_observation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM job.job_id FROM thalion.processing_run AS run
    JOIN thalion.job AS job USING (org_id, job_id, generation)
    WHERE run.run_ref = NEW.run_ref AND NEW.page_number <= run.pdf_page_count AND job.state = 'running'
    FOR UPDATE OF job;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the PDF processing manifest is not open for this page' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION thalion.verify_sealed_pdf_run() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    admitted_locator integer;
BEGIN
    SELECT locator_revision INTO STRICT admitted_locator FROM thalion.processing_config_revision
    WHERE configuration_revision = NEW.configuration_revision;
    IF NEW.pdf_page_count <> (SELECT count(*) FROM thalion.pdf_page_observation WHERE run_ref = NEW.run_ref)
        OR NEW.passage_count <> (
            SELECT count(*) FROM thalion.pdf_page_observation WHERE run_ref = NEW.run_ref AND transcript IS NOT NULL
        )
        OR EXISTS (
            SELECT 1 FROM thalion.passage_excerpt AS excerpt
            JOIN thalion.passage AS passage USING (org_id, space_id, version_id, passage_id)
            LEFT JOIN thalion.pdf_page_observation AS page ON (page.run_ref, page.page_number) =
                (excerpt.run_ref, passage.pdf_page)
            WHERE excerpt.run_ref = NEW.run_ref
              AND (passage.kind <> 'pdf_page' OR passage.locator_revision <> admitted_locator
                   OR sha256(page.transcript) IS DISTINCT FROM excerpt.content_digest)
        ) THEN
        RAISE EXCEPTION 'PDF pages and exact excerpts must commit with the processing manifest' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER pdf_page_observation_open_run BEFORE INSERT ON thalion.pdf_page_observation
FOR EACH ROW EXECUTE FUNCTION thalion.require_open_pdf_observation();
CREATE TRIGGER pdf_page_observation_immutable BEFORE UPDATE OR DELETE ON thalion.pdf_page_observation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER pdf_page_observation_no_truncate BEFORE TRUNCATE ON thalion.pdf_page_observation
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE CONSTRAINT TRIGGER pdf_run_sealed AFTER INSERT ON thalion.processing_run
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.pdf_page_count IS NOT NULL)
EXECUTE FUNCTION thalion.verify_sealed_pdf_run();
