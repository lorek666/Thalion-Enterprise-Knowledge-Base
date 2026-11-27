ALTER TABLE thalion.asset DROP CONSTRAINT asset_media_type_check,
    ADD CHECK (media_type IN (
        'text/markdown', 'text/csv', 'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ));

INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
SELECT greatest(max(configuration_revision), 100) + 1, '1', 'docx_literal_paragraphs_v1', 1
FROM thalion.processing_config_revision;

ALTER TABLE thalion.passage
    ADD COLUMN docx_paragraph integer CHECK (docx_paragraph BETWEEN 1 AND 2048),
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
    );

CREATE UNIQUE INDEX passage_docx_location
    ON thalion.passage (version_id, locator_revision, docx_paragraph) WHERE kind = 'docx_paragraph';

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
        expected_media_type := CASE NEW.kind WHEN 'csv_cell' THEN 'text/csv' WHEN 'pdf_page' THEN 'application/pdf'
                               WHEN 'docx_paragraph' THEN docx_media_type ELSE 'text/markdown' END;
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
