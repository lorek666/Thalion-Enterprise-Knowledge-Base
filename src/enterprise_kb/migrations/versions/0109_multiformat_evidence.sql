ALTER TABLE thalion.asset DROP CONSTRAINT asset_media_type_check,
    ADD CHECK (media_type IN (
        'text/markdown',
        'text/csv',
        'application/pdf',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/html',
        'image/png',
        'image/jpeg'
    ));

INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
SELECT greatest(max(configuration_revision), 100) + 1, '1', 'xlsx_sheet_rows_v1', 1
FROM thalion.processing_config_revision;

INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
SELECT greatest(max(configuration_revision), 100) + 1, '1', 'pptx_slides_v1', 1
FROM thalion.processing_config_revision;

INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
SELECT greatest(max(configuration_revision), 100) + 1, '1', 'html_blocks_v1', 1
FROM thalion.processing_config_revision;

INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
SELECT greatest(max(configuration_revision), 100) + 1, '1', 'image_ocr_v1', 1
FROM thalion.processing_config_revision;

ALTER TABLE thalion.passage
    ADD COLUMN structured_locator text CHECK (
        structured_locator IS NULL OR char_length(btrim(structured_locator)) BETWEEN 1 AND 256
    ),
    DROP CONSTRAINT passage_locator_shape,
    ADD CONSTRAINT passage_locator_shape CHECK (
        (kind IN ('paragraph', 'table', 'blockquote', 'list', 'code')
            AND heading_path IS NOT NULL AND paragraph IS NOT NULL AND byte_start IS NOT NULL AND byte_end IS NOT NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL AND docx_paragraph IS NULL
            AND structured_locator IS NULL)
        OR
        (kind = 'csv_cell' AND csv_record IS NOT NULL AND csv_column IS NOT NULL AND pdf_page IS NULL
            AND heading_path IS NULL AND paragraph IS NULL AND byte_start IS NULL AND byte_end IS NULL
            AND docx_paragraph IS NULL AND structured_locator IS NULL)
        OR
        (kind = 'pdf_page' AND pdf_page IS NOT NULL AND csv_record IS NULL AND csv_column IS NULL
            AND heading_path IS NULL AND paragraph IS NULL AND byte_start IS NULL AND byte_end IS NULL
            AND docx_paragraph IS NULL AND structured_locator IS NULL)
        OR
        (kind = 'docx_paragraph' AND docx_paragraph IS NOT NULL AND heading_path IS NOT NULL
            AND paragraph BETWEEN 1 AND docx_paragraph AND paragraph IS NOT NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL AND byte_start IS NULL AND byte_end IS NULL
            AND structured_locator IS NULL)
        OR
        (kind = 'docx_cell' AND heading_path IS NOT NULL AND paragraph IS NULL AND docx_paragraph IS NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL AND byte_start IS NULL AND byte_end IS NULL
            AND structured_locator IS NULL)
        OR
        (kind IN ('xlsx_row', 'pptx_slide', 'html_block', 'image_ocr')
            AND structured_locator IS NOT NULL AND heading_path IS NOT NULL AND paragraph IS NOT NULL
            AND csv_record IS NULL AND csv_column IS NULL AND pdf_page IS NULL AND docx_paragraph IS NULL
            AND byte_start IS NULL AND byte_end IS NULL)
    );

CREATE UNIQUE INDEX passage_structured_location
    ON thalion.passage (version_id, locator_revision, kind, structured_locator)
    WHERE kind IN ('xlsx_row', 'pptx_slide', 'html_block', 'image_ocr');

ALTER TABLE thalion.passage_excerpt
    ADD COLUMN extracted_text text CHECK (
        extracted_text IS NULL OR (
            octet_length(extracted_text) BETWEEN 1 AND 65536
            AND sha256(convert_to(extracted_text, 'UTF8')) = content_digest
        )
    );

CREATE OR REPLACE FUNCTION thalion.verify_evidence_format() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    actual_media_type text;
    expected_media_type text;
    docx_media_type constant text := 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    xlsx_media_type constant text := 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    pptx_media_type constant text := 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
BEGIN
    SELECT asset.media_type INTO STRICT actual_media_type
    FROM thalion.document_version AS version
    JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id);
    IF TG_TABLE_NAME = 'passage' THEN
        IF NEW.kind = 'image_ocr' THEN
            IF actual_media_type NOT IN ('image/png', 'image/jpeg') THEN
                RAISE EXCEPTION 'the evidence format does not match the original asset' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;
        expected_media_type := CASE
            WHEN NEW.kind IN ('docx_paragraph', 'docx_cell') THEN docx_media_type
            WHEN NEW.kind = 'csv_cell' THEN 'text/csv'
            WHEN NEW.kind = 'pdf_page' THEN 'application/pdf'
            WHEN NEW.kind = 'xlsx_row' THEN xlsx_media_type
            WHEN NEW.kind = 'pptx_slide' THEN pptx_media_type
            WHEN NEW.kind = 'html_block' THEN 'text/html'
            ELSE 'text/markdown' END;
    ELSE
        SELECT CASE profile
            WHEN 'utf8_csv_literal_v1' THEN 'text/csv'
            WHEN 'pdf_pages_v1' THEN 'application/pdf'
            WHEN 'docx_literal_paragraphs_v1' THEN docx_media_type
            WHEN 'xlsx_sheet_rows_v1' THEN xlsx_media_type
            WHEN 'pptx_slides_v1' THEN pptx_media_type
            WHEN 'html_blocks_v1' THEN 'text/html'
            WHEN 'image_ocr_v1' THEN 'image/*'
            ELSE 'text/markdown' END INTO STRICT expected_media_type
        FROM thalion.processing_config_revision WHERE configuration_revision = NEW.configuration_revision;
        IF (NEW.pdf_page_count IS NOT NULL) IS DISTINCT FROM (expected_media_type = 'application/pdf') THEN
            RAISE EXCEPTION 'PDF processing runs require a bounded page count' USING ERRCODE = '23514';
        END IF;
        IF expected_media_type = 'image/*' THEN
            IF actual_media_type NOT IN ('image/png', 'image/jpeg') THEN
                RAISE EXCEPTION 'the evidence format does not match the original asset' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;
    END IF;
    IF actual_media_type IS DISTINCT FROM expected_media_type THEN
        RAISE EXCEPTION 'the evidence format does not match the original asset' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
