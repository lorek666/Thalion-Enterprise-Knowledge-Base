LOCK TABLE thalion.organization, thalion.processing_run, thalion.quality_decision IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE thalion.processing_run ADD UNIQUE (org_id, run_ref);
ALTER TABLE thalion.quality_restriction_item
    DROP CONSTRAINT quality_restriction_item_org_id_decision_ref_fkey,
    ADD COLUMN processing_run_ref uuid,
    ADD COLUMN review_decision_ref uuid GENERATED ALWAYS AS (
        CASE WHEN processing_run_ref IS NULL THEN decision_ref END
    ) STORED,
    ADD CHECK (processing_run_ref IS NULL OR processing_run_ref = decision_ref),
    ADD FOREIGN KEY (org_id, review_decision_ref) REFERENCES thalion.quality_decision (org_id, decision_ref),
    ADD FOREIGN KEY (org_id, processing_run_ref) REFERENCES thalion.processing_run (org_id, run_ref);

CREATE VIEW thalion.pdf_processing_restriction_material AS
SELECT run.org_id, run.run_ref, space.public_id AS space_ref, version_ref.public_id AS version_ref,
       run.configuration_revision, run.manifest_digest, run.recorded_at, run.reason, run.pdf_page_count
FROM thalion.processing_run AS run
JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
     (version.org_id, version.space_id, version.source_id, run.contract_revision)
JOIN thalion.object_identity AS space
  ON (space.org_id, space.space_id, space.object_type, space.object_id) =
     (run.org_id, run.space_id, 'space', run.space_id)
JOIN thalion.object_identity AS version_ref
  ON (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id) =
     (run.org_id, run.space_id, 'document_version', run.version_id)
WHERE run.outcome = 'quarantined' AND run.pdf_page_count IS NOT NULL AND contract.admission = 'synthetic_only';

DO $$
BEGIN
    IF EXISTS (
        SELECT run_ref FROM thalion.processing_run WHERE outcome = 'quarantined' AND pdf_page_count IS NOT NULL
        EXCEPT
        SELECT run_ref FROM thalion.pdf_processing_restriction_material
    ) THEN
        RAISE EXCEPTION 'existing PDF processing quarantine has no exact synthetic restriction scope'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

WITH pending AS (
    SELECT org_id, run_ref, row_number() OVER (PARTITION BY org_id ORDER BY recorded_at, run_ref) AS position,
           count(*) OVER (PARTITION BY org_id) AS total
    FROM thalion.pdf_processing_restriction_material
), bumped AS (
    UPDATE thalion.quality_restriction_stream AS stream SET generation = stream.generation + counts.total
    FROM (SELECT DISTINCT org_id, total FROM pending) AS counts WHERE stream.org_id = counts.org_id
    RETURNING stream.org_id, stream.generation - counts.total AS previous_generation
)
INSERT INTO thalion.quality_restriction_item (decision_ref, org_id, generation, processing_run_ref)
SELECT run_ref, org_id, previous_generation + pending.position, run_ref FROM pending JOIN bumped USING (org_id);

CREATE FUNCTION thalion.enqueue_pdf_processing_quarantine() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    next_generation bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.pdf_processing_restriction_material AS material
        WHERE (material.org_id, material.run_ref) = (NEW.org_id, NEW.run_ref)
    ) THEN
        RAISE EXCEPTION 'PDF processing quarantine requires exact synthetic version and processing scope'
            USING ERRCODE = '23514';
    END IF;
    UPDATE thalion.quality_restriction_stream SET generation = generation + 1
    WHERE org_id = NEW.org_id RETURNING generation INTO STRICT next_generation;
    INSERT INTO thalion.quality_restriction_item (decision_ref, org_id, generation, processing_run_ref)
    VALUES (NEW.run_ref, NEW.org_id, next_generation, NEW.run_ref);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER pdf_processing_quarantine_enqueue AFTER INSERT ON thalion.processing_run
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.outcome = 'quarantined' AND NEW.pdf_page_count IS NOT NULL)
EXECUTE FUNCTION thalion.enqueue_pdf_processing_quarantine();
