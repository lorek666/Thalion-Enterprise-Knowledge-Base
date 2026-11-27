LOCK TABLE thalion.organization, thalion.quality_decision IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE thalion.quality_decision ADD UNIQUE (org_id, decision_ref);

CREATE TABLE thalion.quality_restriction_stream (
    org_id bigint PRIMARY KEY REFERENCES thalion.organization (org_id),
    stream_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0)
);

CREATE TABLE thalion.quality_restriction_item (
    decision_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL REFERENCES thalion.quality_restriction_stream (org_id),
    generation bigint NOT NULL CHECK (generation > 1),
    UNIQUE (org_id, generation),
    FOREIGN KEY (org_id, decision_ref) REFERENCES thalion.quality_decision (org_id, decision_ref)
);

CREATE VIEW thalion.quality_restriction_material AS
SELECT decision.org_id, decision.decision_ref, space.public_id AS space_ref, version_ref.public_id AS version_ref,
       reviewer.public_id AS reviewer_ref, run.run_ref, run.configuration_revision, run.manifest_digest,
       decision.basis_ref, decision.recorded_at
FROM thalion.quality_decision AS decision
JOIN thalion.processing_run AS run USING (org_id, space_id, version_id, run_ref)
JOIN thalion.document_version AS version USING (org_id, space_id, version_id)
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
     (version.org_id, version.space_id, version.source_id, run.contract_revision)
JOIN thalion.object_identity AS space
  ON (space.org_id, space.space_id, space.object_type, space.object_id) =
     (decision.org_id, decision.space_id, 'space', decision.space_id)
JOIN thalion.object_identity AS version_ref
  ON (version_ref.org_id, version_ref.space_id, version_ref.object_type, version_ref.object_id) =
     (decision.org_id, decision.space_id, 'document_version', decision.version_id)
JOIN thalion.object_identity AS reviewer
  ON (reviewer.org_id, reviewer.object_type, reviewer.object_id) =
     (decision.org_id, 'principal', decision.reviewer_id)
WHERE decision.outcome = 'quarantined' AND contract.admission = 'synthetic_only';

DO $$
BEGIN
    IF EXISTS (
        SELECT decision_ref FROM thalion.quality_decision WHERE outcome = 'quarantined'
        EXCEPT
        SELECT decision_ref FROM thalion.quality_restriction_material
    ) THEN
        RAISE EXCEPTION 'existing quality quarantine has no exact synthetic restriction scope'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

INSERT INTO thalion.quality_restriction_stream (org_id, generation)
SELECT org.org_id, count(material.decision_ref) + 1
FROM thalion.organization AS org
LEFT JOIN thalion.quality_restriction_material AS material USING (org_id)
GROUP BY org.org_id;

INSERT INTO thalion.quality_restriction_item (decision_ref, org_id, generation)
SELECT decision_ref, org_id, 1 + row_number() OVER (PARTITION BY org_id ORDER BY recorded_at, decision_ref)
FROM thalion.quality_restriction_material;

CREATE FUNCTION thalion.initialize_quality_restrictions() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    INSERT INTO thalion.quality_restriction_stream (org_id) VALUES (NEW.org_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER quality_restriction_initialize AFTER INSERT ON thalion.organization
FOR EACH ROW EXECUTE FUNCTION thalion.initialize_quality_restrictions();

CREATE FUNCTION thalion.enqueue_quality_restriction() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    next_generation bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.quality_restriction_material AS material
        WHERE (material.org_id, material.decision_ref) = (NEW.org_id, NEW.decision_ref)
    ) THEN
        RAISE EXCEPTION 'quality quarantine requires exact synthetic version and reviewer identities'
            USING ERRCODE = '23514';
    END IF;
    UPDATE thalion.quality_restriction_stream SET generation = generation + 1
    WHERE org_id = NEW.org_id RETURNING generation INTO STRICT next_generation;
    INSERT INTO thalion.quality_restriction_item (decision_ref, org_id, generation)
    VALUES (NEW.decision_ref, NEW.org_id, next_generation);
    RETURN NULL;
END;
$$;

CREATE TRIGGER quality_restriction_enqueue AFTER INSERT ON thalion.quality_decision
FOR EACH ROW WHEN (NEW.outcome = 'quarantined') EXECUTE FUNCTION thalion.enqueue_quality_restriction();

CREATE TRIGGER quality_restriction_item_immutable BEFORE UPDATE OR DELETE ON thalion.quality_restriction_item
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

ALTER TABLE thalion.archive_rebuild_rule_check
    ADD COLUMN quality_stream_ref uuid,
    ADD COLUMN quality_generation bigint CHECK (quality_generation > 0),
    ADD CHECK ((quality_stream_ref IS NULL) = (quality_generation IS NULL));
