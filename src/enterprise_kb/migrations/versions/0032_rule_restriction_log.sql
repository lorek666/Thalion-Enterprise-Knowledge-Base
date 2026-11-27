ALTER TABLE thalion.rule_use_stop ADD UNIQUE (org_id, decision_ref);

CREATE TABLE thalion.rule_restriction_stream (
    org_id bigint PRIMARY KEY REFERENCES thalion.organization (org_id),
    stream_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    generation bigint NOT NULL CHECK (generation > 0)
);

CREATE TABLE thalion.rule_restriction_item (
    decision_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL REFERENCES thalion.rule_restriction_stream (org_id),
    generation bigint NOT NULL CHECK (generation > 0),
    UNIQUE (org_id, generation),
    FOREIGN KEY (org_id, decision_ref) REFERENCES thalion.rule_use_stop (org_id, decision_ref)
);

INSERT INTO thalion.rule_restriction_stream (org_id, generation)
SELECT stop.org_id, count(*)
FROM thalion.rule_use_stop AS stop
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
   = (stop.org_id, stop.space_id, stop.source_id, stop.contract_revision)
WHERE contract.admission = 'synthetic_only'
GROUP BY stop.org_id;

INSERT INTO thalion.rule_restriction_item (decision_ref, org_id, generation)
SELECT stop.decision_ref, stop.org_id,
       row_number() OVER (PARTITION BY stop.org_id ORDER BY stop.recorded_at, stop.decision_ref)
FROM thalion.rule_use_stop AS stop
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
   = (stop.org_id, stop.space_id, stop.source_id, stop.contract_revision)
WHERE contract.admission = 'synthetic_only';

CREATE TRIGGER rule_restriction_item_immutable BEFORE UPDATE OR DELETE ON thalion.rule_restriction_item
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE FUNCTION thalion.enqueue_rule_restriction() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    next_generation bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.source_contract_revision AS contract
        WHERE (contract.org_id, contract.space_id, contract.source_id, contract.revision)
            = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision)
          AND contract.admission = 'synthetic_only'
    ) THEN
        RETURN NULL;
    END IF;
    INSERT INTO thalion.rule_restriction_stream AS stream (org_id, generation)
    VALUES (NEW.org_id, 1)
    ON CONFLICT (org_id) DO UPDATE SET generation = stream.generation + 1
    RETURNING generation INTO next_generation;
    INSERT INTO thalion.rule_restriction_item (decision_ref, org_id, generation)
    VALUES (NEW.decision_ref, NEW.org_id, next_generation);
    RETURN NULL;
END;
$$;

CREATE TRIGGER rule_restriction_enqueue AFTER INSERT ON thalion.rule_use_stop
FOR EACH ROW EXECUTE FUNCTION thalion.enqueue_rule_restriction();

CREATE VIEW thalion.rule_restriction_record AS
SELECT item.org_id, item.generation, stop.decision_ref, space.public_id AS space_ref,
       version.public_id AS version_ref, actor.public_id AS approver_ref, stop.contract_revision,
       stop.kind, stop.basis_ref, stop.recorded_at
FROM thalion.rule_restriction_item AS item
JOIN thalion.rule_use_stop AS stop USING (org_id, decision_ref)
JOIN thalion.object_identity AS space
  ON (space.org_id, space.object_type, space.object_id) = (stop.org_id, 'space', stop.space_id)
JOIN thalion.object_identity AS version
  ON (version.org_id, version.space_id, version.object_type, version.object_id)
   = (stop.org_id, stop.space_id, 'document_version', stop.version_id)
JOIN thalion.object_identity AS actor
  ON (actor.org_id, actor.object_type, actor.object_id) = (stop.org_id, 'principal', stop.decided_by);

CREATE TABLE thalion.rule_log_endpoint (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    log_ref uuid NOT NULL DEFAULT gen_random_uuid()
);
INSERT INTO thalion.rule_log_endpoint DEFAULT VALUES;

CREATE TABLE thalion.rule_log_entry (
    stream_ref uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    decision_ref uuid NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    PRIMARY KEY (stream_ref, generation),
    UNIQUE (stream_ref, decision_ref)
);

CREATE TABLE thalion.rule_log_confirmation (
    decision_ref uuid NOT NULL REFERENCES thalion.rule_restriction_item (decision_ref),
    log_ref uuid NOT NULL,
    confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (decision_ref, log_ref)
);

CREATE TRIGGER rule_log_endpoint_immutable BEFORE UPDATE OR DELETE ON thalion.rule_log_endpoint
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER rule_log_entry_immutable BEFORE UPDATE OR DELETE ON thalion.rule_log_entry
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER rule_log_confirmation_immutable BEFORE UPDATE OR DELETE ON thalion.rule_log_confirmation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
