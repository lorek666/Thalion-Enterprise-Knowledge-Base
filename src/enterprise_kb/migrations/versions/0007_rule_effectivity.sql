ALTER TABLE thalion.source_contract_revision
    ADD COLUMN approver_id bigint,
    ADD CONSTRAINT source_contract_approver_scope FOREIGN KEY (org_id, approver_id)
        REFERENCES thalion.principal (org_id, principal_id),
    ADD CONSTRAINT source_contract_distinct_approver CHECK (approver_id <> collector_id),
    ADD CONSTRAINT source_contract_approver_identity
        UNIQUE (org_id, space_id, source_id, revision, approver_id);

ALTER TABLE thalion.document_version
    ADD CONSTRAINT document_version_scoped_identity
        UNIQUE (org_id, space_id, source_id, document_id, version_id);

CREATE TABLE thalion.rule_effectivity (
    decision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    version_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    approved_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    condition_revision smallint NOT NULL DEFAULT 1 CHECK (condition_revision = 1),
    region text CHECK (region ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    traveler_class text CHECK (traveler_class ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    valid_from date NOT NULL,
    valid_to date,
    replaces_ref uuid UNIQUE,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, source_id, document_id, decision_ref),
    FOREIGN KEY (org_id, space_id, source_id, document_id, version_id)
        REFERENCES thalion.document_version (org_id, space_id, source_id, document_id, version_id),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision, approved_by)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision, approver_id),
    FOREIGN KEY (org_id, space_id, source_id, document_id, replaces_ref)
        REFERENCES thalion.rule_effectivity (org_id, space_id, source_id, document_id, decision_ref),
    CHECK (valid_to IS NULL OR valid_from < valid_to)
);

CREATE INDEX rule_effectivity_by_document ON thalion.rule_effectivity (document_id, valid_from);

CREATE TABLE thalion.rule_use_stop (
    decision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    version_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    decided_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('suspended', 'withdrawn')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (version_id, kind),
    FOREIGN KEY (org_id, space_id, source_id, document_id, version_id)
        REFERENCES thalion.document_version (org_id, space_id, source_id, document_id, version_id),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision, decided_by)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision, approver_id)
);

CREATE TRIGGER rule_effectivity_immutable BEFORE UPDATE OR DELETE ON thalion.rule_effectivity
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER rule_use_stop_immutable BEFORE UPDATE OR DELETE ON thalion.rule_use_stop
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE VIEW thalion.rule_interval AS
SELECT decision.*, least(decision.valid_to, successor.valid_from) AS effective_to
FROM thalion.rule_effectivity AS decision
LEFT JOIN thalion.rule_effectivity AS successor ON successor.replaces_ref = decision.decision_ref;

CREATE FUNCTION thalion.check_rule_decision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'effectivity writes require read committed' USING ERRCODE = '25000';
    END IF;
    PERFORM document_id FROM thalion.document WHERE document_id = NEW.document_id FOR UPDATE;
    IF TG_TABLE_NAME = 'rule_use_stop' THEN
        RETURN NEW;
    END IF;
    IF EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = NEW.version_id) THEN
        RAISE EXCEPTION 'stopped versions cannot be approved' USING ERRCODE = '23514';
    END IF;
    IF NEW.replaces_ref IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM thalion.rule_interval AS previous
        WHERE previous.document_id = NEW.document_id AND previous.decision_ref = NEW.replaces_ref
          AND previous.region IS NOT DISTINCT FROM NEW.region
          AND previous.traveler_class IS NOT DISTINCT FROM NEW.traveler_class
          AND previous.version_id <> NEW.version_id AND previous.valid_from < NEW.valid_from
          AND NOT EXISTS (
              SELECT 1 FROM thalion.rule_effectivity AS successor
              WHERE successor.replaces_ref = NEW.replaces_ref
          )
    ) THEN
        RAISE EXCEPTION 'replacement requires an earlier unsuperseded decision in the same scope'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM thalion.rule_interval AS current
        WHERE current.document_id = NEW.document_id
          AND current.region IS NOT DISTINCT FROM NEW.region
          AND current.traveler_class IS NOT DISTINCT FROM NEW.traveler_class
          AND current.decision_ref IS DISTINCT FROM NEW.replaces_ref
          AND daterange(current.valid_from, current.effective_to, '[)')
              && daterange(NEW.valid_from, NEW.valid_to, '[)')
    ) THEN
        RAISE EXCEPTION 'overlapping decisions require an explicit replacement' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER rule_approval_invariant BEFORE INSERT ON thalion.rule_effectivity
FOR EACH ROW EXECUTE FUNCTION thalion.check_rule_decision();
CREATE TRIGGER rule_stop_serialized BEFORE INSERT ON thalion.rule_use_stop
FOR EACH ROW EXECUTE FUNCTION thalion.check_rule_decision();
