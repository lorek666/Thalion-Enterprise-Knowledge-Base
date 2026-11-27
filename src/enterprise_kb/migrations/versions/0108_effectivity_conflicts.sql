ALTER TABLE thalion.rule_use_stop
    ADD COLUMN reason text CHECK (reason IS NULL OR length(btrim(reason)) BETWEEN 1 AND 500);

CREATE TABLE thalion.rule_effectivity_conflict (
    conflict_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    candidate_version_id bigint NOT NULL,
    existing_decision_ref uuid NOT NULL,
    contract_revision bigint NOT NULL,
    reported_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    candidate_region text CHECK (candidate_region ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    candidate_traveler_class text CHECK (candidate_traveler_class ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    candidate_valid_from date NOT NULL,
    candidate_valid_to date,
    summary text NOT NULL CHECK (length(btrim(summary)) BETWEEN 1 AND 500),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, source_id, document_id, conflict_ref),
    FOREIGN KEY (org_id, space_id, source_id, document_id, candidate_version_id)
        REFERENCES thalion.document_version (org_id, space_id, source_id, document_id, version_id),
    FOREIGN KEY (org_id, space_id, source_id, document_id, existing_decision_ref)
        REFERENCES thalion.rule_effectivity (org_id, space_id, source_id, document_id, decision_ref),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision, reported_by)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision, approver_id),
    CHECK (candidate_valid_to IS NULL OR candidate_valid_from < candidate_valid_to)
);

CREATE INDEX rule_effectivity_conflict_by_document
    ON thalion.rule_effectivity_conflict (org_id, space_id, document_id, recorded_at DESC);

CREATE TABLE thalion.rule_effectivity_conflict_resolution (
    resolution_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conflict_ref uuid NOT NULL UNIQUE,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    decided_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('prefer_new_replace', 'keep_existing', 'narrow_scope', 'withdraw_candidate')),
    conclusion text NOT NULL CHECK (length(btrim(conclusion)) BETWEEN 1 AND 1000),
    linked_decision_ref uuid,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, source_id, document_id, conflict_ref)
        REFERENCES thalion.rule_effectivity_conflict (org_id, space_id, source_id, document_id, conflict_ref),
    FOREIGN KEY (org_id, decided_by) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE TRIGGER rule_effectivity_conflict_immutable
BEFORE UPDATE OR DELETE ON thalion.rule_effectivity_conflict
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER rule_effectivity_conflict_resolution_immutable
BEFORE UPDATE OR DELETE ON thalion.rule_effectivity_conflict_resolution
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE FUNCTION thalion.check_rule_effectivity_conflict() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'effectivity conflict writes require read committed' USING ERRCODE = '25000';
    END IF;
    PERFORM document_id FROM thalion.document
    WHERE (org_id, space_id, source_id, document_id) = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
    FOR UPDATE;
    IF EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = NEW.candidate_version_id)
       OR thalion.document_source_deleted(NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id) THEN
        RAISE EXCEPTION 'stopped or deleted candidate version cannot register an effectivity conflict'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM thalion.rule_interval AS existing
        WHERE (existing.org_id, existing.space_id, existing.source_id, existing.document_id, existing.decision_ref)
            = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id, NEW.existing_decision_ref)
          AND (existing.region IS NULL OR NEW.candidate_region IS NULL OR existing.region = NEW.candidate_region)
          AND (
              existing.traveler_class IS NULL OR NEW.candidate_traveler_class IS NULL
              OR existing.traveler_class = NEW.candidate_traveler_class
          )
          AND daterange(existing.valid_from, existing.effective_to, '[)')
              && daterange(NEW.candidate_valid_from, NEW.candidate_valid_to, '[)')
    ) THEN
        RAISE EXCEPTION 'effectivity conflict requires an actually overlapping existing decision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER rule_effectivity_conflict_invariant
BEFORE INSERT ON thalion.rule_effectivity_conflict
FOR EACH ROW EXECUTE FUNCTION thalion.check_rule_effectivity_conflict();

CREATE FUNCTION thalion.check_rule_effectivity_conflict_resolution() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    is_approver boolean;
    is_responsible boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'effectivity conflict resolutions require read committed' USING ERRCODE = '25000';
    END IF;
    PERFORM document_id FROM thalion.document
    WHERE (org_id, space_id, source_id, document_id) = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
    FOR UPDATE;
    SELECT EXISTS (
        SELECT 1 FROM thalion.source_contract_revision AS contract
        WHERE (contract.org_id, contract.space_id, contract.source_id, contract.revision, contract.approver_id)
            = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision, NEW.decided_by)
    ) INTO is_approver;
    SELECT EXISTS (
        SELECT 1 FROM (
            SELECT responsible_id, expires_at
            FROM thalion.responsibility_assignment
            WHERE (org_id, space_id, source_id, document_id)
                = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
            ORDER BY generation DESC LIMIT 1
        ) AS latest
        WHERE latest.responsible_id = NEW.decided_by
          AND (latest.expires_at IS NULL OR latest.expires_at > clock_timestamp())
    ) INTO is_responsible;
    IF NOT (is_approver OR is_responsible) THEN
        RAISE EXCEPTION 'only the current policy owner or approver may resolve an effectivity conflict'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.linked_decision_ref IS NOT NULL AND NOT (
        EXISTS (
            SELECT 1 FROM thalion.rule_effectivity AS dec
            WHERE (dec.org_id, dec.space_id, dec.source_id, dec.document_id, dec.decision_ref)
                = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id, NEW.linked_decision_ref)
        ) OR EXISTS (
            SELECT 1 FROM thalion.rule_use_stop AS stp
            WHERE (stp.org_id, stp.space_id, stp.source_id, stp.document_id, stp.decision_ref)
                = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id, NEW.linked_decision_ref)
        )
    ) THEN
        RAISE EXCEPTION 'linked resolution decision must belong to the same document'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER rule_effectivity_conflict_resolution_invariant
BEFORE INSERT ON thalion.rule_effectivity_conflict_resolution
FOR EACH ROW EXECUTE FUNCTION thalion.check_rule_effectivity_conflict_resolution();
