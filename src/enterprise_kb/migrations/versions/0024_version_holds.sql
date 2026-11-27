CREATE TABLE thalion.version_hold_decision (
    decision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    prior_generation bigint GENERATED ALWAYS AS (nullif(generation - 1, 0)) STORED,
    action text NOT NULL CHECK (action IN ('establish', 'release')),
    decided_by bigint NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, version_id, generation),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id) REFERENCES thalion.document_version (org_id, space_id, version_id),
    FOREIGN KEY (org_id, space_id, version_id, prior_generation)
        REFERENCES thalion.version_hold_decision (org_id, space_id, version_id, generation),
    FOREIGN KEY (org_id, decided_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CHECK ((generation % 2 = 1) = (action = 'establish'))
);

CREATE VIEW thalion.current_version_hold AS
SELECT DISTINCT ON (org_id, space_id, version_id) org_id, space_id, version_id, generation, action
FROM thalion.version_hold_decision ORDER BY org_id, space_id, version_id, generation DESC;

CREATE FUNCTION thalion.lock_local_hold_target(scope_org bigint, scope_space bigint, target_version bigint, actor_id bigint)
RETURNS boolean LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM document.document_id
    FROM thalion.document_version AS version
    JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
         (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (contract.org_id, contract.approver_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (scope_org, scope_space, target_version)
      AND actor.principal_id = actor_id AND actor.principal_id NOT IN (source.owner_principal_id, space.owner_principal_id)
      AND actor.principal_type = 'employee' AND actor.authority_issuer = 'https://synthetic.invalid' AND NOT actor.disabled
      AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
    FOR SHARE OF source, space, actor FOR UPDATE OF document;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION thalion.verify_local_hold_decision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        WHERE (request.org_id, request.scope_space_id, request.request_id, request.principal_id) =
              (NEW.org_id, NEW.space_id, NEW.request_id, NEW.decided_by)
          AND request.operation = 'decide_hold' AND request.destination = 'internal_lifecycle'
          AND request.outcome IS NULL AND request.delegated_principal_id IS NULL
    ) OR NOT thalion.lock_local_hold_target(NEW.org_id, NEW.space_id, NEW.version_id, NEW.decided_by) THEN
        RAISE EXCEPTION 'active local custodian and matching hold request required' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER version_hold_requires_scope BEFORE INSERT ON thalion.version_hold_decision
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_hold_decision();

CREATE TRIGGER version_hold_decision_immutable BEFORE UPDATE OR DELETE ON thalion.version_hold_decision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

ALTER TABLE thalion.wiki_availability_event DROP CONSTRAINT wiki_availability_event_reason_check,
    ADD CONSTRAINT wiki_availability_event_reason_check CHECK (reason IN (
        'suspended', 'withdrawn', 'quarantined', 'reprocessed', 'policy_changed', 'rule_replaced', 'custody_hold'
    ));

CREATE FUNCTION thalion.stop_held_wiki_publication() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    INSERT INTO thalion.wiki_availability_event (org_id, space_id, publication_ref, reason, cause_ref)
    SELECT DISTINCT input.org_id, input.space_id, input.publication_ref, 'custody_hold', NEW.decision_ref
    FROM thalion.wiki_published_input AS input
    WHERE (input.org_id, input.space_id, input.version_id) = (NEW.org_id, NEW.space_id, NEW.version_id)
    ON CONFLICT (publication_ref, reason, cause_ref) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE TRIGGER wiki_dependency_hold AFTER INSERT ON thalion.version_hold_decision
FOR EACH ROW WHEN (NEW.action = 'establish') EXECUTE FUNCTION thalion.stop_held_wiki_publication();
