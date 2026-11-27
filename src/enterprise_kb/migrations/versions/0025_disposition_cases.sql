CREATE TABLE thalion.disposition_case (
    case_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    version_id bigint NOT NULL,
    policy_revision bigint NOT NULL,
    action text NOT NULL CHECK (action IN ('archive', 'destroy')),
    reason text NOT NULL CHECK (reason IN ('retention_expiry', 'withdrawal')),
    inventory_material bytea NOT NULL,
    inventory_snapshot bytea NOT NULL,
    submitted_by bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT disposition_case_inventory_digest CHECK (
        octet_length(inventory_material) > 0 AND sha256(inventory_material) = inventory_snapshot
    ),
    UNIQUE (org_id, space_id, case_ref, submitted_by, inventory_snapshot),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id) REFERENCES thalion.document_version (org_id, space_id, version_id),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, source_id, policy_revision)
        REFERENCES thalion.retention_policy_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, submitted_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TABLE thalion.disposition_rejection (
    case_ref uuid PRIMARY KEY,
    decision_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    inventory_snapshot bytea NOT NULL,
    submitted_by bigint NOT NULL,
    decided_by bigint NOT NULL CHECK (decided_by <> submitted_by),
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, case_ref, submitted_by, inventory_snapshot)
        REFERENCES thalion.disposition_case (org_id, space_id, case_ref, submitted_by, inventory_snapshot),
    FOREIGN KEY (org_id, decided_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE FUNCTION thalion.local_disposition_request_is_open(
    scope_org bigint, scope_space bigint, target_request uuid, actor_id bigint, target_operation text
) RETURNS boolean LANGUAGE sql SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        JOIN thalion.organization AS organization USING (org_id)
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (request.org_id, request.principal_id)
        WHERE (request.org_id, request.scope_space_id, request.request_id, request.principal_id) =
              (scope_org, scope_space, target_request, actor_id)
          AND request.destination = 'internal_lifecycle' AND request.operation = target_operation
          AND request.configuration_revision = organization.config_revision
          AND request.outcome IS NULL AND request.delegated_principal_id IS NULL
          AND actor.principal_type = 'employee' AND actor.authority_issuer = 'https://synthetic.invalid' AND NOT actor.disabled
        FOR SHARE OF request, organization, actor
    );
$$;

CREATE FUNCTION thalion.verify_local_disposition_case() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.submitted_by, 'submit_disposition_case'
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.document_version AS version
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE (version.org_id, version.space_id, version.source_id, version.version_id, source.contract_revision) =
              (NEW.org_id, NEW.space_id, NEW.source_id, NEW.version_id, NEW.contract_revision)
          AND NEW.submitted_by = source.owner_principal_id AND NEW.submitted_by = space.owner_principal_id
          AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
        FOR SHARE OF source, space
    ) THEN
        RAISE EXCEPTION 'disposition case requires current scoped synthetic ownership and matching request' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION thalion.lock_local_disposition_review(scope_org bigint, scope_space bigint, target_case uuid, actor_id bigint)
RETURNS TABLE (
    version_ref uuid, source_id bigint, contract_revision bigint, version_id bigint,
    action text, reason text, inventory_snapshot bytea, submitted_by bigint
) LANGUAGE sql SET search_path = pg_catalog, thalion AS $$
    SELECT identity.public_id, source.source_id, source.contract_revision, candidate.version_id,
           candidate.action, candidate.reason, candidate.inventory_snapshot, candidate.submitted_by
    FROM thalion.disposition_case AS candidate
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.object_identity AS identity
      ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
         (candidate.org_id, candidate.space_id, 'document_version', candidate.version_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
         (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (contract.org_id, contract.approver_id)
    WHERE (candidate.org_id, candidate.space_id, candidate.case_ref) = (scope_org, scope_space, target_case)
      AND actor.principal_id = actor_id
      AND actor.principal_id NOT IN (candidate.submitted_by, source.owner_principal_id, space.owner_principal_id)
      AND actor.principal_type = 'employee' AND actor.authority_issuer = 'https://synthetic.invalid' AND NOT actor.disabled
      AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
    FOR SHARE OF source, space, actor FOR NO KEY UPDATE OF candidate;
$$;

CREATE FUNCTION thalion.verify_local_disposition_rejection() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.decided_by, 'reject_disposition_case'
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.lock_local_disposition_review(NEW.org_id, NEW.space_id, NEW.case_ref, NEW.decided_by)
    ) THEN
        RAISE EXCEPTION 'disposition rejection requires a current independent reviewer and matching request' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER disposition_case_requires_scope BEFORE INSERT ON thalion.disposition_case
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_disposition_case();

CREATE TRIGGER disposition_rejection_requires_scope BEFORE INSERT ON thalion.disposition_rejection
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_disposition_rejection();

CREATE TRIGGER disposition_case_immutable BEFORE UPDATE OR DELETE ON thalion.disposition_case
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER disposition_rejection_immutable BEFORE UPDATE OR DELETE ON thalion.disposition_rejection
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
