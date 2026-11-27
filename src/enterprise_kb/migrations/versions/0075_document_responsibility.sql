CREATE TABLE thalion.responsibility_assignment (
    assignment_ref uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    responsible_id bigint,
    approved_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    PRIMARY KEY (org_id, space_id, source_id, document_id, generation),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, source_id, document_id)
        REFERENCES thalion.document (org_id, space_id, source_id, document_id),
    FOREIGN KEY (org_id, responsible_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, approved_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CONSTRAINT responsibility_expiry CHECK (expires_at IS NULL OR (responsible_id IS NOT NULL AND expires_at > recorded_at))
);

CREATE FUNCTION thalion.guard_document_responsibility() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM 1 FROM thalion.document AS document
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.organization AS organization USING (org_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS owner
      ON (owner.org_id, owner.principal_id) = (source.org_id, source.owner_principal_id)
    JOIN thalion.request_record AS request
      ON (request.org_id, request.scope_space_id, request.request_id) = (document.org_id, document.space_id, NEW.request_id)
    WHERE (document.org_id, document.space_id, document.source_id, document.document_id)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
      AND source.lifecycle = 'active' AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
      AND owner.principal_id = NEW.approved_by AND owner.principal_type = 'employee'
      AND owner.authority_issuer = 'https://synthetic.invalid' AND NOT owner.disabled
      AND request.principal_id = NEW.approved_by AND request.delegated_principal_id IS NULL AND request.outcome IS NULL
      AND request.configuration_revision = organization.config_revision
      AND request.operation = 'set_document_responsibility' AND request.destination = 'internal_sources'
    FOR SHARE OF source, space, organization, owner, request
    FOR UPDATE OF document;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'an open request from the current source owner is required' USING ERRCODE = '23514';
    END IF;
    IF NEW.responsible_id IS NOT NULL THEN
        PERFORM 1 FROM thalion.principal
        WHERE (org_id, principal_id) = (NEW.org_id, NEW.responsible_id)
          AND principal_type = 'employee' AND authority_issuer = 'https://synthetic.invalid' AND NOT disabled
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'responsibility requires an active employee of this organization' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.generation <> 1 + COALESCE((
        SELECT max(generation) FROM thalion.responsibility_assignment
        WHERE (org_id, space_id, source_id, document_id) = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
    ), 0) THEN
        RAISE EXCEPTION 'responsibility generation must follow the current decision' USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER responsibility_assignment_scoped BEFORE INSERT ON thalion.responsibility_assignment
FOR EACH ROW EXECUTE FUNCTION thalion.guard_document_responsibility();
CREATE TRIGGER responsibility_assignment_immutable BEFORE UPDATE OR DELETE ON thalion.responsibility_assignment
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER responsibility_assignment_no_truncate BEFORE TRUNCATE ON thalion.responsibility_assignment
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
