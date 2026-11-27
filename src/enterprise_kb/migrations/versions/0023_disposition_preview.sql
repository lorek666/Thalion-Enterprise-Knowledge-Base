CREATE TABLE thalion.retention_policy_revision (
    policy_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    previous_revision bigint GENERATED ALWAYS AS (nullif(revision - 1, 0)) STORED,
    decided_by bigint NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    keep_days integer NOT NULL CHECK (keep_days BETWEEN 0 AND 36500),
    action text NOT NULL CHECK (action IN ('retain_only', 'archive', 'destroy')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, source_id, revision),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, source_id, previous_revision)
        REFERENCES thalion.retention_policy_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, decided_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE FUNCTION thalion.verify_local_retention_policy() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.source AS source
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.request_record AS request ON (request.org_id, request.scope_space_id) = (space.org_id, space.space_id)
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (request.org_id, request.principal_id)
        WHERE (source.org_id, source.space_id, source.source_id, source.contract_revision) =
              (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision)
          AND source.owner_principal_id = NEW.decided_by AND space.owner_principal_id = NEW.decided_by
          AND source.lifecycle = 'active' AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
          AND (request.request_id, request.principal_id, request.operation, request.destination) =
              (NEW.request_id, NEW.decided_by, 'register_retention_policy', 'internal_lifecycle')
          AND request.outcome IS NULL AND request.delegated_principal_id IS NULL
          AND actor.principal_type = 'employee' AND actor.authority_issuer = 'https://synthetic.invalid' AND NOT actor.disabled
    ) THEN
        RAISE EXCEPTION 'retention policy requires current scoped synthetic ownership' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER retention_policy_requires_scope BEFORE INSERT ON thalion.retention_policy_revision
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_retention_policy();

CREATE TRIGGER retention_policy_immutable BEFORE UPDATE OR DELETE ON thalion.retention_policy_revision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE INDEX wiki_revision_by_manifest ON thalion.wiki_revision (org_id, space_id, manifest_ref);

CREATE VIEW thalion.lifecycle_version_manifest AS
SELECT DISTINCT version.org_id, version.space_id, version.version_id, entry.manifest_ref
FROM thalion.document_version AS version
JOIN thalion.passage AS part USING (org_id, space_id, version_id)
JOIN thalion.object_identity AS location
  ON (location.org_id, location.space_id, location.object_type, location.object_id) =
     (part.org_id, part.space_id, 'passage', part.passage_id)
JOIN thalion.passage_excerpt AS excerpt
  ON (excerpt.org_id, excerpt.space_id, excerpt.version_id, excerpt.passage_id) =
     (part.org_id, part.space_id, part.version_id, part.passage_id)
JOIN thalion.input_manifest_entry AS entry
  ON (entry.org_id, entry.space_id, entry.source_id, entry.passage_ref, entry.excerpt_revision) =
     (version.org_id, version.space_id, version.source_id, location.public_id, excerpt.excerpt_revision);
