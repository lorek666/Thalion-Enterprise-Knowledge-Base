CREATE TABLE thalion.synthetic_export_request (
    export_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    version_id bigint NOT NULL,
    requester_id bigint NOT NULL,
    snapshot bigint[] NOT NULL CHECK (cardinality(snapshot) = 6),
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, export_ref, requester_id),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, version_id) REFERENCES thalion.document_version (org_id, space_id, version_id),
    FOREIGN KEY (org_id, requester_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TABLE thalion.synthetic_export_approval (
    approval_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    export_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    requester_id bigint NOT NULL,
    approver_id bigint NOT NULL CHECK (approver_id <> requester_id),
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (recorded_at < expires_at AND expires_at <= recorded_at + interval '15 minutes'),
    UNIQUE (org_id, request_id),
    UNIQUE (org_id, space_id, export_ref, requester_id, approval_ref),
    FOREIGN KEY (org_id, space_id, export_ref, requester_id)
        REFERENCES thalion.synthetic_export_request (org_id, space_id, export_ref, requester_id),
    FOREIGN KEY (org_id, approver_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TABLE thalion.synthetic_export_package (
    package_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    export_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    requester_id bigint NOT NULL,
    approval_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    archive_bytes bytea NOT NULL CHECK (octet_length(archive_bytes) BETWEEN 1 AND 16781312),
    archive_digest bytea GENERATED ALWAYS AS (sha256(archive_bytes)) STORED,
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    authority_valid_until timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (recorded_at < authority_valid_until),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, export_ref, requester_id, approval_ref)
        REFERENCES thalion.synthetic_export_approval (org_id, space_id, export_ref, requester_id, approval_ref),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE INDEX synthetic_export_request_version ON thalion.synthetic_export_request (org_id, space_id, version_id);

CREATE VIEW thalion.synthetic_export_target AS
SELECT version.org_id, version.space_id, version.version_id, source.source_id, identity.public_id AS version_ref,
       source.owner_principal_id AS owner_id, space.owner_principal_id AS space_owner_id, contract.approver_id,
       ARRAY[organization.safety_epoch, space.safety_epoch, source.safety_epoch, source.contract_revision, organization.config_revision,
             coalesce(hold.generation, 0)] AS snapshot,
       asset.storage_key, asset.content_digest, asset.byte_length,
       coalesce(hold.action = 'establish', false) OR EXISTS (
           SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = version.version_id
       ) AS blocked
FROM thalion.document_version AS version
JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
JOIN thalion.source AS source USING (org_id, space_id, source_id)
JOIN thalion.organization AS organization USING (org_id)
JOIN thalion.space AS space USING (org_id, space_id)
JOIN thalion.source_contract_revision AS contract
  ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
     (source.org_id, source.space_id, source.source_id, source.contract_revision)
JOIN thalion.object_identity AS identity
  ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
     (version.org_id, version.space_id, 'document_version', version.version_id)
LEFT JOIN thalion.current_version_hold AS hold
  ON (hold.org_id, hold.space_id, hold.version_id) = (version.org_id, version.space_id, version.version_id)
WHERE source.lifecycle = 'active' AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
  AND asset.storage_kind = 'synthetic_file';

CREATE FUNCTION thalion.lock_synthetic_export_target(scope_org bigint, scope_space bigint, target_version bigint)
RETURNS void LANGUAGE sql SET search_path = pg_catalog, thalion AS $$
    SELECT FROM thalion.document_version AS version
    JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (scope_org, scope_space, target_version)
    FOR SHARE OF source, document;
$$;

CREATE FUNCTION thalion.guard_synthetic_export() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    candidate record;
    target record;
    recipient bigint := NEW.requester_id;
    result_actor bigint := NEW.requester_id;
    operation_name text := 'request_original_export';
BEGIN
    IF TG_TABLE_NAME = 'synthetic_export_request' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO STRICT candidate FROM thalion.synthetic_export_request AS request
        WHERE (request.org_id, request.space_id, request.export_ref, request.requester_id) =
              (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
        IF TG_TABLE_NAME = 'synthetic_export_approval' THEN
            result_actor := NEW.approver_id;
            operation_name := 'approve_original_export';
        ELSE
            operation_name := 'export_original_archive';
        END IF;
    END IF;
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, result_actor, operation_name
    ) THEN
        RAISE EXCEPTION 'original archive requires a matching open request' USING ERRCODE = '23514';
    END IF;
    PERFORM thalion.lock_synthetic_export_target(NEW.org_id, NEW.space_id, candidate.version_id);
    SELECT * INTO target FROM thalion.synthetic_export_target
    WHERE (org_id, space_id, version_id) = (NEW.org_id, NEW.space_id, candidate.version_id);
    IF NOT FOUND OR target.blocked OR target.snapshot <> candidate.snapshot
        OR target.owner_id <> recipient OR target.space_owner_id <> recipient
        OR (operation_name = 'approve_original_export' AND target.approver_id IS DISTINCT FROM result_actor)
    THEN
        RAISE EXCEPTION 'original archive requires a current scoped version and independent authorization' USING ERRCODE = '23514';
    END IF;
    IF operation_name = 'export_original_archive' THEN
        IF NOT EXISTS (
            SELECT 1 FROM thalion.synthetic_export_approval AS approval
            JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (approval.org_id, approval.approver_id)
            WHERE approval.approval_ref = NEW.approval_ref AND approval.approver_id = target.approver_id
              AND NOT actor.disabled AND actor.principal_type = 'employee' AND actor.authority_issuer = 'https://synthetic.invalid'
              AND clock_timestamp() < least(approval.expires_at, NEW.authority_valid_until)
            FOR SHARE OF actor
        ) THEN
            RAISE EXCEPTION 'archive sealing requires live independent approval and authority' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_export_request_scope BEFORE INSERT ON thalion.synthetic_export_request
FOR EACH ROW EXECUTE FUNCTION thalion.guard_synthetic_export();
CREATE TRIGGER synthetic_export_approval_scope BEFORE INSERT ON thalion.synthetic_export_approval
FOR EACH ROW EXECUTE FUNCTION thalion.guard_synthetic_export();
CREATE TRIGGER synthetic_export_package_scope BEFORE INSERT ON thalion.synthetic_export_package
FOR EACH ROW EXECUTE FUNCTION thalion.guard_synthetic_export();
CREATE TRIGGER synthetic_export_request_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_export_request
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER synthetic_export_approval_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_export_approval
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER synthetic_export_package_immutable BEFORE UPDATE OR DELETE ON thalion.synthetic_export_package
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
