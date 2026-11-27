ALTER TABLE thalion.organization ADD COLUMN safety_epoch bigint NOT NULL DEFAULT 1 CHECK (safety_epoch > 0);
ALTER TABLE thalion.space ADD COLUMN safety_epoch bigint NOT NULL DEFAULT 1 CHECK (safety_epoch > 0);
ALTER TABLE thalion.source
    ADD COLUMN safety_epoch bigint NOT NULL DEFAULT 1 CHECK (safety_epoch > 0),
    ADD COLUMN local_policy_revision bigint;

CREATE TABLE thalion.policy_revision (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    revision bigint NOT NULL CHECK (revision > 1),
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    basis_ref uuid NOT NULL,
    binding_count integer NOT NULL CHECK (binding_count BETWEEN 0 AND 500),
    policy_ref uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, source_id) REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

ALTER TABLE thalion.source ADD CONSTRAINT source_current_local_policy
    FOREIGN KEY (org_id, space_id, source_id, local_policy_revision)
    REFERENCES thalion.policy_revision (org_id, space_id, source_id, revision);

CREATE TABLE thalion.permission_binding (
    binding_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    revision bigint NOT NULL,
    subject_id bigint NOT NULL,
    passage_ref uuid,
    operation text NOT NULL CHECK (operation = 'read_passage'),
    effect text NOT NULL CHECK (effect IN ('allow', 'deny')),
    purpose text NOT NULL CHECK (purpose = 'employee_evidence'),
    destination text NOT NULL CHECK (destination = 'employee'),
    fields text[] NOT NULL CHECK (fields = ARRAY['excerpt']),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    FOREIGN KEY (org_id, space_id, source_id, revision)
        REFERENCES thalion.policy_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, subject_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, passage_ref) REFERENCES thalion.object_identity (org_id, space_id, public_id),
    CHECK (valid_until IS NULL OR valid_from < valid_until)
);

CREATE INDEX permission_binding_policy ON thalion.permission_binding (org_id, space_id, source_id, revision);

CREATE TRIGGER policy_revision_immutable BEFORE UPDATE OR DELETE ON thalion.policy_revision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER permission_binding_immutable BEFORE UPDATE OR DELETE ON thalion.permission_binding
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE FUNCTION thalion.guard_permission_binding_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    epoch bigint;
BEGIN
    SELECT safety_epoch INTO epoch FROM thalion.source
    WHERE (org_id, space_id, source_id) = (NEW.org_id, NEW.space_id, NEW.source_id)
    FOR UPDATE;
    IF NOT FOUND OR NEW.revision <> epoch + 1 THEN
        RAISE EXCEPTION 'permission bindings can only be added to a new policy' USING ERRCODE = '23514';
    END IF;
    IF NEW.passage_ref IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM thalion.object_identity AS identity
        JOIN thalion.passage AS passage
          ON (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.document_version AS version ON version.version_id = passage.version_id
        WHERE identity.public_id = NEW.passage_ref AND version.source_id = NEW.source_id
    ) THEN
        RAISE EXCEPTION 'permission binding requires a passage in the same source' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER permission_binding_open_revision BEFORE INSERT ON thalion.permission_binding
FOR EACH ROW EXECUTE FUNCTION thalion.guard_permission_binding_insert();

CREATE FUNCTION thalion.seal_policy_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.source
        WHERE (org_id, space_id, source_id) = (NEW.org_id, NEW.space_id, NEW.source_id)
          AND local_policy_revision = NEW.revision
    ) OR NEW.binding_count <> (
        SELECT count(*) FROM thalion.permission_binding
        WHERE (org_id, space_id, source_id, revision) = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.revision)
    ) THEN
        RAISE EXCEPTION 'new policy and complete bindings must become current together' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER policy_revision_sealed AFTER INSERT ON thalion.policy_revision
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.seal_policy_revision();

CREATE FUNCTION thalion.advance_source_safety() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NEW.local_policy_revision IS DISTINCT FROM OLD.local_policy_revision AND (
        NEW.local_policy_revision IS NULL OR NEW.local_policy_revision <> OLD.safety_epoch + 1
    ) THEN
        RAISE EXCEPTION 'a policy change requires a fresh revision' USING ERRCODE = '23514';
    END IF;
    IF (NEW.local_policy_revision, NEW.contract_revision, NEW.lifecycle, NEW.owner_principal_id)
        IS DISTINCT FROM (OLD.local_policy_revision, OLD.contract_revision, OLD.lifecycle, OLD.owner_principal_id)
    THEN
        NEW.safety_epoch := OLD.safety_epoch + 1;
    ELSIF NEW.safety_epoch < OLD.safety_epoch THEN
        RAISE EXCEPTION 'source safety epoch cannot move backwards' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_safety_epoch BEFORE UPDATE ON thalion.source
FOR EACH ROW EXECUTE FUNCTION thalion.advance_source_safety();

CREATE FUNCTION thalion.advance_space_safety() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF (NEW.lifecycle, NEW.classification, NEW.owner_principal_id)
        IS DISTINCT FROM (OLD.lifecycle, OLD.classification, OLD.owner_principal_id)
    THEN
        NEW.safety_epoch := OLD.safety_epoch + 1;
    ELSIF NEW.safety_epoch < OLD.safety_epoch THEN
        RAISE EXCEPTION 'space safety epoch cannot move backwards' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_safety_epoch BEFORE UPDATE ON thalion.space
FOR EACH ROW EXECUTE FUNCTION thalion.advance_space_safety();

CREATE TABLE thalion.delivery_record (
    check_id uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    request_id uuid NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    passage_ref uuid NOT NULL,
    excerpt_revision bigint NOT NULL CHECK (excerpt_revision > 0),
    policy_revision bigint NOT NULL,
    organization_epoch bigint NOT NULL CHECK (organization_epoch > 0),
    space_epoch bigint NOT NULL CHECK (space_epoch > 0),
    source_epoch bigint NOT NULL CHECK (source_epoch >= policy_revision),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    checked_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > checked_at),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    FOREIGN KEY (org_id, space_id, passage_ref) REFERENCES thalion.object_identity (org_id, space_id, public_id),
    FOREIGN KEY (org_id, space_id, source_id, policy_revision)
        REFERENCES thalion.policy_revision (org_id, space_id, source_id, revision)
);

CREATE TRIGGER delivery_record_immutable BEFORE UPDATE OR DELETE ON thalion.delivery_record
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
