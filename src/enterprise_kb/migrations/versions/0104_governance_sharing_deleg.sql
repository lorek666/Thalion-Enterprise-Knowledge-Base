CREATE TABLE thalion.shared_group (
    group_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    owner_space_id bigint NOT NULL,
    target_space_id bigint NOT NULL,
    target_source_id bigint NOT NULL,
    group_principal_id bigint NOT NULL,
    name text NOT NULL CHECK (btrim(name) <> '' AND char_length(name) <= 120),
    purpose text NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
    scope_summary text NOT NULL CHECK (btrim(scope_summary) <> '' AND char_length(scope_summary) <= 240),
    created_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    starts_at timestamptz NOT NULL,
    review_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, owner_space_id, group_ref),
    UNIQUE (org_id, group_principal_id),
    FOREIGN KEY (org_id, owner_space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, target_space_id, target_source_id)
        REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, group_principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, created_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    CONSTRAINT shared_group_window CHECK (
        expires_at > starts_at
        AND expires_at > recorded_at
        AND review_at >= starts_at
        AND review_at <= expires_at
    )
);

CREATE INDEX shared_group_by_owner_space
    ON thalion.shared_group (org_id, owner_space_id, recorded_at DESC, group_ref DESC);
CREATE INDEX shared_group_by_target_source
    ON thalion.shared_group (org_id, target_space_id, target_source_id, expires_at DESC);

CREATE TABLE thalion.shared_group_revocation (
    group_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    owner_space_id bigint NOT NULL,
    revoked_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, owner_space_id, group_ref)
        REFERENCES thalion.shared_group (org_id, owner_space_id, group_ref),
    FOREIGN KEY (org_id, revoked_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TABLE thalion.shared_group_member (
    membership_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    owner_space_id bigint NOT NULL,
    group_ref uuid NOT NULL,
    member_principal_id bigint NOT NULL,
    added_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, owner_space_id, membership_ref),
    FOREIGN KEY (org_id, owner_space_id, group_ref)
        REFERENCES thalion.shared_group (org_id, owner_space_id, group_ref),
    FOREIGN KEY (org_id, member_principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, added_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    CONSTRAINT shared_group_member_window CHECK (expires_at > starts_at AND expires_at > recorded_at)
);

CREATE INDEX shared_group_member_by_member
    ON thalion.shared_group_member (org_id, member_principal_id, group_ref);
CREATE INDEX shared_group_member_by_group
    ON thalion.shared_group_member (org_id, owner_space_id, group_ref, recorded_at DESC);

CREATE TABLE thalion.shared_group_member_revocation (
    membership_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    owner_space_id bigint NOT NULL,
    revoked_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, owner_space_id, membership_ref)
        REFERENCES thalion.shared_group_member (org_id, owner_space_id, membership_ref),
    FOREIGN KEY (org_id, revoked_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TABLE thalion.space_delegation (
    delegation_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    delegator_id bigint NOT NULL,
    delegate_id bigint NOT NULL,
    scopes text[] NOT NULL CHECK (
        cardinality(scopes) >= 1
        AND array_position(scopes, NULL) IS NULL
        AND scopes <@ ARRAY['responsibility_management', 'shared_group_management', 'feedback_handoff_management']::text[]
    ),
    purpose text NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    starts_at timestamptz NOT NULL,
    review_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, delegation_ref),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, delegator_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, delegate_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    CHECK (delegator_id <> delegate_id),
    CONSTRAINT space_delegation_window CHECK (
        expires_at > starts_at
        AND expires_at > recorded_at
        AND review_at >= starts_at
        AND review_at <= expires_at
    )
);

CREATE INDEX space_delegation_by_space
    ON thalion.space_delegation (org_id, space_id, delegate_id, expires_at DESC);

CREATE TABLE thalion.space_delegation_revocation (
    delegation_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    revoked_by bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, delegation_ref)
        REFERENCES thalion.space_delegation (org_id, space_id, delegation_ref),
    FOREIGN KEY (org_id, revoked_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TABLE thalion.space_archive_record (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    archive_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    actor_id bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    archived_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TABLE thalion.governance_handoff_receipt (
    receipt_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    transition_kind text NOT NULL CHECK (transition_kind IN ('transfer', 'departure', 'proxy_replacement')),
    incumbent_id bigint NOT NULL,
    successor_id bigint,
    delegation_ref uuid,
    actor_id bigint NOT NULL,
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    review_at timestamptz NOT NULL,
    handed_off_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_group_member_count integer NOT NULL CHECK (revoked_group_member_count >= 0),
    revoked_delegation_count integer NOT NULL CHECK (revoked_delegation_count >= 0),
    reassigned_document_count integer NOT NULL CHECK (reassigned_document_count >= 0),
    accepted_feedback_handoff_refs uuid[] NOT NULL DEFAULT ARRAY[]::uuid[],
    remaining_open_feedback_count integer NOT NULL CHECK (remaining_open_feedback_count >= 0),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, incumbent_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, successor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, delegation_ref)
        REFERENCES thalion.space_delegation (org_id, space_id, delegation_ref),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    CHECK (successor_id IS NULL OR successor_id <> incumbent_id)
);

CREATE INDEX governance_handoff_by_space
    ON thalion.governance_handoff_receipt (org_id, space_id, handed_off_at DESC, receipt_ref DESC);

CREATE FUNCTION thalion.has_active_space_delegation(
    p_org_id bigint,
    p_space_id bigint,
    p_principal_id bigint,
    p_scope text
) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1
        FROM thalion.space_delegation AS delegation
        JOIN thalion.space AS space
          ON (space.org_id, space.space_id) = (delegation.org_id, delegation.space_id)
        JOIN thalion.principal AS delegator
          ON (delegator.org_id, delegator.principal_id) = (delegation.org_id, delegation.delegator_id)
        JOIN thalion.principal AS delegate
          ON (delegate.org_id, delegate.principal_id) = (delegation.org_id, delegation.delegate_id)
        WHERE delegation.org_id = p_org_id
          AND delegation.space_id = p_space_id
          AND delegation.delegate_id = p_principal_id
          AND p_scope = ANY(delegation.scopes)
          AND space.lifecycle = 'active'
          AND space.owner_principal_id = delegation.delegator_id
          AND delegator.principal_type = 'employee'
          AND delegator.authority_issuer = 'https://synthetic.invalid'
          AND NOT delegator.disabled
          AND delegate.principal_type = 'employee'
          AND delegate.authority_issuer = 'https://synthetic.invalid'
          AND NOT delegate.disabled
          AND delegation.starts_at <= clock_timestamp()
          AND clock_timestamp() < delegation.expires_at
          AND NOT EXISTS (
              SELECT 1 FROM thalion.space_delegation_revocation AS rev
              WHERE rev.delegation_ref = delegation.delegation_ref
          )
    );
$$;

CREATE FUNCTION thalion.guard_shared_group_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM 1
    FROM thalion.space AS owner_space
    JOIN thalion.space AS target_space
      ON (target_space.org_id, target_space.space_id) = (NEW.org_id, NEW.target_space_id)
    JOIN thalion.source AS target_source
      ON (target_source.org_id, target_source.space_id, target_source.source_id)
       = (NEW.org_id, NEW.target_space_id, NEW.target_source_id)
    JOIN thalion.principal AS grp
      ON (grp.org_id, grp.principal_id) = (NEW.org_id, NEW.group_principal_id)
    JOIN thalion.principal AS creator
      ON (creator.org_id, creator.principal_id) = (NEW.org_id, NEW.created_by)
    WHERE (owner_space.org_id, owner_space.space_id) = (NEW.org_id, NEW.owner_space_id)
      AND owner_space.lifecycle = 'active'
      AND target_space.lifecycle = 'active'
      AND target_source.lifecycle = 'active'
      AND grp.principal_type = 'group'
      AND grp.authority_issuer = 'https://synthetic.invalid'
      AND NOT grp.disabled
      AND creator.principal_type = 'employee'
      AND creator.authority_issuer = 'https://synthetic.invalid'
      AND NOT creator.disabled
    FOR SHARE OF owner_space, target_space, target_source, grp, creator;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'shared group requires active spaces, source, group principal, and employee creator'
            USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER shared_group_insert_guard
BEFORE INSERT ON thalion.shared_group
FOR EACH ROW EXECUTE FUNCTION thalion.guard_shared_group_insert();

CREATE FUNCTION thalion.guard_shared_group_member_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    grp thalion.shared_group%ROWTYPE;
BEGIN
    SELECT * INTO STRICT grp
    FROM thalion.shared_group
    WHERE (org_id, owner_space_id, group_ref) = (NEW.org_id, NEW.owner_space_id, NEW.group_ref)
    FOR SHARE;
    IF EXISTS (SELECT 1 FROM thalion.shared_group_revocation WHERE group_ref = NEW.group_ref) THEN
        RAISE EXCEPTION 'cannot add members to a revoked shared group' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM thalion.space AS owner_space
        JOIN thalion.space AS target_space
          ON (target_space.org_id, target_space.space_id) = (grp.org_id, grp.target_space_id)
        WHERE (owner_space.org_id, owner_space.space_id) = (grp.org_id, grp.owner_space_id)
          AND owner_space.lifecycle = 'active' AND target_space.lifecycle = 'active'
    ) THEN
        RAISE EXCEPTION 'cannot add members to a shared group in an archived space' USING ERRCODE = '23514';
    END IF;
    PERFORM 1 FROM thalion.principal
    WHERE (org_id, principal_id) = (NEW.org_id, NEW.member_principal_id)
      AND principal_type = 'employee' AND authority_issuer = 'https://synthetic.invalid' AND NOT disabled
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'shared group member must be an active employee of this organization' USING ERRCODE = '23514';
    END IF;
    IF NEW.starts_at < grp.starts_at OR NEW.expires_at > grp.expires_at THEN
        RAISE EXCEPTION 'shared group membership window must fit inside the shared group window' USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER shared_group_member_insert_guard
BEFORE INSERT ON thalion.shared_group_member
FOR EACH ROW EXECUTE FUNCTION thalion.guard_shared_group_member_insert();

CREATE FUNCTION thalion.guard_space_delegation_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.principal AS delegator
      ON (delegator.org_id, delegator.principal_id) = (space.org_id, NEW.delegator_id)
    JOIN thalion.principal AS delegate
      ON (delegate.org_id, delegate.principal_id) = (space.org_id, NEW.delegate_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.delegator_id
      AND delegator.principal_type = 'employee'
      AND delegator.authority_issuer = 'https://synthetic.invalid'
      AND NOT delegator.disabled
      AND delegate.principal_type = 'employee'
      AND delegate.authority_issuer = 'https://synthetic.invalid'
      AND NOT delegate.disabled
    FOR SHARE OF space, delegator, delegate;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space delegation requires an active space owner delegating to another active employee'
            USING ERRCODE = '23514';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_delegation_insert_guard
BEFORE INSERT ON thalion.space_delegation
FOR EACH ROW EXECUTE FUNCTION thalion.guard_space_delegation_insert();

CREATE FUNCTION thalion.guard_space_archive_record() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.space
        WHERE (org_id, space_id) = (NEW.org_id, NEW.space_id) AND lifecycle = 'archived'
    ) THEN
        RAISE EXCEPTION 'space archive record requires the space lifecycle to be archived' USING ERRCODE = '23514';
    END IF;
    NEW.archived_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_archive_record_guard
BEFORE INSERT ON thalion.space_archive_record
FOR EACH ROW EXECUTE FUNCTION thalion.guard_space_archive_record();

ALTER TABLE thalion.responsibility_assignment
    DROP CONSTRAINT responsibility_assignment_org_id_request_id_key,
    ADD CONSTRAINT responsibility_assignment_doc_request_key
        UNIQUE (org_id, space_id, source_id, document_id, request_id);

CREATE OR REPLACE FUNCTION thalion.guard_document_responsibility() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM 1 FROM thalion.document AS document
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.organization AS organization USING (org_id)
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (source.org_id, source.space_id, source.source_id, source.contract_revision)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (document.org_id, NEW.approved_by)
    JOIN thalion.request_record AS request
      ON (request.org_id, request.scope_space_id, request.request_id) = (document.org_id, document.space_id, NEW.request_id)
    WHERE (document.org_id, document.space_id, document.source_id, document.document_id)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
      AND source.lifecycle = 'active' AND space.lifecycle = 'active' AND contract.admission = 'synthetic_only'
      AND actor.principal_type = 'employee' AND actor.authority_issuer = 'https://synthetic.invalid' AND NOT actor.disabled
      AND (
          source.owner_principal_id = NEW.approved_by
          OR thalion.has_active_space_delegation(NEW.org_id, NEW.space_id, NEW.approved_by, 'responsibility_management')
          OR (request.operation = 'record_transition_handoff' AND space.owner_principal_id = NEW.approved_by)
      )
      AND request.principal_id = NEW.approved_by AND request.delegated_principal_id IS NULL AND request.outcome IS NULL
      AND request.configuration_revision = organization.config_revision
      AND (
          (request.operation = 'set_document_responsibility' AND request.destination = 'internal_sources')
          OR (request.operation = 'record_transition_handoff' AND request.destination = 'internal_governance')
      )
    FOR SHARE OF source, space, organization, actor, request
    FOR UPDATE OF document;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'an open request from the current source owner or active delegate is required' USING ERRCODE = '23514';
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

CREATE TRIGGER shared_group_immutable BEFORE UPDATE OR DELETE ON thalion.shared_group
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER shared_group_no_truncate BEFORE TRUNCATE ON thalion.shared_group
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER shared_group_revocation_immutable BEFORE UPDATE OR DELETE ON thalion.shared_group_revocation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER shared_group_revocation_no_truncate BEFORE TRUNCATE ON thalion.shared_group_revocation
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER shared_group_member_immutable BEFORE UPDATE OR DELETE ON thalion.shared_group_member
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER shared_group_member_no_truncate BEFORE TRUNCATE ON thalion.shared_group_member
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER shared_group_member_revocation_immutable BEFORE UPDATE OR DELETE ON thalion.shared_group_member_revocation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER shared_group_member_revocation_no_truncate BEFORE TRUNCATE ON thalion.shared_group_member_revocation
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER space_delegation_immutable BEFORE UPDATE OR DELETE ON thalion.space_delegation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_delegation_no_truncate BEFORE TRUNCATE ON thalion.space_delegation
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER space_delegation_revocation_immutable BEFORE UPDATE OR DELETE ON thalion.space_delegation_revocation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_delegation_revocation_no_truncate BEFORE TRUNCATE ON thalion.space_delegation_revocation
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER space_archive_record_immutable BEFORE UPDATE OR DELETE ON thalion.space_archive_record
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_archive_record_no_truncate BEFORE TRUNCATE ON thalion.space_archive_record
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TRIGGER governance_handoff_receipt_immutable BEFORE UPDATE OR DELETE ON thalion.governance_handoff_receipt
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER governance_handoff_receipt_no_truncate BEFORE TRUNCATE ON thalion.governance_handoff_receipt
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
