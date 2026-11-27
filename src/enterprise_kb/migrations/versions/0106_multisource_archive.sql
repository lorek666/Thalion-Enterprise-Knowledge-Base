CREATE TABLE thalion.space_archive_request (
    export_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    requester_id bigint NOT NULL,
    source_ids bigint[] NOT NULL CHECK (cardinality(source_ids) BETWEEN 1 AND 20),
    version_ids bigint[] NOT NULL CHECK (cardinality(version_ids) BETWEEN 1 AND 100),
    wiki_publication_refs uuid[] NOT NULL DEFAULT '{}'::uuid[] CHECK (cardinality(wiki_publication_refs) <= 40),
    scope_digest bytea NOT NULL CHECK (octet_length(scope_digest) = 32),
    watermark_digest bytea NOT NULL CHECK (octet_length(watermark_digest) = 32),
    safety_snapshot bigint[] NOT NULL CHECK (cardinality(safety_snapshot) >= 3),
    include_authorization_rules boolean NOT NULL DEFAULT true,
    include_safety_decisions boolean NOT NULL DEFAULT true,
    request_id uuid NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, export_ref),
    UNIQUE (org_id, space_id, export_ref, requester_id),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, requester_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE INDEX space_archive_request_by_space
    ON thalion.space_archive_request (org_id, space_id, requested_at DESC);

CREATE FUNCTION thalion.guard_space_archive_request_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    distinct_sources integer;
    matching_sources integer;
    distinct_versions integer;
    matching_versions integer;
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.requester_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.requester_id
      AND actor.principal_type = 'employee'
      AND actor.authority_issuer = 'https://synthetic.invalid'
      AND NOT actor.disabled
      AND req.principal_id = NEW.requester_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'request_space_archive'
      AND req.destination = 'internal_lifecycle'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF org, actor, req
    FOR UPDATE OF space;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space archive request requires an open request from the active space owner'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(DISTINCT s) INTO distinct_sources FROM unnest(NEW.source_ids) AS s;
    IF distinct_sources <> cardinality(NEW.source_ids) THEN
        RAISE EXCEPTION 'space archive source list must not contain duplicates' USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO matching_sources
    FROM thalion.source AS src
    WHERE (src.org_id, src.space_id) = (NEW.org_id, NEW.space_id)
      AND src.source_id = ANY(NEW.source_ids)
      AND src.owner_principal_id = NEW.requester_id;
    IF matching_sources <> distinct_sources THEN
        RAISE EXCEPTION 'all archived sources must belong to this space and be owned by the requester'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(DISTINCT v) INTO distinct_versions FROM unnest(NEW.version_ids) AS v;
    IF distinct_versions <> cardinality(NEW.version_ids) THEN
        RAISE EXCEPTION 'space archive version list must not contain duplicates' USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO matching_versions
    FROM thalion.document_version AS ver
    WHERE (ver.org_id, ver.space_id) = (NEW.org_id, NEW.space_id)
      AND ver.source_id = ANY(NEW.source_ids)
      AND ver.version_id = ANY(NEW.version_ids);
    IF matching_versions <> distinct_versions THEN
        RAISE EXCEPTION 'all archived versions must belong to the selected space and sources'
            USING ERRCODE = '23514';
    END IF;

    NEW.requested_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_archive_request_insert_guard
BEFORE INSERT ON thalion.space_archive_request
FOR EACH ROW EXECUTE FUNCTION thalion.guard_space_archive_request_insert();

CREATE TRIGGER space_archive_request_immutable BEFORE UPDATE OR DELETE ON thalion.space_archive_request
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_archive_request_no_truncate BEFORE TRUNCATE ON thalion.space_archive_request
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.space_archive_approval (
    approval_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    export_ref uuid NOT NULL UNIQUE,
    requester_id bigint NOT NULL,
    approver_id bigint NOT NULL CHECK (approver_id <> requester_id),
    request_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, export_ref, approval_ref),
    FOREIGN KEY (org_id, space_id, export_ref, requester_id)
        REFERENCES thalion.space_archive_request (org_id, space_id, export_ref, requester_id),
    FOREIGN KEY (org_id, approver_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    CHECK (expires_at > approved_at)
);

CREATE FUNCTION thalion.guard_space_archive_approval_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    req_sources bigint[];
    approved_sources integer;
BEGIN
    SELECT source_ids INTO req_sources
    FROM thalion.space_archive_request
    WHERE (org_id, space_id, export_ref, requester_id)
        = (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
    IF req_sources IS NULL THEN
        RAISE EXCEPTION 'space archive request not found for approval' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.approver_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id <> NEW.approver_id
      AND actor.principal_type = 'employee'
      AND actor.authority_issuer = 'https://synthetic.invalid'
      AND NOT actor.disabled
      AND req.principal_id = NEW.approver_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'approve_space_archive'
      AND req.destination = 'internal_lifecycle'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF space, org, actor, req;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space archive approval requires an independent active employee with an open request'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO approved_sources
    FROM thalion.source AS src
    JOIN thalion.source_contract_revision AS contract
      ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
       = (src.org_id, src.space_id, src.source_id, src.contract_revision)
    WHERE (src.org_id, src.space_id) = (NEW.org_id, NEW.space_id)
      AND src.source_id = ANY(req_sources)
      AND contract.approver_id = NEW.approver_id
      AND src.owner_principal_id <> NEW.approver_id;
    IF approved_sources <> cardinality(req_sources) THEN
        RAISE EXCEPTION 'approver must hold independent approval authority across every archived source'
            USING ERRCODE = '23514';
    END IF;

    NEW.approved_at := clock_timestamp();
    IF NEW.expires_at <= NEW.approved_at OR NEW.expires_at > NEW.approved_at + interval '15 minutes' THEN
        RAISE EXCEPTION 'space archive approval expiry must be within fifteen minutes' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_archive_approval_insert_guard
BEFORE INSERT ON thalion.space_archive_approval
FOR EACH ROW EXECUTE FUNCTION thalion.guard_space_archive_approval_insert();

CREATE TRIGGER space_archive_approval_immutable BEFORE UPDATE OR DELETE ON thalion.space_archive_approval
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_archive_approval_no_truncate BEFORE TRUNCATE ON thalion.space_archive_approval
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.space_archive_package (
    package_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    export_ref uuid NOT NULL UNIQUE,
    requester_id bigint NOT NULL,
    approval_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    format_version text NOT NULL CHECK (format_version = 'thalion.synthetic-space-archive.v1'),
    archive_bytes bytea NOT NULL CHECK (octet_length(archive_bytes) BETWEEN 1 AND 33554432),
    archive_digest bytea GENERATED ALWAYS AS (sha256(archive_bytes)) STORED,
    recovery_watermark jsonb NOT NULL CHECK (jsonb_typeof(recovery_watermark) = 'object'),
    proof_digest bytea NOT NULL CHECK (octet_length(proof_digest) = 32),
    authority_valid_until timestamptz NOT NULL,
    sealed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, export_ref, requester_id)
        REFERENCES thalion.space_archive_request (org_id, space_id, export_ref, requester_id),
    FOREIGN KEY (org_id, space_id, export_ref, approval_ref)
        REFERENCES thalion.space_archive_approval (org_id, space_id, export_ref, approval_ref),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE FUNCTION thalion.guard_space_archive_package_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.requester_id)
    JOIN thalion.space_archive_approval AS approval
      ON (approval.org_id, approval.space_id, approval.export_ref, approval.approval_ref)
       = (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.approval_ref)
    JOIN thalion.principal AS approver
      ON (approver.org_id, approver.principal_id) = (approval.org_id, approval.approver_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.requester_id
      AND actor.principal_type = 'employee'
      AND actor.authority_issuer = 'https://synthetic.invalid'
      AND NOT actor.disabled
      AND approver.principal_type = 'employee'
      AND approver.authority_issuer = 'https://synthetic.invalid'
      AND NOT approver.disabled
      AND approval.expires_at > clock_timestamp()
      AND NEW.authority_valid_until > clock_timestamp()
      AND req.principal_id = NEW.requester_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'seal_space_archive'
      AND req.destination = 'internal_lifecycle'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF space, org, actor, approver, approval, req;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'sealing a space archive requires a live independent approval and open requester session'
            USING ERRCODE = '23514';
    END IF;
    NEW.sealed_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_archive_package_insert_guard
BEFORE INSERT ON thalion.space_archive_package
FOR EACH ROW EXECUTE FUNCTION thalion.guard_space_archive_package_insert();

CREATE TRIGGER space_archive_package_immutable BEFORE UPDATE OR DELETE ON thalion.space_archive_package
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_archive_package_no_truncate BEFORE TRUNCATE ON thalion.space_archive_package
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.space_archive_rebuild (
    rebuild_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    origin_org_id bigint NOT NULL CHECK (origin_org_id > 0),
    origin_space_id bigint NOT NULL CHECK (origin_space_id > 0),
    origin_space_ref uuid NOT NULL,
    export_ref uuid NOT NULL UNIQUE,
    format_version text NOT NULL CHECK (format_version = 'thalion.synthetic-space-archive.v1'),
    archive_digest bytea NOT NULL CHECK (octet_length(archive_digest) = 32),
    recovery_watermark jsonb NOT NULL CHECK (jsonb_typeof(recovery_watermark) = 'object'),
    rule_authority_ref uuid NOT NULL,
    rule_log_ref uuid NOT NULL CHECK (rule_log_ref <> rule_authority_ref),
    rule_stream_ref uuid NOT NULL,
    rule_generation bigint NOT NULL CHECK (rule_generation >= 0),
    source_authority_ref uuid NOT NULL CHECK (source_authority_ref NOT IN (rule_authority_ref, rule_log_ref)),
    source_stream_ref uuid NOT NULL,
    source_generation bigint NOT NULL CHECK (source_generation >= 0),
    alternate_model_profile text NOT NULL CHECK (btrim(alternate_model_profile) <> '' AND char_length(alternate_model_profile) <= 128),
    lexical_index_mode text NOT NULL CHECK (lexical_index_mode IN ('indexed', 'direct_scan')),
    rebuilt_sources integer NOT NULL CHECK (rebuilt_sources >= 1),
    rebuilt_versions integer NOT NULL CHECK (rebuilt_versions >= 1),
    rebuilt_wikis integer NOT NULL CHECK (rebuilt_wikis >= 0),
    replayed_stops integer NOT NULL CHECK (replayed_stops >= 0),
    replayed_deletions integer NOT NULL CHECK (replayed_deletions >= 0),
    replayed_revocations integer NOT NULL CHECK (replayed_revocations >= 0),
    verified_references integer NOT NULL CHECK (verified_references >= 0),
    blocked_references integer NOT NULL CHECK (blocked_references >= 0),
    duration_ms integer NOT NULL CHECK (duration_ms >= 0),
    scratch_bytes bigint NOT NULL CHECK (scratch_bytes >= 0),
    affected_services text[] NOT NULL CHECK (cardinality(affected_services) >= 1),
    rebuilt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id)
);

CREATE FUNCTION thalion.guard_space_archive_rebuild_fenced() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_db_role_setting AS setting
        JOIN pg_database AS db ON db.oid = setting.setdatabase
        WHERE db.datname = current_database() AND setting.setrole = 0
          AND ('thalion.restore_rehearsal=' || current_database()) = ANY(setting.setconfig)
    ) THEN
        RAISE EXCEPTION 'multi-source space archive rebuild requires a fenced restore_rehearsal database'
            USING ERRCODE = '23514';
    END IF;
    NEW.rebuilt_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_archive_rebuild_fenced
BEFORE INSERT ON thalion.space_archive_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.guard_space_archive_rebuild_fenced();

CREATE TRIGGER space_archive_rebuild_immutable BEFORE UPDATE OR DELETE ON thalion.space_archive_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_archive_rebuild_no_truncate BEFORE TRUNCATE ON thalion.space_archive_rebuild
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE FUNCTION thalion.space_archive_wiki_is_current(
    scope_org bigint,
    scope_space bigint,
    admitted_sources bigint[],
    admitted_versions bigint[],
    selected uuid
) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.available_wiki_publication AS publication
        JOIN thalion.wiki_revision AS revision USING (org_id, space_id, topic_key, revision_ref)
        JOIN thalion.input_manifest AS manifest USING (manifest_ref)
        JOIN thalion.delivery_record AS seal ON seal.check_id = manifest.check_id
        CROSS JOIN LATERAL (
            SELECT count(*) AS input_count,
                   sha256(convert_to(jsonb_agg(jsonb_build_array(input.passage_ref, input.excerpt_revision)
                                             ORDER BY input.position)::text, 'UTF8')) AS input_digest,
                   bool_and(input.source_id = ANY(admitted_sources)
                       AND input.version_id = ANY(admitted_versions)
                       AND target.blocked IS FALSE
                       AND checked.policy_revision IS NOT DISTINCT FROM source.local_policy_revision
                       AND ARRAY[checked.organization_epoch, checked.space_epoch, checked.source_epoch] = target.snapshot[1:3]
                       AND run.contract_revision = source.contract_revision
                       AND EXISTS (SELECT 1 FROM thalion.quality_decision AS quality
                                   WHERE quality.run_ref = input.run_ref AND quality.outcome = 'approved')
                       AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision AS quality
                                       WHERE quality.run_ref = input.run_ref AND quality.outcome = 'quarantined')
                       AND NOT EXISTS (SELECT 1 FROM thalion.processing_run AS newer
                                       WHERE newer.version_id = input.version_id
                                         AND newer.configuration_revision > run.configuration_revision)) AS all_current
            FROM thalion.wiki_archive_input AS input
            JOIN thalion.delivery_dependency AS checked
              ON (checked.check_id, checked.org_id, checked.space_id, checked.position, checked.source_id,
                  checked.passage_ref, checked.excerpt_revision) =
                 (publication.check_id, input.org_id, input.space_id, input.position, input.source_id,
                  input.passage_ref, input.excerpt_revision)
            JOIN thalion.processing_run AS run ON run.run_ref = input.run_ref
            JOIN thalion.source AS source
              ON (source.org_id, source.space_id, source.source_id) = (input.org_id, input.space_id, input.source_id)
            LEFT JOIN thalion.synthetic_original_export_target AS target
              ON (target.org_id, target.space_id, target.version_id) = (input.org_id, input.space_id, input.version_id)
            WHERE (input.org_id, input.space_id, input.publication_ref) = (scope_org, scope_space, selected)
        ) AS coverage
        WHERE (publication.org_id, publication.space_id, publication.publication_ref) = (scope_org, scope_space, selected)
          AND coverage.input_count > 0
          AND coverage.input_count = seal.dependency_count
          AND coverage.input_digest = revision.input_digest
          AND coverage.all_current
    );
$$;
