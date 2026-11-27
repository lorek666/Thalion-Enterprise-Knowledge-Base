CREATE FUNCTION thalion.source_restriction_version(
    target_org bigint, target_space bigint, target_source bigint, target_ref uuid
) RETURNS bigint LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT version.version_id
    FROM thalion.object_identity AS identity
    LEFT JOIN thalion.passage AS passage
      ON (passage.org_id, passage.space_id, passage.identity_type, passage.passage_id) =
         (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
    JOIN thalion.document_version AS version
      ON (version.org_id, version.space_id, version.version_id) = (
          identity.org_id, identity.space_id,
          CASE WHEN identity.object_type = 'document_version' THEN identity.object_id ELSE passage.version_id END
      )
    WHERE (identity.org_id, identity.space_id, identity.public_id) = (target_org, target_space, target_ref)
      AND version.source_id = target_source
      AND identity.object_type IN ('document_version', 'passage')
$$;

CREATE TABLE thalion.source_restriction_receipt (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    event_ref uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('withdrawn', 'deleted', 'permission_revoked')),
    target_ref uuid NOT NULL,
    decision_ref uuid NOT NULL,
    local_stop_ref uuid REFERENCES thalion.rule_use_stop (decision_ref),
    authority_ref uuid,
    authority_stream_ref uuid,
    authority_generation bigint CHECK (authority_generation > 0),
    authority_recorded_at timestamptz,
    request_id uuid NOT NULL,
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    outbox_ref uuid NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, source_id, event_ref),
    UNIQUE (org_id, space_id, source_id, authority_ref, authority_stream_ref, authority_generation),
    UNIQUE (org_id, outbox_ref),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, target_ref)
        REFERENCES thalion.object_identity (org_id, space_id, public_id),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, outbox_ref) REFERENCES thalion.outbox_event (org_id, event_id),
    CONSTRAINT source_restriction_kind_provenance CHECK (
        (kind = 'permission_revoked' AND local_stop_ref IS NULL AND decision_ref = event_ref
            AND authority_ref IS NOT NULL AND authority_stream_ref IS NOT NULL
            AND authority_generation IS NOT NULL AND authority_recorded_at IS NOT NULL)
        OR (kind IN ('withdrawn', 'deleted') AND local_stop_ref IS NOT NULL AND decision_ref = local_stop_ref
            AND authority_ref IS NULL AND authority_stream_ref IS NULL
            AND authority_generation IS NULL AND authority_recorded_at IS NULL)
    )
);

CREATE FUNCTION thalion.guard_source_restriction_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    target_version bigint;
BEGIN
    target_version := thalion.source_restriction_version(
        NEW.org_id, NEW.space_id, NEW.source_id, NEW.target_ref
    );
    IF target_version IS NULL OR NOT EXISTS (
        SELECT 1 FROM thalion.outbox_event AS event
        WHERE (event.org_id, event.event_id, event.object_ref, event.event_type) =
              (NEW.org_id, NEW.outbox_ref, NEW.target_ref, 'sources.restriction.acknowledged')
    ) OR (NEW.kind <> 'permission_revoked' AND NOT EXISTS (
        SELECT 1 FROM thalion.rule_use_stop AS stop
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (stop.org_id, stop.space_id, 'document_version', stop.version_id)
        WHERE (stop.org_id, stop.space_id, stop.source_id, stop.version_id) =
              (NEW.org_id, NEW.space_id, NEW.source_id, target_version)
          AND identity.public_id = NEW.target_ref AND stop.decision_ref = NEW.local_stop_ref
          AND stop.basis_ref = NEW.event_ref AND stop.replay_log_ref IS NULL
          AND stop.kind = CASE NEW.kind WHEN 'deleted' THEN 'deletion_blocked' ELSE 'withdrawn' END
    )) THEN
        RAISE EXCEPTION 'source restriction receipt requires exact scoped evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_restriction_receipt_guard BEFORE INSERT ON thalion.source_restriction_receipt
FOR EACH ROW EXECUTE FUNCTION thalion.guard_source_restriction_receipt();
CREATE TRIGGER source_restriction_receipt_immutable BEFORE UPDATE OR DELETE ON thalion.source_restriction_receipt
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_restriction_receipt_no_truncate BEFORE TRUNCATE ON thalion.source_restriction_receipt
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_restriction_outbox_immutable BEFORE UPDATE ON thalion.outbox_event
FOR EACH ROW WHEN (OLD.event_type = 'sources.restriction.acknowledged')
EXECUTE FUNCTION thalion.reject_original_change();
