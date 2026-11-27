CREATE TABLE thalion.source_permission_checkpoint (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    checkpoint_ref uuid NOT NULL,
    previous_checkpoint_ref uuid,
    previous_sequence bigint GENERATED ALWAYS AS (sequence - 1) STORED,
    authority_ref uuid NOT NULL,
    authority_stream_ref uuid NOT NULL,
    authority_generation bigint NOT NULL CHECK (authority_generation >= 0),
    acknowledged_count integer NOT NULL CHECK (acknowledged_count >= 0 AND acknowledged_count <= authority_generation),
    last_acknowledged_generation bigint CHECK (last_acknowledged_generation > 0),
    request_id uuid NOT NULL,
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    outbox_ref uuid NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, source_id, sequence),
    UNIQUE (org_id, space_id, source_id, checkpoint_ref),
    UNIQUE (org_id, space_id, source_id, sequence, checkpoint_ref),
    UNIQUE (org_id, outbox_ref),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, source_id, previous_sequence, previous_checkpoint_ref)
        REFERENCES thalion.source_permission_checkpoint (org_id, space_id, source_id, sequence, checkpoint_ref),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, outbox_ref) REFERENCES thalion.outbox_event (org_id, event_id),
    CHECK ((sequence = 1) = (previous_checkpoint_ref IS NULL)),
    CHECK (checkpoint_ref IS DISTINCT FROM previous_checkpoint_ref),
    CONSTRAINT source_permission_checkpoint_receipt_bounds CHECK (
        (acknowledged_count = 0 AND last_acknowledged_generation IS NULL)
        OR (acknowledged_count > 0 AND last_acknowledged_generation IS NOT NULL
            AND last_acknowledged_generation >= acknowledged_count
            AND last_acknowledged_generation <= authority_generation)
    )
);

CREATE FUNCTION thalion.guard_source_permission_checkpoint() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    prev_auth uuid;
    prev_stream uuid;
    prev_generation bigint;
    receipt_count integer;
    receipt_max_generation bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.outbox_event AS event
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (NEW.org_id, NEW.space_id, 'source', NEW.source_id)
        WHERE (event.org_id, event.event_id, event.object_ref, event.event_type) =
              (NEW.org_id, NEW.outbox_ref, identity.public_id, 'sources.permission.checkpointed')
    ) THEN
        RAISE EXCEPTION 'source permission checkpoint requires a matching source outbox event'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.sequence > 1 THEN
        SELECT authority_ref, authority_stream_ref, authority_generation
        INTO prev_auth, prev_stream, prev_generation
        FROM thalion.source_permission_checkpoint
        WHERE (org_id, space_id, source_id, sequence) =
              (NEW.org_id, NEW.space_id, NEW.source_id, NEW.sequence - 1);
        IF NOT FOUND OR (prev_auth, prev_stream) <> (NEW.authority_ref, NEW.authority_stream_ref)
           OR NEW.authority_generation < prev_generation THEN
            RAISE EXCEPTION 'source permission checkpoint must be monotonic on the same authority stream'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1 FROM thalion.source_restriction_receipt AS other
        WHERE (other.org_id, other.space_id, other.source_id, other.kind) =
              (NEW.org_id, NEW.space_id, NEW.source_id, 'permission_revoked')
          AND (other.authority_ref, other.authority_stream_ref) IS DISTINCT FROM
              (NEW.authority_ref, NEW.authority_stream_ref)
    ) THEN
        RAISE EXCEPTION 'source permission checkpoint conflicts with acknowledged revocation authority stream'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*)::integer, max(authority_generation)
    INTO receipt_count, receipt_max_generation
    FROM thalion.source_restriction_receipt
    WHERE (org_id, space_id, source_id, kind, authority_ref, authority_stream_ref) =
          (NEW.org_id, NEW.space_id, NEW.source_id, 'permission_revoked',
           NEW.authority_ref, NEW.authority_stream_ref);

    IF COALESCE(receipt_max_generation, 0) > NEW.authority_generation
       OR receipt_count <> NEW.acknowledged_count
       OR receipt_max_generation IS DISTINCT FROM NEW.last_acknowledged_generation THEN
        RAISE EXCEPTION 'source permission checkpoint must match acknowledged source revocations'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER source_permission_checkpoint_guard BEFORE INSERT ON thalion.source_permission_checkpoint
FOR EACH ROW EXECUTE FUNCTION thalion.guard_source_permission_checkpoint();
CREATE TRIGGER source_permission_checkpoint_immutable BEFORE UPDATE OR DELETE ON thalion.source_permission_checkpoint
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_permission_checkpoint_no_truncate BEFORE TRUNCATE ON thalion.source_permission_checkpoint
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_permission_checkpoint_outbox_immutable BEFORE UPDATE ON thalion.outbox_event
FOR EACH ROW WHEN (OLD.event_type = 'sources.permission.checkpointed')
EXECUTE FUNCTION thalion.reject_original_change();
