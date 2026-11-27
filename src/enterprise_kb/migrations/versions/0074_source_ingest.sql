CREATE TABLE thalion.source_ingest_batch (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    batch_ref uuid NOT NULL DEFAULT gen_random_uuid(),
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    key_digest bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    item_count integer NOT NULL CHECK (item_count BETWEEN 1 AND 20),
    total_bytes bigint NOT NULL CHECK (total_bytes BETWEEN 0 AND 33554432),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (org_id, batch_ref),
    UNIQUE (org_id, space_id, batch_ref),
    UNIQUE (org_id, actor_id, key_digest),
    FOREIGN KEY (org_id, space_id, source_id) REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TABLE thalion.source_ingest_item (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    batch_ref uuid NOT NULL,
    position integer NOT NULL CHECK (position BETWEEN 0 AND 19),
    display_name text NOT NULL CHECK (char_length(display_name) <= 300),
    media_type text,
    digest bytea CHECK (digest IS NULL OR octet_length(digest) = 32),
    status text NOT NULL CHECK (status IN ('registered', 'duplicate', 'needs_confirmation', 'rejected')),
    document_ref uuid,
    version_ref uuid,
    reason text CHECK (reason IS NULL OR char_length(reason) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, batch_ref, position),
    FOREIGN KEY (org_id, space_id, batch_ref)
        REFERENCES thalion.source_ingest_batch (org_id, space_id, batch_ref),
    FOREIGN KEY (document_ref) REFERENCES thalion.object_identity (public_id),
    FOREIGN KEY (version_ref) REFERENCES thalion.object_identity (public_id),
    CHECK ((status = 'rejected') = (version_ref IS NULL))
);

CREATE TRIGGER source_ingest_item_immutable BEFORE UPDATE OR DELETE ON thalion.source_ingest_item
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE FUNCTION thalion.guard_source_ingest_batch() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'source ingest batches are immutable' USING ERRCODE = '55000';
    END IF;
    IF (NEW.org_id, NEW.space_id, NEW.source_id, NEW.batch_ref, NEW.actor_id, NEW.request_id,
        NEW.key_digest, NEW.input_digest, NEW.item_count, NEW.total_bytes, NEW.created_at)
        IS DISTINCT FROM
       (OLD.org_id, OLD.space_id, OLD.source_id, OLD.batch_ref, OLD.actor_id, OLD.request_id,
        OLD.key_digest, OLD.input_digest, OLD.item_count, OLD.total_bytes, OLD.created_at)
       OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at)
    THEN
        RAISE EXCEPTION 'source ingest batch results are immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_ingest_batch_guard BEFORE UPDATE OR DELETE ON thalion.source_ingest_batch
FOR EACH ROW EXECUTE FUNCTION thalion.guard_source_ingest_batch();
CREATE TRIGGER source_ingest_batch_no_truncate BEFORE TRUNCATE ON thalion.source_ingest_batch
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_ingest_item_no_truncate BEFORE TRUNCATE ON thalion.source_ingest_item
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
