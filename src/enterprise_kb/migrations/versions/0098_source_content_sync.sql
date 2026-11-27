CREATE TABLE thalion.source_sync_page (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    through_cursor uuid NOT NULL,
    previous_cursor uuid,
    previous_sequence bigint GENERATED ALWAYS AS (sequence - 1) STORED,
    request_id uuid NOT NULL,
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    item_count integer NOT NULL CHECK (item_count BETWEEN 0 AND 20),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, source_id, contract_revision, sequence),
    UNIQUE (org_id, space_id, source_id, contract_revision, through_cursor),
    UNIQUE (org_id, space_id, source_id, contract_revision, sequence, through_cursor),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision, previous_sequence, previous_cursor)
        REFERENCES thalion.source_sync_page (org_id, space_id, source_id, contract_revision, sequence, through_cursor),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CHECK ((sequence = 1) = (previous_cursor IS NULL)),
    CHECK (through_cursor IS DISTINCT FROM previous_cursor)
);

CREATE TABLE thalion.source_sync_page_item (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    sequence bigint NOT NULL,
    position integer NOT NULL CHECK (position BETWEEN 0 AND 19),
    document_id bigint NOT NULL,
    version_id bigint NOT NULL,
    PRIMARY KEY (org_id, space_id, source_id, contract_revision, sequence, position),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision, sequence)
        REFERENCES thalion.source_sync_page (org_id, space_id, source_id, contract_revision, sequence),
    FOREIGN KEY (org_id, space_id, source_id, document_id, version_id)
        REFERENCES thalion.document_version (org_id, space_id, source_id, document_id, version_id)
);

CREATE FUNCTION thalion.require_complete_source_sync_page() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    expected_count integer;
    received_count integer;
    last_position integer;
BEGIN
    SELECT page.item_count INTO STRICT expected_count
    FROM thalion.source_sync_page AS page
    WHERE (page.org_id, page.space_id, page.source_id, page.contract_revision, page.sequence)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision, NEW.sequence);
    SELECT count(*), COALESCE(max(item.position), -1) INTO received_count, last_position
    FROM thalion.source_sync_page_item AS item
    WHERE (item.org_id, item.space_id, item.source_id, item.contract_revision, item.sequence)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.contract_revision, NEW.sequence);
    IF received_count <> expected_count OR last_position <> expected_count - 1 THEN
        RAISE EXCEPTION 'Source sync page requires complete ordered item receipts' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_sync_page_complete
AFTER INSERT ON thalion.source_sync_page DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION thalion.require_complete_source_sync_page();
CREATE CONSTRAINT TRIGGER source_sync_page_item_complete
AFTER INSERT ON thalion.source_sync_page_item DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION thalion.require_complete_source_sync_page();

CREATE TRIGGER source_sync_page_immutable BEFORE UPDATE OR DELETE ON thalion.source_sync_page
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_sync_page_item_immutable BEFORE UPDATE OR DELETE ON thalion.source_sync_page_item
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_sync_page_no_truncate BEFORE TRUNCATE ON thalion.source_sync_page
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_sync_page_item_no_truncate BEFORE TRUNCATE ON thalion.source_sync_page_item
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
