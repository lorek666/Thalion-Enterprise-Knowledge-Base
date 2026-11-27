CREATE FUNCTION thalion.valid_source_inventory_differences(
    differences jsonb, entry_count integer, matched_count integer
) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT CASE
        WHEN jsonb_typeof(differences) <> 'array' THEN false
        WHEN jsonb_array_length(differences) > 2000 THEN false
        ELSE (
            SELECT
                COALESCE(bool_and((
                    CASE WHEN jsonb_typeof(detail) = 'array' THEN jsonb_array_length(detail) = 4 ELSE false END
                    AND jsonb_typeof(detail -> 0) = 'string'
                    AND jsonb_typeof(detail -> 1) = 'string'
                    AND (detail ->> 0) COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
                    AND (detail ->> 1) COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
                    AND CASE WHEN detail ->> 3 = 'not_enumerated' THEN jsonb_typeof(detail -> 2) = 'null'
                        ELSE detail ->> 3 IN ('version_not_registered', 'digest_mismatch')
                            AND jsonb_typeof(detail -> 2) = 'string'
                            AND (detail ->> 2) COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
                    END
                ) IS TRUE), true)
                AND count(*) = count(DISTINCT (detail -> 0, detail -> 1))
                AND count(*) FILTER (WHERE detail ->> 3 <> 'not_enumerated') = entry_count - matched_count
                AND matched_count + count(*) FILTER (WHERE detail ->> 3 IN ('not_enumerated', 'digest_mismatch')) <= 1000
            FROM jsonb_array_elements(differences) AS entries(detail)
        )
    END
$$;

CREATE TABLE thalion.source_inventory_receipt (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    contract_revision bigint NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    snapshot_ref uuid NOT NULL,
    previous_snapshot_ref uuid,
    previous_sequence bigint GENERATED ALWAYS AS (sequence - 1) STORED,
    content_position uuid,
    request_id uuid NOT NULL,
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    inventory_digest bytea NOT NULL CHECK (octet_length(inventory_digest) = 32),
    entry_count integer NOT NULL CHECK (entry_count BETWEEN 0 AND 1000),
    matched_count integer NOT NULL CHECK (matched_count BETWEEN 0 AND entry_count),
    differences jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, source_id, contract_revision, sequence),
    UNIQUE (org_id, space_id, source_id, contract_revision, snapshot_ref),
    UNIQUE (org_id, space_id, source_id, contract_revision, sequence, snapshot_ref),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision, previous_sequence, previous_snapshot_ref)
        REFERENCES thalion.source_inventory_receipt (org_id, space_id, source_id, contract_revision, sequence, snapshot_ref),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision, content_position)
        REFERENCES thalion.source_sync_page (org_id, space_id, source_id, contract_revision, through_cursor),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CHECK (thalion.valid_source_inventory_differences(differences, entry_count, matched_count)),
    CHECK ((sequence = 1) = (previous_snapshot_ref IS NULL)),
    CHECK (snapshot_ref IS DISTINCT FROM previous_snapshot_ref)
);

CREATE TRIGGER source_inventory_receipt_immutable BEFORE UPDATE OR DELETE ON thalion.source_inventory_receipt
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_inventory_receipt_no_truncate BEFORE TRUNCATE ON thalion.source_inventory_receipt
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
