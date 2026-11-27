CREATE TABLE thalion.feedback_search_match (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    request_id uuid NOT NULL,
    check_id uuid NOT NULL,
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, request_id, check_id) REFERENCES thalion.delivery_record (org_id, request_id, check_id)
);

CREATE FUNCTION thalion.require_open_feedback_search() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        WHERE (request.org_id, request.scope_space_id, request.request_id) = (NEW.org_id, NEW.space_id, NEW.request_id)
          AND request.operation = 'search' AND request.destination = 'employee'
          AND request.delegated_principal_id IS NULL AND request.outcome IS NULL FOR SHARE
    ) THEN
        RAISE EXCEPTION 'a feedback match must belong to an open scoped employee search' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER feedback_search_match_open BEFORE INSERT ON thalion.feedback_search_match
FOR EACH ROW EXECUTE FUNCTION thalion.require_open_feedback_search();
CREATE TRIGGER feedback_search_match_immutable BEFORE UPDATE OR DELETE ON thalion.feedback_search_match
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
