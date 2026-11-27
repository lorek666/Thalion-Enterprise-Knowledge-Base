ALTER TABLE thalion.search_scope_observation ADD COLUMN empty_fingerprint bytea,
    ADD CHECK (empty_fingerprint IS NULL OR (NOT visibility_limited AND octet_length(empty_fingerprint) = 32));

CREATE FUNCTION thalion.require_empty_search_fingerprint() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        WHERE (request.org_id, request.scope_space_id, request.request_id) = (NEW.org_id, NEW.space_id, NEW.request_id)
          AND request.operation = 'search' AND request.destination = 'employee'
          AND request.delegated_principal_id IS NULL AND request.outcome = 'no_evidence'
          AND request.feedback_order IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM thalion.delivery_record AS delivery
              WHERE (delivery.org_id, delivery.request_id) = (request.org_id, request.request_id)
          )
        FOR SHARE OF request
    ) THEN
        RAISE EXCEPTION 'an empty fingerprint requires a completed scoped search without delivery' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER scoped_empty_search_only BEFORE INSERT ON thalion.search_scope_observation
FOR EACH ROW WHEN (NEW.empty_fingerprint IS NOT NULL) EXECUTE FUNCTION thalion.require_empty_search_fingerprint();
