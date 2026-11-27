ALTER TABLE thalion.delivery_record
    ADD COLUMN source_facets boolean NOT NULL DEFAULT false,
    DROP CONSTRAINT delivery_record_dependency_count_check,
    ADD CONSTRAINT delivery_record_dependency_count_check CHECK (
        dependency_count BETWEEN 1 AND (
            CASE WHEN source_facets THEN 512 WHEN wiki_publication_ref IS NOT NULL THEN 40 ELSE 20 END
        )
    );

ALTER TABLE thalion.delivery_dependency
    DROP CONSTRAINT delivery_dependency_position_check,
    ADD CONSTRAINT delivery_dependency_position_check CHECK (position BETWEEN 1 AND 512);

CREATE FUNCTION thalion.guard_source_facet_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        WHERE (request.org_id, request.request_id) = (NEW.org_id, NEW.request_id)
          AND request.operation = 'search' AND request.destination = 'employee'
          AND request.scope_space_id IS NOT NULL AND request.outcome IS NULL
    ) THEN
        RAISE EXCEPTION 'facets require an open employee search request' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_source_facet_guard BEFORE INSERT ON thalion.delivery_record
FOR EACH ROW WHEN (NEW.source_facets) EXECUTE FUNCTION thalion.guard_source_facet_receipt();
