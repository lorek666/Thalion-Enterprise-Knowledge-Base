ALTER TABLE thalion.wiki ADD COLUMN wiki_ref uuid NOT NULL UNIQUE DEFAULT gen_random_uuid();
ALTER TABLE thalion.wiki_revision ADD COLUMN has_statements boolean NOT NULL DEFAULT false;

CREATE FUNCTION thalion.verify_wiki_statements() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    content jsonb := convert_from(NEW.content, 'UTF8')::jsonb;
    statement jsonb;
    supports jsonb;
BEGIN
    NEW.has_statements := content ? 'statements';
    IF NOT NEW.has_statements THEN
        RETURN NEW;
    END IF;
    IF jsonb_typeof(content -> 'statements') IS DISTINCT FROM 'array'
       OR jsonb_typeof(content -> 'title') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION 'invalid Wiki statement encoding' USING ERRCODE = '23514';
    END IF;
    IF jsonb_array_length(content -> 'statements') NOT BETWEEN 1 AND 20 OR
       char_length(btrim(content ->> 'title')) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'invalid Wiki statement count or title' USING ERRCODE = '23514';
    END IF;
    FOR statement IN SELECT value FROM jsonb_array_elements(content -> 'statements') LOOP
        IF jsonb_typeof(statement -> 'text') IS DISTINCT FROM 'string'
           OR char_length(btrim(statement ->> 'text')) NOT BETWEEN 1 AND 2000
           OR jsonb_typeof(statement -> 'support_groups') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'Wiki statements require text and explicit support groups' USING ERRCODE = '23514';
        END IF;
        IF jsonb_array_length(statement -> 'support_groups') NOT BETWEEN 1 AND 20 THEN
            RAISE EXCEPTION 'invalid Wiki support group count' USING ERRCODE = '23514';
        END IF;
        FOR supports IN SELECT value FROM jsonb_array_elements(statement -> 'support_groups') LOOP
            IF jsonb_typeof(supports) IS DISTINCT FROM 'array' THEN
                RAISE EXCEPTION 'Wiki support group must be an array' USING ERRCODE = '23514';
            END IF;
            IF jsonb_array_length(supports) NOT BETWEEN 1 AND 20 OR jsonb_array_length(supports) <> (
                SELECT count(DISTINCT value) FROM jsonb_array_elements(supports)
            ) OR EXISTS (
                SELECT jsonb_array_elements(supports)
                EXCEPT
                SELECT jsonb_build_array(passage_ref, excerpt_revision)
                FROM thalion.input_manifest_entry
                WHERE manifest_ref = NEW.manifest_ref AND (org_id, space_id) = (NEW.org_id, NEW.space_id)
                  AND (content -> 'citations') @> jsonb_build_array(jsonb_build_array(passage_ref, excerpt_revision))
            ) THEN
                RAISE EXCEPTION 'Wiki statement support must use exact declared citations from its own seal' USING ERRCODE = '23514';
            END IF;
        END LOOP;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER wiki_statement_support BEFORE INSERT ON thalion.wiki_revision
FOR EACH ROW EXECUTE FUNCTION thalion.verify_wiki_statements();

ALTER TABLE thalion.wiki_publication_event ADD UNIQUE (org_id, publication_ref);
ALTER TABLE thalion.delivery_record DROP CONSTRAINT delivery_record_dependency_count_check,
    ADD COLUMN wiki_publication_ref uuid,
    ADD FOREIGN KEY (org_id, wiki_publication_ref) REFERENCES thalion.wiki_publication_event (org_id, publication_ref),
    ADD CONSTRAINT delivery_record_dependency_count_check CHECK (
        dependency_count BETWEEN 1 AND (CASE WHEN wiki_publication_ref IS NULL THEN 20 ELSE 40 END)
    );
ALTER TABLE thalion.delivery_dependency DROP CONSTRAINT delivery_dependency_position_check,
    ADD CONSTRAINT delivery_dependency_position_check CHECK (position BETWEEN 1 AND 40);

CREATE FUNCTION thalion.verify_wiki_search_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        JOIN thalion.current_wiki_publication AS publication USING (org_id)
        JOIN thalion.wiki_revision AS revision USING (org_id, space_id, topic_key, revision_ref)
        WHERE (request.org_id, request.request_id) = (NEW.org_id, NEW.request_id)
          AND request.operation = 'search' AND request.destination = 'employee'
          AND publication.publication_ref = NEW.wiki_publication_ref AND revision.has_statements
    ) OR EXISTS (
        SELECT entry.space_id, entry.source_id, entry.passage_ref, entry.excerpt_revision, entry.policy_revision,
               entry.organization_epoch, entry.space_epoch, entry.source_epoch
        FROM thalion.wiki_publication_event AS publication
        JOIN thalion.delivery_dependency AS entry USING (org_id, check_id)
        WHERE publication.publication_ref = NEW.wiki_publication_ref
        EXCEPT
        SELECT entry.space_id, entry.source_id, entry.passage_ref, entry.excerpt_revision, entry.policy_revision,
               entry.organization_epoch, entry.space_epoch, entry.source_epoch
        FROM thalion.delivery_dependency AS entry WHERE entry.check_id = NEW.check_id
    ) THEN
        RAISE EXCEPTION 'Wiki search delivery requires current reviewed claims and all exact published dependencies'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER wiki_search_receipt_complete AFTER INSERT ON thalion.delivery_record
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.wiki_publication_ref IS NOT NULL)
EXECUTE FUNCTION thalion.verify_wiki_search_receipt();
