CREATE OR REPLACE VIEW thalion.synthetic_export_target AS
SELECT * FROM thalion.synthetic_original_export_target;

CREATE OR REPLACE FUNCTION thalion.pdf_export_scope_admitted(candidate thalion.synthetic_export_request)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, thalion AS $$
    SELECT candidate.wiki_rebuild_digest IS NULL;
$$;

CREATE OR REPLACE FUNCTION thalion.guard_export_wiki_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    candidate thalion.synthetic_export_request%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'synthetic_export_request' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO STRICT candidate FROM thalion.synthetic_export_request AS request
        WHERE (request.org_id, request.space_id, request.export_ref, request.requester_id) =
              (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
    END IF;
    IF candidate.wiki_publication_ref IS NOT NULL THEN
        PERFORM thalion.lock_synthetic_wiki_export(candidate.org_id, candidate.space_id, candidate.wiki_publication_ref);
        IF NOT thalion.export_wiki_is_current(candidate.org_id, candidate.space_id, candidate.version_id, candidate.wiki_publication_ref)
          OR (candidate.wiki_rebuild_digest IS NOT NULL AND EXISTS (
                SELECT 1 FROM thalion.wiki_archive_input AS input
                JOIN thalion.synthetic_export_target AS target USING (org_id, space_id, version_id)
                WHERE (input.org_id, input.space_id, input.publication_ref) =
                      (candidate.org_id, candidate.space_id, candidate.wiki_publication_ref)
                  AND target.media_type <> 'text/markdown'
            ))
        THEN
            RAISE EXCEPTION 'Wiki archive requires the current exact publication and all supported inputs in the approved source'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
