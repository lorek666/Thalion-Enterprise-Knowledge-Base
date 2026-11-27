CREATE TABLE thalion.archive_wiki_rebuild (
    revision_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    origin_org_id bigint NOT NULL CHECK (origin_org_id > 0),
    origin_space_id bigint NOT NULL CHECK (origin_space_id > 0),
    export_ref uuid NOT NULL,
    archive_digest bytea NOT NULL CHECK (octet_length(archive_digest) = 32),
    anchor_ref uuid NOT NULL REFERENCES thalion.object_identity (public_id),
    topic_key text NOT NULL CHECK (topic_key ~ '^[a-z][a-z0-9_-]{0,63}$'),
    content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 131072),
    manifest_graph jsonb NOT NULL CHECK (jsonb_typeof(manifest_graph -> 'manifests') IS NOT DISTINCT FROM 'array'),
    dependencies jsonb NOT NULL CHECK (jsonb_typeof(dependencies -> 'inputs') IS NOT DISTINCT FROM 'array'),
    rebuilt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    UNIQUE (origin_org_id, origin_space_id, export_ref),
    CHECK (dependencies ->> 'revision_id' IS NOT DISTINCT FROM revision_ref::text),
    CHECK (dependencies ->> 'content_sha256' IS NOT DISTINCT FROM encode(sha256(content), 'hex'))
);

CREATE FUNCTION thalion.guard_wiki_rebuild_rehearsal() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_db_role_setting AS setting
        JOIN pg_database AS db ON db.oid = setting.setdatabase
        WHERE db.datname = current_database() AND setting.setrole = 0
          AND ('thalion.restore_rehearsal=' || current_database()) = ANY(setting.setconfig)
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.space AS space
        JOIN thalion.object_identity AS identity USING (org_id, space_id)
        WHERE (space.org_id, space.space_id, space.lifecycle) = (NEW.org_id, NEW.space_id, 'archived')
          AND (identity.public_id, identity.object_type) = (NEW.anchor_ref, 'document_version')
    ) THEN
        RAISE EXCEPTION 'Wiki reconstruction records require a fenced database and archived scope'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER archive_wiki_rebuild_fenced BEFORE INSERT ON thalion.archive_wiki_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.guard_wiki_rebuild_rehearsal();

CREATE TRIGGER archive_wiki_rebuild_immutable BEFORE UPDATE OR DELETE ON thalion.archive_wiki_rebuild
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
