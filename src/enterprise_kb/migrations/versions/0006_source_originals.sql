ALTER TABLE thalion.object_identity
    DROP CONSTRAINT object_identity_object_type_check,
    DROP CONSTRAINT object_identity_check,
    ADD CONSTRAINT object_identity_shape CHECK (
        (object_type = 'principal' AND space_id IS NULL)
        OR (object_type = 'space' AND space_id IS NOT NULL AND space_id = object_id)
        OR (object_type IN ('source', 'document', 'document_version') AND space_id IS NOT NULL)
    ),
    ADD CONSTRAINT object_identity_scoped_type UNIQUE (org_id, space_id, object_type, object_id);

CREATE TABLE thalion.source (
    source_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    identity_type text GENERATED ALWAYS AS ('source'::text) STORED,
    source_key text NOT NULL CHECK (char_length(source_key) BETWEEN 1 AND 128),
    owner_principal_id bigint NOT NULL,
    lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'suspended')),
    contract_revision bigint NOT NULL DEFAULT 1 CHECK (contract_revision > 0),
    UNIQUE (org_id, space_id, source_id),
    UNIQUE (org_id, space_id, source_key),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, owner_principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, identity_type, source_id)
        REFERENCES thalion.object_identity (org_id, space_id, object_type, object_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE thalion.source_contract_revision (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    admission text NOT NULL CHECK (admission = 'synthetic_only'),
    collector_id bigint NOT NULL,
    object_namespace text NOT NULL CHECK (char_length(object_namespace) BETWEEN 1 AND 128),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, source_id) REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, collector_id) REFERENCES thalion.principal (org_id, principal_id)
);

ALTER TABLE thalion.source ADD CONSTRAINT source_current_contract
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision)
        DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE thalion.document (
    document_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    identity_type text GENERATED ALWAYS AS ('document'::text) STORED,
    source_object_key text NOT NULL CHECK (char_length(source_object_key) BETWEEN 1 AND 128),
    incarnation text NOT NULL CHECK (char_length(incarnation) BETWEEN 1 AND 128),
    display_name text NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 300),
    UNIQUE (org_id, space_id, source_id, document_id),
    UNIQUE (org_id, space_id, source_id, source_object_key, incarnation),
    FOREIGN KEY (org_id, space_id, source_id) REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, space_id, identity_type, document_id)
        REFERENCES thalion.object_identity (org_id, space_id, object_type, object_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE thalion.asset (
    asset_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    storage_kind text NOT NULL CHECK (storage_kind = 'synthetic_file'),
    storage_key text NOT NULL CHECK (storage_key ~ '^[0-9a-f]{64}$'),
    media_type text NOT NULL CHECK (media_type = 'text/markdown'),
    byte_length bigint NOT NULL CHECK (byte_length > 0),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    UNIQUE (storage_kind, storage_key),
    UNIQUE (org_id, space_id, source_id, document_id, asset_id),
    FOREIGN KEY (org_id, space_id, source_id, document_id)
        REFERENCES thalion.document (org_id, space_id, source_id, document_id)
);

CREATE TABLE thalion.document_version (
    version_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    identity_type text GENERATED ALWAYS AS ('document_version'::text) STORED,
    contract_revision bigint NOT NULL,
    asset_id uuid NOT NULL UNIQUE,
    source_version_key text NOT NULL CHECK (char_length(source_version_key) BETWEEN 1 AND 128),
    version_label text NOT NULL CHECK (char_length(btrim(version_label)) BETWEEN 1 AND 128),
    registration_sequence bigint NOT NULL CHECK (registration_sequence > 0),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (document_id, source_version_key),
    UNIQUE (document_id, registration_sequence),
    FOREIGN KEY (org_id, space_id, source_id, document_id, asset_id)
        REFERENCES thalion.asset (org_id, space_id, source_id, document_id, asset_id),
    FOREIGN KEY (org_id, space_id, source_id, contract_revision)
        REFERENCES thalion.source_contract_revision (org_id, space_id, source_id, revision),
    FOREIGN KEY (org_id, space_id, identity_type, version_id)
        REFERENCES thalion.object_identity (org_id, space_id, object_type, object_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION thalion.reject_original_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    RAISE EXCEPTION 'registered original metadata is immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER source_contract_immutable BEFORE UPDATE OR DELETE ON thalion.source_contract_revision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER original_asset_immutable BEFORE UPDATE OR DELETE ON thalion.asset
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER document_version_immutable BEFORE UPDATE OR DELETE ON thalion.document_version
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER source_stable_identity
BEFORE UPDATE OF org_id, space_id, source_id, source_key ON thalion.source
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER document_stable_identity
BEFORE UPDATE OF org_id, space_id, source_id, document_id, source_object_key, incarnation
ON thalion.document FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE OR REPLACE FUNCTION thalion.verify_identity_entity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    target thalion.object_identity%ROWTYPE;
    entity_exists boolean;
BEGIN
    IF TG_TABLE_NAME = 'object_identity' THEN
        target := NEW;
    ELSE
        SELECT * INTO target FROM thalion.object_identity
        WHERE object_type = TG_TABLE_NAME
          AND object_id = (to_jsonb(OLD) ->> TG_ARGV[0])::bigint AND org_id = OLD.org_id;
        IF NOT FOUND THEN
            RETURN NULL;
        END IF;
    END IF;

    CASE target.object_type
        WHEN 'principal' THEN
            SELECT EXISTS (
                SELECT 1 FROM thalion.principal
                WHERE principal_id = target.object_id AND org_id = target.org_id
            ) INTO entity_exists;
        WHEN 'space' THEN
            SELECT EXISTS (
                SELECT 1 FROM thalion.space
                WHERE space_id = target.object_id AND org_id = target.org_id
            ) INTO entity_exists;
        WHEN 'source' THEN
            SELECT EXISTS (
                SELECT 1 FROM thalion.source
                WHERE source_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
            ) INTO entity_exists;
        WHEN 'document' THEN
            SELECT EXISTS (
                SELECT 1 FROM thalion.document
                WHERE document_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
            ) INTO entity_exists;
        WHEN 'document_version' THEN
            SELECT EXISTS (
                SELECT 1 FROM thalion.document_version
                WHERE version_id = target.object_id AND (org_id, space_id) = (target.org_id, target.space_id)
            ) INTO entity_exists;
        ELSE
            entity_exists := false;
    END CASE;

    IF NOT entity_exists THEN
        RAISE EXCEPTION 'registered identity requires matching entity in its scope'
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER principal_identity_survives ON thalion.principal;
CREATE CONSTRAINT TRIGGER principal_identity_survives
AFTER DELETE ON thalion.principal DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION thalion.verify_identity_entity('principal_id');
DROP TRIGGER space_identity_survives ON thalion.space;
CREATE CONSTRAINT TRIGGER space_identity_survives
AFTER DELETE ON thalion.space DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION thalion.verify_identity_entity('space_id');
CREATE CONSTRAINT TRIGGER source_identity_survives
AFTER DELETE ON thalion.source DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION thalion.verify_identity_entity('source_id');
CREATE CONSTRAINT TRIGGER document_identity_survives
AFTER DELETE ON thalion.document DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION thalion.verify_identity_entity('document_id');
