CREATE TABLE thalion.glossary_entry (
    entry_ref uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    term text NOT NULL CHECK (char_length(btrim(term)) BETWEEN 1 AND 120),
    normalized_term text NOT NULL CHECK (char_length(normalized_term) BETWEEN 1 AND 120),
    synonyms text[] NOT NULL DEFAULT '{}'::text[] CHECK (cardinality(synonyms) <= 32),
    definition text NOT NULL CHECK (char_length(btrim(definition)) BETWEEN 1 AND 2000),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by bigint NOT NULL,
    updated_by bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, entry_ref),
    UNIQUE (org_id, space_id, normalized_term),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, created_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, updated_by) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE INDEX glossary_entry_active_lookup
    ON thalion.glossary_entry (org_id, space_id, status, normalized_term);

CREATE TABLE thalion.glossary_audit_event (
    event_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    entry_ref uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    action text NOT NULL CHECK (action IN ('created', 'updated', 'deactivated', 'reactivated')),
    term text NOT NULL CHECK (char_length(btrim(term)) BETWEEN 1 AND 120),
    synonyms text[] NOT NULL DEFAULT '{}'::text[] CHECK (cardinality(synonyms) <= 32),
    definition text NOT NULL CHECK (char_length(btrim(definition)) BETWEEN 1 AND 2000),
    status text NOT NULL CHECK (status IN ('active', 'inactive')),
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, entry_ref)
        REFERENCES thalion.glossary_entry (org_id, space_id, entry_ref),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE TRIGGER glossary_audit_event_immutable BEFORE UPDATE OR DELETE ON thalion.glossary_audit_event
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER glossary_audit_event_no_truncate BEFORE TRUNCATE ON thalion.glossary_audit_event
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.document_department (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    department_code text NOT NULL CHECK (department_code ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    department_name text NOT NULL CHECK (char_length(btrim(department_name)) BETWEEN 1 AND 120),
    assigned_by bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, source_id, document_id),
    FOREIGN KEY (org_id, space_id, source_id, document_id)
        REFERENCES thalion.document (org_id, space_id, source_id, document_id),
    FOREIGN KEY (org_id, assigned_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE INDEX document_department_lookup
    ON thalion.document_department (org_id, space_id, department_code);

CREATE TABLE thalion.document_department_event (
    event_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    document_id bigint NOT NULL,
    action text NOT NULL CHECK (action IN ('assigned', 'cleared')),
    department_code text CHECK (department_code IS NULL OR department_code ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    department_name text CHECK (department_name IS NULL OR char_length(btrim(department_name)) BETWEEN 1 AND 120),
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, source_id, document_id)
        REFERENCES thalion.document (org_id, space_id, source_id, document_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CHECK (
        (action = 'assigned' AND department_code IS NOT NULL AND department_name IS NOT NULL)
        OR (action = 'cleared' AND department_code IS NULL AND department_name IS NULL)
    )
);

CREATE TRIGGER document_department_event_immutable BEFORE UPDATE OR DELETE ON thalion.document_department_event
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER document_department_event_no_truncate BEFORE TRUNCATE ON thalion.document_department_event
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
