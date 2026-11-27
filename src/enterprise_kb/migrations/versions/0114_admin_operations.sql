CREATE TABLE thalion.directory_department (
    department_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL REFERENCES thalion.organization (org_id),
    parent_ref uuid,
    external_key text NOT NULL CHECK (char_length(btrim(external_key)) BETWEEN 1 AND 255),
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 255),
    path text NOT NULL CHECK (char_length(btrim(path)) BETWEEN 1 AND 2048),
    active boolean NOT NULL DEFAULT true,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, department_ref),
    UNIQUE (org_id, external_key),
    FOREIGN KEY (org_id, parent_ref) REFERENCES thalion.directory_department (org_id, department_ref)
);

CREATE INDEX directory_department_search
    ON thalion.directory_department (org_id, active, lower(name), department_ref);

CREATE TABLE thalion.principal_directory_profile (
    org_id bigint NOT NULL,
    principal_id bigint NOT NULL,
    department_ref uuid,
    external_key text,
    display_name text NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 255),
    employee_number text CHECK (employee_number IS NULL OR char_length(btrim(employee_number)) BETWEEN 1 AND 128),
    email text CHECK (email IS NULL OR char_length(btrim(email)) BETWEEN 3 AND 320),
    title text CHECK (title IS NULL OR char_length(btrim(title)) BETWEEN 1 AND 255),
    directory_state text NOT NULL DEFAULT 'active'
        CHECK (directory_state IN ('active', 'disabled', 'departed', 'conflict')),
    source text NOT NULL DEFAULT 'local'
        CHECK (source IN ('local', 'csv', 'oidc', 'scim', 'ldap')),
    last_synced_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, principal_id),
    UNIQUE (org_id, external_key),
    UNIQUE (org_id, employee_number),
    FOREIGN KEY (org_id, principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, department_ref) REFERENCES thalion.directory_department (org_id, department_ref)
);

CREATE INDEX principal_directory_profile_search
    ON thalion.principal_directory_profile (org_id, directory_state, lower(display_name), principal_id);
CREATE INDEX principal_directory_profile_department
    ON thalion.principal_directory_profile (org_id, department_ref, directory_state, principal_id);

CREATE TABLE thalion.directory_group_membership (
    org_id bigint NOT NULL,
    group_id bigint NOT NULL,
    member_id bigint NOT NULL,
    source text NOT NULL DEFAULT 'local'
        CHECK (source IN ('local', 'csv', 'oidc', 'scim', 'ldap')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, group_id, member_id),
    CHECK (group_id <> member_id),
    FOREIGN KEY (org_id, group_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, member_id) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE INDEX directory_group_membership_member
    ON thalion.directory_group_membership (org_id, member_id, group_id);

CREATE TABLE thalion.admin_role_assignment (
    assignment_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    principal_id bigint NOT NULL,
    space_id bigint,
    role_key text NOT NULL CHECK (role_key IN (
        'organization_admin', 'space_admin', 'reviewer', 'content_owner', 'knowledge_operator', 'auditor'
    )),
    assigned_by bigint NOT NULL,
    active boolean NOT NULL DEFAULT true,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE NULLS NOT DISTINCT (org_id, principal_id, space_id, role_key),
    FOREIGN KEY (org_id, principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, assigned_by) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE INDEX admin_role_assignment_scope
    ON thalion.admin_role_assignment (org_id, space_id, role_key, active, principal_id);

CREATE TABLE thalion.directory_sync_run (
    sync_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL REFERENCES thalion.organization (org_id),
    requested_by bigint NOT NULL,
    source text NOT NULL CHECK (source IN ('csv', 'oidc', 'scim', 'ldap')),
    state text NOT NULL DEFAULT 'preview'
        CHECK (state IN ('preview', 'running', 'succeeded', 'partial_failure', 'failed')),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    total_rows integer NOT NULL DEFAULT 0 CHECK (total_rows >= 0),
    applied_rows integer NOT NULL DEFAULT 0 CHECK (applied_rows >= 0),
    rejected_rows integer NOT NULL DEFAULT 0 CHECK (rejected_rows >= 0),
    error_report jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    FOREIGN KEY (org_id, requested_by) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE TABLE thalion.admin_task (
    task_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    task_type text NOT NULL CHECK (task_type IN (
        'review_due', 'source_sync_failure', 'permission_change', 'feedback', 'knowledge_gap',
        'document_expiry', 'wiki_review', 'directory_conflict', 'batch_import'
    )),
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'claimed', 'snoozed', 'done', 'cancelled')),
    priority text NOT NULL DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    title text NOT NULL CHECK (char_length(btrim(title)) BETWEEN 1 AND 500),
    description text CHECK (description IS NULL OR char_length(description) <= 10000),
    owner_principal_id bigint,
    collaborator_principal_id bigint,
    subject_ref uuid,
    due_at timestamptz,
    sla_due_at timestamptz,
    escalation_level smallint NOT NULL DEFAULT 0 CHECK (escalation_level >= 0),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, owner_principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, collaborator_principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, subject_ref) REFERENCES thalion.object_identity (org_id, public_id),
    FOREIGN KEY (org_id, created_by) REFERENCES thalion.principal (org_id, principal_id),
    CHECK (sla_due_at IS NULL OR due_at IS NULL OR sla_due_at >= due_at),
    CHECK ((status = 'done') = (completed_at IS NOT NULL)),
    UNIQUE (org_id, task_ref)
);

CREATE INDEX admin_task_queue
    ON thalion.admin_task (org_id, space_id, status, priority, coalesce(sla_due_at, due_at), task_ref);
CREATE INDEX admin_task_owner
    ON thalion.admin_task (org_id, owner_principal_id, status, coalesce(sla_due_at, due_at), task_ref);

CREATE TABLE thalion.notification_preference (
    org_id bigint NOT NULL,
    principal_id bigint NOT NULL,
    event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    channel text NOT NULL CHECK (channel IN ('in_app', 'email', 'im_webhook')),
    enabled boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, principal_id, event_type, channel),
    FOREIGN KEY (org_id, principal_id) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE TABLE thalion.notification_delivery (
    delivery_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    task_ref uuid,
    event_id uuid,
    recipient_id bigint NOT NULL,
    event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    channel text NOT NULL CHECK (channel IN ('in_app', 'email', 'im_webhook')),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sending', 'sent', 'retry', 'dead', 'cancelled')),
    dedupe_key text NOT NULL CHECK (char_length(btrim(dedupe_key)) BETWEEN 1 AND 255),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error text,
    sent_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, dedupe_key),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, task_ref) REFERENCES thalion.admin_task (org_id, task_ref),
    FOREIGN KEY (org_id, event_id) REFERENCES thalion.outbox_event (org_id, event_id),
    FOREIGN KEY (org_id, recipient_id) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE INDEX notification_delivery_queue
    ON thalion.notification_delivery (org_id, status, next_attempt_at, delivery_ref);
CREATE INDEX notification_delivery_recipient
    ON thalion.notification_delivery (org_id, recipient_id, status, created_at DESC);

CREATE TABLE thalion.admin_audit_event (
    event_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint,
    actor_id bigint NOT NULL,
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    object_ref uuid,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, object_ref) REFERENCES thalion.object_identity (org_id, public_id)
);

CREATE INDEX admin_audit_event_scope
    ON thalion.admin_audit_event (org_id, space_id, recorded_at DESC, event_ref);

ALTER TABLE thalion.wiki_revision
    ADD CONSTRAINT wiki_revision_scope_identity UNIQUE (org_id, space_id, revision_ref);

CREATE TABLE thalion.wiki_comment (
    comment_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    revision_ref uuid NOT NULL,
    parent_ref uuid,
    author_id bigint NOT NULL,
    body text NOT NULL CHECK (char_length(btrim(body)) BETWEEN 1 AND 10000),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'deleted')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_by bigint,
    resolved_at timestamptz,
    FOREIGN KEY (org_id, space_id, revision_ref) REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref),
    FOREIGN KEY (org_id, parent_ref) REFERENCES thalion.wiki_comment (org_id, comment_ref),
    FOREIGN KEY (org_id, author_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, resolved_by) REFERENCES thalion.principal (org_id, principal_id),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL AND resolved_by IS NOT NULL)),
    UNIQUE (org_id, comment_ref)
);

CREATE INDEX wiki_comment_revision
    ON thalion.wiki_comment (org_id, space_id, revision_ref, status, created_at, comment_ref);

CREATE TABLE thalion.wiki_attachment (
    attachment_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    revision_ref uuid NOT NULL,
    uploader_id bigint NOT NULL,
    object_key text NOT NULL CHECK (char_length(btrim(object_key)) BETWEEN 1 AND 1024),
    file_name text NOT NULL CHECK (char_length(btrim(file_name)) BETWEEN 1 AND 255),
    media_type text NOT NULL CHECK (char_length(btrim(media_type)) BETWEEN 1 AND 255),
    byte_size bigint NOT NULL CHECK (byte_size BETWEEN 1 AND 52428800),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    scan_state text NOT NULL DEFAULT 'pending'
        CHECK (scan_state IN ('pending', 'clean', 'quarantined', 'failed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, revision_ref) REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref),
    FOREIGN KEY (org_id, uploader_id) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE INDEX wiki_attachment_revision
    ON thalion.wiki_attachment (org_id, space_id, revision_ref, scan_state, created_at);
