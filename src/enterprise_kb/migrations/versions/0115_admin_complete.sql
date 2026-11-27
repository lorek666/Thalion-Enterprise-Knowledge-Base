CREATE TABLE thalion.directory_sync_item (
    sync_ref uuid NOT NULL,
    row_number integer NOT NULL CHECK (row_number > 0),
    external_key text NOT NULL CHECK (char_length(btrim(external_key)) BETWEEN 1 AND 255),
    operation text NOT NULL CHECK (operation IN ('create', 'update', 'disable', 'conflict', 'skip')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'rejected', 'skipped')),
    principal_id bigint,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_code text,
    error_detail text,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (sync_ref, row_number),
    FOREIGN KEY (sync_ref) REFERENCES thalion.directory_sync_run (sync_ref),
    FOREIGN KEY (principal_id) REFERENCES thalion.principal (principal_id)
);

ALTER TABLE thalion.directory_sync_run
    ADD COLUMN IF NOT EXISTS idempotency_key text;
CREATE UNIQUE INDEX IF NOT EXISTS directory_sync_run_idempotency
    ON thalion.directory_sync_run (org_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX directory_sync_item_status
    ON thalion.directory_sync_item (sync_ref, status, row_number);

CREATE TABLE thalion.directory_group_mapping (
    mapping_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    external_group_key text NOT NULL CHECK (char_length(btrim(external_group_key)) BETWEEN 1 AND 255),
    local_group_id bigint,
    role_key text CHECK (role_key IS NULL OR role_key IN (
        'organization_admin', 'space_admin', 'reviewer', 'content_owner', 'knowledge_operator', 'auditor'
    )),
    space_id bigint,
    precedence integer NOT NULL DEFAULT 100 CHECK (precedence BETWEEN 0 AND 10000),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'conflict')),
    created_by bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, external_group_key, role_key, space_id),
    FOREIGN KEY (org_id, local_group_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, created_by) REFERENCES thalion.principal (org_id, principal_id),
    CHECK (local_group_id IS NOT NULL OR role_key IS NOT NULL OR space_id IS NOT NULL)
);

CREATE INDEX directory_group_mapping_lookup
    ON thalion.directory_group_mapping (org_id, external_group_key, status, precedence);

CREATE TABLE thalion.space_membership (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    principal_id bigint NOT NULL,
    membership_kind text NOT NULL CHECK (membership_kind IN ('direct', 'inherited')),
    inherited_from_group_id bigint,
    active boolean NOT NULL DEFAULT true,
    assigned_by bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id, principal_id),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, inherited_from_group_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, assigned_by) REFERENCES thalion.principal (org_id, principal_id),
    CHECK ((membership_kind = 'inherited') = (inherited_from_group_id IS NOT NULL))
);

CREATE INDEX space_membership_principal
    ON thalion.space_membership (org_id, principal_id, active, space_id);

CREATE TABLE thalion.space_settings (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    wiki_enabled boolean NOT NULL DEFAULT true,
    default_reader_scope text NOT NULL DEFAULT 'explicit'
        CHECK (default_reader_scope IN ('explicit', 'members', 'department')),
    notification_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    retention_days integer CHECK (retention_days IS NULL OR retention_days BETWEEN 1 AND 36500),
    updated_by bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, space_id),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, updated_by) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE TABLE thalion.admin_access_grant (
    grant_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    source_id bigint,
    subject_kind text NOT NULL CHECK (subject_kind IN ('principal', 'group', 'department')),
    subject_principal_id bigint,
    subject_department_ref uuid,
    effect text NOT NULL CHECK (effect IN ('allow', 'deny')),
    inherited boolean NOT NULL DEFAULT false,
    parent_grant_ref uuid,
    active boolean NOT NULL DEFAULT true,
    assigned_by bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, space_id, source_id) REFERENCES thalion.source (org_id, space_id, source_id),
    FOREIGN KEY (org_id, subject_principal_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, subject_department_ref) REFERENCES thalion.directory_department (org_id, department_ref),
    FOREIGN KEY (org_id, assigned_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (grant_ref) REFERENCES thalion.admin_access_grant (grant_ref),
    CHECK ((subject_kind = 'department') = (subject_department_ref IS NOT NULL)),
    CHECK ((subject_kind IN ('principal', 'group')) = (subject_principal_id IS NOT NULL)),
    CHECK (NOT inherited OR parent_grant_ref IS NOT NULL)
);

CREATE INDEX admin_access_grant_scope
    ON thalion.admin_access_grant (org_id, space_id, source_id, active, subject_kind);

CREATE TABLE thalion.admin_batch_operation (
    operation_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    actor_id bigint NOT NULL,
    action text NOT NULL CHECK (action IN ('add', 'revoke', 'replace', 'copy')),
    state text NOT NULL DEFAULT 'preview'
        CHECK (state IN ('preview', 'running', 'succeeded', 'partial_failure', 'failed')),
    idempotency_key text NOT NULL CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (org_id, idempotency_key),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE TABLE thalion.admin_batch_item (
    operation_ref uuid NOT NULL,
    row_number integer NOT NULL CHECK (row_number > 0),
    subject_kind text NOT NULL CHECK (subject_kind IN ('principal', 'group', 'department')),
    subject_ref uuid NOT NULL,
    source_ref uuid,
    effect text NOT NULL CHECK (effect IN ('allow', 'deny', 'revoke')),
    outcome text NOT NULL DEFAULT 'pending'
        CHECK (outcome IN ('pending', 'added', 'removed', 'skipped', 'failed', 'manual_review')),
    error_code text,
    error_detail text,
    grant_ref uuid,
    PRIMARY KEY (operation_ref, row_number),
    FOREIGN KEY (operation_ref) REFERENCES thalion.admin_batch_operation (operation_ref),
    FOREIGN KEY (grant_ref) REFERENCES thalion.admin_access_grant (grant_ref)
);

CREATE TABLE thalion.admin_sla_policy (
    policy_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint,
    task_type text NOT NULL,
    warn_before_minutes integer NOT NULL DEFAULT 1440 CHECK (warn_before_minutes >= 0),
    due_minutes integer NOT NULL CHECK (due_minutes > 0),
    escalate_after_minutes integer NOT NULL DEFAULT 60 CHECK (escalate_after_minutes >= 0),
    escalation_role text CHECK (escalation_role IS NULL OR escalation_role IN (
        'organization_admin', 'space_admin', 'reviewer', 'content_owner', 'knowledge_operator', 'auditor'
    )),
    enabled boolean NOT NULL DEFAULT true,
    updated_by bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, task_type),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, updated_by) REFERENCES thalion.principal (org_id, principal_id)
);

ALTER TABLE thalion.admin_task
    ADD COLUMN IF NOT EXISTS snoozed_until timestamptz,
    ADD COLUMN IF NOT EXISTS claimed_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_escalated_at timestamptz,
    ADD COLUMN IF NOT EXISTS escalation_chain bigint[] NOT NULL DEFAULT '{}';

CREATE TABLE thalion.admin_task_history (
    history_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    task_ref uuid NOT NULL,
    actor_id bigint NOT NULL,
    action text NOT NULL CHECK (action IN ('created', 'claimed', 'assigned', 'snoozed', 'reopened', 'completed', 'cancelled', 'escalated', 'commented')),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, task_ref) REFERENCES thalion.admin_task (org_id, task_ref),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id)
);

CREATE INDEX admin_task_history_task
    ON thalion.admin_task_history (org_id, task_ref, recorded_at, history_ref);

CREATE TABLE thalion.notification_endpoint (
    endpoint_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    principal_id bigint NOT NULL,
    channel text NOT NULL CHECK (channel IN ('email', 'im_webhook')),
    address text NOT NULL CHECK (char_length(btrim(address)) BETWEEN 3 AND 2048),
    secret_ref text,
    enabled boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, principal_id, channel),
    FOREIGN KEY (org_id, principal_id) REFERENCES thalion.principal (org_id, principal_id)
);

ALTER TABLE thalion.notification_delivery
    ADD COLUMN IF NOT EXISTS template_key text NOT NULL DEFAULT 'admin.default',
    ADD COLUMN IF NOT EXISTS message_digest bytea,
    ADD COLUMN IF NOT EXISTS locked_at timestamptz,
    ADD COLUMN IF NOT EXISTS read_at timestamptz;

CREATE TABLE thalion.notification_delivery_attempt (
    attempt_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    delivery_ref uuid NOT NULL,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    status text NOT NULL CHECK (status IN ('sent', 'retry', 'dead')),
    error_code text,
    error_detail text,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at timestamptz,
    UNIQUE (delivery_ref, attempt_number),
    FOREIGN KEY (delivery_ref) REFERENCES thalion.notification_delivery (delivery_ref)
);

ALTER TABLE thalion.wiki_comment
    ALTER COLUMN revision_ref DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS draft_ref uuid;

ALTER TABLE thalion.wiki_comment
    ADD CONSTRAINT wiki_comment_target CHECK ((revision_ref IS NOT NULL) <> (draft_ref IS NOT NULL));

CREATE TABLE thalion.wiki_collaboration_draft (
    draft_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    topic_key text NOT NULL,
    author_id bigint NOT NULL,
    reviewer_id bigint,
    based_revision_ref uuid,
    content_format text NOT NULL CHECK (content_format IN ('markdown', 'blocks')),
    markdown text NOT NULL CHECK (char_length(btrim(markdown)) BETWEEN 1 AND 131072),
    blocks jsonb NOT NULL DEFAULT '[]'::jsonb,
    sanitized_digest bytea NOT NULL CHECK (octet_length(sanitized_digest) = 32),
    status text NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'in_review', 'rejected', 'approved', 'archived')),
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (org_id, space_id, topic_key) REFERENCES thalion.wiki (org_id, space_id, topic_key),
    FOREIGN KEY (org_id, author_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, based_revision_ref) REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref)
);

CREATE INDEX wiki_collaboration_draft_queue
    ON thalion.wiki_collaboration_draft (org_id, space_id, status, updated_at DESC, draft_ref);

CREATE TABLE thalion.wiki_draft_version (
    draft_ref uuid NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    saved_by bigint NOT NULL,
    markdown text NOT NULL CHECK (char_length(btrim(markdown)) BETWEEN 1 AND 131072),
    blocks jsonb NOT NULL DEFAULT '[]'::jsonb,
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (draft_ref, version),
    FOREIGN KEY (draft_ref) REFERENCES thalion.wiki_collaboration_draft (draft_ref),
    FOREIGN KEY (saved_by) REFERENCES thalion.principal (principal_id)
);

CREATE TABLE thalion.wiki_comment_mention (
    comment_ref uuid NOT NULL,
    mentioned_principal_id bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (comment_ref, mentioned_principal_id),
    FOREIGN KEY (comment_ref) REFERENCES thalion.wiki_comment (comment_ref),
    FOREIGN KEY (mentioned_principal_id) REFERENCES thalion.principal (principal_id)
);

CREATE TABLE thalion.wiki_review_assignment (
    assignment_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    draft_ref uuid,
    revision_ref uuid,
    reviewer_id bigint NOT NULL,
    assigned_by bigint NOT NULL,
    status text NOT NULL DEFAULT 'assigned' CHECK (status IN ('assigned', 'accepted', 'rejected', 'completed', 'cancelled')),
    due_at timestamptz,
    reason text CHECK (reason IS NULL OR char_length(reason) <= 2000),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, draft_ref, revision_ref),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (draft_ref) REFERENCES thalion.wiki_collaboration_draft (draft_ref),
    FOREIGN KEY (org_id, space_id, revision_ref) REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref),
    FOREIGN KEY (org_id, reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, assigned_by) REFERENCES thalion.principal (org_id, principal_id),
    CHECK ((draft_ref IS NOT NULL) <> (revision_ref IS NOT NULL))
);

CREATE INDEX wiki_review_assignment_queue
    ON thalion.wiki_review_assignment (org_id, space_id, status, due_at, assignment_ref);

CREATE UNIQUE INDEX IF NOT EXISTS space_name_per_org
    ON thalion.space (org_id, lower(btrim(name)));
