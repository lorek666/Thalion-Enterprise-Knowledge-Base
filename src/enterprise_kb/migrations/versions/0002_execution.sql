ALTER TABLE thalion.object_identity
    ADD CONSTRAINT object_identity_org_public UNIQUE (org_id, public_id),
    ADD CONSTRAINT object_identity_space_public UNIQUE (org_id, space_id, public_id);

CREATE TABLE thalion.command_receipt (
    receipt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL REFERENCES thalion.organization (org_id),
    principal_id bigint NOT NULL,
    delegated_principal_id bigint,
    request_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    key_digest bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    configuration_revision bigint NOT NULL CHECK (configuration_revision > 0),
    expected_generation bigint CHECK (expected_generation > 0),
    result_ref uuid,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    FOREIGN KEY (org_id, principal_id)
        REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, delegated_principal_id)
        REFERENCES thalion.principal (org_id, principal_id),
    UNIQUE NULLS NOT DISTINCT (org_id, principal_id, delegated_principal_id, operation, key_digest),
    CHECK (result_ref IS NULL OR completed_at IS NOT NULL)
);

CREATE TABLE thalion.outbox_event (
    org_id bigint NOT NULL,
    event_id uuid NOT NULL DEFAULT gen_random_uuid(),
    event_type text NOT NULL CHECK (event_type ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    object_ref uuid NOT NULL,
    schema_revision integer NOT NULL CHECK (schema_revision > 0),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, event_id),
    FOREIGN KEY (org_id, object_ref) REFERENCES thalion.object_identity (org_id, public_id)
);

CREATE INDEX outbox_event_order ON thalion.outbox_event (org_id, occurred_at, event_id);

CREATE TABLE thalion.event_consumption (
    org_id bigint NOT NULL,
    event_id uuid NOT NULL,
    consumer text NOT NULL CHECK (consumer ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    processed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, event_id, consumer),
    FOREIGN KEY (org_id, event_id) REFERENCES thalion.outbox_event (org_id, event_id)
);

CREATE TABLE thalion.job (
    org_id bigint NOT NULL REFERENCES thalion.organization (org_id),
    job_id uuid NOT NULL DEFAULT gen_random_uuid(),
    space_id bigint NOT NULL,
    target_ref uuid NOT NULL,
    stage text NOT NULL CHECK (stage ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    configuration_revision bigint NOT NULL CHECK (configuration_revision > 0),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    result_ref uuid,
    PRIMARY KEY (org_id, job_id),
    UNIQUE (org_id, space_id, target_ref, stage, input_digest, configuration_revision),
    FOREIGN KEY (org_id, space_id, target_ref)
        REFERENCES thalion.object_identity (org_id, space_id, public_id),
    CHECK ((state = 'succeeded') = (result_ref IS NOT NULL)),
    CHECK (state = 'queued' OR generation > 0)
);

CREATE INDEX job_claim_order ON thalion.job (org_id, stage, available_at, job_id)
    WHERE state IN ('queued', 'running');

CREATE TABLE thalion.job_attempt (
    attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    job_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    worker_id bigint NOT NULL,
    started_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    finished_at timestamptz,
    outcome text NOT NULL DEFAULT 'running'
        CHECK (outcome IN ('running', 'expired', 'retry', 'succeeded')),
    UNIQUE (org_id, job_id, generation),
    FOREIGN KEY (org_id, job_id) REFERENCES thalion.job (org_id, job_id),
    FOREIGN KEY (org_id, worker_id) REFERENCES thalion.principal (org_id, principal_id),
    CHECK (lease_expires_at > started_at),
    CHECK ((outcome = 'running') = (finished_at IS NULL))
);

CREATE UNIQUE INDEX job_single_running_attempt ON thalion.job_attempt (org_id, job_id)
    WHERE outcome = 'running';
