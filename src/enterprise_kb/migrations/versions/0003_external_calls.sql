CREATE TABLE thalion.external_call_budget (
    org_id bigint NOT NULL,
    job_id uuid NOT NULL,
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    maximum_microunits bigint NOT NULL CHECK (maximum_microunits >= 0),
    maximum_calls integer NOT NULL CHECK (maximum_calls > 0),
    allow_unknown_retry boolean NOT NULL,
    PRIMARY KEY (org_id, job_id),
    FOREIGN KEY (org_id, job_id) REFERENCES thalion.job (org_id, job_id)
);

CREATE TABLE thalion.external_call (
    org_id bigint NOT NULL,
    job_id uuid NOT NULL,
    generation bigint NOT NULL,
    call_id uuid NOT NULL DEFAULT gen_random_uuid(),
    route text NOT NULL CHECK (route ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    provider_namespace text NOT NULL CHECK (provider_namespace ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    reserved_microunits bigint NOT NULL CHECK (reserved_microunits >= 0),
    state text NOT NULL DEFAULT 'not_sent' CHECK (state IN (
        'not_sent', 'sent', 'outcome_unknown', 'confirmed_success', 'confirmed_failure'
    )),
    reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatched_at timestamptz,
    abandoned_at timestamptz,
    provider_request_digest bytea CHECK (octet_length(provider_request_digest) = 32),
    PRIMARY KEY (org_id, call_id),
    UNIQUE (org_id, job_id, generation),
    UNIQUE (org_id, provider_namespace, provider_request_digest),
    FOREIGN KEY (org_id, job_id) REFERENCES thalion.external_call_budget (org_id, job_id),
    FOREIGN KEY (org_id, job_id, generation)
        REFERENCES thalion.job_attempt (org_id, job_id, generation),
    CHECK ((state = 'not_sent') = (dispatched_at IS NULL)),
    CHECK (abandoned_at IS NULL OR state = 'not_sent'),
    CHECK ((state IN ('confirmed_success', 'confirmed_failure')) = (
        provider_request_digest IS NOT NULL
    ))
);

CREATE TABLE thalion.external_call_receipt (
    org_id bigint NOT NULL,
    call_id uuid NOT NULL,
    receipt_id uuid NOT NULL,
    previous_receipt_id uuid,
    input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL CHECK (output_tokens >= 0),
    actual_microunits bigint NOT NULL CHECK (actual_microunits >= 0),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, call_id, receipt_id),
    UNIQUE NULLS NOT DISTINCT (org_id, call_id, previous_receipt_id),
    FOREIGN KEY (org_id, call_id) REFERENCES thalion.external_call (org_id, call_id),
    FOREIGN KEY (org_id, call_id, previous_receipt_id)
        REFERENCES thalion.external_call_receipt (org_id, call_id, receipt_id),
    CHECK (receipt_id IS DISTINCT FROM previous_receipt_id)
);

CREATE VIEW thalion.external_call_latest_receipt AS
SELECT current.*
FROM thalion.external_call_receipt AS current
WHERE NOT EXISTS (
    SELECT 1 FROM thalion.external_call_receipt AS followup
    WHERE followup.org_id = current.org_id AND followup.call_id = current.call_id
      AND followup.previous_receipt_id = current.receipt_id
);
