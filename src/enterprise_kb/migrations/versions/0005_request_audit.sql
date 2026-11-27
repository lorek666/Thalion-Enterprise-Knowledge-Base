CREATE TABLE thalion.question_chain (
    org_id bigint NOT NULL,
    question_chain_id uuid NOT NULL,
    principal_id bigint NOT NULL,
    delegated_principal_id bigint,
    client_id text NOT NULL,
    PRIMARY KEY (org_id, question_chain_id),
    FOREIGN KEY (org_id, principal_id)
        REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, delegated_principal_id)
        REFERENCES thalion.principal (org_id, principal_id)
);

CREATE TABLE thalion.request_record (
    org_id bigint NOT NULL,
    request_id uuid NOT NULL,
    principal_id bigint NOT NULL,
    delegated_principal_id bigint,
    client_id text NOT NULL CHECK (client_id ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    operation text NOT NULL CHECK (operation ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    destination text NOT NULL CHECK (destination ~ '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'),
    business_date date NOT NULL,
    configuration_revision bigint NOT NULL CHECK (configuration_revision > 0),
    question_chain_id uuid,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    outcome text CHECK (outcome IN (
        'succeeded', 'rejected', 'no_evidence', 'input_changed', 'dependency_unavailable', 'failed'
    )),
    elapsed_ms bigint CHECK (elapsed_ms >= 0),
    completed_at timestamptz,
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, principal_id)
        REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, delegated_principal_id)
        REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, question_chain_id)
        REFERENCES thalion.question_chain (org_id, question_chain_id),
    CHECK ((outcome IS NULL) = (elapsed_ms IS NULL)),
    CHECK ((outcome IS NULL) = (completed_at IS NULL))
);

CREATE INDEX request_record_by_chain ON thalion.request_record (org_id, question_chain_id)
    WHERE question_chain_id IS NOT NULL;

CREATE FUNCTION thalion.guard_request_record() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.outcome IS NOT NULL THEN
            RAISE EXCEPTION 'a request must be opened before finalization' USING ERRCODE = '55000';
        END IF;
        IF NEW.question_chain_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM thalion.question_chain AS chain
            WHERE chain.org_id = NEW.org_id AND chain.question_chain_id = NEW.question_chain_id
              AND chain.principal_id = NEW.principal_id AND chain.client_id = NEW.client_id
              AND chain.delegated_principal_id IS NOT DISTINCT FROM NEW.delegated_principal_id
        ) THEN
            RAISE EXCEPTION 'request identity differs from the question chain' USING ERRCODE = '55000';
        END IF;
    ELSIF OLD.outcome IS NOT NULL OR NEW.outcome IS NULL OR (
        NEW.org_id, NEW.request_id, NEW.principal_id, NEW.delegated_principal_id, NEW.client_id,
        NEW.operation, NEW.destination, NEW.business_date, NEW.configuration_revision,
        NEW.question_chain_id, NEW.started_at
    ) IS DISTINCT FROM (
        OLD.org_id, OLD.request_id, OLD.principal_id, OLD.delegated_principal_id, OLD.client_id,
        OLD.operation, OLD.destination, OLD.business_date, OLD.configuration_revision,
        OLD.question_chain_id, OLD.started_at
    ) THEN
        RAISE EXCEPTION 'request context and final outcome are immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER request_record_check BEFORE INSERT OR UPDATE ON thalion.request_record
FOR EACH ROW EXECUTE FUNCTION thalion.guard_request_record();

ALTER TABLE thalion.command_receipt
    ADD CONSTRAINT command_receipt_org_identity UNIQUE (org_id, receipt_id);

CREATE TABLE thalion.request_command (
    org_id bigint NOT NULL,
    request_id uuid NOT NULL,
    receipt_id uuid NOT NULL,
    PRIMARY KEY (org_id, request_id, receipt_id),
    FOREIGN KEY (org_id, request_id)
        REFERENCES thalion.request_record (org_id, request_id),
    FOREIGN KEY (org_id, receipt_id)
        REFERENCES thalion.command_receipt (org_id, receipt_id)
);

CREATE TABLE thalion.request_job (
    org_id bigint NOT NULL,
    request_id uuid NOT NULL,
    job_id uuid NOT NULL,
    PRIMARY KEY (org_id, request_id, job_id),
    FOREIGN KEY (org_id, request_id)
        REFERENCES thalion.request_record (org_id, request_id),
    FOREIGN KEY (org_id, job_id)
        REFERENCES thalion.job (org_id, job_id)
);
