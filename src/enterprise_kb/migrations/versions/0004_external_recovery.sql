ALTER TABLE thalion.external_call
    ADD COLUMN artifact_ref uuid,
    ADD COLUMN artifact_digest bytea,
    ADD CONSTRAINT external_call_artifact_valid CHECK (
        (artifact_ref IS NULL AND artifact_digest IS NULL)
        OR (state = 'confirmed_success' AND artifact_ref IS NOT NULL
            AND artifact_digest IS NOT NULL AND octet_length(artifact_digest) = 32)
    ),
    ADD CONSTRAINT external_call_job_identity UNIQUE (org_id, job_id, call_id);

CREATE FUNCTION thalion.reject_call_artifact_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF OLD.artifact_ref IS NOT NULL AND (
        (NEW.org_id, NEW.job_id, NEW.generation, NEW.call_id, NEW.dispatched_at)
            IS DISTINCT FROM (OLD.org_id, OLD.job_id, OLD.generation, OLD.call_id, OLD.dispatched_at)
        OR NEW.artifact_ref IS DISTINCT FROM OLD.artifact_ref
        OR NEW.artifact_digest IS DISTINCT FROM OLD.artifact_digest
        OR NEW.input_digest IS DISTINCT FROM OLD.input_digest
        OR NEW.route IS DISTINCT FROM OLD.route
        OR NEW.provider_namespace IS DISTINCT FROM OLD.provider_namespace
        OR NEW.provider_request_digest IS DISTINCT FROM OLD.provider_request_digest
    ) THEN
        RAISE EXCEPTION 'confirmed call artifact is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER external_call_artifact_immutable BEFORE UPDATE ON thalion.external_call
FOR EACH ROW EXECUTE FUNCTION thalion.reject_call_artifact_change();

ALTER TABLE thalion.job
    DROP CONSTRAINT job_state_check,
    ADD CONSTRAINT job_state_check CHECK (state IN (
        'queued', 'running', 'succeeded', 'awaiting_external', 'external_budget_blocked'
    )),
    ADD COLUMN result_call_id uuid,
    ADD CONSTRAINT job_result_call_scope FOREIGN KEY (org_id, job_id, result_call_id)
        REFERENCES thalion.external_call (org_id, job_id, call_id),
    ADD CONSTRAINT job_result_call_completed CHECK (result_call_id IS NULL OR state = 'succeeded');

DROP INDEX thalion.job_claim_order;
CREATE INDEX job_claim_order ON thalion.job (org_id, stage, available_at, job_id)
    WHERE state IN ('queued', 'running', 'awaiting_external', 'external_budget_blocked');

CREATE VIEW thalion.external_job_ledger AS
SELECT budget.*, usage.*, latest.call_id, latest.generation, latest.route, latest.provider_namespace,
       latest.input_digest, latest.artifact_ref, latest.artifact_digest,
       CASE
           WHEN latest.artifact_ref IS NOT NULL THEN NULL
           WHEN usage.unresolved_calls > 0 AND (NOT budget.allow_unknown_retry OR limit_reached)
               THEN 'awaiting_external'
           WHEN limit_reached THEN 'external_budget_blocked'
       END AS blocked_state
FROM thalion.external_call_budget AS budget
CROSS JOIN LATERAL (
    SELECT COALESCE(sum(receipt.actual_microunits), 0) AS actual_microunits,
           COALESCE(sum(call.reserved_microunits) FILTER (
               WHERE call.state IN ('not_sent', 'sent', 'outcome_unknown')
                 AND call.abandoned_at IS NULL
           ), 0) AS reserved_microunits,
           count(call.dispatched_at) AS dispatched_calls,
           count(*) FILTER (
               WHERE call.state = 'not_sent' AND call.abandoned_at IS NULL
           ) AS active_reservations,
           count(*) FILTER (WHERE call.state IN ('sent', 'outcome_unknown')) AS unresolved_calls
    FROM thalion.external_call AS call
    LEFT JOIN thalion.external_call_latest_receipt AS receipt
      ON receipt.org_id = call.org_id AND receipt.call_id = call.call_id
    WHERE call.org_id = budget.org_id AND call.job_id = budget.job_id
) AS usage
LEFT JOIN LATERAL (
    SELECT call_id, generation, route, provider_namespace, input_digest, artifact_ref, artifact_digest
    FROM thalion.external_call
    WHERE org_id = budget.org_id AND job_id = budget.job_id AND dispatched_at IS NOT NULL
    ORDER BY generation DESC
    LIMIT 1
) AS latest ON true
CROSS JOIN LATERAL (
    SELECT usage.dispatched_calls >= budget.maximum_calls
        OR usage.actual_microunits + usage.reserved_microunits > budget.maximum_microunits
        AS limit_reached
) AS capacity;
