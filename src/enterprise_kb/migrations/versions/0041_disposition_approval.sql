ALTER TABLE thalion.disposition_rejection RENAME TO disposition_decision;

ALTER TABLE thalion.disposition_decision
    ADD COLUMN outcome text NOT NULL DEFAULT 'rejected',
    ADD COLUMN expires_at timestamptz,
    ADD CONSTRAINT disposition_decision_expiry CHECK (
        (outcome = 'rejected' AND expires_at IS NULL) OR (
            outcome = 'approved' AND expires_at IS NOT NULL AND isfinite(expires_at)
            AND expires_at > recorded_at AND expires_at <= recorded_at + interval '15 minutes'
        )
    );

CREATE VIEW thalion.disposition_rejection AS
SELECT case_ref, decision_ref, org_id, space_id, inventory_snapshot, submitted_by, decided_by, request_id, basis_ref, recorded_at
FROM thalion.disposition_decision WHERE outcome = 'rejected'
WITH LOCAL CHECK OPTION;

CREATE FUNCTION thalion.verify_local_disposition_decision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    operation text;
BEGIN
    operation := CASE NEW.outcome
        WHEN 'approved' THEN 'approve_disposition_case'
        WHEN 'rejected' THEN 'reject_disposition_case'
    END;
    IF operation IS NULL OR NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.decided_by, operation
    ) OR NOT EXISTS (
        SELECT 1 FROM thalion.lock_local_disposition_review(NEW.org_id, NEW.space_id, NEW.case_ref, NEW.decided_by)
    ) THEN
        RAISE EXCEPTION 'disposition decision requires a current independent reviewer and matching request' USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'approved' THEN
        NEW.recorded_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER disposition_rejection_requires_scope ON thalion.disposition_decision;
DROP FUNCTION thalion.verify_local_disposition_rejection();
CREATE TRIGGER disposition_decision_requires_scope BEFORE INSERT ON thalion.disposition_decision
FOR EACH ROW EXECUTE FUNCTION thalion.verify_local_disposition_decision();

ALTER TRIGGER disposition_rejection_immutable ON thalion.disposition_decision RENAME TO disposition_decision_immutable;
CREATE TRIGGER disposition_decision_no_truncate BEFORE TRUNCATE ON thalion.disposition_decision
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
