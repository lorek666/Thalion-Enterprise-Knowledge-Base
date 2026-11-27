CREATE TABLE thalion.disposition_copy_receipt (
    receipt_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    case_ref uuid NOT NULL,
    submitted_by bigint NOT NULL,
    inventory_snapshot bytea NOT NULL,
    tombstone_ref uuid NOT NULL REFERENCES thalion.rule_use_stop (decision_ref),
    observed_by bigint NOT NULL,
    request_id uuid NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    copies jsonb NOT NULL CHECK (jsonb_typeof(copies) = 'array' AND jsonb_array_length(copies) BETWEEN 1 AND 500),
    additional_registered_count integer NOT NULL CHECK (additional_registered_count BETWEEN 0 AND 500),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, space_id, case_ref, submitted_by, inventory_snapshot)
        REFERENCES thalion.disposition_case (org_id, space_id, case_ref, submitted_by, inventory_snapshot),
    FOREIGN KEY (org_id, observed_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, request_id)
        REFERENCES thalion.request_record (org_id, scope_space_id, request_id)
);

CREATE FUNCTION thalion.guard_disposition_copy_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    target record;
    sealed jsonb;
BEGIN
    IF NOT thalion.local_disposition_request_is_open(
        NEW.org_id, NEW.space_id, NEW.request_id, NEW.observed_by, 'record_disposition_copy_observations'
    ) THEN
        RAISE EXCEPTION 'copy observations require a matching open request' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO target FROM thalion.lock_local_disposition_review(
        NEW.org_id, NEW.space_id, NEW.case_ref, NEW.observed_by
    );
    IF NOT FOUND OR target.action <> 'destroy' OR target.inventory_snapshot <> NEW.inventory_snapshot THEN
        RAISE EXCEPTION 'copy observations require an independent reviewer and the sealed destroy case' USING ERRCODE = '23514';
    END IF;
    PERFORM thalion.lock_synthetic_export_target(NEW.org_id, NEW.space_id, target.version_id);
    IF NOT EXISTS (
        SELECT 1 FROM thalion.rule_use_stop AS stop
        WHERE (stop.org_id, stop.space_id, stop.source_id, stop.version_id, stop.contract_revision) =
              (NEW.org_id, NEW.space_id, target.source_id, target.version_id, target.contract_revision)
          AND (stop.decision_ref, stop.disposition_case_ref, stop.kind) = (NEW.tombstone_ref, NEW.case_ref, 'deletion_blocked')
    ) OR EXISTS (
        SELECT 1 FROM thalion.current_version_hold AS hold
        WHERE (hold.org_id, hold.space_id, hold.version_id) = (NEW.org_id, NEW.space_id, target.version_id)
          AND hold.action = 'establish'
    ) THEN
        RAISE EXCEPTION 'copy observations require an unheld locally tombstoned version' USING ERRCODE = '23514';
    END IF;
    SELECT convert_from(inventory_material, 'UTF8')::jsonb INTO sealed
    FROM thalion.disposition_case WHERE case_ref = NEW.case_ref;
    IF sealed ->> 0 IS DISTINCT FROM 'local_disposition_inventory.v1'
       OR jsonb_array_length(sealed -> 14) IS DISTINCT FROM jsonb_array_length(NEW.copies)
       OR EXISTS (
           SELECT 1 FROM jsonb_array_elements(NEW.copies) WITH ORDINALITY AS item(detail, position)
           CROSS JOIN LATERAL (SELECT (sealed -> 14) -> (item.position::integer - 1) AS copy) AS origin
           WHERE (
               jsonb_typeof(detail) = 'array' AND jsonb_array_length(detail) = 3
               AND detail ->> 0 = origin.copy ->> 0
               AND CASE detail ->> 1
                   WHEN 'present_verified' THEN detail ->> 0 IN ('original', 'backup') AND detail ->> 2 IS NULL
                   WHEN 'present_in_database' THEN detail ->> 0 NOT IN ('original', 'backup') AND detail ->> 2 IS NULL
                   WHEN 'missing_unverified' THEN detail ->> 0 = 'backup' AND detail ->> 2 IS NULL
                   WHEN 'present_invalid' THEN detail ->> 0 = 'backup' AND detail ->> 2 IS NULL
                   WHEN 'unobserved' THEN detail ->> 2 IS NULL
                   ELSE detail ->> 0 = 'backup' AND detail ->> 1 IN ('absence_verified', 'reappeared') AND EXISTS (
                       SELECT 1 FROM thalion.synthetic_backup_expiry_observation AS observation
                       WHERE (observation.org_id, observation.space_id) = (NEW.org_id, NEW.space_id)
                         AND observation.backup_ref = (origin.copy -> 1 ->> 0)::uuid
                         AND observation.observation_ref = (detail ->> 2)::uuid
                   )
               END
           ) IS NOT TRUE
       ) THEN
        RAISE EXCEPTION 'copy observations do not match the sealed inventory or the expiry evidence' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER disposition_copy_receipt_scope BEFORE INSERT ON thalion.disposition_copy_receipt
FOR EACH ROW EXECUTE FUNCTION thalion.guard_disposition_copy_receipt();
CREATE TRIGGER disposition_copy_receipt_immutable BEFORE UPDATE OR DELETE ON thalion.disposition_copy_receipt
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER disposition_copy_receipt_no_truncate BEFORE TRUNCATE ON thalion.disposition_copy_receipt
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();
