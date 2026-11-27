CREATE TABLE thalion.gap_feedback_link (
    gap_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    feedback_id bigint NOT NULL,
    UNIQUE (org_id, space_id, feedback_id),
    FOREIGN KEY (org_id, space_id, gap_ref) REFERENCES thalion.gap_event (org_id, space_id, gap_ref),
    FOREIGN KEY (org_id, space_id, feedback_id) REFERENCES thalion.feedback (org_id, space_id, feedback_id)
);

CREATE FUNCTION thalion.require_gap_feedback_link() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.gap_event AS gap
        JOIN thalion.feedback AS report ON (report.org_id, report.space_id, report.origin_request_id) =
                                           (gap.org_id, gap.space_id, gap.origin_request_id)
        JOIN thalion.request_record AS origin ON (origin.org_id, origin.scope_space_id, origin.request_id) =
                                                  (gap.org_id, gap.space_id, gap.origin_request_id)
        JOIN thalion.request_record AS filing ON (filing.org_id, filing.scope_space_id, filing.request_id) =
                                                  (report.org_id, report.space_id, report.created_request_id)
        WHERE (gap.org_id, gap.space_id, gap.gap_ref, report.feedback_id) =
              (NEW.org_id, NEW.space_id, NEW.gap_ref, NEW.feedback_id)
          AND gap.feedback_id IS NULL AND report.category = 'missing_evidence'
          AND origin.principal_id = report.reporter_id AND filing.principal_id = report.reporter_id
          AND filing.operation = 'record_feedback' AND filing.destination = 'internal_feedback'
          AND filing.delegated_principal_id IS NULL AND filing.outcome IS NULL
        FOR SHARE OF filing
    ) THEN
        RAISE EXCEPTION 'a standalone gap requires a new report of its own original search' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER gap_feedback_link_scoped BEFORE INSERT ON thalion.gap_feedback_link
FOR EACH ROW EXECUTE FUNCTION thalion.require_gap_feedback_link();
CREATE TRIGGER gap_feedback_link_immutable BEFORE UPDATE OR DELETE ON thalion.gap_feedback_link
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE VIEW thalion.gap_feedback_attachment AS
SELECT org_id, space_id, gap_ref, feedback_id FROM thalion.gap_event WHERE feedback_id IS NOT NULL
UNION ALL
SELECT org_id, space_id, gap_ref, feedback_id FROM thalion.gap_feedback_link;

CREATE OR REPLACE VIEW thalion.open_gap_candidate AS
SELECT gap.* FROM thalion.current_gap AS gap
LEFT JOIN thalion.gap_feedback_attachment AS attachment USING (org_id, space_id, gap_ref)
LEFT JOIN thalion.current_feedback AS report
  ON (report.org_id, report.space_id, report.feedback_id) = (attachment.org_id, attachment.space_id, attachment.feedback_id)
WHERE gap.classification IN ('no_visible_match', 'reported_missing') AND report.state IS DISTINCT FROM 'closed';

CREATE OR REPLACE VIEW thalion.feedback_gap_origin AS
SELECT report.feedback_id, report.org_id, report.space_id, report.reporter_id, origin.client_id,
       origin.business_date, origin.feedback_order, coalesce(scope.empty_fingerprint, matched.fingerprint) AS fingerprint
FROM thalion.feedback AS report
JOIN thalion.gap_feedback_attachment AS attachment USING (org_id, space_id, feedback_id)
JOIN thalion.current_gap AS gap
  ON (gap.org_id, gap.space_id, gap.gap_ref, gap.origin_request_id) =
     (attachment.org_id, attachment.space_id, attachment.gap_ref, report.origin_request_id)
JOIN thalion.request_record AS origin
  ON (origin.org_id, origin.scope_space_id, origin.request_id, origin.principal_id) =
     (report.org_id, report.space_id, report.origin_request_id, report.reporter_id)
JOIN thalion.search_scope_observation AS scope
  ON (scope.org_id, scope.space_id, scope.request_id) = (origin.org_id, origin.scope_space_id, origin.request_id)
LEFT JOIN thalion.feedback_search_match AS matched
  ON (matched.org_id, matched.space_id, matched.request_id) = (scope.org_id, scope.space_id, scope.request_id)
 AND origin.outcome = 'succeeded'
WHERE report.category = 'missing_evidence' AND gap.classification IN ('no_visible_match', 'reported_missing')
  AND origin.operation = 'search' AND origin.destination = 'employee' AND origin.delegated_principal_id IS NULL
  AND NOT scope.visibility_limited AND origin.feedback_order IS NOT NULL
  AND coalesce(scope.empty_fingerprint, matched.fingerprint) IS NOT NULL;
