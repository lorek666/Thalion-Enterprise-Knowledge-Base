CREATE INDEX gap_event_by_feedback ON thalion.gap_event (org_id, space_id, feedback_id) WHERE feedback_id IS NOT NULL;
CREATE INDEX rule_approval_receipt ON thalion.command_receipt (org_id, result_ref)
WHERE operation = 'approve_effectivity' AND completed_at IS NOT NULL;

CREATE VIEW thalion.open_gap_candidate AS
SELECT gap.* FROM thalion.current_gap AS gap
LEFT JOIN thalion.current_feedback AS report USING (org_id, space_id, feedback_id)
WHERE gap.classification IN ('no_visible_match', 'reported_missing') AND report.state IS DISTINCT FROM 'closed';

CREATE VIEW thalion.feedback_gap_origin AS
SELECT report.feedback_id, report.org_id, report.space_id, report.reporter_id, origin.client_id,
       origin.business_date, origin.feedback_order, coalesce(scope.empty_fingerprint, matched.fingerprint) AS fingerprint
FROM thalion.feedback AS report
JOIN thalion.current_gap AS gap
  ON (gap.org_id, gap.space_id, gap.feedback_id, gap.origin_request_id) =
     (report.org_id, report.space_id, report.feedback_id, report.origin_request_id)
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

CREATE VIEW thalion.feedback_gap_supplement AS
SELECT gap.feedback_id, receipt.check_id, shown.position, reader.request_id, reader.principal_id,
       reader.started_at, reader.feedback_order, part.passage_ref, part.excerpt_revision, part.effectivity_ref,
       part.policy_revision, part.organization_epoch, part.space_epoch, part.source_epoch
FROM thalion.feedback_gap_origin AS gap
JOIN thalion.request_record AS reader ON (reader.org_id, reader.scope_space_id) = (gap.org_id, gap.space_id)
JOIN thalion.delivery_record AS receipt ON (receipt.org_id, receipt.request_id) = (reader.org_id, reader.request_id)
JOIN thalion.delivery_citation AS shown ON shown.check_id = receipt.check_id
JOIN thalion.delivery_dependency AS part ON (part.check_id, part.position) = (shown.check_id, shown.position)
JOIN thalion.rule_interval AS rule ON (rule.org_id, rule.space_id, rule.decision_ref) =
                                     (part.org_id, part.space_id, part.effectivity_ref)
JOIN thalion.source AS source ON source.source_id = rule.source_id
JOIN thalion.organization AS organization ON organization.org_id = rule.org_id
JOIN thalion.space AS space ON space.space_id = rule.space_id
JOIN thalion.object_identity AS location
  ON (location.org_id, location.space_id, location.object_type, location.public_id) =
     (part.org_id, part.space_id, 'passage', part.passage_ref)
JOIN LATERAL (
    SELECT run_ref, contract_revision FROM thalion.processing_run
    WHERE version_id = rule.version_id ORDER BY configuration_revision DESC LIMIT 1
) AS current_run ON current_run.contract_revision = source.contract_revision
JOIN thalion.passage_excerpt AS excerpt ON (excerpt.run_ref, excerpt.passage_id, excerpt.excerpt_revision) =
                                           (current_run.run_ref, location.object_id, part.excerpt_revision)
WHERE part.space_id = gap.space_id AND reader.operation = 'read_passage' AND reader.destination = 'employee'
  AND reader.delegated_principal_id IS NULL AND reader.outcome = 'succeeded'
  AND reader.completed_at < receipt.valid_until AND receipt.dependency_count = 1
  AND daterange(rule.valid_from, rule.effective_to, '[)') @> gap.business_date
  AND rule.approved_by <> reader.principal_id AND rule.contract_revision = source.contract_revision
  AND EXISTS (
      SELECT 1 FROM thalion.command_receipt AS approval
      JOIN thalion.request_record AS request ON (request.org_id, request.request_id) = (approval.org_id, approval.request_id)
      WHERE approval.org_id = gap.org_id AND approval.operation = 'approve_effectivity' AND approval.completed_at IS NOT NULL
        AND approval.result_ref = rule.decision_ref AND request.feedback_order > gap.feedback_order
  )
  AND source.lifecycle = 'active' AND space.lifecycle = 'active'
  AND (part.policy_revision, part.organization_epoch, part.space_epoch, part.source_epoch) =
      (source.local_policy_revision, organization.safety_epoch, space.safety_epoch, source.safety_epoch)
  AND EXISTS (
      SELECT 1 FROM thalion.quality_decision
      WHERE run_ref = current_run.run_ref AND outcome = 'approved' AND reviewer_id <> reader.principal_id
  )
  AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision WHERE run_ref = current_run.run_ref AND outcome = 'quarantined')
  AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = rule.version_id)
  AND NOT EXISTS (
      SELECT 1 FROM thalion.current_version_hold WHERE version_id = rule.version_id AND action = 'establish'
  );

CREATE VIEW thalion.feedback_work_correction_candidate AS
SELECT * FROM thalion.feedback_correction_candidate
UNION ALL
SELECT feedback_id, check_id, position, request_id, principal_id, started_at, feedback_order, passage_ref, excerpt_revision
FROM thalion.feedback_gap_supplement;

CREATE FUNCTION thalion.feedback_gap_retest_matches(target bigint, retry_ref uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.feedback_gap_origin AS gap
        JOIN thalion.current_feedback AS report USING (feedback_id)
        JOIN thalion.feedback_decision AS decision
          ON (decision.feedback_id, decision.generation) = (report.feedback_id, report.generation)
        JOIN thalion.feedback_gap_supplement AS supplement
          ON (supplement.feedback_id, supplement.check_id, supplement.position) =
             (decision.feedback_id, decision.correction_check_id, decision.correction_position)
        JOIN thalion.request_record AS retry ON (retry.org_id, retry.scope_space_id, retry.request_id) =
                                                (gap.org_id, gap.space_id, retry_ref)
        JOIN thalion.search_scope_observation AS scope
          ON (scope.org_id, scope.space_id, scope.request_id) = (retry.org_id, retry.scope_space_id, retry.request_id)
        JOIN thalion.feedback_search_match AS matched
          ON (matched.org_id, matched.space_id, matched.request_id) = (scope.org_id, scope.space_id, scope.request_id)
        JOIN thalion.delivery_record AS receipt
          ON (receipt.org_id, receipt.request_id, receipt.check_id) = (matched.org_id, matched.request_id, matched.check_id)
        JOIN thalion.delivery_citation AS shown ON shown.check_id = receipt.check_id
        JOIN thalion.delivery_dependency AS part ON (part.check_id, part.position) = (shown.check_id, shown.position)
        WHERE gap.feedback_id = target AND decision.action = 'mark_corrected' AND NOT scope.visibility_limited
          AND retry.operation = 'search' AND retry.destination = 'employee' AND retry.delegated_principal_id IS NULL
          AND retry.outcome = 'succeeded' AND retry.completed_at < receipt.valid_until
          AND (retry.principal_id, retry.client_id, retry.business_date, matched.fingerprint) =
              (gap.reporter_id, gap.client_id, gap.business_date, gap.fingerprint)
          AND retry.feedback_order > decision.feedback_order
          AND (part.space_id, part.passage_ref, part.excerpt_revision, part.effectivity_ref) =
              (gap.space_id, supplement.passage_ref, supplement.excerpt_revision, supplement.effectivity_ref)
          AND (part.policy_revision, part.organization_epoch, part.space_epoch, part.source_epoch) =
              (supplement.policy_revision, supplement.organization_epoch, supplement.space_epoch, supplement.source_epoch)
    )
$$;

CREATE OR REPLACE FUNCTION thalion.require_feedback_correction_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    missing boolean;
BEGIN
    SELECT category = 'missing_evidence' INTO missing FROM thalion.feedback WHERE feedback_id = NEW.feedback_id;
    IF NEW.action = 'verify_correction' THEN
        IF missing AND NOT EXISTS (
            SELECT 1 FROM thalion.current_feedback AS report
            JOIN thalion.space AS space USING (org_id, space_id)
            WHERE report.feedback_id = NEW.feedback_id AND report.generation + 1 = NEW.generation
              AND report.assignee_id = NEW.assignee_id AND space.owner_principal_id = NEW.actor_id
              AND thalion.feedback_gap_retest_matches(report.feedback_id, NEW.retest_request_id)
        ) THEN
            RAISE EXCEPTION 'a gap requires the same search delivering the exact approved supplement' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.correction_check_id IS NULL THEN
        IF missing OR EXISTS (
            SELECT 1 FROM thalion.feedback_origin_transcription WHERE feedback_id = NEW.feedback_id AND quarantined
        ) THEN
            RAISE EXCEPTION 'this feedback requires exact correction evidence' USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM thalion.feedback_work_correction_candidate AS candidate
        JOIN thalion.current_feedback AS report USING (feedback_id)
        JOIN thalion.feedback_decision AS previous
          ON (previous.feedback_id, previous.generation) = (report.feedback_id, report.generation)
        WHERE (candidate.feedback_id, candidate.check_id, candidate.position, candidate.principal_id) =
              (NEW.feedback_id, NEW.correction_check_id, NEW.correction_position, NEW.actor_id)
          AND report.generation + 1 = NEW.generation AND report.assignee_id = NEW.actor_id
          AND report.state IN ('pending', 'awaiting_retest')
          AND thalion.feedback_request_follows(candidate.feedback_order, candidate.started_at, previous.feedback_order, report.decided_at)
    ) THEN
        RAISE EXCEPTION 'correction must match the assignee and independently approved evidence' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER feedback_correction_exact ON thalion.feedback_decision;
CREATE TRIGGER feedback_correction_exact BEFORE INSERT ON thalion.feedback_decision
FOR EACH ROW WHEN (NEW.action IN ('mark_corrected', 'verify_correction'))
EXECUTE FUNCTION thalion.require_feedback_correction_evidence();
