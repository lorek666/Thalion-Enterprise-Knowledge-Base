CREATE SEQUENCE thalion.feedback_evidence_order;

ALTER TABLE thalion.request_record ADD COLUMN feedback_order bigint;
ALTER TABLE thalion.request_record ALTER COLUMN feedback_order SET DEFAULT nextval('thalion.feedback_evidence_order');
ALTER TABLE thalion.feedback_decision ADD COLUMN feedback_order bigint;
ALTER TABLE thalion.feedback_decision ALTER COLUMN feedback_order SET DEFAULT nextval('thalion.feedback_evidence_order');

CREATE TRIGGER request_feedback_order_immutable BEFORE UPDATE OF feedback_order ON thalion.request_record
FOR EACH ROW WHEN (OLD.feedback_order IS DISTINCT FROM NEW.feedback_order) EXECUTE FUNCTION thalion.reject_original_change();

CREATE FUNCTION thalion.feedback_request_follows(
    request_order bigint, request_time timestamptz, decision_order bigint, decision_time timestamptz
) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE WHEN request_order IS NOT NULL AND decision_order IS NOT NULL
        THEN request_order > decision_order ELSE request_time > decision_time END
$$;

ALTER TABLE thalion.feedback_decision
    ADD COLUMN correction_check_id uuid,
    ADD COLUMN correction_position integer,
    ADD CHECK (correction_check_id IS NULL OR action = 'mark_corrected'),
    ADD FOREIGN KEY (correction_check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id),
    ADD FOREIGN KEY (correction_check_id, correction_position) REFERENCES thalion.delivery_citation (check_id, position) MATCH FULL;

CREATE VIEW thalion.feedback_origin_transcription AS
SELECT report.feedback_id, report.org_id, report.space_id, part.passage_ref, excerpt.passage_id,
       excerpt.version_id, excerpt.content_digest, run.configuration_revision, request.business_date,
       EXISTS (
           SELECT 1 FROM thalion.quality_decision
           WHERE run_ref = excerpt.run_ref AND outcome = 'quarantined'
       ) AS quarantined
FROM thalion.feedback AS report
JOIN thalion.request_record AS request
  ON (request.org_id, request.request_id) = (report.org_id, report.origin_request_id)
JOIN thalion.delivery_dependency AS part
  ON (part.check_id, part.position) = (report.origin_check_id, report.citation_position)
JOIN thalion.object_identity AS identity
  ON (identity.org_id, identity.space_id, identity.public_id, identity.object_type) =
     (part.org_id, part.space_id, part.passage_ref, 'passage')
JOIN thalion.passage_excerpt AS excerpt
  ON (excerpt.passage_id, excerpt.excerpt_revision) = (identity.object_id, part.excerpt_revision)
JOIN thalion.processing_run AS run ON run.run_ref = excerpt.run_ref;

CREATE VIEW thalion.feedback_correction_candidate AS
SELECT original.feedback_id, receipt.check_id, shown.position, request.request_id,
       request.principal_id, request.started_at, request.feedback_order, part.passage_ref, part.excerpt_revision
FROM thalion.feedback_origin_transcription AS original
JOIN thalion.document_version AS version ON version.version_id = original.version_id
JOIN thalion.source AS source ON source.source_id = version.source_id
JOIN LATERAL (
    SELECT run_ref, contract_revision, configuration_revision FROM thalion.processing_run
    WHERE version_id = version.version_id ORDER BY configuration_revision DESC LIMIT 1
) AS current_run ON current_run.contract_revision = source.contract_revision
JOIN thalion.passage_excerpt AS replacement ON replacement.run_ref = current_run.run_ref
JOIN thalion.object_identity AS location
  ON (location.org_id, location.space_id, location.object_type, location.object_id) =
     (replacement.org_id, replacement.space_id, 'passage', replacement.passage_id)
JOIN thalion.delivery_dependency AS part
  ON (part.org_id, part.space_id, part.passage_ref, part.excerpt_revision) =
     (replacement.org_id, replacement.space_id, location.public_id, replacement.excerpt_revision)
JOIN thalion.delivery_citation AS shown USING (check_id, position)
JOIN thalion.delivery_record AS receipt ON (receipt.org_id, receipt.check_id) = (part.org_id, part.check_id)
JOIN thalion.request_record AS request
  ON (request.org_id, request.scope_space_id, request.request_id) = (receipt.org_id, part.space_id, receipt.request_id)
WHERE original.quarantined
  AND current_run.configuration_revision > original.configuration_revision
  AND replacement.passage_id <> original.passage_id AND replacement.content_digest <> original.content_digest
  AND request.operation = 'read_passage' AND request.destination = 'employee' AND request.delegated_principal_id IS NULL
  AND request.business_date = original.business_date
  AND request.outcome = 'succeeded' AND request.completed_at < receipt.valid_until
  AND EXISTS (
      SELECT 1 FROM thalion.quality_decision
      WHERE run_ref = current_run.run_ref AND outcome = 'approved' AND reviewer_id <> request.principal_id
  )
  AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision WHERE run_ref = current_run.run_ref AND outcome = 'quarantined')
  AND NOT EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = version.version_id)
  AND NOT EXISTS (
      SELECT 1 FROM thalion.current_version_hold WHERE version_id = version.version_id AND action = 'establish'
  )
  AND source.lifecycle = 'active';

CREATE INDEX delivery_dependency_by_transcription
ON thalion.delivery_dependency (org_id, space_id, passage_ref, excerpt_revision);

CREATE FUNCTION thalion.require_feedback_correction_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NEW.correction_check_id IS NULL THEN
        IF EXISTS (
            SELECT 1 FROM thalion.feedback_origin_transcription WHERE feedback_id = NEW.feedback_id AND quarantined
        ) THEN
            RAISE EXCEPTION 'a quarantined origin requires an exact corrected reference' USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM thalion.feedback_correction_candidate AS candidate
        JOIN thalion.current_feedback AS report USING (feedback_id)
        JOIN thalion.feedback_decision AS previous
          ON (previous.feedback_id, previous.generation) = (report.feedback_id, report.generation)
        WHERE (candidate.feedback_id, candidate.check_id, candidate.position, candidate.principal_id) =
              (NEW.feedback_id, NEW.correction_check_id, NEW.correction_position, NEW.actor_id)
          AND report.generation + 1 = NEW.generation AND report.assignee_id = NEW.actor_id
          AND report.state IN ('pending', 'awaiting_retest')
          AND thalion.feedback_request_follows(candidate.feedback_order, candidate.started_at, previous.feedback_order, report.decided_at)
    ) THEN
        RAISE EXCEPTION 'correction must match the assignee and independently approved replacement' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER feedback_correction_exact BEFORE INSERT ON thalion.feedback_decision
FOR EACH ROW WHEN (NEW.action = 'mark_corrected') EXECUTE FUNCTION thalion.require_feedback_correction_evidence();
