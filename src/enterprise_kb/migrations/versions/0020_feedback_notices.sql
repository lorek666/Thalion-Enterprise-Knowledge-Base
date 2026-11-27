ALTER TABLE thalion.feedback_decision
    ADD COLUMN conclusion_code text,
    ADD CHECK (conclusion_code IS NULL OR (
        action = 'explain' AND conclusion_code IN ('source_text_confirmed', 'applicability_confirmed')
    ));

CREATE INDEX feedback_by_reporter ON thalion.feedback (org_id, space_id, reporter_id, feedback_id);
