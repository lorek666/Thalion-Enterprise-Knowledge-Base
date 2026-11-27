CREATE TABLE thalion.feedback_evidence_read (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    request_id uuid NOT NULL,
    check_id uuid NOT NULL,
    feedback_id bigint NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    PRIMARY KEY (org_id, request_id),
    FOREIGN KEY (org_id, space_id, feedback_id) REFERENCES thalion.feedback (org_id, space_id, feedback_id),
    FOREIGN KEY (org_id, space_id, request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, request_id, check_id) REFERENCES thalion.delivery_record (org_id, request_id, check_id)
);

CREATE TRIGGER feedback_evidence_read_immutable BEFORE UPDATE OR DELETE ON thalion.feedback_evidence_read
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
