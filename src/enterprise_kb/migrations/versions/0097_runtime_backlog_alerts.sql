CREATE TABLE thalion.runtime_backlog_alert (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    reason text NOT NULL CHECK (reason IN (
        'awaiting_external', 'external_budget_blocked', 'inconsistent', 'lease_expired', 'stalled'
    )),
    PRIMARY KEY (org_id, space_id, reason),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id)
);
