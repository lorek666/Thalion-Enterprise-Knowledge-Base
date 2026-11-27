CREATE INDEX job_backlog_pending_scope
    ON thalion.job (org_id, space_id)
    WHERE state <> 'succeeded';

CREATE INDEX job_backlog_enqueue_scope_time
    ON thalion.job (org_id, space_id, enqueued_at)
    WHERE enqueued_at IS NOT NULL;

CREATE INDEX job_attempt_success_time
    ON thalion.job_attempt (org_id, finished_at)
    INCLUDE (job_id, generation)
    WHERE outcome = 'succeeded';
