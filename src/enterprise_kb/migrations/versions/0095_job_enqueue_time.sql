ALTER TABLE thalion.job ADD COLUMN enqueued_at timestamptz CHECK (isfinite(enqueued_at));
ALTER TABLE thalion.job ALTER COLUMN enqueued_at SET DEFAULT clock_timestamp();

CREATE TRIGGER job_enqueue_time_immutable BEFORE UPDATE OF enqueued_at ON thalion.job
FOR EACH ROW WHEN (OLD.enqueued_at IS DISTINCT FROM NEW.enqueued_at)
EXECUTE FUNCTION thalion.reject_original_change();
