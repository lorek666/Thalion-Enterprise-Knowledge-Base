ALTER TABLE thalion.request_record
    ADD COLUMN ingress text NOT NULL DEFAULT 'unknown'
    CHECK (ingress IN ('unknown', 'http', 'mcp', 'internal'));

CREATE TRIGGER request_ingress_immutable BEFORE UPDATE OF ingress ON thalion.request_record
FOR EACH ROW WHEN (OLD.ingress IS DISTINCT FROM NEW.ingress) EXECUTE FUNCTION thalion.reject_original_change();
