ALTER TABLE thalion.wiki_revision ADD UNIQUE (org_id, space_id, revision_ref);

CREATE TABLE thalion.lint_finding (
    finding_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    business_date date NOT NULL,
    rule text NOT NULL CHECK (rule IN ('statement_conflict', 'unit_mismatch')),
    first_revision_ref uuid NOT NULL,
    second_revision_ref uuid NOT NULL,
    initial_owner_id bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, business_date, rule, first_revision_ref, second_revision_ref),
    UNIQUE (org_id, space_id, finding_ref),
    FOREIGN KEY (org_id, space_id, first_revision_ref) REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref),
    FOREIGN KEY (org_id, space_id, second_revision_ref) REFERENCES thalion.wiki_revision (org_id, space_id, revision_ref),
    FOREIGN KEY (org_id, initial_owner_id) REFERENCES thalion.principal (org_id, principal_id),
    CHECK (first_revision_ref < second_revision_ref)
);

CREATE INDEX lint_first_revision ON thalion.lint_finding (org_id, space_id, first_revision_ref);
CREATE INDEX lint_second_revision ON thalion.lint_finding (org_id, space_id, second_revision_ref);

CREATE TABLE thalion.lint_finding_observation (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    finding_ref uuid NOT NULL,
    report_request_id uuid NOT NULL,
    reporter_id bigint NOT NULL,
    first_origin uuid NOT NULL,
    second_origin uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, report_request_id),
    UNIQUE (finding_ref, first_origin, second_origin),
    FOREIGN KEY (org_id, space_id, finding_ref) REFERENCES thalion.lint_finding (org_id, space_id, finding_ref),
    FOREIGN KEY (org_id, reporter_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, space_id, report_request_id) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, first_origin) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    FOREIGN KEY (org_id, space_id, second_origin) REFERENCES thalion.request_record (org_id, scope_space_id, request_id),
    CHECK (first_origin <> second_origin)
);

CREATE VIEW thalion.lint_search_receipt AS
SELECT request.org_id, request.scope_space_id AS space_id, request.request_id,
       request.principal_id, request.business_date, publication.revision_ref
FROM thalion.request_record AS request
JOIN thalion.delivery_record AS delivery USING (org_id, request_id)
JOIN thalion.wiki_publication_event AS publication
  ON (publication.org_id, publication.space_id, publication.publication_ref) =
     (request.org_id, request.scope_space_id, delivery.wiki_publication_ref)
WHERE request.operation = 'search' AND request.destination = 'employee'
  AND request.delegated_principal_id IS NULL AND request.outcome = 'succeeded'
  AND request.completed_at < delivery.valid_until;

CREATE FUNCTION thalion.verify_lint_observation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.lint_finding AS finding
        JOIN thalion.space AS scope USING (org_id, space_id)
        JOIN thalion.lint_search_receipt AS first USING (org_id, space_id, business_date)
        JOIN thalion.lint_search_receipt AS second USING (org_id, space_id, business_date)
        JOIN thalion.request_record AS report ON (report.org_id, report.scope_space_id) = (finding.org_id, finding.space_id)
        WHERE (finding.org_id, finding.space_id, finding.finding_ref) = (NEW.org_id, NEW.space_id, NEW.finding_ref)
          AND (first.request_id, first.revision_ref, first.principal_id) =
              (NEW.first_origin, finding.first_revision_ref, NEW.reporter_id)
          AND (second.request_id, second.revision_ref, second.principal_id) =
              (NEW.second_origin, finding.second_revision_ref, NEW.reporter_id)
          AND (report.request_id, report.principal_id, report.operation, report.destination) =
              (NEW.report_request_id, NEW.reporter_id, 'emit_finding', 'internal_feedback')
          AND report.outcome IS NULL AND report.delegated_principal_id IS NULL
          AND scope.lifecycle = 'active' AND scope.owner_principal_id = NEW.reporter_id
    ) THEN
        RAISE EXCEPTION 'a finding observation requires both exact same-day search receipts' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER lint_observation_requires_receipts BEFORE INSERT ON thalion.lint_finding_observation
FOR EACH ROW EXECUTE FUNCTION thalion.verify_lint_observation();

CREATE FUNCTION thalion.verify_lint_finding_observed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.lint_finding_observation WHERE finding_ref = NEW.finding_ref
    ) THEN
        RAISE EXCEPTION 'a finding requires at least one verified observation' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER lint_finding_requires_observation AFTER INSERT ON thalion.lint_finding
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.verify_lint_finding_observed();

CREATE TRIGGER lint_finding_immutable BEFORE UPDATE OR DELETE ON thalion.lint_finding
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER lint_finding_observation_immutable BEFORE UPDATE OR DELETE ON thalion.lint_finding_observation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE VIEW thalion.lint_finding_revision AS
SELECT org_id, space_id, finding_ref, first_revision_ref AS revision_ref FROM thalion.lint_finding
UNION ALL
SELECT org_id, space_id, finding_ref, second_revision_ref FROM thalion.lint_finding;

CREATE VIEW thalion.lint_finding_input AS
SELECT finding.org_id, finding.space_id, finding.finding_ref, finding.revision_ref, revision.manifest_ref,
       entry.source_id, entry.passage_ref, entry.excerpt_revision
FROM thalion.lint_finding_revision AS finding
JOIN thalion.wiki_revision AS revision USING (org_id, space_id, revision_ref)
JOIN thalion.input_manifest_entry AS entry USING (org_id, space_id, manifest_ref);
