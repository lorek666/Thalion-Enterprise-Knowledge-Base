CREATE TABLE thalion.compile_template (
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    template_key text NOT NULL CHECK (template_key ~ '^[a-z][a-z0-9_-]{0,63}$'),
    PRIMARY KEY (org_id, space_id, template_key),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id)
);

CREATE TABLE thalion.compile_template_revision (
    revision_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    template_key text NOT NULL,
    prompt text NOT NULL CHECK (btrim(prompt) <> '' AND octet_length(prompt) <= 16384),
    model_profile text NOT NULL CHECK (model_profile = 'synthetic-local'),
    max_input_bytes integer NOT NULL CHECK (max_input_bytes BETWEEN 1 AND 1048576),
    max_output_tokens integer NOT NULL CHECK (max_output_tokens BETWEEN 1 AND 8192),
    author_id bigint NOT NULL,
    reviewer_id bigint NOT NULL CHECK (reviewer_id <> author_id),
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, template_key, revision_ref, reviewer_id),
    FOREIGN KEY (org_id, space_id, template_key)
        REFERENCES thalion.compile_template (org_id, space_id, template_key),
    FOREIGN KEY (org_id, author_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, reviewer_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TABLE thalion.compile_template_admission (
    revision_ref uuid PRIMARY KEY,
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    template_key text NOT NULL,
    reviewer_id bigint NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    basis_ref uuid NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, template_key, revision_ref, decision),
    FOREIGN KEY (org_id, space_id, template_key, revision_ref, reviewer_id)
        REFERENCES thalion.compile_template_revision (org_id, space_id, template_key, revision_ref, reviewer_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TABLE thalion.compile_template_activation (
    activation_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    template_key text NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    prior_generation bigint GENERATED ALWAYS AS (nullif(generation - 1, 0)) STORED,
    revision_ref uuid NOT NULL,
    required_decision text GENERATED ALWAYS AS ('approved'::text) STORED,
    activated_by bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, template_key, generation),
    FOREIGN KEY (org_id, space_id, template_key, prior_generation)
        REFERENCES thalion.compile_template_activation (org_id, space_id, template_key, generation),
    FOREIGN KEY (org_id, space_id, template_key, revision_ref, required_decision)
        REFERENCES thalion.compile_template_admission (org_id, space_id, template_key, revision_ref, decision),
    FOREIGN KEY (org_id, activated_by) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE TRIGGER compile_template_immutable BEFORE UPDATE OR DELETE ON thalion.compile_template
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER compile_template_revision_immutable BEFORE UPDATE OR DELETE ON thalion.compile_template_revision
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER compile_template_admission_immutable BEFORE UPDATE OR DELETE ON thalion.compile_template_admission
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER compile_template_activation_immutable BEFORE UPDATE OR DELETE ON thalion.compile_template_activation
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE VIEW thalion.active_compile_template AS
SELECT latest.org_id, latest.space_id, latest.template_key, latest.revision_ref, latest.generation
FROM (
    SELECT DISTINCT ON (org_id, space_id, template_key)
           org_id, space_id, template_key, revision_ref, generation, activated_by
    FROM thalion.compile_template_activation
    ORDER BY org_id, space_id, template_key, generation DESC
) AS latest
JOIN thalion.space AS space USING (org_id, space_id)
JOIN thalion.compile_template_admission AS admission USING (org_id, space_id, template_key, revision_ref)
JOIN thalion.principal AS owner ON (owner.org_id, owner.principal_id) = (latest.org_id, latest.activated_by)
JOIN thalion.principal AS reviewer ON (reviewer.org_id, reviewer.principal_id) = (latest.org_id, admission.reviewer_id)
WHERE space.lifecycle = 'active' AND space.owner_principal_id = owner.principal_id
  AND owner.principal_id <> reviewer.principal_id
  AND owner.principal_type = 'employee' AND owner.authority_issuer = 'https://synthetic.invalid' AND NOT owner.disabled
  AND reviewer.principal_type = 'employee' AND reviewer.authority_issuer = 'https://synthetic.invalid' AND NOT reviewer.disabled;
