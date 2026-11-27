CREATE TABLE thalion.space_release_config (
    release_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    generation bigint NOT NULL CHECK (generation >= 1),
    prior_generation bigint GENERATED ALWAYS AS (nullif(generation - 1, 0)) STORED,
    action text NOT NULL CHECK (action IN ('trial_switch', 'rollback', 'disable_wiki')),
    wiki_delivery_enabled boolean NOT NULL,
    lexical_index_mode text NOT NULL CHECK (lexical_index_mode IN ('indexed', 'direct_scan')),
    target_release_ref uuid,
    template_key text,
    template_revision_ref uuid,
    observation_window_minutes integer CHECK (
        observation_window_minutes IS NULL OR observation_window_minutes BETWEEN 1 AND 43200
    ),
    min_sample_requests integer CHECK (
        min_sample_requests IS NULL OR min_sample_requests BETWEEN 1 AND 1000000
    ),
    rollback_trigger_summary text NOT NULL CHECK (
        btrim(rollback_trigger_summary) <> '' AND char_length(rollback_trigger_summary) <= 240
    ),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    basis_ref uuid NOT NULL,
    actor_id bigint NOT NULL,
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, generation),
    UNIQUE (org_id, space_id, release_ref),
    FOREIGN KEY (org_id, space_id) REFERENCES thalion.space (org_id, space_id),
    FOREIGN KEY (org_id, space_id, prior_generation)
        REFERENCES thalion.space_release_config (org_id, space_id, generation),
    FOREIGN KEY (org_id, space_id, target_release_ref)
        REFERENCES thalion.space_release_config (org_id, space_id, release_ref),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id),
    CHECK ((template_key IS NULL) = (template_revision_ref IS NULL)),
    CHECK (action <> 'disable_wiki' OR NOT wiki_delivery_enabled),
    CHECK (action <> 'rollback' OR target_release_ref IS NOT NULL),
    CHECK (action = 'rollback' OR target_release_ref IS NULL)
);

CREATE INDEX space_release_config_by_space
    ON thalion.space_release_config (org_id, space_id, generation DESC);

CREATE VIEW thalion.current_space_release_config AS
SELECT DISTINCT ON (org_id, space_id) *
FROM thalion.space_release_config
ORDER BY org_id, space_id, generation DESC;

CREATE FUNCTION thalion.guard_space_release_config_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    target_gen bigint;
BEGIN
    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.organization AS org USING (org_id)
    JOIN thalion.principal AS actor
      ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.actor_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.scope_space_id, req.request_id) = (space.org_id, space.space_id, NEW.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND space.owner_principal_id = NEW.actor_id
      AND actor.principal_type = 'employee'
      AND actor.authority_issuer = 'https://synthetic.invalid'
      AND NOT actor.disabled
      AND req.principal_id = NEW.actor_id
      AND req.delegated_principal_id IS NULL
      AND req.outcome IS NULL
      AND req.operation = 'switch_space_release'
      AND req.destination = 'internal_release'
      AND req.configuration_revision = org.config_revision
    FOR SHARE OF org, actor, req
    FOR UPDATE OF space;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'space release change requires an open request from the active space owner'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.generation <> 1 + COALESCE((
        SELECT max(generation) FROM thalion.space_release_config
        WHERE (org_id, space_id) = (NEW.org_id, NEW.space_id)
    ), 0) THEN
        RAISE EXCEPTION 'space release generation must increment monotonically' USING ERRCODE = '23514';
    END IF;
    IF NEW.target_release_ref IS NOT NULL THEN
        SELECT generation INTO target_gen
        FROM thalion.space_release_config
        WHERE (org_id, space_id, release_ref) = (NEW.org_id, NEW.space_id, NEW.target_release_ref);
        IF target_gen IS NULL OR target_gen >= NEW.generation THEN
            RAISE EXCEPTION 'rollback target release must be an earlier release in the same space'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.template_revision_ref IS NOT NULL THEN
        PERFORM 1
        FROM thalion.compile_template_admission AS admission
        JOIN thalion.principal AS reviewer
          ON (reviewer.org_id, reviewer.principal_id) = (admission.org_id, admission.reviewer_id)
        WHERE (admission.org_id, admission.space_id, admission.template_key, admission.revision_ref)
            = (NEW.org_id, NEW.space_id, NEW.template_key, NEW.template_revision_ref)
          AND admission.decision = 'approved'
          AND admission.reviewer_id <> NEW.actor_id
          AND reviewer.principal_type = 'employee'
          AND reviewer.authority_issuer = 'https://synthetic.invalid'
          AND NOT reviewer.disabled
        FOR SHARE OF reviewer;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'release template must have an active independent approval in this space'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER space_release_config_insert_guard
BEFORE INSERT ON thalion.space_release_config
FOR EACH ROW EXECUTE FUNCTION thalion.guard_space_release_config_insert();

CREATE TRIGGER space_release_config_immutable BEFORE UPDATE OR DELETE ON thalion.space_release_config
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER space_release_config_no_truncate BEFORE TRUNCATE ON thalion.space_release_config
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE TABLE thalion.wiki_topic_rollback (
    rollback_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    topic_key text NOT NULL,
    rollback_seq bigint NOT NULL CHECK (rollback_seq >= 1),
    from_publication_ref uuid NOT NULL,
    target_publication_ref uuid NOT NULL,
    target_revision_ref uuid NOT NULL,
    actor_id bigint NOT NULL,
    check_id uuid NOT NULL UNIQUE,
    basis_ref uuid NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    request_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (org_id, space_id, topic_key, rollback_seq),
    FOREIGN KEY (org_id, space_id, topic_key) REFERENCES thalion.wiki (org_id, space_id, topic_key),
    FOREIGN KEY (org_id, from_publication_ref)
        REFERENCES thalion.wiki_publication_event (org_id, publication_ref),
    FOREIGN KEY (org_id, target_publication_ref)
        REFERENCES thalion.wiki_publication_event (org_id, publication_ref),
    FOREIGN KEY (org_id, space_id, topic_key, target_revision_ref)
        REFERENCES thalion.wiki_revision (org_id, space_id, topic_key, revision_ref),
    FOREIGN KEY (org_id, actor_id) REFERENCES thalion.principal (org_id, principal_id),
    FOREIGN KEY (check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id),
    FOREIGN KEY (org_id, request_id) REFERENCES thalion.request_record (org_id, request_id)
);

CREATE INDEX wiki_topic_rollback_by_topic
    ON thalion.wiki_topic_rollback (org_id, space_id, topic_key, from_publication_ref, rollback_seq DESC);

CREATE FUNCTION thalion.guard_wiki_topic_rollback_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    current_pub thalion.wiki_publication_event%ROWTYPE;
    target_pub thalion.wiki_publication_event%ROWTYPE;
    effective_pub uuid;
    target_author bigint;
    target_digest bytea;
    target_business_date date;
BEGIN
    PERFORM 1 FROM thalion.wiki
    WHERE (org_id, space_id, topic_key) = (NEW.org_id, NEW.space_id, NEW.topic_key)
    FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Wiki topic does not exist in this space' USING ERRCODE = '23514';
    END IF;

    SELECT * INTO current_pub
    FROM thalion.current_wiki_publication
    WHERE (org_id, space_id, topic_key) = (NEW.org_id, NEW.space_id, NEW.topic_key);
    IF current_pub.publication_ref IS NULL OR current_pub.publication_ref <> NEW.from_publication_ref THEN
        RAISE EXCEPTION 'Wiki rollback must reference the current published head of the topic' USING ERRCODE = '23514';
    END IF;

    SELECT * INTO target_pub
    FROM thalion.wiki_publication_event
    WHERE (org_id, space_id, topic_key, publication_ref)
        = (NEW.org_id, NEW.space_id, NEW.topic_key, NEW.target_publication_ref);
    IF target_pub.publication_ref IS NULL OR target_pub.revision_ref <> NEW.target_revision_ref THEN
        RAISE EXCEPTION 'Wiki rollback target must match an existing publication of the same topic' USING ERRCODE = '23514';
    END IF;

    SELECT target_publication_ref INTO effective_pub
    FROM thalion.wiki_topic_rollback
    WHERE (org_id, space_id, topic_key, from_publication_ref)
        = (NEW.org_id, NEW.space_id, NEW.topic_key, NEW.from_publication_ref)
    ORDER BY rollback_seq DESC LIMIT 1;
    effective_pub := COALESCE(effective_pub, current_pub.publication_ref);
    IF effective_pub = NEW.target_publication_ref THEN
        RAISE EXCEPTION 'Wiki topic is already serving the requested target publication' USING ERRCODE = '23514';
    END IF;

    IF NEW.rollback_seq <> 1 + COALESCE((
        SELECT max(rollback_seq) FROM thalion.wiki_topic_rollback
        WHERE (org_id, space_id, topic_key) = (NEW.org_id, NEW.space_id, NEW.topic_key)
    ), 0) THEN
        RAISE EXCEPTION 'Wiki rollback sequence must increment monotonically' USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1 FROM thalion.wiki_availability_event
        WHERE publication_ref = NEW.target_publication_ref
    ) THEN
        RAISE EXCEPTION 'Cannot roll back to a Wiki publication invalidated by current revocations, holds, or deletions'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM thalion.wiki_published_input AS inp
        JOIN thalion.document_version AS ver
          ON (ver.org_id, ver.space_id, ver.version_id) = (inp.org_id, inp.space_id, inp.version_id)
        WHERE inp.publication_ref = NEW.target_publication_ref
          AND (
              thalion.document_source_deleted(ver.org_id, ver.space_id, ver.source_id, ver.document_id)
              OR EXISTS (SELECT 1 FROM thalion.rule_use_stop AS stop WHERE stop.version_id = ver.version_id)
              OR EXISTS (
                  SELECT 1 FROM thalion.current_version_hold AS hold
                  WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                      = (ver.org_id, ver.space_id, ver.version_id, 'establish')
              )
          )
    ) THEN
        RAISE EXCEPTION 'Cannot roll back to a Wiki publication whose inputs are currently stopped, held, or source-deleted'
            USING ERRCODE = '23514';
    END IF;

    SELECT rev.author_id, sha256(rev.content), req.business_date
    INTO STRICT target_author, target_digest, target_business_date
    FROM thalion.wiki_revision AS rev
    JOIN thalion.delivery_record AS d ON (d.org_id, d.check_id) = (target_pub.org_id, target_pub.check_id)
    JOIN thalion.request_record AS req ON (req.org_id, req.request_id) = (d.org_id, d.request_id)
    WHERE (rev.org_id, rev.space_id, rev.topic_key, rev.revision_ref)
        = (NEW.org_id, NEW.space_id, NEW.topic_key, NEW.target_revision_ref);

    IF NEW.actor_id = target_author THEN
        RAISE EXCEPTION 'Wiki author cannot self-rollback their own revision' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM thalion.space AS space
    JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (space.org_id, NEW.actor_id)
    JOIN thalion.principal AS orig_pub ON (orig_pub.org_id, orig_pub.principal_id) = (space.org_id, target_pub.publisher_id)
    JOIN thalion.delivery_record AS delivery ON (delivery.org_id, delivery.check_id) = (NEW.org_id, NEW.check_id)
    JOIN thalion.request_record AS req
      ON (req.org_id, req.request_id) = (delivery.org_id, delivery.request_id)
    WHERE (space.org_id, space.space_id) = (NEW.org_id, NEW.space_id)
      AND space.lifecycle = 'active'
      AND actor.principal_type = 'employee'
      AND actor.authority_issuer = 'https://synthetic.invalid'
      AND NOT actor.disabled
      AND orig_pub.principal_type = 'employee'
      AND orig_pub.authority_issuer = 'https://synthetic.invalid'
      AND NOT orig_pub.disabled
      AND req.request_id = NEW.request_id
      AND req.principal_id = NEW.actor_id
      AND req.delegated_principal_id IS NULL
      AND req.operation = 'rollback_wiki_topic'
      AND req.destination = 'local_workspace'
      AND req.business_date = target_business_date
      AND delivery.payload_digest = target_digest
      AND delivery.valid_until > clock_timestamp()
      AND thalion.same_wiki_dependency_snapshot(target_pub.check_id, NEW.check_id)
    FOR SHARE OF space, actor, orig_pub;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Wiki rollback does not match current authority receipt or dependency snapshot'
            USING ERRCODE = '23514';
    END IF;

    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER wiki_topic_rollback_insert_guard
BEFORE INSERT ON thalion.wiki_topic_rollback
FOR EACH ROW EXECUTE FUNCTION thalion.guard_wiki_topic_rollback_insert();

CREATE TRIGGER wiki_topic_rollback_immutable BEFORE UPDATE OR DELETE ON thalion.wiki_topic_rollback
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
CREATE TRIGGER wiki_topic_rollback_no_truncate BEFORE TRUNCATE ON thalion.wiki_topic_rollback
FOR EACH STATEMENT EXECUTE FUNCTION thalion.reject_original_change();

CREATE OR REPLACE VIEW thalion.available_wiki_publication AS
WITH effective_pointer AS (
    SELECT COALESCE(rb.target_publication_ref, current_pub.publication_ref) AS publication_ref
    FROM thalion.current_wiki_publication AS current_pub
    LEFT JOIN LATERAL (
        SELECT rollback.target_publication_ref
        FROM thalion.wiki_topic_rollback AS rollback
        WHERE (rollback.org_id, rollback.space_id, rollback.topic_key, rollback.from_publication_ref)
            = (current_pub.org_id, current_pub.space_id, current_pub.topic_key, current_pub.publication_ref)
        ORDER BY rollback.rollback_seq DESC
        LIMIT 1
    ) AS rb ON true
)
SELECT publication.*
FROM effective_pointer AS ptr
JOIN thalion.wiki_publication_event AS publication USING (publication_ref)
LEFT JOIN thalion.current_space_release_config AS cfg
  ON (cfg.org_id, cfg.space_id) = (publication.org_id, publication.space_id)
WHERE COALESCE(cfg.wiki_delivery_enabled, true)
  AND NOT EXISTS (
      SELECT 1 FROM thalion.wiki_availability_event AS stopped
      WHERE stopped.publication_ref = publication.publication_ref
  );

CREATE OR REPLACE FUNCTION thalion.verify_wiki_search_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.request_record AS request
        JOIN thalion.available_wiki_publication AS publication USING (org_id)
        JOIN thalion.wiki_revision AS revision USING (org_id, space_id, topic_key, revision_ref)
        WHERE (request.org_id, request.request_id) = (NEW.org_id, NEW.request_id)
          AND request.operation = 'search' AND request.destination = 'employee'
          AND publication.publication_ref = NEW.wiki_publication_ref AND revision.has_statements
    ) OR EXISTS (
        SELECT entry.space_id, entry.source_id, entry.passage_ref, entry.excerpt_revision, entry.policy_revision,
               entry.organization_epoch, entry.space_epoch, entry.source_epoch
        FROM thalion.wiki_publication_event AS publication
        JOIN thalion.delivery_dependency AS entry USING (org_id, check_id)
        WHERE publication.publication_ref = NEW.wiki_publication_ref
        EXCEPT
        SELECT entry.space_id, entry.source_id, entry.passage_ref, entry.excerpt_revision, entry.policy_revision,
               entry.organization_epoch, entry.space_epoch, entry.source_epoch
        FROM thalion.delivery_dependency AS entry WHERE entry.check_id = NEW.check_id
    ) THEN
        RAISE EXCEPTION 'Wiki search delivery requires current reviewed claims and all exact published dependencies'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;
