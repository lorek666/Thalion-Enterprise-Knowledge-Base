ALTER TABLE thalion.delivery_dependency ADD COLUMN effectivity_ref uuid REFERENCES thalion.rule_effectivity (decision_ref);

CREATE FUNCTION thalion.verify_delivery_effectivity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.rule_effectivity AS decision
        JOIN thalion.passage AS part ON part.version_id = decision.version_id
        JOIN thalion.object_identity AS location
          ON (location.org_id, location.space_id, location.object_type, location.object_id) =
             (part.org_id, part.space_id, 'passage', part.passage_id)
        WHERE (decision.org_id, decision.space_id, decision.source_id, decision.decision_ref, location.public_id) =
              (NEW.org_id, NEW.space_id, NEW.source_id, NEW.effectivity_ref, NEW.passage_ref)
    ) THEN
        RAISE EXCEPTION 'delivery effectivity must apply to the exact passage version' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_effectivity_scoped BEFORE INSERT ON thalion.delivery_dependency
FOR EACH ROW WHEN (NEW.effectivity_ref IS NOT NULL) EXECUTE FUNCTION thalion.verify_delivery_effectivity();

ALTER TABLE thalion.wiki_publication_event ADD UNIQUE (org_id, space_id, publication_ref);

CREATE TABLE thalion.wiki_availability_event (
    event_ref uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id bigint NOT NULL,
    space_id bigint NOT NULL,
    publication_ref uuid NOT NULL,
    reason text NOT NULL CHECK (reason IN ('suspended', 'withdrawn', 'quarantined', 'reprocessed', 'policy_changed', 'rule_replaced')),
    cause_ref uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (publication_ref, reason, cause_ref),
    UNIQUE (org_id, space_id, event_ref),
    FOREIGN KEY (org_id, space_id, publication_ref)
        REFERENCES thalion.wiki_publication_event (org_id, space_id, publication_ref)
);

CREATE TRIGGER wiki_availability_immutable BEFORE UPDATE OR DELETE ON thalion.wiki_availability_event
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();

CREATE VIEW thalion.available_wiki_publication AS
SELECT publication.* FROM thalion.current_wiki_publication AS publication
WHERE NOT EXISTS (
    SELECT 1 FROM thalion.wiki_availability_event AS stopped WHERE stopped.publication_ref = publication.publication_ref
);

CREATE VIEW thalion.pending_wiki_rebuild AS
SELECT stopped.org_id, stopped.space_id, stopped.event_ref, publication.topic_key
FROM thalion.wiki_availability_event AS stopped
JOIN thalion.current_wiki_publication AS publication USING (org_id, space_id, publication_ref);

CREATE VIEW thalion.wiki_published_input AS
SELECT publication.org_id, publication.space_id, publication.publication_ref, request.business_date,
       dependency.source_id, dependency.policy_revision, dependency.effectivity_ref,
       excerpt.version_id, excerpt.run_ref, run.configuration_revision
FROM thalion.wiki_publication_event AS publication
JOIN thalion.delivery_record AS delivery USING (org_id, check_id)
JOIN thalion.request_record AS request USING (org_id, request_id)
JOIN thalion.delivery_dependency AS dependency
  ON (dependency.org_id, dependency.space_id, dependency.check_id) = (publication.org_id, publication.space_id, publication.check_id)
JOIN thalion.object_identity AS location
  ON (location.org_id, location.space_id, location.public_id, location.object_type) =
     (dependency.org_id, dependency.space_id, dependency.passage_ref, 'passage')
JOIN thalion.passage_excerpt AS excerpt
  ON (excerpt.org_id, excerpt.space_id, excerpt.passage_id, excerpt.excerpt_revision) =
     (location.org_id, location.space_id, location.object_id, dependency.excerpt_revision)
JOIN thalion.processing_run AS run ON run.run_ref = excerpt.run_ref;

CREATE FUNCTION thalion.record_wiki_input_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    stop_reason text;
    cause uuid;
    affected_version bigint;
    affected_source bigint;
    affected_run uuid;
    new_processing bigint;
    new_policy bigint;
    previous_decision uuid;
    cutoff date;
BEGIN
    IF TG_TABLE_NAME = 'rule_use_stop' THEN
        stop_reason := NEW.kind;
        cause := NEW.decision_ref;
        affected_version := NEW.version_id;
    ELSIF TG_TABLE_NAME = 'quality_decision' THEN
        stop_reason := 'quarantined';
        cause := NEW.decision_ref;
        affected_version := NEW.version_id;
        affected_run := NEW.run_ref;
    ELSIF TG_TABLE_NAME = 'processing_run' THEN
        stop_reason := 'reprocessed';
        cause := NEW.run_ref;
        affected_version := NEW.version_id;
        new_processing := NEW.configuration_revision;
    ELSIF TG_TABLE_NAME = 'source' THEN
        stop_reason := 'policy_changed';
        affected_source := NEW.source_id;
        new_policy := NEW.local_policy_revision;
        SELECT policy_ref INTO STRICT cause FROM thalion.policy_revision
        WHERE (org_id, space_id, source_id, revision) = (NEW.org_id, NEW.space_id, affected_source, new_policy);
    ELSIF TG_TABLE_NAME = 'rule_effectivity' THEN
        stop_reason := 'rule_replaced';
        cause := NEW.decision_ref;
        previous_decision := NEW.replaces_ref;
        cutoff := NEW.valid_from;
        SELECT version_id INTO STRICT affected_version FROM thalion.rule_effectivity WHERE decision_ref = previous_decision;
    END IF;

    INSERT INTO thalion.wiki_availability_event (org_id, space_id, publication_ref, reason, cause_ref)
    SELECT DISTINCT input.org_id, input.space_id, input.publication_ref, stop_reason, cause
    FROM thalion.wiki_published_input AS input
    WHERE (input.org_id, input.space_id) = (NEW.org_id, NEW.space_id)
      AND (affected_version IS NULL OR input.version_id = affected_version)
      AND (affected_source IS NULL OR input.source_id = affected_source)
      AND (affected_run IS NULL OR input.run_ref = affected_run)
      AND (new_processing IS NULL OR input.configuration_revision < new_processing)
      AND (new_policy IS NULL OR input.policy_revision < new_policy)
      AND (previous_decision IS NULL OR (input.effectivity_ref = previous_decision AND input.business_date >= cutoff))
    ON CONFLICT (publication_ref, reason, cause_ref) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE TRIGGER wiki_dependency_rule_stop AFTER INSERT ON thalion.rule_use_stop
FOR EACH ROW EXECUTE FUNCTION thalion.record_wiki_input_change();
CREATE TRIGGER wiki_dependency_quarantine AFTER INSERT ON thalion.quality_decision
FOR EACH ROW WHEN (NEW.outcome = 'quarantined') EXECUTE FUNCTION thalion.record_wiki_input_change();
CREATE TRIGGER wiki_dependency_reprocessed AFTER INSERT ON thalion.processing_run
FOR EACH ROW WHEN (NEW.configuration_revision > 1) EXECUTE FUNCTION thalion.record_wiki_input_change();
CREATE TRIGGER wiki_dependency_policy_changed AFTER UPDATE OF local_policy_revision ON thalion.source
FOR EACH ROW WHEN (NEW.local_policy_revision IS NOT NULL AND OLD.local_policy_revision IS DISTINCT FROM NEW.local_policy_revision)
EXECUTE FUNCTION thalion.record_wiki_input_change();
CREATE TRIGGER wiki_dependency_rule_replaced AFTER INSERT ON thalion.rule_effectivity
FOR EACH ROW WHEN (NEW.replaces_ref IS NOT NULL) EXECUTE FUNCTION thalion.record_wiki_input_change();

INSERT INTO thalion.wiki_availability_event (org_id, space_id, publication_ref, reason, cause_ref)
SELECT DISTINCT input.org_id, input.space_id, input.publication_ref, change.reason, change.cause_ref
FROM thalion.wiki_published_input AS input
CROSS JOIN LATERAL (
    SELECT stop.kind AS reason, stop.decision_ref AS cause_ref
    FROM thalion.rule_use_stop AS stop WHERE stop.version_id = input.version_id
    UNION ALL
    SELECT 'quarantined', quality.decision_ref FROM thalion.quality_decision AS quality
    WHERE quality.run_ref = input.run_ref AND quality.outcome = 'quarantined'
    UNION ALL
    SELECT 'reprocessed', newer.run_ref FROM thalion.processing_run AS newer
    WHERE newer.version_id = input.version_id AND newer.configuration_revision > input.configuration_revision
    UNION ALL
    SELECT 'policy_changed', policy.policy_ref FROM thalion.source AS source
    JOIN thalion.policy_revision AS policy ON (policy.org_id, policy.space_id, policy.source_id, policy.revision) =
        (source.org_id, source.space_id, source.source_id, source.local_policy_revision)
    WHERE source.source_id = input.source_id AND policy.revision > input.policy_revision
) AS change
ON CONFLICT (publication_ref, reason, cause_ref) DO NOTHING;

ALTER TABLE thalion.input_manifest
    ADD COLUMN rebuild_event_ref uuid,
    ADD FOREIGN KEY (org_id, space_id, rebuild_event_ref) REFERENCES thalion.wiki_availability_event (org_id, space_id, event_ref),
    ADD CHECK (rebuild_event_ref IS NULL OR (direct_count > 0 AND cardinality(parent_refs) = 0));

CREATE FUNCTION thalion.verify_wiki_rebuild_lineage() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM thalion.input_manifest AS manifest
        JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
        JOIN thalion.wiki_publication_event AS publication ON publication.publication_ref = stopped.publication_ref
        WHERE manifest.manifest_ref = NEW.manifest_ref AND publication.topic_key <> NEW.topic_key
    ) THEN
        RAISE EXCEPTION 'clean Wiki rebuild lineage must belong to the same topic' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER wiki_rebuild_lineage BEFORE INSERT ON thalion.wiki_revision
FOR EACH ROW EXECUTE FUNCTION thalion.verify_wiki_rebuild_lineage();

CREATE FUNCTION thalion.verify_rebuild_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM thalion.wiki_revision AS revision
        JOIN thalion.input_manifest AS manifest USING (manifest_ref)
        JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
        JOIN thalion.wiki_publication_event AS previous ON previous.publication_ref = stopped.publication_ref
        WHERE revision.revision_ref = NEW.revision_ref AND previous.generation <> NEW.generation - 1
    ) THEN
        RAISE EXCEPTION 'clean Wiki rebuild must replace its original stopped generation' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER wiki_rebuild_generation BEFORE INSERT ON thalion.wiki_publication_event
FOR EACH ROW EXECUTE FUNCTION thalion.verify_rebuild_generation();

CREATE FUNCTION thalion.verify_wiki_search_availability() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.available_wiki_publication WHERE publication_ref = NEW.wiki_publication_ref
    ) THEN
        RAISE EXCEPTION 'stopped Wiki publications cannot receive a search receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER wiki_search_requires_availability AFTER INSERT ON thalion.delivery_record
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.wiki_publication_ref IS NOT NULL)
EXECUTE FUNCTION thalion.verify_wiki_search_availability();
