ALTER TABLE thalion.synthetic_export_request
    ADD COLUMN wiki_publication_ref uuid,
    ADD FOREIGN KEY (org_id, space_id, wiki_publication_ref)
        REFERENCES thalion.wiki_publication_event (org_id, space_id, publication_ref),
    ADD CHECK (wiki_publication_ref IS NULL OR transcript_run_ref IS NULL);

CREATE INDEX synthetic_export_wiki_publication ON thalion.synthetic_export_request (wiki_publication_ref)
WHERE wiki_publication_ref IS NOT NULL;

CREATE VIEW thalion.wiki_archive_input AS
SELECT publication.org_id, publication.space_id, publication.publication_ref, entry.source_id, entry.position,
       entry.passage_ref, entry.excerpt_revision, excerpt.version_id, excerpt.run_ref, excerpt.content_digest,
       version.document_id, identity.public_id AS version_ref
FROM thalion.wiki_publication_event AS publication
JOIN thalion.wiki_revision AS revision USING (org_id, space_id, revision_ref)
JOIN thalion.input_manifest_entry AS entry
  ON (entry.org_id, entry.space_id, entry.manifest_ref) = (revision.org_id, revision.space_id, revision.manifest_ref)
JOIN thalion.object_identity AS location
  ON (location.org_id, location.space_id, location.public_id, location.object_type) =
     (entry.org_id, entry.space_id, entry.passage_ref, 'passage')
JOIN thalion.passage_excerpt AS excerpt
  ON (excerpt.org_id, excerpt.space_id, excerpt.passage_id, excerpt.excerpt_revision) =
     (location.org_id, location.space_id, location.object_id, entry.excerpt_revision)
JOIN thalion.document_version AS version
  ON (version.org_id, version.space_id, version.version_id) = (excerpt.org_id, excerpt.space_id, excerpt.version_id)
JOIN thalion.object_identity AS identity
  ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
     (version.org_id, version.space_id, 'document_version', version.version_id)
WHERE entry.source_id = version.source_id;

CREATE FUNCTION thalion.export_wiki_is_current(scope_org bigint, scope_space bigint, anchor_version bigint, selected uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1 FROM thalion.available_wiki_publication AS publication
        JOIN thalion.wiki_revision AS revision USING (org_id, space_id, topic_key, revision_ref)
        JOIN thalion.input_manifest AS manifest USING (manifest_ref)
        JOIN thalion.delivery_record AS seal ON seal.check_id = manifest.check_id
        JOIN thalion.synthetic_export_target AS anchor
          ON (anchor.org_id, anchor.space_id, anchor.version_id) = (publication.org_id, publication.space_id, anchor_version)
        CROSS JOIN LATERAL (
            SELECT count(*) AS input_count, bool_or(input.version_id = anchor_version) AS includes_anchor,
                   sha256(convert_to(jsonb_agg(jsonb_build_array(input.passage_ref, input.excerpt_revision)
                                             ORDER BY input.position)::text, 'UTF8')) AS input_digest,
                   bool_and(input.source_id = anchor.source_id AND target.blocked IS FALSE
                       AND checked.policy_revision IS NOT DISTINCT FROM source.local_policy_revision
                       AND ARRAY[checked.organization_epoch, checked.space_epoch, checked.source_epoch] = target.snapshot[1:3]
                       AND run.contract_revision = source.contract_revision
                       AND EXISTS (SELECT 1 FROM thalion.quality_decision AS quality
                                   WHERE quality.run_ref = input.run_ref AND quality.outcome = 'approved')
                       AND NOT EXISTS (SELECT 1 FROM thalion.quality_decision AS quality
                                       WHERE quality.run_ref = input.run_ref AND quality.outcome = 'quarantined')
                       AND NOT EXISTS (SELECT 1 FROM thalion.processing_run AS newer
                                       WHERE newer.version_id = input.version_id
                                         AND newer.configuration_revision > run.configuration_revision)) AS all_current
            FROM thalion.wiki_archive_input AS input
            JOIN thalion.delivery_dependency AS checked
              ON (checked.check_id, checked.org_id, checked.space_id, checked.position, checked.source_id,
                  checked.passage_ref, checked.excerpt_revision) =
                 (publication.check_id, input.org_id, input.space_id, input.position, input.source_id,
                  input.passage_ref, input.excerpt_revision)
            JOIN thalion.processing_run AS run ON run.run_ref = input.run_ref
            JOIN thalion.source AS source
              ON (source.org_id, source.space_id, source.source_id) = (input.org_id, input.space_id, input.source_id)
            LEFT JOIN thalion.synthetic_export_target AS target
              ON (target.org_id, target.space_id, target.version_id) = (input.org_id, input.space_id, input.version_id)
            WHERE (input.org_id, input.space_id, input.publication_ref) = (scope_org, scope_space, selected)
        ) AS coverage
        WHERE (publication.org_id, publication.space_id, publication.publication_ref) = (scope_org, scope_space, selected)
          AND NOT anchor.blocked AND coverage.input_count = seal.dependency_count AND coverage.input_digest = revision.input_digest
          AND coverage.includes_anchor AND coverage.all_current
    );
$$;

CREATE FUNCTION thalion.lock_synthetic_wiki_export(scope_org bigint, scope_space bigint, selected uuid)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM document.document_id FROM thalion.wiki_archive_input AS input
    JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
    WHERE (input.org_id, input.space_id, input.publication_ref) = (scope_org, scope_space, selected)
    ORDER BY document.document_id FOR SHARE OF document;
    PERFORM wiki.topic_key FROM thalion.wiki_publication_event AS publication
    JOIN thalion.wiki AS wiki USING (org_id, space_id, topic_key)
    WHERE (publication.org_id, publication.space_id, publication.publication_ref) = (scope_org, scope_space, selected)
    FOR SHARE OF wiki;
END;
$$;

CREATE FUNCTION thalion.guard_export_wiki_scope() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    candidate thalion.synthetic_export_request%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'synthetic_export_request' THEN
        candidate := NEW;
    ELSE
        SELECT * INTO STRICT candidate FROM thalion.synthetic_export_request AS request
        WHERE (request.org_id, request.space_id, request.export_ref, request.requester_id) =
              (NEW.org_id, NEW.space_id, NEW.export_ref, NEW.requester_id);
    END IF;
    IF candidate.wiki_publication_ref IS NOT NULL THEN
        PERFORM thalion.lock_synthetic_wiki_export(candidate.org_id, candidate.space_id, candidate.wiki_publication_ref);
        IF NOT thalion.export_wiki_is_current(candidate.org_id, candidate.space_id, candidate.version_id, candidate.wiki_publication_ref) THEN
            RAISE EXCEPTION 'Wiki archive requires the current exact publication and all inputs in the approved source'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_export_request_wiki_scope BEFORE INSERT ON thalion.synthetic_export_request
FOR EACH ROW EXECUTE FUNCTION thalion.guard_export_wiki_scope();
CREATE TRIGGER synthetic_export_approval_wiki_scope BEFORE INSERT ON thalion.synthetic_export_approval
FOR EACH ROW EXECUTE FUNCTION thalion.guard_export_wiki_scope();
CREATE TRIGGER synthetic_export_package_wiki_scope BEFORE INSERT ON thalion.synthetic_export_package
FOR EACH ROW EXECUTE FUNCTION thalion.guard_export_wiki_scope();
