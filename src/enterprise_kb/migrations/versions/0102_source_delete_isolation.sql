CREATE INDEX source_restriction_deleted_lookup
    ON thalion.source_restriction_receipt (org_id, space_id, source_id, local_stop_ref)
    WHERE kind = 'deleted';

CREATE FUNCTION thalion.document_source_deleted(
    target_org bigint, target_space bigint, target_source bigint, target_document bigint
) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, thalion AS $$
    SELECT EXISTS (
        SELECT 1
        FROM thalion.source_restriction_receipt AS receipt
        JOIN thalion.rule_use_stop AS stop
          ON stop.decision_ref = receipt.local_stop_ref
        WHERE (receipt.org_id, receipt.space_id, receipt.source_id, receipt.kind)
            = (target_org, target_space, target_source, 'deleted')
          AND (stop.org_id, stop.space_id, stop.source_id, stop.document_id, stop.kind)
            = (target_org, target_space, target_source, target_document, 'deletion_blocked')
    )
$$;

CREATE FUNCTION thalion.lock_source_deleted_document() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    target_document bigint;
BEGIN
    SELECT stop.document_id INTO target_document
    FROM thalion.rule_use_stop AS stop
    WHERE stop.decision_ref = NEW.local_stop_ref;
    IF target_document IS NOT NULL THEN
        PERFORM document_id FROM thalion.document
        WHERE (org_id, space_id, source_id, document_id)
            = (NEW.org_id, NEW.space_id, NEW.source_id, target_document)
        FOR UPDATE;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_restriction_deleted_lock
BEFORE INSERT ON thalion.source_restriction_receipt
FOR EACH ROW WHEN (NEW.kind = 'deleted')
EXECUTE FUNCTION thalion.lock_source_deleted_document();

CREATE FUNCTION thalion.stop_wiki_for_source_deleted_document() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    target_document bigint;
BEGIN
    SELECT stop.document_id INTO target_document
    FROM thalion.rule_use_stop AS stop
    WHERE stop.decision_ref = NEW.local_stop_ref;
    IF target_document IS NOT NULL THEN
        INSERT INTO thalion.wiki_availability_event (org_id, space_id, publication_ref, reason, cause_ref)
        SELECT DISTINCT input.org_id, input.space_id, input.publication_ref, 'deletion_blocked', NEW.local_stop_ref
        FROM thalion.wiki_published_input AS input
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.version_id)
           = (input.org_id, input.space_id, input.version_id)
        WHERE (version.org_id, version.space_id, version.source_id, version.document_id)
            = (NEW.org_id, NEW.space_id, NEW.source_id, target_document)
        ON CONFLICT (publication_ref, reason, cause_ref) DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER source_restriction_deleted_wiki
AFTER INSERT ON thalion.source_restriction_receipt
FOR EACH ROW WHEN (NEW.kind = 'deleted')
EXECUTE FUNCTION thalion.stop_wiki_for_source_deleted_document();

CREATE FUNCTION thalion.guard_document_version_source_deleted() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM document_id FROM thalion.document
    WHERE (org_id, space_id, source_id, document_id)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
    FOR SHARE;
    IF thalion.document_source_deleted(NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id) THEN
        RAISE EXCEPTION 'cannot register a new version for a source-deleted document incarnation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER document_version_source_deleted_guard
BEFORE INSERT ON thalion.document_version
FOR EACH ROW EXECUTE FUNCTION thalion.guard_document_version_source_deleted();

CREATE FUNCTION thalion.guard_rule_effectivity_source_deleted() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF thalion.document_source_deleted(NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id) THEN
        RAISE EXCEPTION 'cannot approve effectivity for a source-deleted document incarnation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER rule_effectivity_source_deleted_guard
BEFORE INSERT ON thalion.rule_effectivity
FOR EACH ROW EXECUTE FUNCTION thalion.guard_rule_effectivity_source_deleted();

CREATE FUNCTION thalion.guard_sync_page_item_source_deleted() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    PERFORM document_id FROM thalion.document
    WHERE (org_id, space_id, source_id, document_id)
        = (NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id)
    FOR SHARE;
    IF thalion.document_source_deleted(NEW.org_id, NEW.space_id, NEW.source_id, NEW.document_id) THEN
        RAISE EXCEPTION 'cannot commit a new sync page item for a source-deleted document incarnation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_sync_page_item_source_deleted_guard
BEFORE INSERT ON thalion.source_sync_page_item
FOR EACH ROW EXECUTE FUNCTION thalion.guard_sync_page_item_source_deleted();

CREATE FUNCTION thalion.guard_lexical_index_stopped() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
DECLARE
    version_source bigint;
    version_document bigint;
BEGIN
    SELECT source_id, document_id INTO version_source, version_document
    FROM thalion.document_version
    WHERE (org_id, space_id, version_id) = (NEW.org_id, NEW.space_id, NEW.version_id);
    IF EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = NEW.version_id)
       OR (version_document IS NOT NULL
           AND thalion.document_source_deleted(NEW.org_id, NEW.space_id, version_source, version_document)) THEN
        RAISE EXCEPTION 'stopped or source-deleted versions cannot be lexically indexed'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER synthetic_lexical_index_stop_guard
BEFORE INSERT ON thalion.synthetic_lexical_index
FOR EACH ROW EXECUTE FUNCTION thalion.guard_lexical_index_stopped();

INSERT INTO thalion.wiki_availability_event (org_id, space_id, publication_ref, reason, cause_ref)
SELECT DISTINCT input.org_id, input.space_id, input.publication_ref, 'deletion_blocked', receipt.local_stop_ref
FROM thalion.source_restriction_receipt AS receipt
JOIN thalion.rule_use_stop AS stop ON stop.decision_ref = receipt.local_stop_ref
JOIN thalion.document_version AS version
  ON (version.org_id, version.space_id, version.source_id, version.document_id)
   = (stop.org_id, stop.space_id, stop.source_id, stop.document_id)
JOIN thalion.wiki_published_input AS input
  ON (input.org_id, input.space_id, input.version_id)
   = (version.org_id, version.space_id, version.version_id)
WHERE receipt.kind = 'deleted'
ON CONFLICT (publication_ref, reason, cause_ref) DO NOTHING;
