ALTER TABLE thalion.permission_binding DROP CONSTRAINT permission_binding_fields_check;
ALTER TABLE thalion.permission_binding ADD CONSTRAINT permission_binding_fields_check CHECK (
    cardinality(fields) BETWEEN 1 AND 5 AND array_position(fields, NULL) IS NULL
    AND fields <@ ARRAY['excerpt', 'citation', 'title', 'location', 'version']
);

ALTER TABLE thalion.delivery_record
    ADD CONSTRAINT delivery_record_org_check_identity UNIQUE (check_id, org_id),
    ADD COLUMN dependency_count integer NOT NULL DEFAULT 1 CHECK (dependency_count BETWEEN 1 AND 20);

CREATE TABLE thalion.delivery_dependency (
    check_id uuid NOT NULL,
    org_id bigint NOT NULL,
    position integer NOT NULL CHECK (position BETWEEN 1 AND 20),
    space_id bigint NOT NULL,
    source_id bigint NOT NULL,
    passage_ref uuid NOT NULL,
    excerpt_revision bigint NOT NULL CHECK (excerpt_revision > 0),
    policy_revision bigint NOT NULL,
    organization_epoch bigint NOT NULL CHECK (organization_epoch > 0),
    space_epoch bigint NOT NULL CHECK (space_epoch > 0),
    source_epoch bigint NOT NULL CHECK (source_epoch >= policy_revision),
    PRIMARY KEY (check_id, position),
    UNIQUE (check_id, passage_ref),
    FOREIGN KEY (check_id, org_id) REFERENCES thalion.delivery_record (check_id, org_id),
    FOREIGN KEY (org_id, space_id, passage_ref) REFERENCES thalion.object_identity (org_id, space_id, public_id),
    FOREIGN KEY (org_id, space_id, source_id, policy_revision)
        REFERENCES thalion.policy_revision (org_id, space_id, source_id, revision)
);

CREATE FUNCTION thalion.guard_delivery_dependency() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.object_identity AS identity
        JOIN thalion.passage_excerpt AS excerpt ON excerpt.passage_id = identity.object_id
        JOIN thalion.document_version AS version ON version.version_id = excerpt.version_id
        WHERE (identity.org_id, identity.space_id, identity.public_id, identity.object_type) =
              (NEW.org_id, NEW.space_id, NEW.passage_ref, 'passage')
          AND excerpt.excerpt_revision = NEW.excerpt_revision AND version.source_id = NEW.source_id
    ) THEN
        RAISE EXCEPTION 'delivery requires an exact excerpt in the same source' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER delivery_dependency_exact_excerpt BEFORE INSERT ON thalion.delivery_dependency
FOR EACH ROW EXECUTE FUNCTION thalion.guard_delivery_dependency();

INSERT INTO thalion.delivery_dependency (
    check_id, org_id, position, space_id, source_id, passage_ref, excerpt_revision,
    policy_revision, organization_epoch, space_epoch, source_epoch
)
SELECT check_id, org_id, 1, space_id, source_id, passage_ref, excerpt_revision,
       policy_revision, organization_epoch, space_epoch, source_epoch
FROM thalion.delivery_record;

ALTER TABLE thalion.delivery_record
    ALTER COLUMN dependency_count DROP DEFAULT,
    DROP COLUMN space_id,
    DROP COLUMN source_id,
    DROP COLUMN passage_ref,
    DROP COLUMN excerpt_revision,
    DROP COLUMN policy_revision,
    DROP COLUMN organization_epoch,
    DROP COLUMN space_epoch,
    DROP COLUMN source_epoch;

CREATE FUNCTION thalion.verify_delivery_dependencies() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, thalion AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM thalion.delivery_record AS delivery
        JOIN thalion.delivery_dependency AS dependency USING (check_id, org_id)
        WHERE delivery.check_id = NEW.check_id
        GROUP BY delivery.dependency_count
        HAVING count(*) = delivery.dependency_count AND max(dependency.position) = delivery.dependency_count
    ) THEN
        RAISE EXCEPTION 'delivery and its complete ordered dependencies must commit together'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER delivery_record_sealed AFTER INSERT ON thalion.delivery_record
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.verify_delivery_dependencies();
CREATE CONSTRAINT TRIGGER delivery_dependency_sealed AFTER INSERT ON thalion.delivery_dependency
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION thalion.verify_delivery_dependencies();
CREATE TRIGGER delivery_dependency_immutable BEFORE UPDATE OR DELETE ON thalion.delivery_dependency
FOR EACH ROW EXECUTE FUNCTION thalion.reject_original_change();
