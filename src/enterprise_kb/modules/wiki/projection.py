from dataclasses import dataclass
from datetime import date
import json
from uuid import UUID

from psycopg import Connection


@dataclass(frozen=True)
class SearchPublication:
    wiki_ref: UUID
    topic_key: str
    publication_ref: UUID
    revision_ref: UUID
    check_id: UUID


def list_search_publications(
    connection: Connection, org_id: int, space_id: int, business_date: date, limit: int,
) -> tuple[SearchPublication, ...]:
    rows = connection.execute(
        """
        SELECT wiki.wiki_ref, wiki.topic_key, publication.publication_ref, publication.revision_ref, publication.check_id
        FROM thalion.available_wiki_publication AS publication
        JOIN thalion.wiki AS wiki USING (org_id, space_id, topic_key)
        JOIN thalion.wiki_revision AS revision USING (org_id, space_id, topic_key, revision_ref)
        JOIN thalion.delivery_record AS delivery
          ON (publication.org_id, publication.check_id) = (delivery.org_id, delivery.check_id)
        JOIN thalion.request_record AS request
          ON (delivery.org_id, delivery.request_id) = (request.org_id, request.request_id)
        WHERE (publication.org_id, publication.space_id, request.business_date) = (%s, %s, %s)
          AND revision.has_statements
        ORDER BY wiki.wiki_ref LIMIT %s
        """,
        (org_id, space_id, business_date, limit),
    ).fetchall()
    return tuple(SearchPublication(*row) for row in rows)


def search_publication_dependencies(connection: Connection, publication: SearchPublication):
    return connection.execute(
        """
        SELECT space_id, source_id, passage_ref, excerpt_revision, policy_revision,
               organization_epoch, space_epoch, source_epoch
        FROM thalion.delivery_dependency WHERE check_id = %s ORDER BY position
        """, (publication.check_id,),
    ).fetchall()


def load_search_fields(connection: Connection, publication: SearchPublication) -> dict:
    content, = connection.execute(
        "SELECT content FROM thalion.wiki_revision WHERE revision_ref = %s AND has_statements",
        (publication.revision_ref,),
    ).fetchone()
    manuscript = json.loads(content)
    return {
        "source_type": "wiki", "wiki_id": str(publication.wiki_ref), "revision_id": str(publication.revision_ref),
        "title": manuscript["title"],
        "claims": [{
            "text": statement["text"],
            "passage_ids": list(dict.fromkeys(ref for group in statement["support_groups"] for ref, _ in group)),
        } for statement in manuscript["statements"]],
    }


def is_available_publication(
    connection: Connection, org_id: int, space_id: int, topic_key: str, publication_ref: UUID,
) -> bool:
    scope = (org_id, space_id, topic_key)
    connection.execute(
        "SELECT 1 FROM thalion.wiki WHERE (org_id, space_id, topic_key) = (%s, %s, %s) FOR SHARE", scope,
    ).fetchone()
    return connection.execute(
        """
        SELECT 1 FROM thalion.available_wiki_publication
        WHERE (org_id, space_id, topic_key, publication_ref) = (%s, %s, %s, %s)
        """, (*scope, publication_ref),
    ).fetchone() is not None
