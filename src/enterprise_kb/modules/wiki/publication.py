import re
from collections.abc import Callable
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.access.delivery import AuthorityDecision, DeliveryCheck, DeliveryContext
from enterprise_kb.modules.access.policy import WIKI_PUBLISH_ACCESS, WIKI_READ_ACCESS
from enterprise_kb.modules.access.travel import authorize_travel_dependency_payload
from enterprise_kb.runtime.commands import IdempotencyConflict, execute_command

from .drafts import WikiResult, _Changed, _append_wiki_event, _command, _entries, _generation
from .projection import is_available_publication


def _load_content(connection, org_id, space_id, revision_ref):
    return connection.execute(
        "SELECT content FROM thalion.wiki_revision WHERE (org_id, space_id, revision_ref) = (%s, %s, %s)",
        (org_id, space_id, revision_ref),
    ).fetchone()[0]


def publish_revision(
    connection: Connection, context: DeliveryContext, space_id: int, revision_ref: UUID, review_ref: UUID, key: str,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> WikiResult:
    if (context.operation, context.purpose, context.destination) != WIKI_PUBLISH_ACCESS:
        return WikiResult("rejected")
    scope = (context.org_id, space_id)
    snapshot = None
    result_ref = None
    command = _command(context, key, space_id, str(revision_ref), str(review_ref))

    def resolve(transaction):
        nonlocal snapshot
        snapshot = transaction.execute(
            """
            SELECT revision.topic_key, revision.manifest_ref, material.expected_generation, review.check_id,
                   previous.generation
            FROM thalion.wiki_revision AS revision
            JOIN thalion.wiki_review AS review USING (org_id, space_id, revision_ref, reviewer_id)
            JOIN thalion.wiki_review_material AS material ON material.check_id = review.material_check_id
            JOIN thalion.input_manifest AS manifest USING (manifest_ref)
            LEFT JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
            LEFT JOIN thalion.wiki_publication_event AS previous ON previous.publication_ref = stopped.publication_ref
            WHERE (revision.org_id, revision.space_id, revision.revision_ref, review.review_ref, review.reviewer_id)
                = (%s, %s, %s, %s, %s) AND review.decision = 'approved'
            """, (*scope, revision_ref, review_ref, context.principal_id),
        ).fetchone()
        if snapshot is None:
            return ()
        if snapshot[2] is None or (snapshot[4] is not None and snapshot[2] != snapshot[4]):
            raise _Changed()
        return _entries(transaction, context, space_id, snapshot[1])

    def seal(transaction, delivery):
        nonlocal result_ref
        topic, _, expected_generation, reviewed_check, _ = snapshot
        topic_scope = (*scope, topic)
        check_id = delivery.check.check_id
        if not transaction.execute(
            "SELECT thalion.same_wiki_dependency_snapshot(%s, %s)", (reviewed_check, check_id),
        ).fetchone()[0]:
            raise _Changed()

        def apply(write):
            if _generation(write, topic_scope, writing=True) != expected_generation:
                raise _Changed()
            published = write.execute(
                """
                INSERT INTO thalion.wiki_publication_event (
                    org_id, space_id, topic_key, generation, revision_ref, review_ref, publisher_id, check_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING publication_ref
                """, (*topic_scope, expected_generation + 1, revision_ref, review_ref, context.principal_id, check_id),
            ).fetchone()[0]
            _append_wiki_event(write, *scope, "wiki.revision.published")
            return published

        result_ref = execute_command(transaction, command, apply).result_ref

    try:
        delivery = authorize_travel_dependency_payload(
            connection, context, space_id, region=region, traveler_class=traveler_class, check_authority=check_authority,
            resolve=resolve, build_payload=lambda: _load_content(connection, *scope, revision_ref), seal=seal,
        )
    except (_Changed, IdempotencyConflict):
        return WikiResult("input_changed")
    return WikiResult(delivery.status, result_ref if delivery.status == "succeeded" else None)


def read_current_revision(
    connection: Connection, context: DeliveryContext, space_id: int, topic_key: str,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> WikiResult:
    if (context.operation, context.purpose, context.destination) != WIKI_READ_ACCESS or not re.fullmatch(
        r"[a-z][a-z0-9_-]{0,63}", topic_key,
    ):
        return WikiResult("rejected")
    scope = (context.org_id, space_id, topic_key)
    snapshot = None

    def resolve(transaction):
        nonlocal snapshot
        snapshot = transaction.execute(
            """
            SELECT publication.publication_ref, publication.revision_ref, revision.manifest_ref
            FROM thalion.available_wiki_publication AS publication
            JOIN thalion.wiki_revision AS revision USING (org_id, space_id, topic_key, revision_ref)
            WHERE (publication.org_id, publication.space_id, publication.topic_key) = (%s, %s, %s)
            """, scope,
        ).fetchone()
        if snapshot is None:
            return ()
        return _entries(transaction, context, space_id, snapshot[2])

    def verify_pointer(transaction, _delivery):
        if not is_available_publication(transaction, *scope, snapshot[0]):
            raise _Changed()

    try:
        delivery = authorize_travel_dependency_payload(
            connection, context, space_id, region=region, traveler_class=traveler_class, check_authority=check_authority,
            resolve=resolve, build_payload=lambda: _load_content(connection, *scope[:2], snapshot[1]), seal=verify_pointer,
        )
    except _Changed:
        return WikiResult("input_changed")
    if delivery.status != "succeeded":
        return WikiResult(delivery.status)
    return WikiResult("succeeded", snapshot[1], delivery.payload, valid_until=delivery.valid_until)
