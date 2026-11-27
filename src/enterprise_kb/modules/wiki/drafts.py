from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Literal
from uuid import UUID

from psycopg import Connection
from psycopg.types.json import Jsonb

from enterprise_kb.modules.access.delivery import AuthorityDecision, DeliveryCheck, DeliveryContext, DeliveryDecision
from enterprise_kb.modules.access.policy import WIKI_CANDIDATE_ACCESS, WIKI_PREVIEW_ACCESS, WIKI_REVIEW_ACCESS
from enterprise_kb.modules.access.travel import authorize_travel_dependency_payload
from enterprise_kb.modules.sources.registry import sql_admitted_issuer
from enterprise_kb.runtime.commands import CommandEnvelope, IdempotencyConflict, execute_command
from enterprise_kb.runtime.events import append_event


class _Rejected(Exception):
    pass


class _Changed(Exception):
    pass


@dataclass(frozen=True)
class WikiStatement:
    text: str = field(repr=False)
    support_groups: tuple[tuple[tuple[UUID, int], ...], ...]


@dataclass(frozen=True)
class ManualCandidate:
    topic_key: str
    title: str = field(repr=False)
    markdown: str = field(repr=False)
    manifest_ref: UUID
    reviewer_id: int
    basis_ref: UUID
    citations: tuple[tuple[UUID, int], ...]
    statements: tuple[WikiStatement, ...] = ()


@dataclass(frozen=True)
class WikiResult:
    status: Literal["succeeded", "no_evidence", "rejected", "input_changed", "dependency_unavailable"]
    ref: UUID | None = None
    payload: bytes | None = field(default=None, repr=False)
    input_digest: bytes | None = None
    valid_until: datetime | None = None
    review_material_ref: UUID | None = None
    expected_generation: int | None = None


def _json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _statement_content(statements, citations):
    if len(statements) > 20:
        raise _Rejected()
    encoded = []
    for statement in statements:
        groups = statement.support_groups
        if (not statement.text.strip() or len(statement.text) > 2000 or "\x00" in statement.text
                or not 1 <= len(groups) <= 20):
            raise _Rejected()
        supports = []
        for group in groups:
            if (not 1 <= len(group) <= 20 or len(set(group)) != len(group) or not set(group) <= citations
                    or any(not isinstance(ref, UUID) or type(revision) is not int for ref, revision in group)):
                raise _Rejected()
            supports.append([[str(ref), revision] for ref, revision in group])
        encoded.append({"text": statement.text, "support_groups": supports})
    return encoded


def _command(context, key, *parts):
    return CommandEnvelope(
        context.org_id, context.principal_id, None, context.request_id, context.operation, key,
        sha256(_json(parts)).digest(), 1, None,
    )


def _entries(connection, context, space_id, manifest_ref):
    return tuple(connection.execute(
        """
        SELECT entry.passage_ref, entry.excerpt_revision
        FROM thalion.input_manifest_entry AS entry
        JOIN thalion.delivery_record AS origin USING (org_id, check_id)
        JOIN thalion.request_record AS origin_request ON (origin.org_id, origin.request_id) =
            (origin_request.org_id, origin_request.request_id)
        JOIN thalion.request_record AS current_request ON current_request.org_id = origin.org_id
            AND current_request.request_id = %s AND current_request.business_date = origin_request.business_date
        WHERE (entry.org_id, entry.space_id, entry.manifest_ref) = (%s, %s, %s) ORDER BY entry.position
        """,
        (context.request_id, context.org_id, space_id, manifest_ref),
    ).fetchall())


def _current_reviewer(connection, org_id, reviewer_id):
    return connection.execute(
        f"""
        SELECT 1 FROM thalion.principal WHERE (org_id, principal_id) = (%s, %s)
          AND principal_type = 'employee' AND {sql_admitted_issuer('authority_issuer')} AND NOT disabled
        FOR SHARE
        """,
        (org_id, reviewer_id),
    ).fetchone() is not None


def _append_wiki_event(connection, org_id, space_id, event_type):
    space_ref = connection.execute(
        """
        SELECT public_id FROM thalion.object_identity
        WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'space', %s)
        """,
        (org_id, space_id, space_id),
    ).fetchone()[0]
    append_event(connection, org_id, event_type, space_ref, space_id=space_id)


def _generation(connection, scope, *, writing):
    locking = " FOR NO KEY UPDATE" if writing else " FOR SHARE"
    connection.execute(
        "SELECT 1 FROM thalion.wiki WHERE (org_id, space_id, topic_key) = (%s, %s, %s)" + locking, scope,
    ).fetchone()
    return connection.execute(
        """
        SELECT coalesce(max(generation), 0) FROM thalion.wiki_publication_event
        WHERE (org_id, space_id, topic_key) = (%s, %s, %s)
        """, scope,
    ).fetchone()[0]


def create_manual_candidate(
    connection: Connection, context: DeliveryContext, space_id: int, draft: ManualCandidate, key: str,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> WikiResult:
    if (context.operation, context.purpose, context.destination) != WIKI_CANDIDATE_ACCESS:
        return WikiResult("rejected")
    citations = tuple(draft.citations)
    if (
        draft.reviewer_id == context.principal_id or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", draft.topic_key)
        or not draft.title.strip() or len(draft.title) > 256 or not draft.markdown.strip()
        or "\x00" in draft.title or "\x00" in draft.markdown
        or not 1 <= len(citations) <= 20 or len(set(citations)) != len(citations)
        or any(not isinstance(ref, UUID) or type(revision) is not int or revision < 1 for ref, revision in citations)
    ):
        return WikiResult("rejected")
    contents = {"title": draft.title, "markdown": draft.markdown,
                "citations": [[str(ref), revision] for ref, revision in citations]}
    try:
        if draft.statements:
            contents["statements"] = _statement_content(draft.statements, set(citations))
        content = _json(contents)
    except (_Rejected, UnicodeError):
        return WikiResult("rejected")
    if len(content) > 131072:
        return WikiResult("rejected")
    scope = (context.org_id, space_id)
    manifest_scope = (*scope, context.principal_id, draft.manifest_ref)
    command = _command(context, key, space_id, draft.topic_key, str(draft.manifest_ref), draft.reviewer_id,
                       str(draft.basis_ref), sha256(content).hexdigest())
    revision_ref = None

    def resolve(transaction):
        if transaction.execute(
            """
            SELECT 1 FROM thalion.input_manifest AS manifest
            LEFT JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
            LEFT JOIN thalion.wiki_publication_event AS previous ON previous.publication_ref = stopped.publication_ref
            WHERE (manifest.org_id, manifest.space_id, manifest.author_id, manifest.manifest_ref) = (%s, %s, %s, %s)
              AND (manifest.rebuild_event_ref IS NULL OR previous.topic_key = %s)
            """, (*manifest_scope, draft.topic_key),
        ).fetchone() is None:
            return ()
        entries = _entries(transaction, context, space_id, draft.manifest_ref)
        if not set(citations) <= set(entries):
            return ()
        support_sets = [contents["citations"], *(
            group for statement in contents.get("statements", ()) for group in statement["support_groups"]
        )]
        complete, = transaction.execute(
            """
            SELECT bool_and(thalion.wiki_evidence_groups_complete(%s, %s, refs))
            FROM jsonb_array_elements(%s) AS refs
            """, (*scope, Jsonb(support_sets)),
        ).fetchone()
        return entries if complete else ()

    def seal(transaction, decision: DeliveryDecision):
        nonlocal revision_ref
        if not _current_reviewer(transaction, context.org_id, draft.reviewer_id):
            raise _Rejected()

        def apply(write):
            write.execute(
                "INSERT INTO thalion.wiki (org_id, space_id, topic_key) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (*scope, draft.topic_key),
            )
            recorded = write.execute(
                """
                INSERT INTO thalion.wiki_revision (
                    org_id, space_id, topic_key, author_id, reviewer_id, basis_ref, manifest_ref, input_digest, content, check_id
                ) SELECT org_id, space_id, %s, author_id, %s, %s, manifest_ref, expanded_digest, %s, %s
                  FROM thalion.input_manifest WHERE (org_id, space_id, author_id, manifest_ref) = (%s, %s, %s, %s)
                RETURNING revision_ref
                """,
                (draft.topic_key, draft.reviewer_id, draft.basis_ref, content, decision.check.check_id, *manifest_scope),
            ).fetchone()[0]
            _append_wiki_event(write, *scope, "wiki.revision.created")
            return recorded

        revision_ref = execute_command(transaction, command, apply).result_ref

    try:
        delivery = authorize_travel_dependency_payload(
            connection, context, space_id, region=region, traveler_class=traveler_class, check_authority=check_authority,
            resolve=resolve, build_payload=lambda: content, seal=seal,
        )
    except _Rejected:
        return WikiResult("rejected")
    except IdempotencyConflict:
        return WikiResult("input_changed")
    return WikiResult(delivery.status, revision_ref if delivery.status == "succeeded" else None)


def _review_workflow(connection, context, space_id, revision_ref, *, region, traveler_class, check_authority,
                     expected=None, review=None):
    access = WIKI_PREVIEW_ACCESS if review is None else WIKI_REVIEW_ACCESS
    if (context.operation, context.purpose, context.destination) != access:
        return WikiResult("rejected")
    scope = (context.org_id, space_id, revision_ref, context.principal_id)
    snapshot = None
    material_ref = None
    result_ref = revision_ref

    def resolve(transaction):
        nonlocal snapshot
        snapshot = transaction.execute(
            """
            SELECT revision.manifest_ref, revision.content_digest, revision.input_digest, revision.topic_key,
                   coalesce(current.generation, 0), previous.generation
            FROM thalion.wiki_revision AS revision
            LEFT JOIN thalion.current_wiki_publication AS current USING (org_id, space_id, topic_key)
            JOIN thalion.input_manifest AS manifest USING (manifest_ref)
            LEFT JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
            LEFT JOIN thalion.wiki_publication_event AS previous ON previous.publication_ref = stopped.publication_ref
            WHERE (revision.org_id, revision.space_id, revision.revision_ref, revision.reviewer_id) = (%s, %s, %s, %s)
            """,
            scope,
        ).fetchone()
        if snapshot is None:
            return ()
        if expected is not None and snapshot[1:3] != expected:
            raise _Changed()
        return _entries(transaction, context, space_id, snapshot[0])

    def build_payload():
        return connection.execute(
            "SELECT content FROM thalion.wiki_revision WHERE (org_id, space_id, revision_ref, reviewer_id) = (%s, %s, %s, %s)",
            scope,
        ).fetchone()[0]

    def seal(transaction, delivery: DeliveryDecision):
        nonlocal result_ref, material_ref
        values = (*scope, *snapshot[1:3], delivery.check.check_id)
        topic_scope = (*scope[:2], snapshot[3])
        if review is None:
            if _generation(transaction, topic_scope, writing=False) != snapshot[4]:
                raise _Changed()
            material_ref = delivery.check.check_id
            transaction.execute(
                """
                INSERT INTO thalion.wiki_review_material (
                    org_id, space_id, revision_ref, reviewer_id, content_digest, input_digest, check_id, expected_generation
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (*values, snapshot[4]),
            )
            return
        outcome, reason, basis_ref, key, preview_ref = review
        command = _command(context, key, space_id, str(revision_ref), *(digest.hex() for digest in expected),
                           outcome, reason, str(basis_ref), str(preview_ref))

        def apply(write):
            material = write.execute(
                """
                SELECT expected_generation, thalion.same_wiki_dependency_snapshot(check_id, %s)
                FROM thalion.wiki_review_material
                WHERE (org_id, space_id, revision_ref, reviewer_id) = (%s, %s, %s, %s)
                  AND check_id = %s
                """, (delivery.check.check_id, *scope, preview_ref),
            ).fetchone()
            if material is None:
                raise _Rejected()
            if (not material[1] or material[0] != _generation(write, topic_scope, writing=False)
                    or (snapshot[5] is not None and material[0] != snapshot[5])):
                raise _Changed()
            row = write.execute(
                """
                INSERT INTO thalion.wiki_review (
                    org_id, space_id, revision_ref, reviewer_id, content_digest, input_digest, check_id,
                    decision, reason_code, basis_ref, material_check_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (revision_ref) DO NOTHING RETURNING review_ref
                """, (*values, outcome, reason, basis_ref, preview_ref),
            ).fetchone()
            if row is None:
                raise _Changed()
            _append_wiki_event(write, *scope[:2], "wiki.revision.reviewed")
            return row[0]

        result_ref = execute_command(transaction, command, apply).result_ref

    try:
        delivery = authorize_travel_dependency_payload(
            connection, context, space_id, region=region, traveler_class=traveler_class, check_authority=check_authority,
            resolve=resolve, build_payload=build_payload, seal=seal,
        )
    except _Rejected:
        return WikiResult("rejected")
    except (_Changed, IdempotencyConflict):
        return WikiResult("input_changed")
    if delivery.status != "succeeded":
        return WikiResult(delivery.status)
    if review is not None:
        return WikiResult("succeeded", result_ref)
    return WikiResult("succeeded", result_ref, delivery.payload, snapshot[2], delivery.valid_until, material_ref, snapshot[4])


def read_candidate_for_review(
    connection: Connection, context: DeliveryContext, space_id: int, revision_ref: UUID,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> WikiResult:
    return _review_workflow(connection, context, space_id, revision_ref, region=region,
                            traveler_class=traveler_class, check_authority=check_authority)


def submit_review(
    connection: Connection, context: DeliveryContext, space_id: int, revision_ref: UUID,
    content_digest: bytes, input_digest: bytes, decision: Literal["approved", "rejected"], reason_code: str,
    basis_ref: UUID, key: str, *, review_material_ref: UUID | None, region: str, traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> WikiResult:
    if (not isinstance(content_digest, bytes) or not isinstance(input_digest, bytes)
            or len(content_digest) != 32 or len(input_digest) != 32 or decision not in ("approved", "rejected")
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason_code) or not isinstance(review_material_ref, UUID)):
        return WikiResult("rejected")
    return _review_workflow(connection, context, space_id, revision_ref, region=region,
                            traveler_class=traveler_class, check_authority=check_authority,
                            expected=(content_digest, input_digest),
                            review=(decision, reason_code, basis_ref, key, review_material_ref))
