from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.access.delivery import AuthorityDecision, DeliveryCheck, DeliveryContext, DeliveryDecision
from enterprise_kb.modules.access.travel import assemble_travel_excerpts
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore


@dataclass(frozen=True)
class PreparedWikiInputs:
    status: Literal["succeeded", "no_evidence", "rejected", "input_changed", "dependency_unavailable"]
    manifest_ref: UUID | None = None
    payload: bytes | None = field(default=None, repr=False)
    valid_until: datetime | None = None


class _RebuildChanged(Exception):
    pass


def prepare_wiki_inputs(
    connection: Connection, context: DeliveryContext, space_id: int,
    direct: tuple[tuple[UUID, int], ...], parents: tuple[UUID, ...], store: SyntheticOriginalStore,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> PreparedWikiInputs:
    """Assemble only local synthetic excerpts; the seal does not authorize reuse or egress."""
    return _prepare_inputs(connection, context, space_id, direct, parents, store, region=region,
                           traveler_class=traveler_class, check_authority=check_authority)


def prepare_clean_wiki_inputs(
    connection: Connection, context: DeliveryContext, space_id: int, event_ref: UUID,
    direct: tuple[tuple[UUID, int], ...], store: SyntheticOriginalStore,
    *, region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> PreparedWikiInputs:
    if not isinstance(event_ref, UUID) or not direct:
        return PreparedWikiInputs("rejected")
    return _prepare_inputs(connection, context, space_id, direct, (), store, region=region, traveler_class=traveler_class,
                           check_authority=check_authority, rebuild_event_ref=event_ref)


def _prepare_inputs(connection, context, space_id, direct, parents, store, *, region, traveler_class, check_authority,
                    rebuild_event_ref=None):
    direct, parents = tuple(direct), tuple(parents)
    if (
        len(direct) > 20 or len(parents) > 8 or len(set(parents)) != len(parents)
        or len({ref for ref, _ in direct}) != len(direct)
        or any(type(revision) is not int or revision < 1 for _, revision in direct)
    ):
        return PreparedWikiInputs("rejected")
    expanded = dict(direct)
    manifest_ref = None
    rebuild_topic = None

    def find_rebuild_topic(transaction):
        return transaction.execute(
            """
            SELECT topic_key FROM thalion.pending_wiki_rebuild
            WHERE (org_id, space_id, event_ref) = (%s, %s, %s)
            """, (context.org_id, space_id, rebuild_event_ref),
        ).fetchone()

    def resolve(transaction):
        nonlocal rebuild_topic
        if rebuild_event_ref is not None:
            rebuild_topic = find_rebuild_topic(transaction)
            if rebuild_topic is None:
                return ()
        if parents:
            rows = transaction.execute(
                """
                SELECT manifest.manifest_ref, entry.passage_ref, entry.excerpt_revision
                FROM thalion.input_manifest AS manifest
                JOIN thalion.input_manifest_entry AS entry USING (manifest_ref)
                WHERE (manifest.org_id, manifest.space_id, manifest.author_id) = (%s, %s, %s)
                  AND manifest.manifest_ref = ANY(%s)
                ORDER BY array_position(%s::uuid[], manifest.manifest_ref), entry.position
                """,
                (context.org_id, space_id, context.principal_id, list(parents), list(parents)),
            ).fetchall()
            if {row[0] for row in rows} != set(parents):
                return ()
            for _, ref, revision in rows:
                if expanded.setdefault(ref, revision) != revision or len(expanded) > 20:
                    return ()
        return tuple(expanded.items())

    def seal(transaction, decision: DeliveryDecision):
        nonlocal manifest_ref
        if decision.check is None:
            raise RuntimeError("An input seal requires a successful authorization receipt.")
        if rebuild_event_ref is not None:
            transaction.execute(
                "SELECT 1 FROM thalion.wiki WHERE (org_id, space_id, topic_key) = (%s, %s, %s) FOR SHARE",
                (context.org_id, space_id, rebuild_topic[0]),
            ).fetchone()
            if find_rebuild_topic(transaction) != rebuild_topic:
                raise _RebuildChanged
        manifest_ref = transaction.execute(
            """
            INSERT INTO thalion.input_manifest (
                org_id, space_id, author_id, check_id, direct_count, parent_refs, rebuild_event_ref
            ) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING manifest_ref
            """,
            (context.org_id, space_id, context.principal_id, decision.check.check_id, len(direct), list(parents),
             rebuild_event_ref),
        ).fetchone()[0]

    try:
        decision = assemble_travel_excerpts(
            connection, context, space_id, store, region=region, traveler_class=traveler_class,
            check_authority=check_authority, resolve=resolve, seal=seal,
        )
    except _RebuildChanged:
        return PreparedWikiInputs("input_changed")
    if decision.status != "succeeded":
        return PreparedWikiInputs(decision.status)
    if manifest_ref is None:
        raise RuntimeError("Prepared Wiki inputs require a sealed manifest.")
    return PreparedWikiInputs(decision.status, manifest_ref, decision.payload, decision.valid_until)
