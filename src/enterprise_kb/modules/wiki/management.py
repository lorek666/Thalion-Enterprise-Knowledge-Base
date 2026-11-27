from datetime import UTC
import json
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.access import policy
from enterprise_kb.modules.sources.registry import has_source_delete_isolation, sql_admitted_issuer


PAGE_SIZE = 20
WORKFLOW_PAGE_SIZE = 50
WIKI_STATUS_OPERATION = "read_wiki_status"
WIKI_WORKFLOW_READ_OPERATIONS = frozenset({
    WIKI_STATUS_OPERATION,
    policy.WIKI_PREVIEW_ACCESS[0],
    policy.WIKI_REVIEW_ACCESS[0],
    policy.WIKI_PUBLISH_ACCESS[0],
})
_REVIEW_STAGES = ("awaiting_review", "approved", "rejected", "stale")
_TOPIC_REVIEW_COUNTS = """
    SELECT count(*) FILTER (WHERE assessed.stage = 'awaiting_review') AS awaiting_review,
           count(*) FILTER (WHERE assessed.stage = 'approved') AS approved,
           count(*) FILTER (WHERE assessed.stage = 'rejected') AS rejected,
           count(*) FILTER (WHERE assessed.stage = 'stale') AS stale
    FROM (
        SELECT CASE
            WHEN review.decision = 'rejected' THEN 'rejected'
            WHEN old.publication_ref IS NOT NULL AND old.publication_ref IS DISTINCT FROM current.publication_ref
                THEN 'stale'
            WHEN review.decision = 'approved' AND material.expected_generation IS DISTINCT FROM
                 coalesce(current.generation, 0) THEN 'stale'
            WHEN review.decision = 'approved' THEN 'approved'
            ELSE 'awaiting_review'
        END AS stage
        FROM thalion.wiki_revision AS revision
        JOIN thalion.input_manifest AS manifest USING (manifest_ref)
        LEFT JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
        LEFT JOIN thalion.wiki_publication_event AS old ON old.publication_ref = stopped.publication_ref
        LEFT JOIN thalion.wiki_review AS review ON review.revision_ref = revision.revision_ref
        LEFT JOIN thalion.wiki_review_material AS material ON material.check_id = review.material_check_id
        WHERE (revision.org_id, revision.space_id, revision.topic_key) = (topic.org_id, topic.space_id, topic.topic_key)
          AND NOT EXISTS (SELECT 1 FROM thalion.wiki_publication_event AS previous
                          WHERE previous.revision_ref = revision.revision_ref)
    ) AS assessed
"""


def may_read_topic_status(connection: Connection, org_id: int, space_id: int, principal_id: int) -> bool:
    return connection.execute(
        f"""
        SELECT 1 FROM thalion.space AS space JOIN thalion.principal AS owner
          ON (owner.org_id, owner.principal_id) = (space.org_id, space.owner_principal_id)
        WHERE (space.org_id, space.space_id, owner.principal_id) = (%s, %s, %s)
          AND space.lifecycle = 'active' AND owner.principal_type = 'employee'
          AND {sql_admitted_issuer('owner.authority_issuer')} AND NOT owner.disabled
        FOR SHARE OF space, owner
        """, (org_id, space_id, principal_id),
    ).fetchone() is not None


def list_topic_status(connection: Connection, org_id: int, space_id: int, after: UUID | None) -> tuple[list[dict], str | None]:
    rows = connection.execute(
        f"""
        WITH page AS MATERIALIZED (
            SELECT org_id, space_id, topic_key, wiki_ref FROM thalion.wiki
            WHERE (org_id, space_id) = (%s, %s) AND (%s::uuid IS NULL OR wiki_ref > %s)
            ORDER BY wiki_ref LIMIT %s
        )
        SELECT topic.wiki_ref, current.generation, ARRAY(
            SELECT DISTINCT reason FROM thalion.wiki_availability_event AS stopped
            WHERE stopped.publication_ref = current.publication_ref ORDER BY reason
        ), stats.awaiting_review, stats.approved, stats.rejected, stats.stale
        FROM page AS topic LEFT JOIN thalion.current_wiki_publication AS current USING (org_id, space_id, topic_key)
        CROSS JOIN LATERAL ({_TOPIC_REVIEW_COUNTS}) AS stats ORDER BY topic.wiki_ref
        """, (org_id, space_id, after, after, PAGE_SIZE + 1),
    ).fetchall()
    topics = [
        {
            "wiki_id": str(wiki_ref), "generation": generation,
            "state": "needs_rebuild" if reasons else "published" if generation is not None else "not_published",
            "reasons": reasons,
            "review": dict(zip(_REVIEW_STAGES, counts, strict=True)),
        }
        for wiki_ref, generation, reasons, *counts in rows[:PAGE_SIZE]
    ]
    return topics, topics[-1]["wiki_id"] if len(rows) > PAGE_SIZE else None


def count_review_backlog(connection: Connection, org_id: int, space_id: int) -> dict[str, int]:
    counts = connection.execute(
        f"""
        SELECT coalesce(sum(stats.awaiting_review), 0)::bigint, coalesce(sum(stats.approved), 0)::bigint,
               coalesce(sum(stats.rejected), 0)::bigint, coalesce(sum(stats.stale), 0)::bigint
        FROM thalion.wiki AS topic
        LEFT JOIN thalion.current_wiki_publication AS current USING (org_id, space_id, topic_key)
        CROSS JOIN LATERAL ({_TOPIC_REVIEW_COUNTS}) AS stats
        WHERE (topic.org_id, topic.space_id) = (%s, %s)
        """, (org_id, space_id),
    ).fetchone()
    return dict(zip(_REVIEW_STAGES, counts, strict=True))


def resolve_reviewer(connection: Connection, org_id: int, employee_ref: UUID) -> int | None:
    row = connection.execute(
        f"""
        SELECT employee.principal_id
        FROM thalion.object_identity AS identity
        JOIN thalion.principal AS employee
          ON (employee.org_id, employee.principal_id) = (identity.org_id, identity.object_id)
        WHERE identity.org_id = %s AND identity.object_type = 'principal' AND identity.public_id = %s
          AND employee.principal_type = 'employee' AND {sql_admitted_issuer('employee.authority_issuer')} AND NOT employee.disabled
        FOR SHARE OF employee
        """,
        (org_id, employee_ref),
    ).fetchone()
    return row[0] if row is not None else None


def list_workflow_revisions(
    connection: Connection, org_id: int, space_id: int, principal_id: int,
    *, is_owner: bool, wiki_ref: UUID | None = None,
) -> dict:
    rows = connection.execute(
        """
        SELECT revision.revision_ref, topic.wiki_ref,
               CASE
                   WHEN pub.publication_ref IS NOT NULL THEN 'published'
                   WHEN review.decision = 'rejected' THEN 'rejected'
                   WHEN old.publication_ref IS NOT NULL AND old.publication_ref IS DISTINCT FROM current.publication_ref
                       THEN 'stale'
                   WHEN review.decision = 'approved'
                        AND material.expected_generation IS DISTINCT FROM coalesce(current.generation, 0)
                       THEN 'stale'
                   WHEN review.decision = 'approved' THEN 'approved'
                   ELSE 'awaiting_review'
               END AS stage,
               origin_req.business_date,
               manifest.rebuild_event_ref,
               revision.author_id = %s AS authored_by_me,
               revision.reviewer_id = %s AS assigned_to_me,
               review.review_ref,
               review.decision,
               review.reason_code,
               material.expected_generation,
               pub.generation,
               revision.recorded_at
        FROM thalion.wiki_revision AS revision
        JOIN thalion.wiki AS topic
          ON (topic.org_id, topic.space_id, topic.topic_key) = (revision.org_id, revision.space_id, revision.topic_key)
        JOIN thalion.input_manifest AS manifest USING (manifest_ref)
        JOIN thalion.delivery_record AS origin_delivery
          ON (origin_delivery.org_id, origin_delivery.check_id) = (manifest.org_id, manifest.check_id)
        JOIN thalion.request_record AS origin_req
          ON (origin_req.org_id, origin_req.request_id) = (origin_delivery.org_id, origin_delivery.request_id)
        LEFT JOIN thalion.current_wiki_publication AS current
          ON (current.org_id, current.space_id, current.topic_key) = (topic.org_id, topic.space_id, topic.topic_key)
        LEFT JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
        LEFT JOIN thalion.wiki_publication_event AS old ON old.publication_ref = stopped.publication_ref
        LEFT JOIN thalion.wiki_publication_event AS pub ON pub.revision_ref = revision.revision_ref
        LEFT JOIN thalion.wiki_review AS review ON review.revision_ref = revision.revision_ref
        LEFT JOIN thalion.wiki_review_material AS material ON material.check_id = review.material_check_id
        WHERE (revision.org_id, revision.space_id) = (%s, %s)
          AND (%s::uuid IS NULL OR topic.wiki_ref = %s)
          AND (%s OR revision.reviewer_id = %s)
        ORDER BY revision.recorded_at DESC, revision.revision_ref DESC
        LIMIT %s
        """,
        (principal_id, principal_id, org_id, space_id, wiki_ref, wiki_ref, is_owner, principal_id, WORKFLOW_PAGE_SIZE),
    ).fetchall()
    revisions = [
        {
            "revision_id": str(rev_ref),
            "wiki_id": str(w_ref),
            "stage": stage,
            "business_date": business_date.isoformat(),
            "is_rebuild": rebuild_ref is not None,
            "rebuild_event_id": str(rebuild_ref) if rebuild_ref is not None else None,
            "authored_by_me": authored_by_me,
            "assigned_to_me": assigned_to_me,
            "review_id": str(review_ref) if review_ref is not None else None,
            "review_decision": decision,
            "review_reason": reason,
            "expected_generation": expected_gen,
            "published_generation": pub_gen,
            "created_at": recorded_at.astimezone(UTC).isoformat(),
        }
        for (
            rev_ref, w_ref, stage, business_date, rebuild_ref, authored_by_me, assigned_to_me,
            review_ref, decision, reason, expected_gen, pub_gen, recorded_at,
        ) in rows
    ]
    pending_rebuilds = []
    if is_owner:
        rebuild_rows = connection.execute(
            """
            SELECT stopped.event_ref, topic.wiki_ref, current.generation, stopped.reason, stopped.recorded_at
            FROM thalion.wiki_availability_event AS stopped
            JOIN thalion.current_wiki_publication AS current USING (org_id, space_id, publication_ref)
            JOIN thalion.wiki AS topic
              ON (topic.org_id, topic.space_id, topic.topic_key) = (current.org_id, current.space_id, current.topic_key)
            WHERE (stopped.org_id, stopped.space_id) = (%s, %s)
              AND (%s::uuid IS NULL OR topic.wiki_ref = %s)
            ORDER BY stopped.recorded_at DESC, stopped.event_ref DESC
            LIMIT %s
            """,
            (org_id, space_id, wiki_ref, wiki_ref, WORKFLOW_PAGE_SIZE),
        ).fetchall()
        pending_rebuilds = [
            {
                "event_id": str(event_ref),
                "wiki_id": str(w_ref),
                "generation": generation,
                "reason": reason,
                "recorded_at": recorded_at.astimezone(UTC).isoformat(),
            }
            for event_ref, w_ref, generation, reason, recorded_at in rebuild_rows
        ]
    return {"revisions": revisions, "pending_rebuilds": pending_rebuilds}


def list_manifest_inputs(
    connection: Connection, org_id: int, space_id: int, revision_ref: UUID, cited: set[tuple[str, int]],
) -> list[dict]:
    rows = connection.execute(
        """
        SELECT entry.passage_ref, entry.excerpt_revision
        FROM thalion.wiki_revision AS revision
        JOIN thalion.input_manifest_entry AS entry USING (manifest_ref)
        WHERE (revision.org_id, revision.space_id, revision.revision_ref) = (%s, %s, %s)
        ORDER BY entry.position
        """,
        (org_id, space_id, revision_ref),
    ).fetchall()
    return [
        {
            "passage_id": str(passage_ref),
            "excerpt_revision": excerpt_revision,
            "cited": (str(passage_ref), excerpt_revision) in cited,
        }
        for passage_ref, excerpt_revision in rows
    ]


def build_previous_comparison(
    connection: Connection, org_id: int, space_id: int, revision_ref: UUID, expected_generation: int | None,
    candidate_content: dict, *, previous_payload: bytes | None = None,
) -> dict:
    if not expected_generation:
        return {"previous_generation": 0, "previous_content_available": False}
    if previous_payload is None:
        return {"previous_generation": expected_generation, "previous_content_available": False}
    previous = json.loads(previous_payload)
    prev_citations = {(ref, rev) for ref, rev in previous.get("citations", ())}
    curr_citations = {(ref, rev) for ref, rev in candidate_content.get("citations", ())}
    return {
        "previous_generation": expected_generation,
        "previous_content_available": True,
        "previous_title": previous.get("title", ""),
        "previous_markdown": previous.get("markdown", ""),
        "added_citations": [[ref, rev] for ref, rev in sorted(curr_citations - prev_citations)],
        "removed_citations": [[ref, rev] for ref, rev in sorted(prev_citations - curr_citations)],
    }


def topic_key_for_revision(
    connection: Connection, org_id: int, space_id: int, revision_ref: UUID, reviewer_id: int,
) -> tuple[str, bool] | None:
    row = connection.execute(
        """
        SELECT revision.topic_key,
               EXISTS (
                   SELECT 1 FROM thalion.available_wiki_publication AS avail
                   WHERE (avail.org_id, avail.space_id, avail.topic_key)
                       = (revision.org_id, revision.space_id, revision.topic_key)
               )
        FROM thalion.wiki_revision AS revision
        WHERE (revision.org_id, revision.space_id, revision.revision_ref, revision.reviewer_id)
            = (%s, %s, %s, %s)
        """,
        (org_id, space_id, revision_ref, reviewer_id),
    ).fetchone()
    return (row[0], row[1]) if row is not None else None


def diagnose_publish_change(
    connection: Connection, org_id: int, space_id: int, revision_ref: UUID, review_ref: UUID, reviewer_id: int,
) -> dict | None:
    header = connection.execute(
        """
        SELECT revision.topic_key, material.expected_generation,
               coalesce(current.generation, 0) AS current_generation,
               review.check_id, review_req.business_date, previous.generation
        FROM thalion.wiki_revision AS revision
        JOIN thalion.wiki_review AS review USING (org_id, space_id, revision_ref, reviewer_id)
        JOIN thalion.wiki_review_material AS material ON material.check_id = review.material_check_id
        JOIN thalion.delivery_record AS review_delivery
          ON (review_delivery.org_id, review_delivery.check_id) = (review.org_id, review.check_id)
        JOIN thalion.request_record AS review_req
          ON (review_req.org_id, review_req.request_id) = (review_delivery.org_id, review_delivery.request_id)
        JOIN thalion.input_manifest AS manifest USING (manifest_ref)
        LEFT JOIN thalion.current_wiki_publication AS current
          ON (current.org_id, current.space_id, current.topic_key)
           = (revision.org_id, revision.space_id, revision.topic_key)
        LEFT JOIN thalion.wiki_availability_event AS stopped ON stopped.event_ref = manifest.rebuild_event_ref
        LEFT JOIN thalion.wiki_publication_event AS previous ON previous.publication_ref = stopped.publication_ref
        WHERE (revision.org_id, revision.space_id, revision.revision_ref, review.review_ref, review.reviewer_id)
            = (%s, %s, %s, %s, %s)
          AND review.decision = 'approved'
        """,
        (org_id, space_id, revision_ref, review_ref, reviewer_id),
    ).fetchone()
    if header is None:
        return None
    _topic_key, expected_gen, current_gen, review_check_id, business_date, rebuild_base_gen = header
    generation_changed = (
        expected_gen is None
        or expected_gen != current_gen
        or (rebuild_base_gen is not None and expected_gen != rebuild_base_gen)
    )
    delete_expr = (
        "thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
        if has_source_delete_isolation(connection)
        else "false"
    )
    dep_rows = connection.execute(
        f"""
        SELECT dep.passage_ref, dep.excerpt_revision,
               {delete_expr} AS source_deleted,
               ARRAY(
                   SELECT DISTINCT stop.kind FROM thalion.rule_use_stop AS stop
                   WHERE stop.version_id = version.version_id ORDER BY stop.kind
               ) AS stops,
               (source.lifecycle <> 'active' OR space.lifecycle <> 'active') AS inactive_scope,
               EXISTS (
                   SELECT 1 FROM thalion.current_version_hold AS hold
                   WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                       = (version.org_id, version.space_id, version.version_id, 'establish')
               ) AS held,
               EXISTS (
                   SELECT 1 FROM thalion.quality_decision AS qd
                   WHERE qd.run_ref = excerpt.run_ref AND qd.outcome = 'quarantined'
               ) AS quarantined,
               (latest_run.run_ref IS DISTINCT FROM excerpt.run_ref) AS reprocessed,
               (
                   source.local_policy_revision IS DISTINCT FROM dep.policy_revision
                   OR org.safety_epoch IS DISTINCT FROM dep.organization_epoch
                   OR space.safety_epoch IS DISTINCT FROM dep.space_epoch
                   OR source.safety_epoch IS DISTINCT FROM dep.source_epoch
               ) AS policy_changed,
               NOT EXISTS (
                   SELECT 1 FROM thalion.rule_interval AS rule
                   WHERE (rule.org_id, rule.space_id, rule.document_id)
                       = (version.org_id, version.space_id, version.document_id)
                     AND rule.decision_ref = dep.effectivity_ref
                     AND daterange(rule.valid_from, rule.effective_to, '[)') @> %s::date
               ) AS rule_replaced
        FROM thalion.delivery_dependency AS dep
        JOIN thalion.object_identity AS loc
          ON (loc.org_id, loc.space_id, loc.object_type, loc.public_id)
           = (dep.org_id, dep.space_id, 'passage', dep.passage_ref)
        JOIN thalion.passage_excerpt AS excerpt
          ON (excerpt.org_id, excerpt.space_id, excerpt.passage_id, excerpt.excerpt_revision)
           = (loc.org_id, loc.space_id, loc.object_id, dep.excerpt_revision)
        JOIN thalion.document_version AS version
          ON (version.org_id, version.space_id, version.version_id)
           = (excerpt.org_id, excerpt.space_id, excerpt.version_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id)
           = (version.org_id, version.space_id, version.source_id)
        JOIN thalion.space AS space
          ON (space.org_id, space.space_id) = (version.org_id, version.space_id)
        JOIN thalion.organization AS org ON org.org_id = version.org_id
        LEFT JOIN LATERAL (
            SELECT run_ref FROM thalion.processing_run
            WHERE version_id = version.version_id
            ORDER BY configuration_revision DESC LIMIT 1
        ) AS latest_run ON true
        WHERE (dep.org_id, dep.space_id, dep.check_id) = (%s, %s, %s)
        ORDER BY dep.position
        """,
        (business_date, org_id, space_id, review_check_id),
    ).fetchall()
    changed_passages = []
    for (
        passage_ref, excerpt_rev, source_deleted, stops, inactive_scope,
        held, quarantined, reprocessed, policy_changed, rule_replaced,
    ) in dep_rows:
        item_reasons: list[str] = []
        if source_deleted or "deletion_blocked" in stops:
            item_reasons.append("deletion_blocked")
        if "withdrawn" in stops:
            item_reasons.append("withdrawn")
        if "suspended" in stops or inactive_scope:
            item_reasons.append("suspended")
        if held:
            item_reasons.append("custody_hold")
        if quarantined:
            item_reasons.append("quarantined")
        if reprocessed:
            item_reasons.append("reprocessed")
        if policy_changed:
            item_reasons.append("policy_changed")
        if rule_replaced:
            item_reasons.append("rule_replaced")
        if item_reasons:
            changed_passages.append({
                "passage_id": str(passage_ref),
                "excerpt_revision": excerpt_rev,
                "reasons": item_reasons,
            })
    return {
        "topic_generation_changed": generation_changed,
        "expected_generation": expected_gen,
        "current_generation": current_gen,
        "changed_passages": changed_passages,
    }
