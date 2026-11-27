from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from hashlib import sha256
import re
from typing import Literal
from uuid import UUID

from psycopg import Connection, errors

from enterprise_kb.modules.access.delivery import AuthorityDecision, DeliveryCheck, DeliveryContext
from enterprise_kb.modules.access.policy import WIKI_ROLLBACK_ACCESS
from enterprise_kb.modules.access.travel import authorize_travel_dependency_payload
from enterprise_kb.modules.retrieval import vector as retrieval_vector
from enterprise_kb.modules.sources.registry import SourceWrite, _digest, sql_admitted_issuer, sql_issuers_same_mode
from enterprise_kb.modules.wiki.drafts import _Changed, _entries
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, IdempotencyConflict, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed


READ_SPACE_RELEASE = "read_space_release"
SWITCH_SPACE_RELEASE = "switch_space_release"
ROLLBACK_WIKI_TOPIC = WIKI_ROLLBACK_ACCESS[0]
DESTINATION = "internal_release"
OPERATIONS = frozenset({READ_SPACE_RELEASE, SWITCH_SPACE_RELEASE, ROLLBACK_WIKI_TOPIC})
RELEASE_ACTIONS = frozenset({"trial_switch", "rollback", "disable_wiki"})
LEXICAL_MODES = frozenset({"indexed", "direct_scan", "hybrid_vector"})
CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
TEMPLATE_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
MAX_LIST_ITEMS = 100


class ReleaseNotAdmitted(Exception):
    pass


class ReleaseConflict(Exception):
    pass


@dataclass(frozen=True)
class SpaceReleaseState:
    release_ref: UUID | None
    generation: int
    action: str
    wiki_delivery_enabled: bool
    lexical_index_mode: str
    template_key: str | None
    template_revision_ref: UUID | None
    observation_window_minutes: int | None
    min_sample_requests: int | None
    rollback_trigger_summary: str | None
    recorded_at: str | None
    vector_model_id: str | None = None


@dataclass(frozen=True)
class WikiRollbackResult:
    status: Literal["succeeded", "rejected", "input_changed", "dependency_unavailable", "conflict"]
    rollback_ref: UUID | None = None
    target_publication_ref: UUID | None = None
    target_revision_ref: UUID | None = None
    stop_reasons: tuple[str, ...] = ()


def _validate_code(value: str, label: str) -> str:
    if not isinstance(value, str) or not CODE_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid {label}.")
    return value


def _validate_text(value: str, max_length: int, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise ValueError(f"Invalid {label}.")
    return value.strip()


def _require_space_owner(
    connection: Connection, context: SourceWrite, space_id: int, operation: str, *, lock_space: bool = False,
) -> tuple[UUID, int]:
    _require_read_committed(connection)
    require_open_request(connection, context.org_id, context.request_id, context.principal_id, None, operation=operation)
    lock_clause = "FOR UPDATE OF space" if lock_space else "FOR SHARE OF space"
    row = connection.execute(
        f"""
        SELECT sid.public_id, org.config_revision
        FROM thalion.space AS space
        JOIN thalion.organization AS org USING (org_id)
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (space.org_id, space.space_id, 'space', space.space_id)
        JOIN thalion.principal AS actor
          ON (actor.org_id, actor.principal_id) = (space.org_id, %s)
        WHERE (space.org_id, space.space_id) = (%s, %s)
          AND space.lifecycle = 'active'
          AND space.owner_principal_id = actor.principal_id
          AND actor.principal_type = 'employee'
          AND {sql_admitted_issuer('actor.authority_issuer')}
          AND NOT actor.disabled
        FOR SHARE OF org, actor
        {lock_clause}
        """,
        (context.principal_id, context.org_id, space_id),
    ).fetchone()
    if row is None:
        raise ReleaseNotAdmitted("Active synthetic space owner is required for space release control.")
    return row[0], row[1]


def current_space_release(connection: Connection, org_id: int, space_id: int) -> SpaceReleaseState:
    if connection.execute("SELECT to_regclass('thalion.space_release_config') IS NOT NULL").fetchone()[0] is not True:
        return SpaceReleaseState(None, 0, "default", True, "indexed", None, None, None, None, None, None)
    row = connection.execute(
        """
        SELECT release_ref, generation, action, wiki_delivery_enabled, lexical_index_mode,
               template_key, template_revision_ref, observation_window_minutes,
               min_sample_requests, rollback_trigger_summary, recorded_at, vector_model_id
        FROM thalion.current_space_release_config
        WHERE (org_id, space_id) = (%s, %s)
        """,
        (org_id, space_id),
    ).fetchone()
    if row is None:
        return SpaceReleaseState(None, 0, "default", True, "indexed", None, None, None, None, None, None)
    return SpaceReleaseState(
        row[0], row[1], row[2], bool(row[3]), row[4], row[5], row[6],
        row[7], row[8], row[9], row[10].astimezone(UTC).isoformat(), row[11],
    )


def read_space_release_overview(connection: Connection, context: SourceWrite, space_id: int) -> dict:
    with connection.transaction():
        space_ref, _ = _require_space_owner(connection, context, space_id, READ_SPACE_RELEASE)
        current = current_space_release(connection, context.org_id, space_id)
        history_rows = connection.execute(
            """
            SELECT cfg.release_ref, cfg.generation, cfg.action, cfg.wiki_delivery_enabled,
                   cfg.lexical_index_mode, cfg.target_release_ref, cfg.template_key,
                   cfg.template_revision_ref, cfg.observation_window_minutes,
                   cfg.min_sample_requests, cfg.rollback_trigger_summary, cfg.reason_code,
                   cfg.basis_ref, cfg.recorded_at, actor_id.public_id, cfg.vector_model_id
            FROM thalion.space_release_config AS cfg
            JOIN thalion.object_identity AS actor_id
              ON (actor_id.org_id, actor_id.object_type, actor_id.object_id) = (cfg.org_id, 'principal', cfg.actor_id)
            WHERE (cfg.org_id, cfg.space_id) = (%s, %s)
            ORDER BY cfg.generation DESC
            LIMIT %s
            """,
            (context.org_id, space_id, MAX_LIST_ITEMS),
        ).fetchall()
        template_rows = connection.execute(
            """
            SELECT rev.template_key, rev.revision_ref, rev.model_profile,
                   active.generation AS active_generation,
                   active.revision_ref = rev.revision_ref AS is_active
            FROM thalion.compile_template_revision AS rev
            JOIN thalion.compile_template_admission AS adm
              ON (adm.org_id, adm.space_id, adm.template_key, adm.revision_ref)
               = (rev.org_id, rev.space_id, rev.template_key, rev.revision_ref)
            JOIN thalion.principal AS reviewer
              ON (reviewer.org_id, reviewer.principal_id) = (adm.org_id, adm.reviewer_id)
            LEFT JOIN thalion.active_compile_template AS active
              ON (active.org_id, active.space_id, active.template_key) = (rev.org_id, rev.space_id, rev.template_key)
            WHERE (rev.org_id, rev.space_id) = (%s, %s)
              AND adm.decision = 'approved'
              AND NOT reviewer.disabled
            ORDER BY rev.template_key, rev.recorded_at DESC, rev.revision_ref DESC
            LIMIT %s
            """,
            (context.org_id, space_id, MAX_LIST_ITEMS),
        ).fetchall()
        topic_rows = connection.execute(
            """
            SELECT w.wiki_ref,
                   cur.publication_ref AS head_pub,
                   cur.generation AS head_gen,
                   cur.revision_ref AS head_rev,
                   COALESCE(rb.target_publication_ref, cur.publication_ref) AS eff_pub,
                   eff.generation AS eff_gen,
                   eff.revision_ref AS eff_rev,
                   rb.rollback_ref IS NOT NULL AS rolled_back,
                   avail.publication_ref IS NOT NULL AS available,
                   ARRAY(
                       SELECT DISTINCT ev.reason FROM thalion.wiki_availability_event AS ev
                       WHERE ev.publication_ref = eff.publication_ref ORDER BY ev.reason
                   ) AS effective_stop_reasons
            FROM thalion.wiki AS w
            JOIN thalion.current_wiki_publication AS cur USING (org_id, space_id, topic_key)
            LEFT JOIN LATERAL (
                SELECT rollback_ref, target_publication_ref
                FROM thalion.wiki_topic_rollback AS r
                WHERE (r.org_id, r.space_id, r.topic_key, r.from_publication_ref)
                    = (cur.org_id, cur.space_id, cur.topic_key, cur.publication_ref)
                ORDER BY r.rollback_seq DESC LIMIT 1
            ) AS rb ON true
            JOIN thalion.wiki_publication_event AS eff
              ON eff.publication_ref = COALESCE(rb.target_publication_ref, cur.publication_ref)
            LEFT JOIN thalion.available_wiki_publication AS avail
              ON avail.publication_ref = eff.publication_ref
            WHERE (w.org_id, w.space_id) = (%s, %s)
            ORDER BY w.wiki_ref
            LIMIT %s
            """,
            (context.org_id, space_id, MAX_LIST_ITEMS),
        ).fetchall()
        pub_rows = connection.execute(
            """
            SELECT w.wiki_ref, p.publication_ref, p.generation, p.revision_ref, p.recorded_at,
                   ARRAY(
                       SELECT DISTINCT ev.reason FROM thalion.wiki_availability_event AS ev
                       WHERE ev.publication_ref = p.publication_ref ORDER BY ev.reason
                   ) AS stop_reasons
            FROM thalion.wiki AS w
            JOIN thalion.wiki_publication_event AS p USING (org_id, space_id, topic_key)
            WHERE (w.org_id, w.space_id) = (%s, %s)
            ORDER BY w.wiki_ref, p.generation DESC
            """,
            (context.org_id, space_id),
        ).fetchall()
    pubs_by_wiki: dict[UUID, list[dict]] = {}
    for wiki_ref, pub_ref, gen, rev_ref, rec_at, stop_reasons in pub_rows:
        pubs_by_wiki.setdefault(wiki_ref, []).append({
            "publication_id": str(pub_ref),
            "generation": gen,
            "revision_id": str(rev_ref),
            "recorded_at": rec_at.astimezone(UTC).isoformat(),
            "stop_reasons": list(stop_reasons),
            "rollback_eligible": len(stop_reasons) == 0,
        })
    return {
        "space_id": str(space_ref),
        "current": {
            "release_id": str(current.release_ref) if current.release_ref else None,
            "generation": current.generation,
            "action": current.action,
            "wiki_delivery_enabled": current.wiki_delivery_enabled,
            "lexical_index_mode": current.lexical_index_mode,
            "vector_model_id": current.vector_model_id,
            "template_key": current.template_key,
            "template_revision_id": str(current.template_revision_ref) if current.template_revision_ref else None,
            "observation_window_minutes": current.observation_window_minutes,
            "min_sample_requests": current.min_sample_requests,
            "rollback_trigger_summary": current.rollback_trigger_summary,
            "recorded_at": current.recorded_at,
        },
        "releases": [
            {
                "release_id": str(row[0]),
                "generation": row[1],
                "action": row[2],
                "wiki_delivery_enabled": bool(row[3]),
                "lexical_index_mode": row[4],
                "vector_model_id": row[15],
                "target_release_id": str(row[5]) if row[5] else None,
                "template_key": row[6],
                "template_revision_id": str(row[7]) if row[7] else None,
                "observation_window_minutes": row[8],
                "min_sample_requests": row[9],
                "rollback_trigger_summary": row[10],
                "reason_code": row[11],
                "basis_ref": str(row[12]),
                "recorded_at": row[13].astimezone(UTC).isoformat(),
                "actor_id": str(row[14]),
            }
            for row in history_rows
        ],
        "approved_templates": [
            {
                "template_key": row[0],
                "revision_id": str(row[1]),
                "model_profile": row[2],
                "active_generation": row[3],
                "is_active": bool(row[4]),
            }
            for row in template_rows
        ],
        "wiki_topics": [
            {
                "wiki_id": str(row[0]),
                "head_publication_id": str(row[1]),
                "head_generation": row[2],
                "head_revision_id": str(row[3]),
                "effective_publication_id": str(row[4]),
                "effective_generation": row[5],
                "effective_revision_id": str(row[6]),
                "rolled_back": bool(row[7]),
                "available": bool(row[8]),
                "stop_reasons": list(row[9]),
                "publications": pubs_by_wiki.get(row[0], []),
            }
            for row in topic_rows
        ],
    }


def switch_space_release(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    *,
    action: Literal["trial_switch", "rollback", "disable_wiki"],
    wiki_delivery_enabled: bool | None = None,
    lexical_index_mode: Literal["indexed", "direct_scan", "hybrid_vector"] | None = None,
    vector_model_id: str | None = None,
    target_release_ref: UUID | None = None,
    template_key: str | None = None,
    template_revision_ref: UUID | None = None,
    observation_window_minutes: int | None = None,
    min_sample_requests: int | None = None,
    rollback_trigger_summary: str,
    reason_code: str,
    basis_ref: UUID,
) -> dict:
    if action not in RELEASE_ACTIONS:
        raise ValueError("Invalid space release action.")
    clean_reason = _validate_code(reason_code, "reason_code")
    clean_trigger = _validate_text(rollback_trigger_summary, 240, "rollback_trigger_summary")
    if observation_window_minutes is not None and (
        type(observation_window_minutes) is not int or not 1 <= observation_window_minutes <= 43200
    ):
        raise ValueError("Invalid observation_window_minutes.")
    if min_sample_requests is not None and (
        type(min_sample_requests) is not int or not 1 <= min_sample_requests <= 1_000_000
    ):
        raise ValueError("Invalid min_sample_requests.")
    if (template_key is None) != (template_revision_ref is None):
        raise ValueError("template_key and template_revision_ref must be supplied together.")
    if template_key is not None and not TEMPLATE_KEY_PATTERN.fullmatch(template_key):
        raise ValueError("Invalid template_key.")
    if action == "rollback" and target_release_ref is None:
        raise ValueError("Rollback requires target_release_ref.")
    if action != "rollback" and target_release_ref is not None:
        raise ValueError("target_release_ref is only valid for rollback actions.")
    if action == "disable_wiki":
        if wiki_delivery_enabled is True:
            raise ValueError("disable_wiki requires wiki_delivery_enabled to be false.")
        wiki_delivery_enabled = False
        if lexical_index_mode is None:
            lexical_index_mode = "indexed"

    with connection.transaction():
        space_ref, config_rev = _require_space_owner(
            connection, context, space_id, SWITCH_SPACE_RELEASE, lock_space=True,
        )
        resolved_wiki = wiki_delivery_enabled
        resolved_lexical = lexical_index_mode
        resolved_vector_model = vector_model_id
        resolved_tpl_key = template_key
        resolved_tpl_rev = template_revision_ref
        if action == "rollback":
            target = connection.execute(
                """
                SELECT wiki_delivery_enabled, lexical_index_mode, vector_model_id, template_key, template_revision_ref
                FROM thalion.space_release_config
                WHERE (org_id, space_id, release_ref) = (%s, %s, %s)
                """,
                (context.org_id, space_id, target_release_ref),
            ).fetchone()
            if target is None:
                raise ReleaseNotAdmitted("Rollback target release does not belong to this space.")
            t_wiki, t_lex, t_vec, t_key, t_rev = target
            if resolved_wiki is not None and resolved_wiki != bool(t_wiki):
                raise ValueError("Rollback wiki_delivery_enabled must match target release.")
            if resolved_lexical is not None and resolved_lexical != t_lex:
                raise ValueError("Rollback lexical_index_mode must match target release.")
            if resolved_vector_model is not None and resolved_vector_model != t_vec:
                raise ValueError("Rollback vector_model_id must match target release.")
            if resolved_tpl_key is not None and (resolved_tpl_key, resolved_tpl_rev) != (t_key, t_rev):
                raise ValueError("Rollback template must match target release.")
            resolved_wiki, resolved_lexical, resolved_vector_model, resolved_tpl_key, resolved_tpl_rev = (
                bool(t_wiki), t_lex, t_vec, t_key, t_rev,
            )
        else:
            if type(resolved_wiki) is not bool or resolved_lexical not in LEXICAL_MODES:
                raise ValueError("Space release switch requires explicit wiki_delivery_enabled and lexical_index_mode.")
            if resolved_lexical == "hybrid_vector":
                if resolved_vector_model is None:
                    resolved_vector_model = retrieval_vector.DEFAULT_MODEL_ID
                if not retrieval_vector.is_valid_model_id(resolved_vector_model):
                    raise ValueError("Invalid vector_model_id.")
            elif resolved_vector_model is not None:
                raise ValueError("vector_model_id is only allowed when lexical_index_mode is 'hybrid_vector'.")

        if resolved_tpl_rev is not None:
            approved = connection.execute(
                f"""
                SELECT 1
                FROM thalion.compile_template_admission AS adm
                JOIN thalion.principal AS reviewer
                  ON (reviewer.org_id, reviewer.principal_id) = (adm.org_id, adm.reviewer_id)
                JOIN thalion.principal AS actor
                  ON (actor.org_id, actor.principal_id) = (adm.org_id, %s)
                WHERE (adm.org_id, adm.space_id, adm.template_key, adm.revision_ref) = (%s, %s, %s, %s)
                  AND adm.decision = 'approved'
                  AND adm.reviewer_id <> %s
                  AND reviewer.principal_type = 'employee'
                  AND {sql_issuers_same_mode('reviewer.authority_issuer', 'actor.authority_issuer')}
                  AND NOT reviewer.disabled
                FOR SHARE OF reviewer
                """,
                (context.principal_id, context.org_id, space_id, resolved_tpl_key, resolved_tpl_rev, context.principal_id),
            ).fetchone()
            if approved is None:
                raise ReleaseNotAdmitted("Selected template revision is not independently approved in this space.")

        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, SWITCH_SPACE_RELEASE,
            context.idempotency_key, _digest(
                "switch_space_release", space_id, action, resolved_wiki, resolved_lexical, resolved_vector_model,
                str(target_release_ref) if target_release_ref else None,
                resolved_tpl_key, str(resolved_tpl_rev) if resolved_tpl_rev else None,
                observation_window_minutes, min_sample_requests, clean_trigger, clean_reason, str(basis_ref),
            ), config_rev, None,
        )

        def apply(transaction):
            next_gen = 1 + transaction.execute(
                "SELECT coalesce(max(generation), 0) FROM thalion.space_release_config WHERE (org_id, space_id) = (%s, %s)",
                (context.org_id, space_id),
            ).fetchone()[0]
            try:
                release_ref, = transaction.execute(
                    """
                    INSERT INTO thalion.space_release_config (
                        org_id, space_id, generation, action, wiki_delivery_enabled, lexical_index_mode,
                        vector_model_id, target_release_ref, template_key, template_revision_ref,
                        observation_window_minutes, min_sample_requests, rollback_trigger_summary,
                        reason_code, basis_ref, actor_id, request_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING release_ref
                    """,
                    (
                        context.org_id, space_id, next_gen, action, resolved_wiki, resolved_lexical,
                        resolved_vector_model, target_release_ref, resolved_tpl_key, resolved_tpl_rev,
                        observation_window_minutes, min_sample_requests, clean_trigger,
                        clean_reason, basis_ref, context.principal_id, context.request_id,
                    ),
                ).fetchone()
            except errors.CheckViolation as exc:
                raise ReleaseConflict(str(exc)) from None
            if resolved_tpl_rev is not None:
                family = (context.org_id, space_id, resolved_tpl_key)
                transaction.execute(
                    """
                    SELECT 1 FROM thalion.compile_template
                    WHERE (org_id, space_id, template_key) = (%s, %s, %s) FOR NO KEY UPDATE
                    """,
                    family,
                ).fetchone()
                current_tpl_gen = transaction.execute(
                    """
                    SELECT coalesce(max(generation), 0) FROM thalion.compile_template_activation
                    WHERE (org_id, space_id, template_key) = (%s, %s, %s)
                    """,
                    family,
                ).fetchone()[0]
                transaction.execute(
                    """
                    INSERT INTO thalion.compile_template_activation (
                        org_id, space_id, template_key, generation, revision_ref, activated_by, request_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (*family, current_tpl_gen + 1, resolved_tpl_rev, context.principal_id, context.request_id),
                )
                append_event(transaction, context.org_id, "wiki.template_activated", space_ref, space_id=space_id)
            append_event(transaction, context.org_id, "release.space_switched", space_ref, space_id=space_id)
            return release_ref

        receipt = execute_command(connection, command, apply)
        row = connection.execute(
            """
            SELECT release_ref, generation, action, wiki_delivery_enabled, lexical_index_mode,
                   target_release_ref, template_key, template_revision_ref,
                   observation_window_minutes, min_sample_requests, rollback_trigger_summary,
                   reason_code, basis_ref, recorded_at, vector_model_id
            FROM thalion.space_release_config
            WHERE release_ref = %s
            """,
            (receipt.result_ref,),
        ).fetchone()
    return {
        "release_id": str(row[0]),
        "space_id": str(space_ref),
        "generation": row[1],
        "action": row[2],
        "wiki_delivery_enabled": bool(row[3]),
        "lexical_index_mode": row[4],
        "vector_model_id": row[14],
        "target_release_id": str(row[5]) if row[5] else None,
        "template_key": row[6],
        "template_revision_id": str(row[7]) if row[7] else None,
        "observation_window_minutes": row[8],
        "min_sample_requests": row[9],
        "rollback_trigger_summary": row[10],
        "reason_code": row[11],
        "basis_ref": str(row[12]),
        "recorded_at": row[13].astimezone(UTC).isoformat(),
    }


def rollback_wiki_topic(
    connection: Connection,
    context: DeliveryContext,
    space_id: int,
    wiki_ref: UUID,
    target_revision_ref: UUID,
    *,
    basis_ref: UUID,
    reason_code: str,
    key: str,
    region: str,
    traveler_class: str,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> WikiRollbackResult:
    if (context.operation, context.purpose, context.destination) != WIKI_ROLLBACK_ACCESS:
        return WikiRollbackResult("rejected")
    clean_reason = _validate_code(reason_code, "reason_code")
    scope = (context.org_id, space_id)
    snapshot = None
    stop_reasons: tuple[str, ...] = ()
    result_ref: UUID | None = None
    conflict_flag = False
    request_digest = _digest(
        "rollback_wiki_topic", space_id, str(wiki_ref), str(target_revision_ref),
        str(basis_ref), clean_reason,
    )
    command: CommandEnvelope | None = None

    def resolve(transaction):
        nonlocal snapshot, stop_reasons, conflict_flag, command
        row = transaction.execute(
            """
            SELECT w.topic_key,
                   cur.publication_ref AS head_pub,
                   tgt.publication_ref AS target_pub,
                   tgt.check_id AS target_check_id,
                   rev.manifest_ref,
                   rev.author_id,
                   orig_pub.disabled AS publisher_disabled,
                   COALESCE(rb.target_publication_ref, cur.publication_ref) AS effective_pub,
                   ARRAY(
                       SELECT DISTINCT ev.reason FROM thalion.wiki_availability_event AS ev
                       WHERE ev.publication_ref = tgt.publication_ref ORDER BY ev.reason
                   ) AS stop_reasons,
                   sid.public_id AS space_ref,
                   org.config_revision
            FROM thalion.wiki AS w
            JOIN thalion.organization AS org ON org.org_id = w.org_id
            JOIN thalion.object_identity AS sid
              ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id) = (w.org_id, w.space_id, 'space', w.space_id)
            JOIN thalion.current_wiki_publication AS cur
              ON (cur.org_id, cur.space_id, cur.topic_key) = (w.org_id, w.space_id, w.topic_key)
            JOIN thalion.wiki_publication_event AS tgt
              ON (tgt.org_id, tgt.space_id, tgt.topic_key, tgt.revision_ref)
               = (w.org_id, w.space_id, w.topic_key, %s)
            JOIN thalion.wiki_revision AS rev
              ON (rev.org_id, rev.space_id, rev.topic_key, rev.revision_ref)
               = (tgt.org_id, tgt.space_id, tgt.topic_key, tgt.revision_ref)
            JOIN thalion.principal AS orig_pub
              ON (orig_pub.org_id, orig_pub.principal_id) = (tgt.org_id, tgt.publisher_id)
            LEFT JOIN LATERAL (
                SELECT target_publication_ref FROM thalion.wiki_topic_rollback AS r
                WHERE (r.org_id, r.space_id, r.topic_key, r.from_publication_ref)
                    = (cur.org_id, cur.space_id, cur.topic_key, cur.publication_ref)
                ORDER BY r.rollback_seq DESC LIMIT 1
            ) AS rb ON true
            WHERE (w.org_id, w.space_id, w.wiki_ref) = (%s, %s, %s)
            """,
            (target_revision_ref, context.org_id, space_id, wiki_ref),
        ).fetchone()
        if row is None:
            return ()
        (
            topic_key, head_pub, target_pub, target_check_id, manifest_ref,
            author_id, publisher_disabled, effective_pub, reasons, space_ref, config_rev,
        ) = row
        if context.principal_id == author_id or publisher_disabled:
            return ()
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, ROLLBACK_WIKI_TOPIC,
            key, request_digest, config_rev, None,
        )
        if reasons:
            stop_reasons = tuple(reasons)
            raise _Changed()
        if effective_pub == target_pub:
            existing = transaction.execute(
                """
                SELECT input_digest FROM thalion.command_receipt
                WHERE org_id = %s AND principal_id = %s
                  AND delegated_principal_id IS NULL
                  AND operation = %s AND key_digest = %s
                """,
                (context.org_id, context.principal_id, ROLLBACK_WIKI_TOPIC, sha256(key.encode("utf-8")).digest()),
            ).fetchone()
            if existing is None:
                conflict_flag = True
                raise _Changed()
            if bytes(existing[0]) != request_digest:
                raise IdempotencyConflict("Idempotency key was already used with a different rollback payload.")
        snapshot = (topic_key, head_pub, target_pub, target_check_id, space_ref)
        return _entries(transaction, context, space_id, manifest_ref)

    def build_payload():
        return connection.execute(
            "SELECT content FROM thalion.wiki_revision WHERE (org_id, space_id, revision_ref) = (%s, %s, %s)",
            (*scope, target_revision_ref),
        ).fetchone()[0]

    def seal(transaction, delivery):
        nonlocal result_ref, stop_reasons
        topic_key, head_pub, target_pub, target_check_id, space_ref = snapshot
        check_id = delivery.check.check_id
        if not transaction.execute(
            "SELECT thalion.same_wiki_dependency_snapshot(%s, %s)", (target_check_id, check_id),
        ).fetchone()[0]:
            raise _Changed()

        def apply(write):
            write.execute(
                "SELECT 1 FROM thalion.wiki WHERE (org_id, space_id, topic_key) = (%s, %s, %s) FOR NO KEY UPDATE",
                (*scope, topic_key),
            ).fetchone()
            next_seq = 1 + write.execute(
                "SELECT coalesce(max(rollback_seq), 0) FROM thalion.wiki_topic_rollback WHERE (org_id, space_id, topic_key) = (%s, %s, %s)",
                (*scope, topic_key),
            ).fetchone()[0]
            try:
                rollback_ref, = write.execute(
                    """
                    INSERT INTO thalion.wiki_topic_rollback (
                        org_id, space_id, topic_key, rollback_seq, from_publication_ref,
                        target_publication_ref, target_revision_ref, actor_id, check_id,
                        basis_ref, reason_code, request_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING rollback_ref
                    """,
                    (
                        *scope, topic_key, next_seq, head_pub, target_pub, target_revision_ref,
                        context.principal_id, check_id, basis_ref, clean_reason, context.request_id,
                    ),
                ).fetchone()
            except errors.CheckViolation:
                raise _Changed() from None
            append_event(write, context.org_id, "release.wiki_rolled_back", space_ref, space_id=space_id)
            return rollback_ref

        result_ref = execute_command(transaction, command, apply).result_ref

    try:
        delivery = authorize_travel_dependency_payload(
            connection, context, space_id, region=region, traveler_class=traveler_class,
            check_authority=check_authority, resolve=resolve, build_payload=build_payload, seal=seal,
        )
    except IdempotencyConflict:
        return WikiRollbackResult("conflict")
    except _Changed:
        if conflict_flag:
            return WikiRollbackResult("conflict")
        return WikiRollbackResult("input_changed", stop_reasons=stop_reasons)
    if delivery.status == "succeeded" and snapshot is not None:
        return WikiRollbackResult("succeeded", result_ref, snapshot[2], target_revision_ref)
    return WikiRollbackResult(delivery.status)
