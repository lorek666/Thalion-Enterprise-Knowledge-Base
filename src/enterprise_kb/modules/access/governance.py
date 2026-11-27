from datetime import UTC, datetime
import re
from uuid import UUID, uuid4

from psycopg import Connection, errors

from enterprise_kb.modules.sources.registry import (
    ADMITTED_ADMISSIONS, SourceWrite, _digest, is_admitted_issuer, issuer_matches_admission,
    issuers_same_mode, sql_admitted_issuer, sql_issuers_same_mode,
)
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed

from .rules import require_aware


READ_GOVERNANCE = "read_space_governance"
MANAGE_SHARED_GROUP = "manage_shared_group"
MANAGE_DELEGATION = "manage_space_delegation"
ARCHIVE_SPACE = "archive_space"
HANDOFF_TRANSITION = "record_transition_handoff"
WRITE_OPERATIONS = frozenset({
    MANAGE_SHARED_GROUP,
    MANAGE_DELEGATION,
    ARCHIVE_SPACE,
    HANDOFF_TRANSITION,
})
OPERATIONS = WRITE_OPERATIONS | {READ_GOVERNANCE}
DESTINATION = "internal_governance"
DELEGATION_SCOPES = frozenset({
    "responsibility_management",
    "shared_group_management",
    "feedback_handoff_management",
})
TRANSITION_KINDS = frozenset({"transfer", "departure", "proxy_replacement"})
CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_LIST_ITEMS = 200


class GovernanceNotAdmitted(Exception):
    pass


class GovernanceConflict(Exception):
    pass


def _validate_code(value: str, label: str) -> str:
    if not isinstance(value, str) or not CODE_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid {label}.")
    return value


def _validate_text(value: str, max_length: int, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise ValueError(f"Invalid {label}.")
    return value.strip()


def _principal_issuer(connection: Connection, org_id: int, principal_id: int) -> str:
    row = connection.execute(
        "SELECT authority_issuer FROM thalion.principal WHERE (org_id, principal_id) = (%s, %s)",
        (org_id, principal_id),
    ).fetchone()
    if row is None or not is_admitted_issuer(row[0]):
        raise GovernanceNotAdmitted("Principal lacks an admitted authority issuer.")
    return row[0]


def _resolve_principal(
    connection: Connection,
    org_id: int,
    public_ref: UUID,
    *,
    active_employee: bool = False,
    expected_issuer: str | None = None,
) -> int:
    row = connection.execute(
        """
        SELECT p.principal_id, p.principal_type, p.authority_issuer, p.disabled
        FROM thalion.object_identity AS oi
        JOIN thalion.principal AS p
          ON (p.org_id, p.identity_type, p.principal_id) = (oi.org_id, oi.object_type, oi.object_id)
        WHERE oi.org_id = %s AND oi.object_type = 'principal' AND oi.public_id = %s
        FOR SHARE OF p
        """,
        (org_id, public_ref),
    ).fetchone()
    if row is None:
        raise GovernanceNotAdmitted("Principal is outside this organization.")
    principal_id, principal_type, issuer, disabled = row
    if principal_type != "employee" or not is_admitted_issuer(issuer):
        raise GovernanceNotAdmitted("Principal must be an admitted employee.")
    if expected_issuer is not None and not issuers_same_mode(issuer, expected_issuer):
        raise GovernanceNotAdmitted("Target employee authority mode does not match caller mode.")
    if active_employee and disabled:
        raise GovernanceNotAdmitted("Target employee is disabled.")
    return principal_id


def _has_delegation(connection: Connection, org_id: int, space_id: int, principal_id: int, scope: str) -> bool:
    return bool(connection.execute(
        "SELECT thalion.has_active_space_delegation(%s, %s, %s, %s)",
        (org_id, space_id, principal_id, scope),
    ).fetchone()[0])


def _require_space_actor(
    connection: Connection, context: SourceWrite, space_id: int, operation: str,
    *, required_scope: str | None = None, owner_only: bool = False,
    allow_archived_read: bool = False, lock_space: bool = False,
) -> tuple[bool, int, int, str]:
    _require_read_committed(connection)
    require_open_request(connection, context.org_id, context.request_id, context.principal_id, None, operation=operation)
    lock_clause = "FOR UPDATE OF space" if lock_space else "FOR SHARE OF space"
    row = connection.execute(
        f"""
        SELECT space.owner_principal_id = actor.principal_id, org.config_revision, space.safety_epoch, space.lifecycle
        FROM thalion.space AS space
        JOIN thalion.organization AS org USING (org_id)
        JOIN thalion.principal AS owner ON (owner.org_id, owner.principal_id) = (space.org_id, space.owner_principal_id)
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (space.org_id, %s)
        WHERE (space.org_id, space.space_id) = (%s, %s)
          AND actor.principal_type = 'employee'
          AND {sql_admitted_issuer('actor.authority_issuer')}
          AND {sql_issuers_same_mode('actor.authority_issuer', 'owner.authority_issuer')}
          AND NOT actor.disabled
        FOR SHARE OF org, actor
        {lock_clause}
        """,
        (context.principal_id, context.org_id, space_id),
    ).fetchone()
    if row is None:
        raise GovernanceNotAdmitted("Active synthetic employee in scoped space is required.")
    is_owner, config_rev, safety_epoch, lifecycle = row
    if lifecycle != "active" and not allow_archived_read:
        raise GovernanceNotAdmitted("Space is archived and no longer admits governance changes.")
    if owner_only:
        if not is_owner:
            raise GovernanceNotAdmitted("Current space owner is required for this governance action.")
    elif required_scope is not None:
        if not is_owner and not _has_delegation(connection, context.org_id, space_id, context.principal_id, required_scope):
            raise GovernanceNotAdmitted("Current space owner or active delegate for the required scope is required.")
    else:
        if not is_owner and not any(
            _has_delegation(connection, context.org_id, space_id, context.principal_id, scope)
            for scope in DELEGATION_SCOPES
        ):
            raise GovernanceNotAdmitted("Current space owner or active delegate is required.")
    return is_owner, config_rev, safety_epoch, lifecycle


def _bump_spaces_safety_epoch(connection: Connection, org_id: int, space_ids: set[int]) -> None:
    for target_space_id in sorted(space_ids):
        connection.execute(
            """
            UPDATE thalion.space SET safety_epoch = safety_epoch + 1
            WHERE (org_id, space_id) = (%s, %s)
            """,
            (org_id, target_space_id),
        )


def _append_space_event(connection: Connection, org_id: int, space_id: int, event_type: str) -> None:
    space_ref, = connection.execute(
        """
        SELECT public_id FROM thalion.object_identity
        WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'space', %s)
        """,
        (org_id, space_id, space_id),
    ).fetchone()
    append_event(connection, org_id, event_type, space_ref, space_id=space_id)


def read_governance_overview(connection: Connection, context: SourceWrite, space_id: int) -> dict:
    with connection.transaction():
        _, _, safety_epoch, lifecycle = _require_space_actor(
            connection, context, space_id, READ_GOVERNANCE, allow_archived_read=True,
        )
        space_ref, space_name, classification, owner_ref = connection.execute(
            """
            SELECT sp_id.public_id, sp.name, sp.classification, ow_id.public_id
            FROM thalion.space AS sp
            JOIN thalion.object_identity AS sp_id
              ON (sp_id.org_id, sp_id.space_id, sp_id.object_type, sp_id.object_id)
               = (sp.org_id, sp.space_id, 'space', sp.space_id)
            JOIN thalion.object_identity AS ow_id
              ON (ow_id.org_id, ow_id.object_type, ow_id.object_id)
               = (sp.org_id, 'principal', sp.owner_principal_id)
            WHERE (sp.org_id, sp.space_id) = (%s, %s)
            """,
            (context.org_id, space_id),
        ).fetchone()
        archive_row = connection.execute(
            """
            SELECT ar.archive_ref, ar.reason_code, ar.basis_ref, ar.archived_at, act_id.public_id
            FROM thalion.space_archive_record AS ar
            JOIN thalion.object_identity AS act_id
              ON (act_id.org_id, act_id.object_type, act_id.object_id)
               = (ar.org_id, 'principal', ar.actor_id)
            WHERE (ar.org_id, ar.space_id) = (%s, %s)
            """,
            (context.org_id, space_id),
        ).fetchone()
        group_rows = connection.execute(
            """
            SELECT g.group_ref, gp_id.public_id AS group_principal_ref,
                   os_id.public_id AS owner_space_ref, ts_id.public_id AS target_space_ref,
                   src_id.public_id AS target_source_ref,
                   g.name, g.purpose, g.scope_summary, g.starts_at, g.review_at, g.expires_at, g.recorded_at,
                   rev.revoked_at, rev.reason_code,
                   CASE
                       WHEN rev.group_ref IS NOT NULL THEN 'revoked'
                       WHEN os.lifecycle <> 'active' OR ts.lifecycle <> 'active' THEN 'space_archived'
                       WHEN gp.disabled THEN 'disabled'
                       WHEN g.expires_at <= clock_timestamp() THEN 'expired'
                       WHEN g.starts_at > clock_timestamp() THEN 'scheduled'
                       ELSE 'active'
                   END AS state
            FROM thalion.shared_group AS g
            JOIN thalion.space AS os ON (os.org_id, os.space_id) = (g.org_id, g.owner_space_id)
            JOIN thalion.space AS ts ON (ts.org_id, ts.space_id) = (g.org_id, g.target_space_id)
            JOIN thalion.principal AS gp ON (gp.org_id, gp.principal_id) = (g.org_id, g.group_principal_id)
            JOIN thalion.object_identity AS gp_id
              ON (gp_id.org_id, gp_id.object_type, gp_id.object_id) = (g.org_id, 'principal', g.group_principal_id)
            JOIN thalion.object_identity AS os_id
              ON (os_id.org_id, os_id.space_id, os_id.object_type, os_id.object_id)
               = (g.org_id, g.owner_space_id, 'space', g.owner_space_id)
            JOIN thalion.object_identity AS ts_id
              ON (ts_id.org_id, ts_id.space_id, ts_id.object_type, ts_id.object_id)
               = (g.org_id, g.target_space_id, 'space', g.target_space_id)
            JOIN thalion.object_identity AS src_id
              ON (src_id.org_id, src_id.space_id, src_id.object_type, src_id.object_id)
               = (g.org_id, g.target_space_id, 'source', g.target_source_id)
            LEFT JOIN thalion.shared_group_revocation AS rev ON rev.group_ref = g.group_ref
            WHERE g.org_id = %s AND (g.owner_space_id = %s OR g.target_space_id = %s)
            ORDER BY g.recorded_at DESC, g.group_ref DESC
            LIMIT %s
            """,
            (context.org_id, space_id, space_id, MAX_LIST_ITEMS),
        ).fetchall()
        group_refs = [row[0] for row in group_rows]
        members_by_group: dict[UUID, list[dict]] = {ref: [] for ref in group_refs}
        if group_refs:
            member_rows = connection.execute(
                """
                SELECT m.group_ref, m.membership_ref, mp_id.public_id,
                       m.starts_at, m.expires_at, mrev.revoked_at, mrev.reason_code,
                       CASE
                           WHEN mrev.membership_ref IS NOT NULL THEN 'revoked'
                           WHEN mp.disabled THEN 'inactive'
                           WHEN m.expires_at <= clock_timestamp() THEN 'expired'
                           WHEN m.starts_at > clock_timestamp() THEN 'scheduled'
                           ELSE 'active'
                       END AS state
                FROM thalion.shared_group_member AS m
                JOIN thalion.principal AS mp ON (mp.org_id, mp.principal_id) = (m.org_id, m.member_principal_id)
                JOIN thalion.object_identity AS mp_id
                  ON (mp_id.org_id, mp_id.object_type, mp_id.object_id) = (m.org_id, 'principal', m.member_principal_id)
                LEFT JOIN thalion.shared_group_member_revocation AS mrev ON mrev.membership_ref = m.membership_ref
                WHERE m.org_id = %s AND m.group_ref = ANY(%s)
                ORDER BY m.recorded_at DESC, m.membership_ref DESC
                """,
                (context.org_id, group_refs),
            ).fetchall()
            for grp_ref, mem_ref, emp_ref, m_start, m_exp, m_rev, m_reason, m_state in member_rows:
                members_by_group[grp_ref].append({
                    "membership_id": str(mem_ref),
                    "member_id": str(emp_ref),
                    "starts_at": m_start.astimezone(UTC).isoformat(),
                    "expires_at": m_exp.astimezone(UTC).isoformat(),
                    "state": m_state,
                    **({"revoked_at": m_rev.astimezone(UTC).isoformat(), "reason_code": m_reason} if m_rev else {}),
                })

        delegation_rows = connection.execute(
            """
            SELECT d.delegation_ref, del_id.public_id, tgt_id.public_id,
                   d.scopes, d.purpose, d.starts_at, d.review_at, d.expires_at, d.recorded_at,
                   rev.revoked_at, rev.reason_code,
                   CASE
                       WHEN rev.delegation_ref IS NOT NULL THEN 'revoked'
                       WHEN sp.lifecycle <> 'active' THEN 'space_archived'
                       WHEN sp.owner_principal_id <> d.delegator_id OR del_p.disabled OR tgt_p.disabled THEN 'inactive'
                       WHEN d.expires_at <= clock_timestamp() THEN 'expired'
                       WHEN d.starts_at > clock_timestamp() THEN 'scheduled'
                       ELSE 'active'
                   END AS state
            FROM thalion.space_delegation AS d
            JOIN thalion.space AS sp ON (sp.org_id, sp.space_id) = (d.org_id, d.space_id)
            JOIN thalion.principal AS del_p ON (del_p.org_id, del_p.principal_id) = (d.org_id, d.delegator_id)
            JOIN thalion.principal AS tgt_p ON (tgt_p.org_id, tgt_p.principal_id) = (d.org_id, d.delegate_id)
            JOIN thalion.object_identity AS del_id
              ON (del_id.org_id, del_id.object_type, del_id.object_id) = (d.org_id, 'principal', d.delegator_id)
            JOIN thalion.object_identity AS tgt_id
              ON (tgt_id.org_id, tgt_id.object_type, tgt_id.object_id) = (d.org_id, 'principal', d.delegate_id)
            LEFT JOIN thalion.space_delegation_revocation AS rev ON rev.delegation_ref = d.delegation_ref
            WHERE (d.org_id, d.space_id) = (%s, %s)
            ORDER BY d.recorded_at DESC, d.delegation_ref DESC
            LIMIT %s
            """,
            (context.org_id, space_id, MAX_LIST_ITEMS),
        ).fetchall()

        handoff_rows = connection.execute(
            """
            SELECT r.receipt_ref, r.transition_kind, inc_id.public_id, suc_id.public_id,
                   r.delegation_ref, act_id.public_id, r.basis_ref, r.review_at, r.handed_off_at,
                   r.revoked_group_member_count, r.revoked_delegation_count,
                   r.reassigned_document_count, r.accepted_feedback_handoff_refs,
                   r.remaining_open_feedback_count
            FROM thalion.governance_handoff_receipt AS r
            JOIN thalion.object_identity AS inc_id
              ON (inc_id.org_id, inc_id.object_type, inc_id.object_id) = (r.org_id, 'principal', r.incumbent_id)
            LEFT JOIN thalion.object_identity AS suc_id
              ON (suc_id.org_id, suc_id.object_type, suc_id.object_id) = (r.org_id, 'principal', r.successor_id)
            JOIN thalion.object_identity AS act_id
              ON (act_id.org_id, act_id.object_type, act_id.object_id) = (r.org_id, 'principal', r.actor_id)
            WHERE (r.org_id, r.space_id) = (%s, %s)
            ORDER BY r.handed_off_at DESC, r.receipt_ref DESC
            LIMIT %s
            """,
            (context.org_id, space_id, MAX_LIST_ITEMS),
        ).fetchall()

    return {
        "space": {
            "space_id": str(space_ref),
            "name": space_name,
            "classification": classification,
            "owner_id": str(owner_ref),
            "lifecycle": lifecycle,
            "safety_epoch": safety_epoch,
            "archive": None if archive_row is None else {
                "archive_id": str(archive_row[0]),
                "reason_code": archive_row[1],
                "basis_id": str(archive_row[2]),
                "archived_at": archive_row[3].astimezone(UTC).isoformat(),
                "actor_id": str(archive_row[4]),
            },
        },
        "shared_groups": [
            {
                "group_id": str(grp_ref),
                "group_principal_id": str(gp_ref),
                "owner_space_id": str(os_ref),
                "target_space_id": str(ts_ref),
                "target_source_id": str(src_ref),
                "name": name,
                "purpose": purpose,
                "scope_summary": scope_summary,
                "starts_at": starts_at.astimezone(UTC).isoformat(),
                "review_at": review_at.astimezone(UTC).isoformat(),
                "expires_at": expires_at.astimezone(UTC).isoformat(),
                "state": state,
                **({"revoked_at": rev_at.astimezone(UTC).isoformat(), "reason_code": rev_reason} if rev_at else {}),
                "members": members_by_group[grp_ref],
            }
            for (
                grp_ref, gp_ref, os_ref, ts_ref, src_ref, name, purpose, scope_summary,
                starts_at, review_at, expires_at, _, rev_at, rev_reason, state,
            ) in group_rows
        ],
        "delegations": [
            {
                "delegation_id": str(d_ref),
                "delegator_id": str(del_ref),
                "delegate_id": str(tgt_ref),
                "scopes": list(scopes),
                "purpose": purpose,
                "starts_at": starts_at.astimezone(UTC).isoformat(),
                "review_at": review_at.astimezone(UTC).isoformat(),
                "expires_at": expires_at.astimezone(UTC).isoformat(),
                "state": state,
                **({"revoked_at": rev_at.astimezone(UTC).isoformat(), "reason_code": rev_reason} if rev_at else {}),
            }
            for (
                d_ref, del_ref, tgt_ref, scopes, purpose, starts_at, review_at, expires_at,
                _, rev_at, rev_reason, state,
            ) in delegation_rows
        ],
        "handoff_receipts": [
            {
                "receipt_id": str(r_ref),
                "transition_kind": kind,
                "incumbent_id": str(inc_ref),
                "successor_id": str(suc_ref) if suc_ref else None,
                "delegation_id": str(del_ref) if del_ref else None,
                "actor_id": str(act_ref),
                "basis_id": str(basis_ref),
                "review_at": review_at.astimezone(UTC).isoformat(),
                "handed_off_at": handed_off_at.astimezone(UTC).isoformat(),
                "revoked_group_member_count": m_cnt,
                "revoked_delegation_count": d_cnt,
                "reassigned_document_count": doc_cnt,
                "accepted_feedback_handoff_ids": [str(ref) for ref in fb_refs],
                "remaining_open_feedback_count": rem_cnt,
            }
            for (
                r_ref, kind, inc_ref, suc_ref, del_ref, act_ref, basis_ref, review_at,
                handed_off_at, m_cnt, d_cnt, doc_cnt, fb_refs, rem_cnt,
            ) in handoff_rows
        ],
    }


def create_shared_group(
    connection: Connection,
    context: SourceWrite,
    owner_space_id: int,
    *,
    target_source_ref: UUID,
    name: str,
    purpose: str,
    scope_summary: str,
    starts_at: datetime,
    review_at: datetime,
    expires_at: datetime,
    basis_ref: UUID,
) -> dict:
    clean_name = _validate_text(name, 120, "shared group name")
    clean_purpose = _validate_code(purpose, "shared group purpose")
    clean_scope = _validate_text(scope_summary, 240, "shared group scope summary")
    require_aware(starts_at)
    require_aware(review_at)
    require_aware(expires_at)
    start_utc = starts_at.astimezone(UTC)
    review_utc = review_at.astimezone(UTC)
    expiry_utc = expires_at.astimezone(UTC)
    if not (start_utc <= review_utc <= expiry_utc and expiry_utc > start_utc):
        raise ValueError("Shared group review_at and expires_at must satisfy starts_at <= review_at <= expires_at.")

    with connection.transaction():
        _, config_rev, _, _ = _require_space_actor(
            connection, context, owner_space_id, MANAGE_SHARED_GROUP,
            required_scope="shared_group_management", lock_space=True,
        )
        target = connection.execute(
            """
            SELECT src.space_id, src.source_id, src.owner_principal_id, ts.owner_principal_id,
                   src.lifecycle, ts.lifecycle, c.admission
            FROM thalion.object_identity AS oi
            JOIN thalion.source AS src
              ON (src.org_id, src.space_id, src.identity_type, src.source_id)
               = (oi.org_id, oi.space_id, oi.object_type, oi.object_id)
            JOIN thalion.space AS ts ON (ts.org_id, ts.space_id) = (src.org_id, src.space_id)
            JOIN thalion.source_contract_revision AS c
              ON (c.org_id, c.space_id, c.source_id, c.revision)
               = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            WHERE oi.org_id = %s AND oi.object_type = 'source' AND oi.public_id = %s
            FOR SHARE OF src, ts
            """,
            (context.org_id, target_source_ref),
        ).fetchone()
        if target is None:
            raise GovernanceNotAdmitted("Target source is outside this organization.")
        actor_issuer = _principal_issuer(connection, context.org_id, context.principal_id)
        target_space_id, target_source_id, src_owner_id, ts_owner_id, src_life, ts_life, admission = target
        if (
            src_life != "active"
            or ts_life != "active"
            or admission not in ADMITTED_ADMISSIONS
            or not issuer_matches_admission(actor_issuer, admission)
        ):
            raise GovernanceNotAdmitted("Target source and space must be active and match caller admission mode.")
        if target_space_id != owner_space_id and context.principal_id not in (src_owner_id, ts_owner_id):
            raise GovernanceNotAdmitted("Cross-space shared groups require authority over the target source or target space.")

        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, MANAGE_SHARED_GROUP,
            context.idempotency_key, _digest(
                "create_shared_group", owner_space_id, target_space_id, str(target_source_ref),
                clean_name, clean_purpose, clean_scope,
                start_utc.isoformat(), review_utc.isoformat(), expiry_utc.isoformat(), str(basis_ref),
            ), config_rev, None,
        )

        def apply(transaction):
            group_principal_id, = transaction.execute(
                """
                INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
                VALUES (%s, 'group', %s, %s) RETURNING principal_id
                """,
                (context.org_id, actor_issuer, f"shared-group:{uuid4()}"),
            ).fetchone()
            transaction.execute(
                """
                INSERT INTO thalion.object_identity (object_type, object_id, org_id)
                VALUES ('principal', %s, %s)
                """,
                (group_principal_id, context.org_id),
            )
            try:
                group_ref, = transaction.execute(
                    """
                    INSERT INTO thalion.shared_group (
                        org_id, owner_space_id, target_space_id, target_source_id, group_principal_id,
                        name, purpose, scope_summary, created_by, basis_ref, request_id,
                        starts_at, review_at, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING group_ref
                    """,
                    (
                        context.org_id, owner_space_id, target_space_id, target_source_id, group_principal_id,
                        clean_name, clean_purpose, clean_scope, context.principal_id, basis_ref, context.request_id,
                        start_utc, review_utc, expiry_utc,
                    ),
                ).fetchone()
            except errors.CheckViolation as exc:
                if exc.diag.constraint_name == "shared_group_window":
                    raise ValueError("Shared group expiry must be in the future.") from None
                raise
            _bump_spaces_safety_epoch(transaction, context.org_id, {owner_space_id, target_space_id})
            _append_space_event(transaction, context.org_id, owner_space_id, "access.shared_group.created")
            return group_ref

        receipt = execute_command(connection, command, apply)
        row = connection.execute(
            """
            SELECT g.group_ref, gp_id.public_id, os_id.public_id, ts_id.public_id,
                   g.starts_at, g.review_at, g.expires_at
            FROM thalion.shared_group AS g
            JOIN thalion.object_identity AS gp_id
              ON (gp_id.org_id, gp_id.object_type, gp_id.object_id) = (g.org_id, 'principal', g.group_principal_id)
            JOIN thalion.object_identity AS os_id
              ON (os_id.org_id, os_id.space_id, os_id.object_type, os_id.object_id)
               = (g.org_id, g.owner_space_id, 'space', g.owner_space_id)
            JOIN thalion.object_identity AS ts_id
              ON (ts_id.org_id, ts_id.space_id, ts_id.object_type, ts_id.object_id)
               = (g.org_id, g.target_space_id, 'space', g.target_space_id)
            WHERE g.group_ref = %s
            """,
            (receipt.result_ref,),
        ).fetchone()
    return {
        "group_id": str(row[0]),
        "group_principal_id": str(row[1]),
        "owner_space_id": str(row[2]),
        "target_space_id": str(row[3]),
        "target_source_id": str(target_source_ref),
        "starts_at": row[4].astimezone(UTC).isoformat(),
        "review_at": row[5].astimezone(UTC).isoformat(),
        "expires_at": row[6].astimezone(UTC).isoformat(),
    }


def add_shared_group_member(
    connection: Connection,
    context: SourceWrite,
    owner_space_id: int,
    group_ref: UUID,
    *,
    member_ref: UUID,
    starts_at: datetime,
    expires_at: datetime,
    basis_ref: UUID,
) -> dict:
    require_aware(starts_at)
    require_aware(expires_at)
    start_utc = starts_at.astimezone(UTC)
    expiry_utc = expires_at.astimezone(UTC)
    if expiry_utc <= start_utc:
        raise ValueError("Member expiry must follow member start time.")
    with connection.transaction():
        _, config_rev, _, _ = _require_space_actor(
            connection, context, owner_space_id, MANAGE_SHARED_GROUP,
            required_scope="shared_group_management", lock_space=True,
        )
        grp = connection.execute(
            """
            SELECT target_space_id, starts_at, expires_at
            FROM thalion.shared_group
            WHERE (org_id, owner_space_id, group_ref) = (%s, %s, %s)
            FOR UPDATE
            """,
            (context.org_id, owner_space_id, group_ref),
        ).fetchone()
        if grp is None:
            raise GovernanceNotAdmitted("Shared group is outside this space.")
        target_space_id, grp_starts, grp_expires = grp
        if start_utc < grp_starts.astimezone(UTC) or expiry_utc > grp_expires.astimezone(UTC):
            raise ValueError("Member validity window must fit inside the shared group validity window.")
        actor_issuer = _principal_issuer(connection, context.org_id, context.principal_id)
        member_id = _resolve_principal(connection, context.org_id, member_ref, active_employee=True, expected_issuer=actor_issuer)
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, MANAGE_SHARED_GROUP,
            context.idempotency_key, _digest(
                "add_shared_group_member", owner_space_id, str(group_ref), member_id,
                start_utc.isoformat(), expiry_utc.isoformat(), str(basis_ref),
            ), config_rev, None,
        )

        def apply(transaction):
            if transaction.execute(
                "SELECT 1 FROM thalion.shared_group_revocation WHERE group_ref = %s", (group_ref,),
            ).fetchone() is not None:
                raise GovernanceConflict("Shared group has already been revoked.")
            try:
                membership_ref, = transaction.execute(
                    """
                    INSERT INTO thalion.shared_group_member (
                        org_id, owner_space_id, group_ref, member_principal_id,
                        added_by, basis_ref, request_id, starts_at, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING membership_ref
                    """,
                    (
                        context.org_id, owner_space_id, group_ref, member_id,
                        context.principal_id, basis_ref, context.request_id, start_utc, expiry_utc,
                    ),
                ).fetchone()
            except errors.CheckViolation as exc:
                if exc.diag.constraint_name == "shared_group_member_window":
                    raise ValueError("Member expiry must be in the future.") from None
                raise GovernanceConflict("Shared group cannot accept this member.") from None
            _bump_spaces_safety_epoch(transaction, context.org_id, {owner_space_id, target_space_id})
            _append_space_event(transaction, context.org_id, owner_space_id, "access.shared_group.member_added")
            return membership_ref

        receipt = execute_command(connection, command, apply)
    return {
        "membership_id": str(receipt.result_ref),
        "group_id": str(group_ref),
        "member_id": str(member_ref),
        "starts_at": start_utc.isoformat(),
        "expires_at": expiry_utc.isoformat(),
    }


def _load_revocable_group(connection: Connection, context: SourceWrite, space_id: int, group_ref: UUID):
    row = connection.execute(
        """
        SELECT g.owner_space_id, g.target_space_id, g.target_source_id, g.group_principal_id,
               os.owner_principal_id, ts.owner_principal_id, src.owner_principal_id
        FROM thalion.shared_group AS g
        JOIN thalion.space AS os ON (os.org_id, os.space_id) = (g.org_id, g.owner_space_id)
        JOIN thalion.space AS ts ON (ts.org_id, ts.space_id) = (g.org_id, g.target_space_id)
        JOIN thalion.source AS src
          ON (src.org_id, src.space_id, src.source_id) = (g.org_id, g.target_space_id, g.target_source_id)
        WHERE g.org_id = %s AND g.group_ref = %s
          AND (g.owner_space_id = %s OR g.target_space_id = %s)
        FOR UPDATE OF g
        """,
        (context.org_id, group_ref, space_id, space_id),
    ).fetchone()
    if row is None:
        raise GovernanceNotAdmitted("Shared group is outside this space.")
    owner_space_id, target_space_id, target_source_id, grp_principal_id, os_owner, ts_owner, src_owner = row
    allowed = (
        context.principal_id in (os_owner, ts_owner, src_owner)
        or _has_delegation(connection, context.org_id, owner_space_id, context.principal_id, "shared_group_management")
    )
    if not allowed:
        raise GovernanceNotAdmitted("Caller is not authorized to revoke this shared group or membership.")
    return owner_space_id, target_space_id, target_source_id, grp_principal_id


def revoke_shared_group_member(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    group_ref: UUID,
    membership_ref: UUID,
    *,
    reason_code: str,
    basis_ref: UUID,
) -> dict:
    clean_reason = _validate_code(reason_code, "reason_code")
    with connection.transaction():
        _require_read_committed(connection)
        require_open_request(
            connection, context.org_id, context.request_id, context.principal_id, None, operation=MANAGE_SHARED_GROUP,
        )
        config_rev, = connection.execute(
            f"""
            SELECT org.config_revision FROM thalion.organization AS org
            JOIN thalion.principal AS p ON (p.org_id, p.principal_id) = (org.org_id, %s)
            WHERE org.org_id = %s AND p.principal_type = 'employee'
              AND {sql_admitted_issuer('p.authority_issuer')} AND NOT p.disabled
            FOR SHARE OF org, p
            """,
            (context.principal_id, context.org_id),
        ).fetchone() or (None,)
        if config_rev is None:
            raise GovernanceNotAdmitted("Active admitted employee is required.")
        owner_space_id, target_space_id, _, _ = _load_revocable_group(connection, context, space_id, group_ref)
        exists = connection.execute(
            """
            SELECT 1 FROM thalion.shared_group_member
            WHERE (org_id, owner_space_id, group_ref, membership_ref) = (%s, %s, %s, %s)
            FOR UPDATE
            """,
            (context.org_id, owner_space_id, group_ref, membership_ref),
        ).fetchone()
        if exists is None:
            raise GovernanceNotAdmitted("Shared group membership was not found.")
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, MANAGE_SHARED_GROUP,
            context.idempotency_key, _digest(
                "revoke_shared_group_member", owner_space_id, str(group_ref), str(membership_ref),
                clean_reason, str(basis_ref),
            ), config_rev, None,
        )

        def apply(transaction):
            if transaction.execute(
                "SELECT 1 FROM thalion.shared_group_member_revocation WHERE membership_ref = %s",
                (membership_ref,),
            ).fetchone() is not None:
                raise GovernanceConflict("Shared group membership is already revoked.")
            transaction.execute(
                """
                INSERT INTO thalion.shared_group_member_revocation (
                    membership_ref, org_id, owner_space_id, revoked_by, basis_ref, request_id, reason_code
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (membership_ref, context.org_id, owner_space_id, context.principal_id,
                 basis_ref, context.request_id, clean_reason),
            )
            _bump_spaces_safety_epoch(transaction, context.org_id, {owner_space_id, target_space_id})
            _append_space_event(transaction, context.org_id, owner_space_id, "access.shared_group.member_revoked")
            return membership_ref

        execute_command(connection, command, apply)
    return {"group_id": str(group_ref), "membership_id": str(membership_ref), "state": "revoked"}


def revoke_shared_group(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    group_ref: UUID,
    *,
    reason_code: str,
    basis_ref: UUID,
) -> dict:
    clean_reason = _validate_code(reason_code, "reason_code")
    with connection.transaction():
        _require_read_committed(connection)
        require_open_request(
            connection, context.org_id, context.request_id, context.principal_id, None, operation=MANAGE_SHARED_GROUP,
        )
        config_rev, = connection.execute(
            f"""
            SELECT org.config_revision FROM thalion.organization AS org
            JOIN thalion.principal AS p ON (p.org_id, p.principal_id) = (org.org_id, %s)
            WHERE org.org_id = %s AND p.principal_type = 'employee'
              AND {sql_admitted_issuer('p.authority_issuer')} AND NOT p.disabled
            FOR SHARE OF org, p
            """,
            (context.principal_id, context.org_id),
        ).fetchone() or (None,)
        if config_rev is None:
            raise GovernanceNotAdmitted("Active admitted employee is required.")
        owner_space_id, target_space_id, _, group_principal_id = _load_revocable_group(
            connection, context, space_id, group_ref,
        )
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, MANAGE_SHARED_GROUP,
            context.idempotency_key, _digest(
                "revoke_shared_group", owner_space_id, str(group_ref), clean_reason, str(basis_ref),
            ), config_rev, None,
        )

        def apply(transaction):
            if transaction.execute(
                "SELECT 1 FROM thalion.shared_group_revocation WHERE group_ref = %s", (group_ref,),
            ).fetchone() is not None:
                raise GovernanceConflict("Shared group is already revoked.")
            transaction.execute(
                """
                INSERT INTO thalion.shared_group_revocation (
                    group_ref, org_id, owner_space_id, revoked_by, basis_ref, request_id, reason_code
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (group_ref, context.org_id, owner_space_id, context.principal_id,
                 basis_ref, context.request_id, clean_reason),
            )
            transaction.execute(
                "UPDATE thalion.principal SET disabled = true WHERE (org_id, principal_id) = (%s, %s)",
                (context.org_id, group_principal_id),
            )
            _bump_spaces_safety_epoch(transaction, context.org_id, {owner_space_id, target_space_id})
            _append_space_event(transaction, context.org_id, owner_space_id, "access.shared_group.revoked")
            return group_ref

        execute_command(connection, command, apply)
    return {"group_id": str(group_ref), "state": "revoked"}


def create_delegation(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    *,
    delegate_ref: UUID,
    scopes: tuple[str, ...],
    purpose: str,
    starts_at: datetime,
    review_at: datetime,
    expires_at: datetime,
    basis_ref: UUID,
) -> dict:
    clean_scopes = tuple(sorted(set(scopes)))
    if not clean_scopes or not set(clean_scopes) <= DELEGATION_SCOPES:
        raise ValueError("Invalid space delegation scopes.")
    clean_purpose = _validate_code(purpose, "delegation purpose")
    require_aware(starts_at)
    require_aware(review_at)
    require_aware(expires_at)
    start_utc = starts_at.astimezone(UTC)
    review_utc = review_at.astimezone(UTC)
    expiry_utc = expires_at.astimezone(UTC)
    if not (start_utc <= review_utc <= expiry_utc and expiry_utc > start_utc):
        raise ValueError("Delegation review_at and expires_at must satisfy starts_at <= review_at <= expires_at.")

    with connection.transaction():
        _, config_rev, _, _ = _require_space_actor(
            connection, context, space_id, MANAGE_DELEGATION, owner_only=True, lock_space=True,
        )
        actor_issuer = _principal_issuer(connection, context.org_id, context.principal_id)
        delegate_id = _resolve_principal(connection, context.org_id, delegate_ref, active_employee=True, expected_issuer=actor_issuer)
        if delegate_id == context.principal_id:
            raise ValueError("Space owner cannot delegate governance authority to self.")
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, MANAGE_DELEGATION,
            context.idempotency_key, _digest(
                "create_delegation", space_id, delegate_id, list(clean_scopes), clean_purpose,
                start_utc.isoformat(), review_utc.isoformat(), expiry_utc.isoformat(), str(basis_ref),
            ), config_rev, None,
        )

        def apply(transaction):
            try:
                delegation_ref, = transaction.execute(
                    """
                    INSERT INTO thalion.space_delegation (
                        org_id, space_id, delegator_id, delegate_id, scopes, purpose,
                        basis_ref, request_id, starts_at, review_at, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING delegation_ref
                    """,
                    (
                        context.org_id, space_id, context.principal_id, delegate_id, list(clean_scopes),
                        clean_purpose, basis_ref, context.request_id, start_utc, review_utc, expiry_utc,
                    ),
                ).fetchone()
            except errors.CheckViolation as exc:
                if exc.diag.constraint_name == "space_delegation_window":
                    raise ValueError("Delegation expiry must be in the future.") from None
                raise
            _append_space_event(transaction, context.org_id, space_id, "access.delegation.created")
            return delegation_ref

        receipt = execute_command(connection, command, apply)
    return {
        "delegation_id": str(receipt.result_ref),
        "delegate_id": str(delegate_ref),
        "scopes": list(clean_scopes),
        "purpose": clean_purpose,
        "starts_at": start_utc.isoformat(),
        "review_at": review_utc.isoformat(),
        "expires_at": expiry_utc.isoformat(),
    }


def revoke_delegation(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    delegation_ref: UUID,
    *,
    reason_code: str,
    basis_ref: UUID,
) -> dict:
    clean_reason = _validate_code(reason_code, "reason_code")
    with connection.transaction():
        _, config_rev, _, _ = _require_space_actor(
            connection, context, space_id, MANAGE_DELEGATION, owner_only=True, lock_space=True,
        )
        row = connection.execute(
            """
            SELECT 1 FROM thalion.space_delegation
            WHERE (org_id, space_id, delegation_ref) = (%s, %s, %s) FOR UPDATE
            """,
            (context.org_id, space_id, delegation_ref),
        ).fetchone()
        if row is None:
            raise GovernanceNotAdmitted("Delegation was not found in this space.")
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, MANAGE_DELEGATION,
            context.idempotency_key, _digest(
                "revoke_delegation", space_id, str(delegation_ref), clean_reason, str(basis_ref),
            ), config_rev, None,
        )

        def apply(transaction):
            if transaction.execute(
                "SELECT 1 FROM thalion.space_delegation_revocation WHERE delegation_ref = %s",
                (delegation_ref,),
            ).fetchone() is not None:
                raise GovernanceConflict("Delegation has already been revoked.")
            transaction.execute(
                """
                INSERT INTO thalion.space_delegation_revocation (
                    delegation_ref, org_id, space_id, revoked_by, basis_ref, request_id, reason_code
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (delegation_ref, context.org_id, space_id, context.principal_id,
                 basis_ref, context.request_id, clean_reason),
            )
            _bump_spaces_safety_epoch(transaction, context.org_id, {space_id})
            _append_space_event(transaction, context.org_id, space_id, "access.delegation.revoked")
            return delegation_ref

        execute_command(connection, command, apply)
    return {"delegation_id": str(delegation_ref), "state": "revoked"}


def archive_space(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    *,
    reason_code: str,
    basis_ref: UUID,
) -> dict:
    clean_reason = _validate_code(reason_code, "reason_code")
    with connection.transaction():
        _, config_rev, _, lifecycle = _require_space_actor(
            connection, context, space_id, ARCHIVE_SPACE, owner_only=True,
            allow_archived_read=True, lock_space=True,
        )
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, ARCHIVE_SPACE,
            context.idempotency_key, _digest("archive_space", space_id, clean_reason, str(basis_ref)), config_rev,
            None,
        )

        def apply(transaction):
            if lifecycle == "archived":
                raise GovernanceConflict("Space is already archived.")
            linked = transaction.execute(
                """
                SELECT group_principal_id, target_space_id
                FROM thalion.shared_group
                WHERE (org_id, owner_space_id) = (%s, %s)
                FOR UPDATE
                """,
                (context.org_id, space_id),
            ).fetchall()
            group_principals = [row[0] for row in linked]
            external_target_spaces = {row[1] for row in linked if row[1] != space_id}
            transaction.execute(
                """
                UPDATE thalion.space SET lifecycle = 'archived'
                WHERE (org_id, space_id) = (%s, %s)
                """,
                (context.org_id, space_id),
            )
            if group_principals:
                transaction.execute(
                    """
                    UPDATE thalion.principal SET disabled = true
                    WHERE org_id = %s AND principal_id = ANY(%s)
                    """,
                    (context.org_id, group_principals),
                )
            if external_target_spaces:
                _bump_spaces_safety_epoch(transaction, context.org_id, external_target_spaces)
            archive_ref, = transaction.execute(
                """
                INSERT INTO thalion.space_archive_record (
                    org_id, space_id, actor_id, basis_ref, request_id, reason_code
                ) VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING archive_ref
                """,
                (context.org_id, space_id, context.principal_id, basis_ref, context.request_id, clean_reason),
            ).fetchone()
            _append_space_event(transaction, context.org_id, space_id, "access.space.archived")
            return archive_ref

        receipt = execute_command(connection, command, apply)
        archived_at, new_epoch, disabled_groups = connection.execute(
            """
            SELECT ar.archived_at, sp.safety_epoch,
                   (SELECT count(*) FROM thalion.shared_group WHERE (org_id, owner_space_id) = (ar.org_id, ar.space_id))
            FROM thalion.space_archive_record AS ar
            JOIN thalion.space AS sp USING (org_id, space_id)
            WHERE ar.archive_ref = %s
            """,
            (receipt.result_ref,),
        ).fetchone()
    return {
        "archive_id": str(receipt.result_ref),
        "lifecycle": "archived",
        "safety_epoch": new_epoch,
        "disabled_shared_groups": disabled_groups,
        "archived_at": archived_at.astimezone(UTC).isoformat(),
    }


def inspect_transition(connection: Connection, context: SourceWrite, space_id: int, principal_ref: UUID) -> dict:
    with connection.transaction():
        _require_space_actor(connection, context, space_id, READ_GOVERNANCE, allow_archived_read=True)
        actor_issuer = _principal_issuer(connection, context.org_id, context.principal_id)
        incumbent_id = _resolve_principal(connection, context.org_id, principal_ref, active_employee=False, expected_issuer=actor_issuer)
        disabled, = connection.execute(
            "SELECT disabled FROM thalion.principal WHERE (org_id, principal_id) = (%s, %s)",
            (context.org_id, incumbent_id),
        ).fetchone()
        doc_rows = connection.execute(
            """
            SELECT DISTINCT ON (ra.source_id, ra.document_id)
                   doc_id.public_id, ra.generation, ra.responsible_id, ra.expires_at
            FROM thalion.responsibility_assignment AS ra
            JOIN thalion.object_identity AS doc_id
              ON (doc_id.org_id, doc_id.space_id, doc_id.object_type, doc_id.object_id)
               = (ra.org_id, ra.space_id, 'document', ra.document_id)
            WHERE (ra.org_id, ra.space_id) = (%s, %s)
            ORDER BY ra.source_id, ra.document_id, ra.generation DESC
            """,
            (context.org_id, space_id),
        ).fetchall()
        active_docs = [
            {
                "document_id": str(doc_ref),
                "generation": gen,
                "expires_at": exp.astimezone(UTC).isoformat() if exp else None,
            }
            for doc_ref, gen, resp_id, exp in doc_rows
            if resp_id == incumbent_id and (exp is None or exp > datetime.now(UTC))
        ]
        fb_rows = connection.execute(
            """
            SELECT fb_id.public_id, cf.generation, cf.state
            FROM thalion.current_feedback AS cf
            JOIN thalion.object_identity AS fb_id
              ON (fb_id.org_id, fb_id.space_id, fb_id.object_type, fb_id.object_id)
               = (cf.org_id, cf.space_id, 'feedback', cf.feedback_id)
            WHERE (cf.org_id, cf.space_id, cf.assignee_id) = (%s, %s, %s)
              AND cf.state = 'pending'
            ORDER BY cf.feedback_id
            """,
            (context.org_id, space_id, incumbent_id),
        ).fetchall()
        mem_rows = connection.execute(
            """
            SELECT m.group_ref, m.membership_ref, m.expires_at
            FROM thalion.shared_group_member AS m
            JOIN thalion.shared_group AS g
              ON (g.org_id, g.owner_space_id, g.group_ref) = (m.org_id, m.owner_space_id, m.group_ref)
            WHERE m.org_id = %s AND m.member_principal_id = %s
              AND (g.owner_space_id = %s OR g.target_space_id = %s)
              AND m.expires_at > clock_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.shared_group_revocation AS grev WHERE grev.group_ref = g.group_ref
              )
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.shared_group_member_revocation AS mrev
                  WHERE mrev.membership_ref = m.membership_ref
              )
            ORDER BY m.recorded_at DESC
            """,
            (context.org_id, incumbent_id, space_id, space_id),
        ).fetchall()
        in_del_rows = connection.execute(
            """
            SELECT d.delegation_ref, d.scopes, d.expires_at
            FROM thalion.space_delegation AS d
            WHERE (d.org_id, d.space_id, d.delegate_id) = (%s, %s, %s)
              AND d.expires_at > clock_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.space_delegation_revocation AS rev WHERE rev.delegation_ref = d.delegation_ref
              )
            ORDER BY d.recorded_at DESC
            """,
            (context.org_id, space_id, incumbent_id),
        ).fetchall()
        out_del_rows = connection.execute(
            """
            SELECT d.delegation_ref, d.scopes, d.expires_at
            FROM thalion.space_delegation AS d
            WHERE (d.org_id, d.space_id, d.delegator_id) = (%s, %s, %s)
              AND d.expires_at > clock_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.space_delegation_revocation AS rev WHERE rev.delegation_ref = d.delegation_ref
              )
            ORDER BY d.recorded_at DESC
            """,
            (context.org_id, space_id, incumbent_id),
        ).fetchall()

    return {
        "employee_id": str(principal_ref),
        "employee_active": not disabled,
        "active_document_responsibilities": active_docs,
        "open_feedback_items": [
            {"feedback_id": str(fb_ref), "generation": gen, "state": state}
            for fb_ref, gen, state in fb_rows
        ],
        "active_shared_group_memberships": [
            {"group_id": str(g_ref), "membership_id": str(m_ref), "expires_at": exp.astimezone(UTC).isoformat()}
            for g_ref, m_ref, exp in mem_rows
        ],
        "active_incoming_delegations": [
            {"delegation_id": str(d_ref), "scopes": list(scopes), "expires_at": exp.astimezone(UTC).isoformat()}
            for d_ref, scopes, exp in in_del_rows
        ],
        "active_outgoing_delegations": [
            {"delegation_id": str(d_ref), "scopes": list(scopes), "expires_at": exp.astimezone(UTC).isoformat()}
            for d_ref, scopes, exp in out_del_rows
        ],
    }


def record_transition_handoff(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    incumbent_ref: UUID,
    *,
    transition_kind: str,
    successor_ref: UUID | None,
    delegation_ref: UUID | None,
    review_at: datetime,
    basis_ref: UUID,
    reassign_documents: bool = True,
    revoke_outgoing_delegations: bool = False,
    accepted_feedback_handoff_refs: tuple[UUID, ...] = (),
) -> dict:
    if transition_kind not in TRANSITION_KINDS:
        raise ValueError("Invalid transition kind.")
    require_aware(review_at)
    review_utc = review_at.astimezone(UTC)
    fb_handoff_refs = tuple(sorted(set(accepted_feedback_handoff_refs)))

    with connection.transaction():
        is_owner, config_rev, _, _ = _require_space_actor(
            connection, context, space_id, HANDOFF_TRANSITION, lock_space=True,
        )
        if reassign_documents and not is_owner and not _has_delegation(
            connection, context.org_id, space_id, context.principal_id, "responsibility_management",
        ):
            raise GovernanceNotAdmitted("Reassigning document responsibilities requires owner or responsibility_management delegation.")
        actor_issuer = _principal_issuer(connection, context.org_id, context.principal_id)
        incumbent_id = _resolve_principal(connection, context.org_id, incumbent_ref, active_employee=False, expected_issuer=actor_issuer)
        if incumbent_id == context.principal_id:
            raise GovernanceNotAdmitted("Caller cannot execute their own transition handoff.")
        successor_id = None
        if successor_ref is not None:
            successor_id = _resolve_principal(connection, context.org_id, successor_ref, active_employee=True, expected_issuer=actor_issuer)
            if successor_id == incumbent_id:
                raise ValueError("Successor must differ from incumbent.")
        if delegation_ref is not None:
            found = connection.execute(
                """
                SELECT 1 FROM thalion.space_delegation
                WHERE (org_id, space_id, delegation_ref) = (%s, %s, %s)
                """,
                (context.org_id, space_id, delegation_ref),
            ).fetchone()
            if found is None:
                raise GovernanceNotAdmitted("Referenced delegation does not belong to this space.")

        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, HANDOFF_TRANSITION,
            context.idempotency_key, _digest(
                "record_transition_handoff", space_id, transition_kind, incumbent_id, successor_id,
                str(delegation_ref) if delegation_ref else None, review_utc.isoformat(),
                str(basis_ref), reassign_documents, revoke_outgoing_delegations,
                [str(ref) for ref in fb_handoff_refs],
            ), config_rev, None,
        )

        def apply(transaction):
            if fb_handoff_refs:
                verified = transaction.execute(
                    """
                    SELECT fh.handoff_ref, fh.incumbent_id, fh.successor_id, res.outcome
                    FROM thalion.feedback_handoff AS fh
                    LEFT JOIN thalion.feedback_handoff_resolution AS res USING (org_id, space_id, handoff_ref)
                    WHERE (fh.org_id, fh.space_id) = (%s, %s) AND fh.handoff_ref = ANY(%s)
                    """,
                    (context.org_id, space_id, list(fb_handoff_refs)),
                ).fetchall()
                if len(verified) != len(fb_handoff_refs):
                    raise GovernanceConflict("Referenced feedback handoff was not found in this space.")
                for _, fh_inc, fh_suc, fh_outcome in verified:
                    if fh_inc != incumbent_id or fh_outcome != "accepted":
                        raise GovernanceConflict("Referenced feedback handoff must be accepted for the incumbent.")
                    if successor_id is not None and fh_suc != successor_id:
                        raise GovernanceConflict("Referenced feedback handoff successor does not match.")

            # 1. Revoke all active shared group memberships for incumbent related to this space.
            memberships = transaction.execute(
                """
                SELECT m.membership_ref, m.owner_space_id, g.target_space_id
                FROM thalion.shared_group_member AS m
                JOIN thalion.shared_group AS g
                  ON (g.org_id, g.owner_space_id, g.group_ref) = (m.org_id, m.owner_space_id, m.group_ref)
                WHERE m.org_id = %s AND m.member_principal_id = %s
                  AND (g.owner_space_id = %s OR g.target_space_id = %s)
                  AND NOT EXISTS (
                      SELECT 1 FROM thalion.shared_group_member_revocation AS mrev
                      WHERE mrev.membership_ref = m.membership_ref
                  )
                FOR UPDATE OF m
                """,
                (context.org_id, incumbent_id, space_id, space_id),
            ).fetchall()
            affected_spaces: set[int] = {space_id}
            for mem_ref, mem_owner_space, target_space in memberships:
                transaction.execute(
                    """
                    INSERT INTO thalion.shared_group_member_revocation (
                        membership_ref, org_id, owner_space_id, revoked_by, basis_ref, request_id, reason_code
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (mem_ref, context.org_id, mem_owner_space, context.principal_id,
                     basis_ref, context.request_id, f"transition_{transition_kind}"),
                )
                affected_spaces.add(mem_owner_space)
                affected_spaces.add(target_space)

            # 2. Revoke active incoming delegations (and optionally outgoing delegations) in this space.
            del_filter = (
                "(d.delegate_id = %s OR d.delegator_id = %s)"
                if revoke_outgoing_delegations else "d.delegate_id = %s"
            )
            del_params = (
                (context.org_id, space_id, incumbent_id, incumbent_id)
                if revoke_outgoing_delegations else (context.org_id, space_id, incumbent_id)
            )
            delegations = transaction.execute(
                f"""
                SELECT d.delegation_ref
                FROM thalion.space_delegation AS d
                WHERE (d.org_id, d.space_id) = (%s, %s) AND {del_filter}
                  AND NOT EXISTS (
                      SELECT 1 FROM thalion.space_delegation_revocation AS rev
                      WHERE rev.delegation_ref = d.delegation_ref
                  )
                FOR UPDATE OF d
                """,
                del_params,
            ).fetchall()
            for (del_ref,) in delegations:
                transaction.execute(
                    """
                    INSERT INTO thalion.space_delegation_revocation (
                        delegation_ref, org_id, space_id, revoked_by, basis_ref, request_id, reason_code
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (del_ref, context.org_id, space_id, context.principal_id,
                     basis_ref, context.request_id, f"transition_{transition_kind}"),
                )

            # 3. Reassign or revoke active document responsibilities held by incumbent in this space.
            reassigned_count = 0
            if reassign_documents:
                latest_docs = transaction.execute(
                    """
                    SELECT DISTINCT ON (ra.source_id, ra.document_id)
                           ra.source_id, ra.document_id, ra.generation, ra.responsible_id, ra.expires_at
                    FROM thalion.responsibility_assignment AS ra
                    JOIN thalion.source AS src
                      ON (src.org_id, src.space_id, src.source_id) = (ra.org_id, ra.space_id, ra.source_id)
                    WHERE (ra.org_id, ra.space_id) = (%s, %s) AND src.lifecycle = 'active'
                    ORDER BY ra.source_id, ra.document_id, ra.generation DESC
                    """,
                    (context.org_id, space_id),
                ).fetchall()
                now_ts, = transaction.execute("SELECT clock_timestamp()").fetchone()
                for src_id, doc_id, gen, resp_id, exp in latest_docs:
                    if resp_id != incumbent_id or (exp is not None and exp <= now_ts):
                        continue
                    transaction.execute(
                        """
                        INSERT INTO thalion.responsibility_assignment (
                            org_id, space_id, source_id, document_id, generation,
                            responsible_id, approved_by, basis_ref, request_id, expires_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NULL)
                        """,
                        (
                            context.org_id, space_id, src_id, doc_id, gen + 1,
                            successor_id, context.principal_id, basis_ref, context.request_id,
                        ),
                    )
                    reassigned_count += 1

            remaining_open, = transaction.execute(
                """
                SELECT count(*) FROM thalion.current_feedback
                WHERE (org_id, space_id, assignee_id) = (%s, %s, %s) AND state = 'pending'
                """,
                (context.org_id, space_id, incumbent_id),
            ).fetchone()
            _bump_spaces_safety_epoch(transaction, context.org_id, affected_spaces)
            receipt_ref, = transaction.execute(
                """
                INSERT INTO thalion.governance_handoff_receipt (
                    org_id, space_id, transition_kind, incumbent_id, successor_id, delegation_ref,
                    actor_id, basis_ref, request_id, review_at,
                    revoked_group_member_count, revoked_delegation_count, reassigned_document_count,
                    accepted_feedback_handoff_refs, remaining_open_feedback_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING receipt_ref
                """,
                (
                    context.org_id, space_id, transition_kind, incumbent_id, successor_id, delegation_ref,
                    context.principal_id, basis_ref, context.request_id, review_utc,
                    len(memberships), len(delegations), reassigned_count,
                    list(fb_handoff_refs), remaining_open,
                ),
            ).fetchone()
            _append_space_event(transaction, context.org_id, space_id, "access.governance.handoff_recorded")
            return receipt_ref

        receipt = execute_command(connection, command, apply)
        row = connection.execute(
            """
            SELECT receipt_ref, transition_kind, delegation_ref, review_at, handed_off_at,
                   revoked_group_member_count, revoked_delegation_count, reassigned_document_count,
                   accepted_feedback_handoff_refs, remaining_open_feedback_count
            FROM thalion.governance_handoff_receipt
            WHERE receipt_ref = %s
            """,
            (receipt.result_ref,),
        ).fetchone()
    return {
        "receipt_id": str(row[0]),
        "transition_kind": row[1],
        "incumbent_id": str(incumbent_ref),
        "successor_id": str(successor_ref) if successor_ref else None,
        "delegation_id": str(row[2]) if row[2] else None,
        "review_at": row[3].astimezone(UTC).isoformat(),
        "handed_off_at": row[4].astimezone(UTC).isoformat(),
        "revoked_group_member_count": row[5],
        "revoked_delegation_count": row[6],
        "reassigned_document_count": row[7],
        "accepted_feedback_handoff_ids": [str(ref) for ref in row[8]],
        "remaining_open_feedback_count": row[9],
    }
