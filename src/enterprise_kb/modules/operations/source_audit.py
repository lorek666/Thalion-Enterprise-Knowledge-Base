from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.sources.registry import sql_admitted_admission, sql_issuer_matches_admission

from .context import OperationsCall, OperationsNotAdmitted, require_current_scope, require_scope


READ = "read_source_audit"
DESTINATION = "internal_audit"
PAGE_SIZE = 20


def require_source_owner(connection: Connection, call: OperationsCall, source_ref: UUID, space_owner: int) -> int:
    if space_owner != call.principal_id:
        raise OperationsNotAdmitted("Source audit requires the current space owner.")
    source = connection.execute(
        f"""
        SELECT source.source_id
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS owner
          ON (owner.org_id, owner.principal_id) = (source.org_id, source.owner_principal_id)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
          AND source.owner_principal_id = %s
          AND {sql_admitted_admission('contract.admission')}
          AND {sql_issuer_matches_admission('owner.authority_issuer', 'contract.admission')}
        FOR SHARE OF source
        """,
        (call.org_id, call.space_id, source_ref, call.principal_id),
    ).fetchone()
    if source is None:
        raise OperationsNotAdmitted("Source audit requires the current synthetic source owner.")
    return source[0]


def pin_release_scope(connection: Connection, call: OperationsCall, source_ref: UUID) -> int:
    return require_source_owner(
        connection, call, source_ref, require_current_scope(connection, call, READ, destination=DESTINATION),
    )


def list_source_requests(
    connection: Connection, call: OperationsCall, source_ref: UUID, after: UUID | None, request_ref: UUID | None,
) -> dict:
    source_id = require_source_owner(connection, call, source_ref, require_scope(connection, call, READ, destination=DESTINATION))
    scope = call.org_id, call.space_id, source_id
    anchor_time = None
    if after is not None:
        anchor = connection.execute(
            """
            SELECT request.started_at FROM thalion.request_record AS request
            WHERE (request.org_id, request.scope_space_id, request.request_id) = (%s, %s, %s)
              AND request.outcome IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM thalion.source_audit_request AS link
                  WHERE (link.org_id, link.space_id, link.source_id, link.request_id) = (%s, %s, %s, request.request_id)
              )
            """,
            (call.org_id, call.space_id, after, *scope),
        ).fetchone()
        if anchor is None:
            raise ValueError("The audit cursor is not in the requested source.")
        anchor_time = anchor[0]
    rows = connection.execute(
        """
        WITH linked_requests AS MATERIALIZED (
            SELECT DISTINCT request_id FROM thalion.source_audit_request
            WHERE (org_id, space_id, source_id) = (%s, %s, %s)
              AND (%s::uuid IS NULL OR request_id = %s)
        )
        SELECT request.request_id, actor.public_id, request.operation, request.destination, request.outcome,
               request.started_at, request.completed_at, request.elapsed_ms
        FROM linked_requests AS link
        JOIN LATERAL (
            SELECT request_id, org_id, principal_id, operation, destination, outcome, started_at, completed_at, elapsed_ms
            FROM thalion.request_record
            WHERE (org_id, scope_space_id, request_id) = (%s, %s, link.request_id) AND outcome IS NOT NULL
              AND (started_at, request_id) < (
                  COALESCE(%s::timestamptz, 'infinity'), COALESCE(%s::uuid, '00000000-0000-0000-0000-000000000000')
              )
            LIMIT 1
        ) AS request ON true
        LEFT JOIN thalion.object_identity AS actor
          ON (actor.org_id, actor.object_type, actor.object_id) = (request.org_id, 'principal', request.principal_id)
        ORDER BY request.started_at DESC, request.request_id DESC
        LIMIT %s
        """,
        (*scope, request_ref, request_ref, call.org_id, call.space_id, anchor_time, after, PAGE_SIZE + 1),
    ).fetchall()
    return {
        "source_id": str(source_ref),
        "requests": [{
            "request_id": str(request_id), "actor_id": str(actor_id) if actor_id is not None else None,
            "operation": operation, "destination": destination, "outcome": outcome, "started_at": started.isoformat(),
            "completed_at": completed.isoformat(), "elapsed_ms": elapsed,
        } for request_id, actor_id, operation, destination, outcome, started, completed, elapsed in rows[:PAGE_SIZE]],
        "next_cursor": str(rows[PAGE_SIZE - 1][0]) if len(rows) > PAGE_SIZE else None,
    }


def record_access(connection: Connection, call: OperationsCall, source_id: int):
    connection.execute(
        """
        INSERT INTO thalion.source_audit_access (org_id, space_id, source_id, request_id)
        VALUES (%s, %s, %s, %s)
        """,
        (call.org_id, call.space_id, source_id, call.request_id),
    )
