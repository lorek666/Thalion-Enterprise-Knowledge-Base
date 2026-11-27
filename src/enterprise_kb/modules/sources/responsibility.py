from datetime import datetime
from uuid import UUID

from psycopg import Connection, errors

from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed

from .registry import SourceNotAdmitted, SourceWrite, _digest, sql_admitted_admission, sql_issuer_matches_admission, sql_issuer_matches_value


READ = "read_document_responsibility"
SET = "set_document_responsibility"
DESTINATION = "internal_sources"


class ResponsibilityConflict(Exception):
    pass


def _scope(connection, context, space_id, document_ref, operation):
    _require_read_committed(connection)
    require_open_request(connection, context.org_id, context.request_id, context.principal_id, None, operation=operation)
    lock = "UPDATE" if operation == SET else "SHARE"
    has_delegation = connection.execute(
        "SELECT to_regprocedure('thalion.has_active_space_delegation(bigint,bigint,bigint,text)') IS NOT NULL",
    ).fetchone()[0]
    delegate_clause = (
        "OR thalion.has_active_space_delegation(document.org_id, document.space_id, actor.principal_id, 'responsibility_management')"
        if has_delegation else ""
    )
    selected = connection.execute(
        f"""
        SELECT document.source_id, document.document_id, source.contract_revision, contract.admission
        FROM thalion.object_identity AS identity
        JOIN thalion.document AS document
          ON (document.org_id, document.space_id, document.identity_type, document.document_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id) = (document.org_id, document.space_id, document.source_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (document.org_id, document.space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS actor
          ON (actor.org_id, actor.principal_id) = (document.org_id, %s)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND {sql_admitted_admission('contract.admission')}
          AND actor.principal_type = 'employee'
          AND {sql_issuer_matches_admission('actor.authority_issuer', 'contract.admission')}
          AND NOT actor.disabled
          AND (source.owner_principal_id = actor.principal_id {delegate_clause})
        FOR SHARE OF source, space, actor
        FOR {lock} OF document
        """,
        (context.principal_id, context.org_id, space_id, document_ref),
    ).fetchone()
    if selected is None:
        raise SourceNotAdmitted("Only the current scoped source owner or active delegate may manage document responsibility.")
    source_id, document_id, contract, admission = selected
    return (context.org_id, space_id, source_id, document_id), contract, admission


def read_synthetic_responsibility(
    connection: Connection, context: SourceWrite, space_id: int, document_ref: UUID,
) -> dict:
    with connection.transaction():
        scope, _, admission = _scope(connection, context, space_id, document_ref, READ)
        issuer_ok = sql_issuer_matches_value("employee.authority_issuer", admission)
        current = connection.execute(
            f"""
            SELECT assignment.generation, identity.public_id, assignment.expires_at,
                   CASE WHEN assignment.responsible_id IS NULL THEN 'unassigned'
                        WHEN assignment.expires_at <= clock_timestamp() THEN 'expired'
                        WHEN employee.principal_type IS DISTINCT FROM 'employee' OR employee.disabled
                             OR NOT COALESCE({issuer_ok}, FALSE) THEN 'inactive'
                        ELSE 'assigned' END AS state
            FROM thalion.responsibility_assignment AS assignment
            LEFT JOIN thalion.principal AS employee
              ON (employee.org_id, employee.principal_id) = (assignment.org_id, assignment.responsible_id)
            LEFT JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.object_type, identity.object_id)
               = (employee.org_id, employee.identity_type, employee.principal_id)
            WHERE (assignment.org_id, assignment.space_id, assignment.source_id, assignment.document_id) = (%s, %s, %s, %s)
            ORDER BY assignment.generation DESC LIMIT 1
            """, scope,
        ).fetchone()
    generation, subject, expires_at, state = current or (0, None, None, "unassigned")
    return {"document_id": str(document_ref), "generation": generation,
            "responsible_id": str(subject) if state == "assigned" else None,
            "state": state, "expires_at": expires_at.isoformat() if expires_at else None}


def set_synthetic_responsibility(
    connection: Connection, context: SourceWrite, space_id: int, document_ref: UUID, expected: int,
    subject: UUID | None, basis: UUID, expires_at: datetime | None,
) -> dict:
    if type(expected) is not int or not 0 <= expected < 2**63 - 1 or (
        expires_at is not None and (subject is None or expires_at.utcoffset() is None)
    ):
        raise ValueError("Invalid responsibility generation or expiry.")
    with connection.transaction():
        scope, contract, admission = _scope(connection, context, space_id, document_ref, SET)
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, SET, context.idempotency_key,
            _digest(space_id, str(document_ref), str(subject) if subject else None, str(basis), expected,
                    expires_at.isoformat() if expires_at else None), contract, expected or None,
        )

        def apply(transaction):
            generation, = transaction.execute(
                """SELECT COALESCE(max(generation), 0) FROM thalion.responsibility_assignment
                WHERE (org_id, space_id, source_id, document_id) = (%s, %s, %s, %s)""", scope,
            ).fetchone()
            if generation != expected:
                raise ResponsibilityConflict("The document responsibility generation changed.")
            responsible_id = None
            if subject is not None:
                issuer_ok = sql_issuer_matches_value("employee.authority_issuer", admission)
                selected = transaction.execute(
                    f"""
                    SELECT employee.principal_id FROM thalion.object_identity AS identity
                    JOIN thalion.principal AS employee
                      ON (employee.org_id, employee.identity_type, employee.principal_id)
                       = (identity.org_id, identity.object_type, identity.object_id)
                    WHERE (identity.org_id, identity.public_id) = (%s, %s)
                      AND employee.principal_type = 'employee' AND {issuer_ok} AND NOT employee.disabled
                    FOR SHARE OF employee
                    """, (context.org_id, subject),
                ).fetchone()
                if selected is None:
                    raise SourceNotAdmitted("The assigned employee is outside the admitted organization or inactive.")
                responsible_id, = selected
            try:
                reference, = transaction.execute(
                    """
                    INSERT INTO thalion.responsibility_assignment (
                        org_id, space_id, source_id, document_id, generation,
                        responsible_id, approved_by, basis_ref, request_id, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING assignment_ref
                    """, (*scope, expected + 1, responsible_id, context.principal_id, basis, context.request_id, expires_at),
                ).fetchone()
            except errors.CheckViolation as error:
                if error.diag.constraint_name == "responsibility_expiry":
                    raise ValueError("Responsibility expiry must be in the future.") from None
                raise
            append_event(transaction, context.org_id, "sources.document.responsibility_changed", document_ref, space_id=space_id)
            return reference

        receipt = execute_command(connection, command, apply)
        if receipt.result_ref is None:
            raise RuntimeError("Responsibility registration did not produce a receipt.")
        return {"assignment_id": str(receipt.result_ref), "generation": expected + 1}
