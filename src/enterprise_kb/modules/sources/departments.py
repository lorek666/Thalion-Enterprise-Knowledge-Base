from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
import re
from uuid import UUID

from psycopg import Connection

from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed

from .registry import SourceNotAdmitted, SourceWrite, _digest, sql_issuer_matches_admission


READ = "read_document_department"
SET = "set_document_department"
OPERATIONS = frozenset({READ, SET})
DESTINATION = "internal_sources"
DEPARTMENT_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@dataclass(frozen=True)
class DocumentDepartment:
    document_ref: UUID
    department_code: str | None
    department_name: str | None
    recorded_at: datetime | None

    def to_dict(self) -> dict:
        return {
            "document_id": str(self.document_ref),
            "department_code": self.department_code,
            "department_name": self.department_name,
            "recorded_at": self.recorded_at.isoformat() if self.recorded_at else None,
        }


def validate_department_code(code: str) -> str:
    if not isinstance(code, str) or not DEPARTMENT_CODE_PATTERN.fullmatch(code):
        raise ValueError("Invalid department_code format.")
    return code


def validate_department_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("Invalid department_name.")
    cleaned = name.strip()
    if not 1 <= len(cleaned) <= 120 or any(not ch.isprintable() for ch in cleaned):
        raise ValueError("Invalid department_name.")
    return cleaned


def _scope_document(connection: Connection, context: SourceWrite, space_id: int, document_ref: UUID, operation: str):
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
        SELECT document.source_id, document.document_id, source.contract_revision
        FROM thalion.object_identity AS identity
        JOIN thalion.document AS document
          ON (document.org_id, document.space_id, document.identity_type, document.document_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id) = (document.org_id, document.space_id, document.source_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (document.org_id, document.space_id)
        JOIN thalion.principal AS actor
          ON (actor.org_id, actor.principal_id) = (document.org_id, %s)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND actor.principal_type = 'employee' AND NOT actor.disabled
          AND {sql_issuer_matches_admission("actor.authority_issuer", "contract.admission")}
          AND (source.owner_principal_id = actor.principal_id {delegate_clause})
        FOR SHARE OF source, space, actor
        FOR {lock} OF document
        """,
        (context.principal_id, context.org_id, space_id, document_ref),
    ).fetchone()
    if selected is None:
        raise SourceNotAdmitted("Only the current scoped source owner or active delegate may manage document department metadata.")
    return (context.org_id, space_id, selected[0], selected[1]), selected[2]


def read_document_department(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    document_ref: UUID,
) -> DocumentDepartment:
    with connection.transaction():
        scope, _ = _scope_document(connection, context, space_id, document_ref, READ)
        row = connection.execute(
            """
            SELECT department_code, department_name, recorded_at
            FROM thalion.document_department
            WHERE (org_id, space_id, source_id, document_id) = (%s, %s, %s, %s)
            """,
            scope,
        ).fetchone()
    if row is None:
        return DocumentDepartment(document_ref, None, None, None)
    return DocumentDepartment(document_ref, row[0], row[1], row[2])


def set_document_department(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    document_ref: UUID,
    department_code: str | None,
    department_name: str | None,
) -> DocumentDepartment:
    if department_code is None and department_name is None:
        action = "cleared"
        code = None
        name = None
    elif department_code is not None and department_name is not None:
        action = "assigned"
        code = validate_department_code(department_code)
        name = validate_department_name(department_name)
    else:
        raise ValueError("Both department_code and department_name must be supplied together, or both omitted to clear.")

    digest = _digest("document_department.v1", space_id, str(document_ref), action, code, name)
    with connection.transaction():
        scope, contract_rev = _scope_document(connection, context, space_id, document_ref, SET)

        def apply(tx):
            if action == "cleared":
                tx.execute(
                    """
                    DELETE FROM thalion.document_department
                    WHERE (org_id, space_id, source_id, document_id) = (%s, %s, %s, %s)
                    """,
                    scope,
                )
            else:
                tx.execute(
                    """
                    INSERT INTO thalion.document_department (
                        org_id, space_id, source_id, document_id,
                        department_code, department_name, assigned_by, request_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (org_id, space_id, source_id, document_id) DO UPDATE
                    SET department_code = EXCLUDED.department_code,
                        department_name = EXCLUDED.department_name,
                        assigned_by = EXCLUDED.assigned_by,
                        request_id = EXCLUDED.request_id,
                        recorded_at = clock_timestamp()
                    """,
                    (*scope, code, name, context.principal_id, context.request_id),
                )
            tx.execute(
                """
                INSERT INTO thalion.document_department_event (
                    org_id, space_id, source_id, document_id, action,
                    department_code, department_name, actor_id, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (*scope, action, code, name, context.principal_id, context.request_id),
            )
            append_event(tx, context.org_id, f"sources.document.department.{action}", document_ref, space_id=space_id)
            return document_ref

        execute_command(
            connection,
            CommandEnvelope(
                context.org_id, context.principal_id, None, context.request_id,
                SET, f"document_department:{space_id}:{document_ref}:{context.idempotency_key}",
                digest, contract_rev, None,
            ),
            apply,
        )
        row = connection.execute(
            """
            SELECT department_code, department_name, recorded_at
            FROM thalion.document_department
            WHERE (org_id, space_id, source_id, document_id) = (%s, %s, %s, %s)
            """,
            scope,
        ).fetchone()
    if row is None:
        return DocumentDepartment(document_ref, None, None, None)
    return DocumentDepartment(document_ref, row[0], row[1], row[2])


def list_departments_for_documents(
    connection: Connection,
    org_id: int,
    space_id: int,
    document_refs: Collection[UUID],
) -> dict[UUID, tuple[str, str]]:
    if not document_refs:
        return {}
    rows = connection.execute(
        """
        SELECT identity.public_id, dept.department_code, dept.department_name
        FROM thalion.object_identity AS identity
        JOIN thalion.document_department AS dept
          ON (dept.org_id, dept.space_id, dept.document_id)
           = (identity.org_id, identity.space_id, identity.object_id)
        WHERE (identity.org_id, identity.space_id, identity.object_type) = (%s, %s, 'document')
          AND identity.public_id = ANY(%s)
        """,
        (org_id, space_id, sorted(document_refs)),
    ).fetchall()
    return {row[0]: (row[1], row[2]) for row in rows}
