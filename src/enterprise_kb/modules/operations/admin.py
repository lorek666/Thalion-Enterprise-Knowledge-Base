from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable
from uuid import UUID, uuid4

from psycopg import Connection

from enterprise_kb.runtime.audit import finish_open_request, finish_request, start_request, RequestStart


READ_DIRECTORY = "read_admin_directory"
READ_DASHBOARD = "read_knowledge_dashboard"
MANAGE_TASKS = "manage_admin_tasks"
MANAGE_DIRECTORY = "manage_admin_directory"
DESTINATION = "internal_management"
SOURCE_PICKER_READERS = "read_local_policy"
SOURCE_PICKER_SYNC = "read_source_sync_status"
SOURCE_PICKER_USAGES = frozenset({"readers", "sync"})
SOURCE_PICKER_OPERATIONS = {"readers": SOURCE_PICKER_READERS, "sync": SOURCE_PICKER_SYNC}
ROLE_KEYS = frozenset({
    "organization_admin", "space_admin", "reviewer", "content_owner", "knowledge_operator", "auditor",
})


class AdminNotAdmitted(Exception):
    pass


class AdminConflict(Exception):
    pass


@dataclass(frozen=True)
class AdminReadResult:
    request_id: UUID
    status: int
    payload: dict


def _require_active_employee(connection: Connection, caller):
    row = connection.execute(
        """
        SELECT principal.principal_id
        FROM thalion.principal
        WHERE (principal.org_id, principal.principal_id) = (%s, %s)
          AND principal.principal_type = 'employee' AND NOT principal.disabled
        """,
        (caller.org_id, caller.principal_id),
    ).fetchone()
    if row is None:
        raise AdminNotAdmitted("An active employee is required.")


def _require_active_space_owner(connection: Connection, caller):
    _require_active_employee(connection, caller)
    row = connection.execute(
        """
        SELECT space.space_id
        FROM thalion.space
        WHERE (space.org_id, space.space_id, space.owner_principal_id) = (%s, %s, %s)
          AND space.lifecycle = 'active'
        """,
        (caller.org_id, caller.space_id, caller.principal_id),
    ).fetchone()
    if row is None:
        raise AdminNotAdmitted("The current active space owner is required.")


def _require_source_picker(connection: Connection, caller, usage: str):
    if usage not in SOURCE_PICKER_USAGES or SOURCE_PICKER_OPERATIONS[usage] not in caller.credential.operations:
        raise AdminNotAdmitted("The requested source picker is not available to this caller.")
    if usage == "sync":
        _require_active_space_owner(connection, caller)
    else:
        _require_active_employee(connection, caller)


def _source_cursor_id(connection: Connection, caller, after: str | None) -> int | None:
    if after is None:
        return None
    try:
        cursor = UUID(after)
    except ValueError:
        raise ValueError("The source picker cursor must be an opaque UUID.") from None
    row = connection.execute(
        """
        SELECT source.source_id
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        WHERE (identity.org_id, identity.space_id, identity.object_type, identity.public_id)
            = (%s, %s, 'source', %s)
        """,
        (caller.org_id, caller.space_id, cursor),
    ).fetchone()
    if row is None:
        raise ValueError("The source picker cursor is not in the current scope.")
    return row[0]


def list_source_options(connection: Connection, caller, *, usage: str, query: str, limit: int, after: str | None):
    _require_source_picker(connection, caller, usage)
    if not 1 <= limit <= 100 or len(query) > 120 or "\x00" in query:
        raise ValueError("Invalid source picker filters.")
    after_id = _source_cursor_id(connection, caller, after)
    search = query.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{search}%"
    rows = connection.execute(
        """
        SELECT identity.public_id, source.source_id, source.source_key, source.lifecycle
        FROM thalion.source AS source
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (source.org_id, source.space_id, source.identity_type, source.source_id)
        WHERE (source.org_id, source.space_id, source.owner_principal_id) = (%s, %s, %s)
          AND source.lifecycle IN ('active', 'suspended')
          AND (%s = '' OR lower(source.source_key) LIKE %s ESCAPE '\\')
          AND (%s::bigint IS NULL OR source.source_id > %s)
        ORDER BY source.source_id
        LIMIT %s
        """,
        (caller.org_id, caller.space_id, caller.principal_id, search, pattern, after_id, after_id, limit + 1),
    ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    sources = [{"id": str(row[0]), "name": row[2], "status": row[3]} for row in rows]
    return {"sources": sources, "next_cursor": str(rows[-1][0]) if has_more and rows else None}


def list_directory_options(connection: Connection, caller, *, query: str, limit: int = 50):
    if READ_DIRECTORY not in caller.credential.operations:
        raise AdminNotAdmitted("Directory lookup is not available to this caller.")
    _require_active_employee(connection, caller)
    if not 1 <= limit <= 100 or len(query) > 120 or "\x00" in query:
        raise ValueError("Invalid directory filters.")
    pattern = f"%{query.strip().lower()}%"
    rows = connection.execute(
        """
        SELECT profile.principal_id, profile.display_name, profile.employee_number, profile.email,
               profile.title, profile.directory_state, department.name
        FROM thalion.principal_directory_profile AS profile
        JOIN thalion.principal AS principal USING (org_id, principal_id)
        LEFT JOIN thalion.directory_department AS department
          ON (department.org_id, department.department_ref) = (profile.org_id, profile.department_ref)
        WHERE profile.org_id = %s AND principal.principal_type = 'employee'
          AND (lower(profile.display_name) LIKE %s OR lower(coalesce(profile.employee_number, '')) LIKE %s
               OR lower(coalesce(profile.email, '')) LIKE %s)
        ORDER BY profile.display_name, profile.principal_id
        LIMIT %s
        """,
        (caller.org_id, pattern, pattern, pattern, limit),
    ).fetchall()
    return {"people": [
        {"id": row[0], "name": row[1], "employee_number": row[2], "email": row[3],
         "title": row[4], "status": row[5], "department": row[6]}
        for row in rows
    ]}


def _audit_read(connect: Callable[[], Connection], caller, operation: str, action: Callable[[Connection], dict]):
    request_id = uuid4()
    now = datetime.now(UTC)
    try:
        with connect() as connection:
            start_request(connection, RequestStart(
                caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                operation, DESTINATION, now.astimezone(caller.business_timezone).date(),
                caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
            ))
            with connection.transaction():
                payload = action(connection)
                payload = {"request_id": str(request_id), **payload}
                finish_open_request(connection, caller.org_id, request_id, "succeeded", 0)
            return AdminReadResult(request_id, 200, payload)
    except AdminNotAdmitted:
        try:
            with connect() as connection:
                finish_request(connection, caller.org_id, request_id, "rejected", 0)
        except Exception:
            pass
        return AdminReadResult(request_id, 403, {"request_id": str(request_id), "error": {"code": "forbidden"}})
    except ValueError as error:
        try:
            with connect() as connection:
                finish_request(connection, caller.org_id, request_id, "rejected", 0)
        except Exception:
            pass
        return AdminReadResult(request_id, 400, {"request_id": str(request_id), "error": {"code": "invalid_arguments", "message": str(error)}})


def read_source_options(connect: Callable[[], Connection], caller, *, usage: str, query: str, limit: int, after: str | None):
    return _audit_read(connect, caller, SOURCE_PICKER_OPERATIONS.get(usage, "invalid_arguments"), lambda connection: list_source_options(
        connection, caller, usage=usage, query=query, limit=limit, after=after,
    ))


def read_directory_options(connect: Callable[[], Connection], caller, *, query: str, limit: int):
    return _audit_read(connect, caller, READ_DIRECTORY, lambda connection: list_directory_options(
        connection, caller, query=query, limit=limit,
    ))
