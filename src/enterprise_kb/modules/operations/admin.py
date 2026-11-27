from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import csv
from hashlib import sha256
import io
import json
import re
from typing import Callable
from uuid import UUID, uuid4

from psycopg import Connection

from enterprise_kb.runtime.audit import finish_open_request, finish_request, start_request, RequestStart


READ_DIRECTORY = "read_admin_directory"
READ_DASHBOARD = "read_knowledge_dashboard"
MANAGE_TASKS = "manage_admin_tasks"
MANAGE_DIRECTORY = "manage_admin_directory"
READ_SPACES = "read_admin_spaces"
MANAGE_SPACES = "manage_admin_spaces"
READ_NOTIFICATIONS = "read_admin_notifications"
MANAGE_WIKI = "manage_wiki_collaboration"
DESTINATION = "internal_management"
SOURCE_PICKER_READERS = "read_local_policy"
SOURCE_PICKER_SYNC = "read_source_sync_status"
SOURCE_PICKER_USAGES = frozenset({"readers", "sync"})
SOURCE_PICKER_OPERATIONS = {"readers": SOURCE_PICKER_READERS, "sync": SOURCE_PICKER_SYNC}
ROLE_KEYS = frozenset({
    "organization_admin", "space_admin", "reviewer", "content_owner", "knowledge_operator", "auditor",
})
TASK_STATUSES = frozenset({"open", "claimed", "snoozed", "done", "cancelled"})
TASK_TYPES = frozenset({
    "review_due", "source_sync_failure", "permission_change", "feedback", "knowledge_gap",
    "document_expiry", "wiki_review", "directory_conflict", "batch_import",
})
EVENT_TYPES = frozenset({
    "review.due", "review.overdue", "wiki.revision", "source.sync_failed", "source.sync_recovered",
    "permission.changed", "feedback.created", "knowledge_gap.created", "document.expiring",
    "document.expired", "batch.imported",
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


def _iso(value):
    return value.astimezone(UTC).isoformat() if value is not None else None


def _json_digest(value) -> bytes:
    return sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).digest()


def _require_operation(caller, operation: str):
    if operation not in caller.credential.operations:
        raise AdminNotAdmitted("The requested management operation is not available to this caller.")


def _has_role(connection: Connection, caller, roles: set[str], *, space_id: int | None = None) -> bool:
    scope = caller.space_id if space_id is None else space_id
    return connection.execute(
        """
        SELECT 1
        FROM thalion.space
        WHERE (space.org_id, space.space_id, space.owner_principal_id) = (%s, %s, %s)
          AND space.lifecycle = 'active'
        UNION ALL
        SELECT 1
        FROM thalion.admin_role_assignment AS assignment
        JOIN thalion.principal AS principal
          ON (principal.org_id, principal.principal_id) = (assignment.org_id, assignment.principal_id)
        WHERE assignment.org_id = %s AND assignment.principal_id = %s
          AND assignment.active AND assignment.role_key = ANY(%s)
          AND assignment.space_id IS NOT DISTINCT FROM %s
          AND NOT principal.disabled
        LIMIT 1
        """,
        (caller.org_id, scope, caller.principal_id, caller.org_id, caller.principal_id, list(roles), scope),
    ).fetchone() is not None


def _require_role(connection: Connection, caller, roles: set[str], *, space_id: int | None = None):
    _require_active_employee(connection, caller)
    if not _has_role(connection, caller, roles, space_id=space_id):
        raise AdminNotAdmitted("The caller has no role for this management scope.")


def _public_principal(connection: Connection, caller, value: str, *, allow_group: bool = True) -> int:
    try:
        reference = UUID(value)
    except (TypeError, ValueError):
        raise ValueError("A stable principal reference is required.") from None
    allowed = ("employee", "group") if allow_group else ("employee",)
    row = connection.execute(
        """
        SELECT principal.principal_id
        FROM thalion.object_identity AS identity
        JOIN thalion.principal AS principal
          ON (principal.org_id, principal.identity_type, principal.principal_id)
           = (identity.org_id, identity.object_type, identity.object_id)
        WHERE identity.org_id = %s AND identity.object_type = 'principal'
          AND identity.public_id = %s AND principal.principal_type = ANY(%s)
        """,
        (caller.org_id, reference, list(allowed)),
    ).fetchone()
    if row is None:
        raise AdminNotAdmitted("The principal is outside the caller's organization or scope.")
    return row[0]


def _public_space(connection: Connection, caller, value: str) -> int:
    try:
        reference = UUID(value)
    except (TypeError, ValueError):
        raise ValueError("A stable space reference is required.") from None
    row = connection.execute(
        """
        SELECT space.space_id FROM thalion.object_identity AS identity
        JOIN thalion.space AS space USING (org_id, space_id)
        WHERE identity.org_id = %s AND identity.object_type = 'space' AND identity.public_id = %s
        """, (caller.org_id, reference),
    ).fetchone()
    if row is None:
        raise AdminNotAdmitted("The space is outside the caller's organization.")
    return row[0]


def _audit_event(connection: Connection, caller, action: str, *, space_id: int | None = None, detail=None, object_ref=None):
    connection.execute(
        """
        INSERT INTO thalion.admin_audit_event (org_id, space_id, actor_id, action, object_ref, detail)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (caller.org_id, space_id, caller.principal_id, action, object_ref, json.dumps(detail or {}, ensure_ascii=False)),
    )


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
          AND source.owner_principal_id = %s
          AND source.lifecycle IN ('active', 'suspended')
        """,
        (caller.org_id, caller.space_id, cursor, caller.principal_id),
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
        SELECT identity.public_id, profile.display_name, profile.employee_number, profile.email,
               profile.title, profile.directory_state, department.name,
               coalesce(array_agg(DISTINCT group_profile.display_name)
                        FILTER (WHERE group_profile.display_name IS NOT NULL), '{}')
        FROM thalion.principal_directory_profile AS profile
        JOIN thalion.principal AS principal USING (org_id, principal_id)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.object_type, identity.object_id)
           = (profile.org_id, 'principal', profile.principal_id)
        LEFT JOIN thalion.directory_department AS department
          ON (department.org_id, department.department_ref) = (profile.org_id, profile.department_ref)
        LEFT JOIN thalion.directory_group_membership AS membership
          ON (membership.org_id, membership.member_id) = (profile.org_id, profile.principal_id)
        LEFT JOIN thalion.principal_directory_profile AS group_profile
          ON (group_profile.org_id, group_profile.principal_id) = (membership.org_id, membership.group_id)
        WHERE profile.org_id = %s AND principal.principal_type = 'employee'
          AND (lower(profile.display_name) LIKE %s OR lower(coalesce(profile.employee_number, '')) LIKE %s
               OR lower(coalesce(profile.email, '')) LIKE %s)
        GROUP BY identity.public_id, profile.display_name, profile.employee_number, profile.email,
                 profile.title, profile.directory_state, department.name, profile.principal_id
        ORDER BY profile.display_name, profile.principal_id
        LIMIT %s
        """,
        (caller.org_id, pattern, pattern, pattern, limit),
    ).fetchall()
    return {"people": [
        {"id": str(row[0]), "name": row[1], "employee_number": row[2], "email": row[3],
         "title": row[4], "status": row[5], "department": row[6], "groups": list(row[7] or []),
         "selectable": row[5] == "active"}
        for row in rows
    ]}


def list_reader_subject_options(
    connection: Connection,
    caller,
    *,
    source_ref: UUID,
    query: str,
    limit: int = 50,
    after: str | None = None,
):
    if READ_DIRECTORY not in caller.credential.operations or SOURCE_PICKER_READERS not in caller.credential.operations:
        raise AdminNotAdmitted("Reader subject lookup is not available to this caller.")
    _require_active_employee(connection, caller)
    source = connection.execute(
        """
        SELECT source.source_id
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        WHERE (identity.org_id, identity.space_id, identity.object_type, identity.public_id)
              = (%s, %s, 'source', %s)
          AND source.owner_principal_id = %s
          AND source.lifecycle IN ('active', 'suspended')
        """,
        (caller.org_id, caller.space_id, source_ref, caller.principal_id),
    ).fetchone()
    if source is None:
        raise AdminNotAdmitted("Reader subjects must be selected inside the managed source scope.")
    if not 1 <= limit <= 100 or len(query) > 120 or "\x00" in query:
        raise ValueError("Invalid reader subject filters.")
    after_ref = None
    if after is not None:
        try:
            after_ref = UUID(after)
        except ValueError:
            raise ValueError("The reader subject cursor must be an opaque UUID.") from None
    search = query.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{search}%"
    rows = connection.execute(
        """
        WITH subjects AS (
            SELECT identity.public_id, principal.principal_id, 'person'::text AS subject_kind,
                   profile.display_name AS name, profile.employee_number, profile.email,
                   profile.title, profile.directory_state AS status, department.name AS department
            FROM thalion.principal AS principal
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.object_type, identity.object_id)
               = (principal.org_id, principal.identity_type, principal.principal_id)
            JOIN thalion.principal_directory_profile AS profile
              ON (profile.org_id, profile.principal_id) = (principal.org_id, principal.principal_id)
            LEFT JOIN thalion.directory_department AS department
              ON (department.org_id, department.department_ref) = (profile.org_id, profile.department_ref)
            WHERE principal.org_id = %s AND principal.principal_type = 'employee'
            UNION ALL
            SELECT identity.public_id, principal.principal_id, 'group'::text,
                   principal.authority_subject_key, NULL, NULL, NULL,
                   CASE WHEN principal.disabled THEN 'disabled' ELSE 'active' END, NULL
            FROM thalion.principal AS principal
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.object_type, identity.object_id)
               = (principal.org_id, principal.identity_type, principal.principal_id)
            WHERE principal.org_id = %s AND principal.principal_type = 'group'
        )
        SELECT public_id, principal_id, subject_kind, name, employee_number, email, title, status, department
        FROM subjects
        WHERE (name ILIKE %s ESCAPE '\\' OR lower(coalesce(employee_number, '')) LIKE %s ESCAPE '\\'
               OR lower(coalesce(email, '')) LIKE %s ESCAPE '\\')
          AND (%s::uuid IS NULL OR (name, principal_id) > (
              SELECT name, principal_id FROM subjects WHERE public_id = %s
          ))
        ORDER BY name, principal_id
        LIMIT %s
        """,
        (caller.org_id, caller.org_id, pattern, pattern, pattern, after_ref, after_ref, limit + 1),
    ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    subjects = [{
        "id": str(row[0]), "kind": row[2], "name": row[3], "employee_number": row[4],
        "email": row[5], "title": row[6], "status": row[7], "department": row[8],
        "selectable": row[7] == "active",
    } for row in rows]
    return {"subjects": subjects, "next_cursor": str(rows[-1][0]) if has_more and rows else None}


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


def read_reader_subject_options(
    connect: Callable[[], Connection],
    caller,
    *,
    source_ref: UUID,
    query: str,
    limit: int,
    after: str | None,
):
    return _audit_read(connect, caller, READ_DIRECTORY, lambda connection: list_reader_subject_options(
        connection, caller, source_ref=source_ref, query=query, limit=limit, after=after,
    ))


def _audit_write(connect: Callable[[], Connection], caller, operation: str, action: Callable[[Connection, UUID], dict]):
    request_id = uuid4()
    started = datetime.now(UTC)
    try:
        with connect() as connection:
            start_request(connection, RequestStart(
                caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                operation, DESTINATION, started.astimezone(caller.business_timezone).date(),
                caller.configuration_revision, space_id=caller.space_id, ingress=caller.ingress,
            ))
            with connection.transaction():
                payload = action(connection, request_id)
                _audit_event(connection, caller, operation, space_id=caller.space_id, detail=payload)
                finish_open_request(connection, caller.org_id, request_id, "succeeded", 0)
            return AdminReadResult(request_id, 200, {"request_id": str(request_id), **payload})
    except AdminNotAdmitted:
        try:
            with connect() as connection:
                finish_request(connection, caller.org_id, request_id, "rejected", 0)
        except Exception:
            pass
        return AdminReadResult(request_id, 403, {"request_id": str(request_id), "error": {"code": "forbidden"}})
    except (AdminConflict, ValueError) as error:
        try:
            with connect() as connection:
                finish_request(connection, caller.org_id, request_id, "rejected", 0)
        except Exception:
            pass
        return AdminReadResult(request_id, 409 if isinstance(error, AdminConflict) else 400, {
            "request_id": str(request_id), "error": {"code": "conflict" if isinstance(error, AdminConflict) else "invalid_arguments", "message": str(error)},
        })


def _directory_rows(payload):
    if not isinstance(payload, list) or len(payload) > 5000:
        raise ValueError("Directory rows must be a list of at most 5000 entries.")
    required = {"external_key", "display_name"}
    allowed = required | {"employee_number", "email", "title", "department_external_key", "status", "group_external_keys"}
    normalized = []
    seen = set()
    for index, row in enumerate(payload, 1):
        if not isinstance(row, dict) or not required <= row.keys() or set(row) - allowed:
            raise ValueError(f"Directory row {index} has invalid fields.")
        external = str(row["external_key"]).strip()
        display = str(row["display_name"]).strip()
        if not external or len(external) > 255 or not display or len(display) > 255 or external in seen:
            raise ValueError(f"Directory row {index} has a missing or duplicate external key.")
        seen.add(external)
        status = row.get("status", "active")
        if status not in {"active", "disabled", "departed", "conflict"}:
            raise ValueError(f"Directory row {index} has an invalid status.")
        groups = row.get("group_external_keys", [])
        if not isinstance(groups, list) or len(groups) > 100 or any(not isinstance(group, str) or not group.strip() for group in groups):
            raise ValueError(f"Directory row {index} has invalid groups.")
        normalized.append({
            "external_key": external, "display_name": display,
            "employee_number": str(row["employee_number"]).strip() if row.get("employee_number") else None,
            "email": str(row["email"]).strip() if row.get("email") else None,
            "title": str(row["title"]).strip() if row.get("title") else None,
            "department_external_key": str(row["department_external_key"]).strip() if row.get("department_external_key") else None,
            "status": status, "group_external_keys": sorted(set(group.strip() for group in groups)),
        })
    return normalized


def parse_directory_csv(content: str) -> list[dict]:
    if not isinstance(content, str) or len(content.encode("utf-8")) > 5 * 1024 * 1024:
        raise ValueError("Directory CSV is missing or exceeds 5 MiB.")
    try:
        sample = content[:4096]
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(content), dialect=dialect)
    if not reader.fieldnames:
        raise ValueError("Directory CSV must include a header row.")
    rows = []
    for row in reader:
        groups = row.get("group_external_keys", "")
        rows.append({**row, "group_external_keys": [item.strip() for item in groups.split("|") if item.strip()]})
    return _directory_rows(rows)


def _directory_preview(connection: Connection, caller, rows, *, source: str, idempotency_key: str):
    _require_operation(caller, MANAGE_DIRECTORY)
    _require_role(connection, caller, {"organization_admin", "knowledge_operator"})
    if source not in {"csv", "oidc", "scim", "ldap"} or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", idempotency_key):
        raise ValueError("Invalid directory sync source or idempotency key.")
    rows = _directory_rows(rows)
    digest = _json_digest(rows)
    existing = connection.execute(
        "SELECT sync_ref, state, input_digest FROM thalion.directory_sync_run WHERE org_id = %s AND idempotency_key = %s",
        (caller.org_id, idempotency_key),
    ).fetchone()
    if existing is not None:
        if existing[2] != digest:
            raise AdminConflict("The idempotency key is already bound to different directory data.")
        return {"sync_id": str(existing[0]), "state": existing[1], "replayed": True}
    sync_ref = connection.execute(
        """
        INSERT INTO thalion.directory_sync_run
            (org_id, requested_by, source, input_digest, idempotency_key, total_rows)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING sync_ref
        """, (caller.org_id, caller.principal_id, source, digest, idempotency_key, len(rows)),
    ).fetchone()[0]
    preview = []
    for row_number, row in enumerate(rows, 1):
        existing_row = connection.execute(
            """
            SELECT principal_id, directory_state, display_name, employee_number, email, title
            FROM thalion.principal_directory_profile
            WHERE org_id = %s AND external_key = %s
            """, (caller.org_id, row["external_key"]),
        ).fetchone()
        operation = "create" if existing_row is None else "update"
        if existing_row is not None and existing_row[1] == row["status"] and tuple(row.get(key) for key in ("display_name", "employee_number", "email", "title")) == existing_row[2:]:
            operation = "skip"
        preview.append({"row_number": row_number, "external_key": row["external_key"], "operation": operation,
                        "principal_ref": None, "error": None})
        connection.execute(
            """
            INSERT INTO thalion.directory_sync_item (sync_ref, row_number, external_key, operation, principal_id, payload)
            VALUES (%s, %s, %s, %s, %s, %s)
            """, (sync_ref, row_number, row["external_key"], operation,
                   existing_row[0] if existing_row else None, json.dumps(row, ensure_ascii=False)),
        )
    return {"sync_id": str(sync_ref), "state": "preview", "total_rows": len(rows), "items": preview, "input_digest": digest.hex()}


def preview_directory_sync(connect: Callable[[], Connection], caller, *, rows, source: str, idempotency_key: str):
    return _audit_write(connect, caller, MANAGE_DIRECTORY, lambda connection, _: _directory_preview(
        connection, caller, rows, source=source, idempotency_key=idempotency_key,
    ))


def apply_directory_sync(connect: Callable[[], Connection], caller, *, sync_id: str):
    def action(connection, _):
        _require_operation(caller, MANAGE_DIRECTORY)
        _require_role(connection, caller, {"organization_admin", "knowledge_operator"})
        try:
            sync_ref = UUID(sync_id)
        except (TypeError, ValueError):
            raise ValueError("Invalid directory sync reference.") from None
        run = connection.execute(
            "SELECT source, state, input_digest FROM thalion.directory_sync_run WHERE org_id = %s AND sync_ref = %s FOR UPDATE",
            (caller.org_id, sync_ref),
        ).fetchone()
        if run is None or run[1] not in {"preview", "failed", "partial_failure"}:
            raise AdminConflict("The directory sync is not ready to apply or has already completed.")
        items = connection.execute(
            "SELECT row_number, payload::text, operation FROM thalion.directory_sync_item WHERE sync_ref = %s ORDER BY row_number FOR UPDATE",
            (sync_ref,),
        ).fetchall()
        applied = rejected = 0
        errors = []
        for row_number, raw, operation in items:
            row = json.loads(raw)
            try:
                department_ref = None
                department_key = row.get("department_external_key")
                if department_key:
                    department_ref = connection.execute(
                        """
                        INSERT INTO thalion.directory_department (org_id, external_key, name, path)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (org_id, external_key) DO UPDATE SET name = EXCLUDED.name, path = EXCLUDED.path, active = true
                        RETURNING department_ref
                        """, (caller.org_id, department_key, department_key, department_key),
                    ).fetchone()[0]
                existing = connection.execute(
                    "SELECT principal_id FROM thalion.principal_directory_profile WHERE org_id = %s AND external_key = %s FOR UPDATE",
                    (caller.org_id, row["external_key"]),
                ).fetchone()
                if existing is None:
                    principal_id = connection.execute(
                        """
                        INSERT INTO thalion.principal
                            (org_id, principal_type, authority_issuer, authority_subject_key, disabled)
                        VALUES (%s, 'employee', 'https://directory.invalid', %s, %s) RETURNING principal_id
                        """, (caller.org_id, row["external_key"], row["status"] != "active"),
                    ).fetchone()[0]
                    connection.execute(
                        "INSERT INTO thalion.object_identity (org_id, object_type, object_id) VALUES (%s, 'principal', %s)",
                        (caller.org_id, principal_id),
                    )
                else:
                    principal_id = existing[0]
                connection.execute(
                    """
                    INSERT INTO thalion.principal_directory_profile
                        (org_id, principal_id, department_ref, external_key, display_name, employee_number, email, title, directory_state, source, last_synced_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, clock_timestamp())
                    ON CONFLICT (org_id, principal_id) DO UPDATE SET department_ref = EXCLUDED.department_ref,
                        external_key = EXCLUDED.external_key, display_name = EXCLUDED.display_name,
                        employee_number = EXCLUDED.employee_number, email = EXCLUDED.email, title = EXCLUDED.title,
                        directory_state = EXCLUDED.directory_state, source = EXCLUDED.source, last_synced_at = EXCLUDED.last_synced_at,
                        updated_at = clock_timestamp()
                    """, (caller.org_id, principal_id, department_ref, row["external_key"], row["display_name"],
                           row["employee_number"], row["email"], row["title"], row["status"], run[0]),
                )
                connection.execute(
                    "UPDATE thalion.principal SET disabled = %s WHERE org_id = %s AND principal_id = %s",
                    (row["status"] != "active", caller.org_id, principal_id),
                )
                connection.execute(
                    "UPDATE thalion.directory_sync_item SET status = 'applied', principal_id = %s WHERE sync_ref = %s AND row_number = %s",
                    (principal_id, sync_ref, row_number),
                )
                applied += 1
            except Exception as error:
                rejected += 1
                errors.append({"row_number": row_number, "error": type(error).__name__})
                connection.execute(
                    "UPDATE thalion.directory_sync_item SET status = 'rejected', error_code = 'row_rejected', error_detail = %s WHERE sync_ref = %s AND row_number = %s",
                    (str(error)[:500], sync_ref, row_number),
                )
        state = "succeeded" if not rejected else "partial_failure"
        connection.execute(
            """
            UPDATE thalion.directory_sync_run SET state = %s, applied_rows = %s, rejected_rows = %s,
                error_report = %s, completed_at = clock_timestamp() WHERE sync_ref = %s
            """, (state, applied, rejected, json.dumps(errors, ensure_ascii=False), sync_ref),
        )
        return {"sync_id": str(sync_ref), "state": state, "applied_rows": applied, "rejected_rows": rejected, "errors": errors}
    return _audit_write(connect, caller, MANAGE_DIRECTORY, action)


def list_admin_options(connection: Connection, caller, *, kind: str, query: str, limit: int = 50, after: str | None = None):
    _require_operation(caller, READ_DIRECTORY if kind in {"people", "groups", "departments"} else READ_SPACES)
    _require_active_employee(connection, caller)
    if kind not in {"people", "groups", "departments", "spaces", "sources"}:
        raise ValueError("Invalid management option kind.")
    if not 1 <= limit <= 100 or len(query) > 120 or "\x00" in query:
        raise ValueError("Invalid management option filters.")
    search = query.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{search}%"
    if kind == "people":
        rows = connection.execute(
            """
            SELECT identity.public_id, profile.display_name, profile.employee_number, profile.email,
                   profile.title, profile.directory_state, department.name
            FROM thalion.principal_directory_profile AS profile
            JOIN thalion.principal AS principal USING (org_id, principal_id)
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.object_type, identity.object_id)
               = (profile.org_id, 'principal', profile.principal_id)
            LEFT JOIN thalion.directory_department AS department
              ON (department.org_id, department.department_ref) = (profile.org_id, profile.department_ref)
            WHERE profile.org_id = %s AND principal.principal_type = 'employee'
              AND (lower(profile.display_name) LIKE %s ESCAPE '\\'
                   OR lower(coalesce(profile.employee_number, '')) LIKE %s ESCAPE '\\'
                   OR lower(coalesce(profile.email, '')) LIKE %s ESCAPE '\\')
            ORDER BY profile.display_name, profile.principal_id LIMIT %s
            """, (caller.org_id, pattern, pattern, pattern, limit + 1),
        ).fetchall()
        items = [{"id": str(row[0]), "kind": "person", "name": row[1], "employee_number": row[2],
                  "email": row[3], "title": row[4], "status": row[5], "department": row[6],
                  "selectable": row[5] == "active"} for row in rows[:limit]]
    elif kind == "groups":
        rows = connection.execute(
            """
            SELECT identity.public_id, principal.authority_subject_key,
                   CASE WHEN principal.disabled THEN 'disabled' ELSE 'active' END
            FROM thalion.principal AS principal
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.object_type, identity.object_id)
               = (principal.org_id, principal.identity_type, principal.principal_id)
            WHERE principal.org_id = %s AND principal.principal_type = 'group'
              AND lower(principal.authority_subject_key) LIKE %s ESCAPE '\\'
            ORDER BY principal.authority_subject_key, principal.principal_id LIMIT %s
            """, (caller.org_id, pattern, limit + 1),
        ).fetchall()
        items = [{"id": str(row[0]), "kind": "group", "name": row[1], "status": row[2], "selectable": row[2] == "active"} for row in rows[:limit]]
    elif kind == "departments":
        rows = connection.execute(
            """
            SELECT department_ref, name, path, active
            FROM thalion.directory_department
            WHERE org_id = %s AND lower(name) LIKE %s ESCAPE '\\'
            ORDER BY path, department_ref LIMIT %s
            """, (caller.org_id, pattern, limit + 1),
        ).fetchall()
        items = [{"id": str(row[0]), "kind": "department", "name": row[1], "path": row[2],
                  "status": "active" if row[3] else "disabled", "selectable": row[3]} for row in rows[:limit]]
    elif kind == "spaces":
        can_see_all = _has_role(connection, caller, {"organization_admin", "knowledge_operator"}, space_id=caller.space_id)
        rows = connection.execute(
            """
            SELECT identity.public_id, space.name, space.lifecycle, owner_profile.display_name,
                   count(DISTINCT member.principal_id), count(DISTINCT source.source_id)
            FROM thalion.space AS space
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.object_type, identity.object_id)
               = (space.org_id, space.identity_type, space.space_id)
            JOIN thalion.principal_directory_profile AS owner_profile
              ON (owner_profile.org_id, owner_profile.principal_id) = (space.org_id, space.owner_principal_id)
            LEFT JOIN thalion.space_membership AS member
              ON (member.org_id, member.space_id) = (space.org_id, space.space_id) AND member.active
            LEFT JOIN thalion.source AS source
              ON (source.org_id, source.space_id) = (space.org_id, space.space_id) AND source.lifecycle IN ('active', 'suspended')
            WHERE space.org_id = %s AND lower(space.name) LIKE %s ESCAPE '\\'
              AND (%s OR space.space_id = %s)
            GROUP BY identity.public_id, space.name, space.lifecycle, owner_profile.display_name, space.space_id
            ORDER BY space.name, space.space_id LIMIT %s
            """, (caller.org_id, pattern, can_see_all, caller.space_id, limit + 1),
        ).fetchall()
        items = [{"id": str(row[0]), "kind": "space", "name": row[1], "status": row[2], "owner": row[3],
                  "member_count": row[4], "source_count": row[5], "selectable": row[2] == "active"} for row in rows[:limit]]
    else:
        rows = connection.execute(
            """
            SELECT identity.public_id, source.source_key, source.lifecycle,
                   owner_profile.display_name, count(DISTINCT version.version_id)
            FROM thalion.source AS source
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
               = (source.org_id, source.space_id, source.identity_type, source.source_id)
            JOIN thalion.principal_directory_profile AS owner_profile
              ON (owner_profile.org_id, owner_profile.principal_id) = (source.org_id, source.owner_principal_id)
            LEFT JOIN thalion.document_version AS version
              ON (version.org_id, version.space_id, version.source_id) = (source.org_id, source.space_id, source.source_id)
            WHERE source.org_id = %s AND source.space_id = %s
              AND lower(source.source_key) LIKE %s ESCAPE '\\' AND source.lifecycle IN ('active', 'suspended')
            GROUP BY identity.public_id, source.source_key, source.lifecycle, owner_profile.display_name, source.source_id
            ORDER BY source.source_key, source.source_id LIMIT %s
            """, (caller.org_id, caller.space_id, pattern, limit + 1),
        ).fetchall()
        items = [{"id": str(row[0]), "kind": "source", "name": row[1], "status": row[2],
                  "owner": row[3], "document_count": row[4], "selectable": row[2] == "active"} for row in rows[:limit]]
    return {kind: items, "next_cursor": None if len(rows) <= limit else str(items[-1]["id"])}


def read_admin_options(connect: Callable[[], Connection], caller, *, kind: str, query: str, limit: int, after: str | None):
    operation = READ_DIRECTORY if kind in {"people", "groups", "departments"} else READ_SPACES
    return _audit_read(connect, caller, operation, lambda connection: list_admin_options(
        connection, caller, kind=kind, query=query, limit=limit, after=after,
    ))


def list_admin_tasks(connection: Connection, caller, *, status: str | None = None, task_type: str | None = None, limit: int = 50):
    _require_operation(caller, MANAGE_TASKS)
    _require_active_employee(connection, caller)
    if status is not None and status not in TASK_STATUSES or task_type is not None and task_type not in TASK_TYPES:
        raise ValueError("Invalid task filters.")
    if not 1 <= limit <= 100:
        raise ValueError("Invalid task limit.")
    can_see_all = _has_role(connection, caller, {"organization_admin", "knowledge_operator"}, space_id=caller.space_id)
    rows = connection.execute(
        """
        SELECT task.task_ref, task.task_type, task.status, task.priority, task.title, task.description,
               owner_identity.public_id, owner_profile.display_name, task.due_at, task.sla_due_at,
               task.escalation_level, task.created_at, task.updated_at
        FROM thalion.admin_task AS task
        LEFT JOIN thalion.object_identity AS owner_identity
          ON (owner_identity.org_id, owner_identity.object_type, owner_identity.object_id)
           = (task.org_id, 'principal', task.owner_principal_id)
        LEFT JOIN thalion.principal_directory_profile AS owner_profile
          ON (owner_profile.org_id, owner_profile.principal_id) = (task.org_id, task.owner_principal_id)
        WHERE task.org_id = %s AND (%s OR task.space_id = %s)
          AND (%s::text IS NULL OR task.status = %s)
          AND (%s::text IS NULL OR task.task_type = %s)
        ORDER BY coalesce(task.sla_due_at, task.due_at, task.created_at), task.task_ref
        LIMIT %s
        """, (caller.org_id, can_see_all, caller.space_id, status, status, task_type, task_type, limit),
    ).fetchall()
    return {"tasks": [{"id": str(row[0]), "type": row[1], "status": row[2], "priority": row[3], "title": row[4],
                        "description": row[5], "owner_id": str(row[6]) if row[6] else None, "owner_name": row[7],
                        "due_at": _iso(row[8]), "sla_due_at": _iso(row[9]), "escalation_level": row[10],
                        "created_at": _iso(row[11]), "updated_at": _iso(row[12]),
                        "overdue": row[9] is not None and row[9] < datetime.now(UTC)} for row in rows]}


def read_admin_tasks(connect: Callable[[], Connection], caller, *, status: str | None, task_type: str | None, limit: int):
    return _audit_read(connect, caller, MANAGE_TASKS, lambda connection: list_admin_tasks(
        connection, caller, status=status, task_type=task_type, limit=limit,
    ))


def _parse_iso(value: str | None, *, field: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an ISO-8601 timestamp with timezone.") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone.")
    return parsed.astimezone(UTC)


def _task_ref(value: str) -> UUID:
    try:
        return UUID(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid task reference.") from None


def _insert_task_history(connection: Connection, caller, task_ref: UUID, action: str, detail=None):
    connection.execute(
        "INSERT INTO thalion.admin_task_history (org_id, task_ref, actor_id, action, detail) VALUES (%s, %s, %s, %s, %s)",
        (caller.org_id, task_ref, caller.principal_id, action, json.dumps(detail or {}, ensure_ascii=False)),
    )


def _queue_notification(connection: Connection, caller, *, space_id: int, recipient_id: int, event_type: str,
                        task_ref: UUID | None = None, title: str, body: str, dedupe_key: str):
    if event_type not in EVENT_TYPES:
        raise ValueError("Unsupported notification event.")
    preference = connection.execute(
        "SELECT enabled FROM thalion.notification_preference WHERE (org_id, principal_id, event_type, channel) = (%s, %s, %s, 'in_app')",
        (caller.org_id, recipient_id, event_type),
    ).fetchone()
    if preference is not None and not preference[0]:
        return None
    payload = {"title": title[:200], "body": body[:2000], "task_ref": str(task_ref) if task_ref else None}
    delivery = connection.execute(
        """
        INSERT INTO thalion.notification_delivery
            (org_id, space_id, task_ref, recipient_id, event_type, channel, dedupe_key, payload, message_digest)
        VALUES (%s, %s, %s, %s, %s, 'in_app', %s, %s, %s)
        ON CONFLICT (org_id, dedupe_key) DO NOTHING
        RETURNING delivery_ref
        """, (caller.org_id, space_id, task_ref, recipient_id, event_type, dedupe_key,
               json.dumps(payload, ensure_ascii=False), _json_digest(payload)),
    ).fetchone()
    return delivery[0] if delivery else None


def create_admin_task(connect: Callable[[], Connection], caller, *, values: dict, idempotency_key: str):
    def action(connection, _):
        _require_operation(caller, MANAGE_TASKS)
        _require_role(connection, caller, {"organization_admin", "space_admin", "knowledge_operator", "reviewer"})
        if not isinstance(values, dict) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", idempotency_key):
            raise ValueError("Invalid task payload or idempotency key.")
        task_type = values.get("task_type")
        if task_type not in TASK_TYPES:
            raise ValueError("Invalid task type.")
        title = values.get("title")
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 500:
            raise ValueError("Task title is required and must be at most 500 characters.")
        priority = values.get("priority", "normal")
        if priority not in {"low", "normal", "high", "urgent"}:
            raise ValueError("Invalid task priority.")
        existing = connection.execute(
            "SELECT task_ref, status FROM thalion.admin_task WHERE org_id = %s AND metadata ->> 'idempotency_key' = %s",
            (caller.org_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            return {"task_id": str(existing[0]), "status": existing[1], "replayed": True}
        owner_id = caller.principal_id
        if values.get("owner_ref"):
            owner_id = _public_principal(connection, caller, values["owner_ref"], allow_group=False)
        due_at = _parse_iso(values.get("due_at"), field="due_at") or datetime.now(UTC) + timedelta(hours=24)
        sla_row = connection.execute(
            """
            SELECT due_minutes FROM thalion.admin_sla_policy
            WHERE org_id = %s AND task_type = %s AND enabled AND (space_id = %s OR space_id IS NULL)
            ORDER BY space_id NULLS LAST LIMIT 1
            """, (caller.org_id, task_type, caller.space_id),
        ).fetchone()
        sla_due = datetime.now(UTC) + timedelta(minutes=sla_row[0]) if sla_row else due_at
        subject_ref = None
        if values.get("subject_ref"):
            try:
                subject_ref = UUID(values["subject_ref"])
            except (TypeError, ValueError):
                raise ValueError("subject_ref must be a stable object reference.") from None
            if connection.execute("SELECT 1 FROM thalion.object_identity WHERE org_id = %s AND public_id = %s", (caller.org_id, subject_ref)).fetchone() is None:
                raise AdminNotAdmitted("The task subject is outside the caller's organization.")
        task_ref = connection.execute(
            """
            INSERT INTO thalion.admin_task
                (org_id, space_id, task_type, priority, title, description, owner_principal_id,
                 subject_ref, due_at, sla_due_at, metadata, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING task_ref
            """, (caller.org_id, caller.space_id, task_type, priority, title.strip(), values.get("description"),
                   owner_id, subject_ref, due_at, sla_due, json.dumps({"idempotency_key": idempotency_key}, ensure_ascii=False), caller.principal_id),
        ).fetchone()[0]
        _insert_task_history(connection, caller, task_ref, "created", {"task_type": task_type})
        _queue_notification(connection, caller, space_id=caller.space_id, recipient_id=owner_id, event_type="review.due",
                            task_ref=task_ref, title=title.strip(), body=values.get("description", ""),
                            dedupe_key=f"task:{task_ref}:created:{owner_id}")
        return {"task_id": str(task_ref), "status": "open", "due_at": _iso(due_at), "sla_due_at": _iso(sla_due)}
    return _audit_write(connect, caller, MANAGE_TASKS, action)


def transition_admin_task(connect: Callable[[], Connection], caller, *, task_id: str, values: dict):
    def action(connection, _):
        _require_operation(caller, MANAGE_TASKS)
        _require_role(connection, caller, {"organization_admin", "space_admin", "knowledge_operator", "reviewer"})
        task_ref = _task_ref(task_id)
        task = connection.execute(
            "SELECT status, owner_principal_id, space_id FROM thalion.admin_task WHERE org_id = %s AND task_ref = %s FOR UPDATE",
            (caller.org_id, task_ref),
        ).fetchone()
        if task is None or task[2] != caller.space_id and not _has_role(connection, caller, {"organization_admin", "knowledge_operator"}, space_id=task[2]):
            raise AdminNotAdmitted("The task is outside the caller's permitted scope.")
        if not isinstance(values, dict) or values.get("status") not in TASK_STATUSES:
            raise ValueError("Invalid task status.")
        status = values["status"]
        owner_id = task[1]
        if values.get("owner_ref"):
            owner_id = _public_principal(connection, caller, values["owner_ref"], allow_group=False)
        completed_at = datetime.now(UTC) if status == "done" else None
        connection.execute(
            """
            UPDATE thalion.admin_task SET status = %s, owner_principal_id = %s,
                completed_at = %s, updated_at = clock_timestamp(), claimed_at = CASE WHEN %s = 'claimed' THEN clock_timestamp() ELSE claimed_at END
            WHERE org_id = %s AND task_ref = %s
            """, (status, owner_id, completed_at, status, caller.org_id, task_ref),
        )
        action_name = {"claimed": "claimed", "done": "completed", "cancelled": "cancelled", "snoozed": "snoozed", "open": "reopened"}.get(status, "assigned")
        _insert_task_history(connection, caller, task_ref, action_name, {"owner_id": owner_id})
        return {"task_id": str(task_ref), "status": status, "owner_id": owner_id}
    return _audit_write(connect, caller, MANAGE_TASKS, action)


def list_notifications(connection: Connection, caller, *, unread_only: bool = False, limit: int = 50):
    _require_operation(caller, READ_NOTIFICATIONS)
    _require_active_employee(connection, caller)
    if not 1 <= limit <= 100:
        raise ValueError("Invalid notification limit.")
    rows = connection.execute(
        """
        SELECT delivery_ref, event_type, channel, status, payload, read_at, created_at, sent_at, last_error
        FROM thalion.notification_delivery
        WHERE org_id = %s AND recipient_id = %s AND (%s = false OR read_at IS NULL)
        ORDER BY created_at DESC, delivery_ref DESC LIMIT %s
        """, (caller.org_id, caller.principal_id, unread_only, limit),
    ).fetchall()
    unread = connection.execute(
        "SELECT count(*) FROM thalion.notification_delivery WHERE org_id = %s AND recipient_id = %s AND read_at IS NULL",
        (caller.org_id, caller.principal_id),
    ).fetchone()[0]
    return {"unread_count": unread, "notifications": [{"id": str(row[0]), "event_type": row[1], "channel": row[2],
        "status": row[3], "payload": row[4], "read": row[5] is not None, "created_at": _iso(row[6]),
        "sent_at": _iso(row[7]), "last_error": row[8]} for row in rows]}


def read_notifications(connect: Callable[[], Connection], caller, *, unread_only: bool, limit: int):
    return _audit_read(connect, caller, READ_NOTIFICATIONS, lambda connection: list_notifications(
        connection, caller, unread_only=unread_only, limit=limit,
    ))


def mark_notifications_read(connect: Callable[[], Connection], caller, *, notification_ids: list[str]):
    def action(connection, _):
        _require_operation(caller, READ_NOTIFICATIONS)
        _require_active_employee(connection, caller)
        if not isinstance(notification_ids, list) or len(notification_ids) > 100:
            raise ValueError("At most 100 notifications can be marked at once.")
        refs = []
        for value in notification_ids:
            try:
                refs.append(UUID(value))
            except (TypeError, ValueError):
                raise ValueError("Invalid notification reference.") from None
        changed = connection.execute(
            "UPDATE thalion.notification_delivery SET read_at = clock_timestamp() WHERE org_id = %s AND recipient_id = %s AND delivery_ref = ANY(%s) RETURNING delivery_ref",
            (caller.org_id, caller.principal_id, refs),
        ).fetchall()
        return {"marked": len(changed)}
    return _audit_write(connect, caller, READ_NOTIFICATIONS, action)


def list_spaces(connection: Connection, caller, *, query: str = "", limit: int = 50):
    _require_operation(caller, READ_SPACES)
    _require_active_employee(connection, caller)
    if not 1 <= limit <= 100 or len(query) > 120:
        raise ValueError("Invalid space filters.")
    pattern = f"%{query.strip().lower().replace('%', '\\%').replace('_', '\\_')}%"
    can_see_all = _has_role(connection, caller, {"organization_admin", "knowledge_operator"}, space_id=caller.space_id)
    rows = connection.execute(
        """
        SELECT identity.public_id, space.space_id, space.name, space.classification, space.lifecycle,
               owner_identity.public_id, owner_profile.display_name, count(DISTINCT member.principal_id),
               count(DISTINCT source.source_id), settings.wiki_enabled
        FROM thalion.space AS space
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.object_type, identity.object_id)
           = (space.org_id, space.identity_type, space.space_id)
        JOIN thalion.object_identity AS owner_identity
          ON (owner_identity.org_id, owner_identity.object_type, owner_identity.object_id)
           = (space.org_id, 'principal', space.owner_principal_id)
        LEFT JOIN thalion.principal_directory_profile AS owner_profile
          ON (owner_profile.org_id, owner_profile.principal_id) = (space.org_id, space.owner_principal_id)
        LEFT JOIN thalion.space_membership AS member
          ON (member.org_id, member.space_id) = (space.org_id, space.space_id) AND member.active
        LEFT JOIN thalion.source AS source
          ON (source.org_id, source.space_id) = (space.org_id, space.space_id) AND source.lifecycle IN ('active', 'suspended')
        LEFT JOIN thalion.space_settings AS settings
          ON (settings.org_id, settings.space_id) = (space.org_id, space.space_id)
        WHERE space.org_id = %s AND lower(space.name) LIKE %s ESCAPE '\\'
          AND (%s OR space.space_id = %s)
        GROUP BY identity.public_id, space.space_id, space.name, space.classification, space.lifecycle,
                 owner_identity.public_id, owner_profile.display_name, settings.wiki_enabled
        ORDER BY space.name, space.space_id LIMIT %s
        """, (caller.org_id, pattern, can_see_all, caller.space_id, limit),
    ).fetchall()
    return {"spaces": [{"id": str(row[0]), "name": row[2], "classification": row[3], "status": row[4],
        "owner_id": str(row[5]), "owner_name": row[6], "member_count": row[7], "source_count": row[8],
        "wiki_enabled": row[9] if row[9] is not None else True} for row in rows]}


def read_spaces(connect: Callable[[], Connection], caller, *, query: str, limit: int):
    return _audit_read(connect, caller, READ_SPACES, lambda connection: list_spaces(connection, caller, query=query, limit=limit))


def create_space(connect: Callable[[], Connection], caller, *, values: dict, idempotency_key: str):
    def action(connection, _):
        _require_operation(caller, MANAGE_SPACES)
        _require_role(connection, caller, {"organization_admin"}, space_id=caller.space_id)
        if not isinstance(values, dict) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", idempotency_key):
            raise ValueError("Invalid space payload or idempotency key.")
        name = values.get("name", "").strip() if isinstance(values.get("name"), str) else ""
        classification = values.get("classification", "internal")
        if not 1 <= len(name) <= 255 or not 1 <= len(classification) <= 64:
            raise ValueError("Space name and classification are required.")
        owner_id = caller.principal_id
        if values.get("owner_ref"):
            owner_id = _public_principal(connection, caller, values["owner_ref"], allow_group=False)
        if connection.execute("SELECT disabled FROM thalion.principal WHERE org_id = %s AND principal_id = %s", (caller.org_id, owner_id)).fetchone() != (False,):
            raise AdminNotAdmitted("An active employee must own the space.")
        existing = connection.execute("SELECT public_id FROM thalion.object_identity WHERE org_id = %s AND object_type = 'space' AND object_id = (SELECT space_id FROM thalion.space WHERE org_id = %s AND lower(name) = lower(%s))", (caller.org_id, caller.org_id, name)).fetchone()
        if existing is not None:
            return {"space_id": str(existing[0]), "replayed": True}
        space_id = connection.execute(
            "INSERT INTO thalion.space (org_id, name, classification, owner_principal_id) VALUES (%s, %s, %s, %s) RETURNING space_id",
            (caller.org_id, name, classification, owner_id),
        ).fetchone()[0]
        space_ref = connection.execute(
            "INSERT INTO thalion.object_identity (org_id, object_type, object_id, space_id) VALUES (%s, 'space', %s, %s) RETURNING public_id",
            (caller.org_id, space_id, space_id),
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO thalion.space_settings (org_id, space_id, wiki_enabled, default_reader_scope, updated_by) VALUES (%s, %s, %s, %s, %s)",
            (caller.org_id, space_id, values.get("wiki_enabled", True), values.get("default_reader_scope", "explicit"), caller.principal_id),
        )
        connection.execute(
            "INSERT INTO thalion.space_membership (org_id, space_id, principal_id, membership_kind, active, assigned_by) VALUES (%s, %s, %s, 'direct', true, %s)",
            (caller.org_id, space_id, owner_id, caller.principal_id),
        )
        connection.execute(
            """
            INSERT INTO thalion.admin_role_assignment (org_id, principal_id, space_id, role_key, assigned_by)
            VALUES (%s, %s, %s, 'space_admin', %s)
            ON CONFLICT (org_id, principal_id, space_id, role_key) DO UPDATE SET active = true
            """, (caller.org_id, owner_id, space_id, caller.principal_id),
        )
        return {"space_id": str(space_ref), "name": name, "owner_id": owner_id, "status": "active"}
    return _audit_write(connect, caller, MANAGE_SPACES, action)


def assign_role(connect: Callable[[], Connection], caller, *, values: dict):
    def action(connection, _):
        _require_operation(caller, MANAGE_SPACES)
        _require_role(connection, caller, {"organization_admin"}, space_id=caller.space_id)
        if not isinstance(values, dict) or values.get("role_key") not in ROLE_KEYS or not values.get("principal_ref"):
            raise ValueError("A principal and valid role are required.")
        principal_id = _public_principal(connection, caller, values["principal_ref"], allow_group=False)
        space_id = None if not values.get("space_ref") else _public_space(connection, caller, values["space_ref"])
        if space_id is not None and not _has_role(connection, caller, {"organization_admin", "space_admin"}, space_id=space_id):
            raise AdminNotAdmitted("The caller cannot manage this space role.")
        assignment_ref = connection.execute(
            """
            INSERT INTO thalion.admin_role_assignment (org_id, principal_id, space_id, role_key, assigned_by)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (org_id, principal_id, space_id, role_key) DO UPDATE SET active = true, assigned_by = EXCLUDED.assigned_by
            RETURNING assignment_ref
            """, (caller.org_id, principal_id, space_id, values["role_key"], caller.principal_id),
        ).fetchone()[0]
        return {"assignment_id": str(assignment_ref), "principal_id": principal_id, "space_id": space_id, "role_key": values["role_key"], "active": True}
    return _audit_write(connect, caller, MANAGE_SPACES, action)


def set_principal_status(connect: Callable[[], Connection], caller, *, principal_ref: str, enabled: bool):
    def action(connection, _):
        _require_operation(caller, MANAGE_DIRECTORY)
        _require_role(connection, caller, {"organization_admin", "knowledge_operator"})
        principal_id = _public_principal(connection, caller, principal_ref, allow_group=False)
        if principal_id == caller.principal_id and not enabled:
            raise AdminConflict("An administrator cannot disable the current account.")
        updated = connection.execute(
            "UPDATE thalion.principal SET disabled = %s WHERE org_id = %s AND principal_id = %s AND principal_type = 'employee' RETURNING principal_id",
            (not enabled, caller.org_id, principal_id),
        ).fetchone()
        if updated is None:
            raise AdminNotAdmitted("The user is not in the permitted directory scope.")
        connection.execute(
            "UPDATE thalion.principal_directory_profile SET directory_state = %s, updated_at = clock_timestamp() WHERE org_id = %s AND principal_id = %s",
            ("active" if enabled else "disabled", caller.org_id, principal_id),
        )
        return {"principal_ref": principal_ref, "enabled": enabled}
    return _audit_write(connect, caller, MANAGE_DIRECTORY, action)
