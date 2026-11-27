from dataclasses import dataclass, field
from hashlib import sha256
import json
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.sources.registry import sql_admitted_issuer, sql_issuers_same_mode
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed


DESTINATION = "internal_feedback"


class OperationsNotAdmitted(Exception):
    pass


@dataclass(frozen=True)
class OperationsCall:
    org_id: int
    space_id: int
    principal_id: int
    request_id: UUID
    key: str = field(repr=False)
    configuration_revision: int


def require_scope(connection: Connection, call: OperationsCall, operation: str, *, destination: str = DESTINATION) -> int:
    _require_read_committed(connection)
    require_open_request(connection, call.org_id, call.request_id, call.principal_id, None, operation=operation)
    return require_current_scope(connection, call, operation, destination=destination)


def require_current_scope(connection: Connection, call: OperationsCall, operation: str, *, destination: str) -> int:
    scope = connection.execute(
        f"""
        SELECT space.owner_principal_id FROM thalion.request_record AS request
        JOIN thalion.organization AS organization USING (org_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (request.org_id, request.scope_space_id)
        JOIN thalion.principal AS owner ON (owner.org_id, owner.principal_id) = (space.org_id, space.owner_principal_id)
        JOIN thalion.principal AS employee ON (employee.org_id, employee.principal_id) = (request.org_id, request.principal_id)
        WHERE (request.org_id, request.scope_space_id, request.request_id) = (%s, %s, %s)
          AND request.principal_id = %s AND request.delegated_principal_id IS NULL
          AND request.operation = %s AND request.destination = %s AND request.configuration_revision = %s
          AND request.configuration_revision = organization.config_revision
          AND space.lifecycle = 'active' AND employee.principal_type = 'employee'
          AND {sql_admitted_issuer('employee.authority_issuer')}
          AND {sql_issuers_same_mode('employee.authority_issuer', 'owner.authority_issuer')}
          AND NOT employee.disabled
        FOR SHARE OF organization, space, employee
        """, (call.org_id, call.space_id, call.request_id, call.principal_id, operation, destination,
              call.configuration_revision),
    ).fetchone()
    if scope is None:
        raise OperationsNotAdmitted("An active employee and space are required for this operation.")
    return scope[0]


def command_for(call: OperationsCall, operation: str, values: tuple, expected: int | None = None) -> CommandEnvelope:
    digest = sha256(json.dumps((call.space_id, *values), separators=(",", ":")).encode()).digest()
    return CommandEnvelope(
        call.org_id, call.principal_id, None, call.request_id, operation, call.key,
        digest, call.configuration_revision, expected,
    )


def append_space_event(connection: Connection, call: OperationsCall, event_type: str):
    ref, = connection.execute(
        """
        SELECT public_id FROM thalion.object_identity
        WHERE (org_id, space_id, object_type, object_id) = (%s, %s, 'space', %s)
        """, (call.org_id, call.space_id, call.space_id),
    ).fetchone()
    append_event(connection, call.org_id, event_type, ref, space_id=call.space_id)
