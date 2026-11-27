from psycopg import Connection

from enterprise_kb.runtime.job_backlog import read_job_backlog

from .context import OperationsCall, OperationsNotAdmitted, require_current_scope, require_scope


READ = "read_runtime_backlog"
DESTINATION = "internal_management"
VISIBLE_STAGES = ("parse", "synthetic_model_excerpts")


def _require_owner(owner_id: int, call: OperationsCall):
    if owner_id != call.principal_id:
        raise OperationsNotAdmitted("Runtime backlog requires the current space owner.")


def observe(connection: Connection, call: OperationsCall) -> dict:
    _require_owner(require_scope(connection, call, READ, destination=DESTINATION), call)
    return read_job_backlog(connection, call.org_id, call.space_id, visible_stages=VISIBLE_STAGES, include_estimate=True)


def pin_release_scope(connection: Connection, call: OperationsCall):
    _require_owner(require_current_scope(connection, call, READ, destination=DESTINATION), call)
