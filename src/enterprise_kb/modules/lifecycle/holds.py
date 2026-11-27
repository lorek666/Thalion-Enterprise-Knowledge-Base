from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.lifecycle.disposition import DESTINATION
from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, command_for, require_scope
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


DECIDE = "decide_hold"
OUTCOMES = {"establish": ("held", "established"), "release": ("released", "released")}


class HoldConflict(Exception):
    pass


def decide_hold(
    connection: Connection, call: OperationsCall, ref: UUID, action: str, expected: int, basis: UUID,
) -> dict:
    if action not in OUTCOMES or type(expected) is not int or not 0 <= expected < 2**63 - 1:
        raise ValueError("Invalid hold action or expected generation.")
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        require_scope(connection, call, DECIDE, destination=DESTINATION)
        row = connection.execute(
            """
            SELECT object_id FROM thalion.object_identity
            WHERE (org_id, space_id, public_id, object_type) = (%s, %s, %s, 'document_version')
            """, (call.org_id, call.space_id, ref),
        ).fetchone()
        if row is None or not connection.execute(
            "SELECT thalion.lock_local_hold_target(%s, %s, %s, %s)",
            (call.org_id, call.space_id, row[0], call.principal_id),
        ).fetchone()[0]:
            raise OperationsNotAdmitted("A current independently authorized synthetic custodian is required.")
        scope = (call.org_id, call.space_id, row[0])
        command = command_for(call, DECIDE, (str(ref), action, expected, str(basis)))
        state, event = OUTCOMES[action]

        def apply(transaction):
            latest = transaction.execute(
                "SELECT generation, action FROM thalion.current_version_hold WHERE (org_id, space_id, version_id) = (%s, %s, %s)",
                scope,
            ).fetchone()
            generation, prior = latest or (0, "release")
            if generation != expected or prior == action:
                raise HoldConflict("The hold changed or is not in the state required by this decision.")
            decision, = transaction.execute(
                """
                INSERT INTO thalion.version_hold_decision (
                    org_id, space_id, version_id, generation, action, decided_by, request_id, basis_ref
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING decision_ref
                """, (*scope, expected + 1, action, call.principal_id, call.request_id, basis),
            ).fetchone()
            append_event(transaction, call.org_id, f"lifecycle.version_hold.{event}", ref, space_id=call.space_id)
            return decision

        decision = execute_command(connection, command, apply).result_ref
        return {"decision_id": str(decision), "generation": expected + 1, "state": state}
