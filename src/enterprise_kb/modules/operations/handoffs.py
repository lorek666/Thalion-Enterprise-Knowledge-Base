from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, append_space_event, command_for, require_scope
from enterprise_kb.modules.operations.feedback import FeedbackConflict, _active_employee, resolve_assignee
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


AUTHORIZE = "authorize_feedback_handoff"
ACCEPT = "accept_feedback_handoff"
REVOKE = "revoke_feedback_handoff"
MAX_ITEMS = 20
MAX_WINDOW = timedelta(minutes=15)


@dataclass(frozen=True)
class HandoffSpec:
    incumbent: UUID
    successor: UUID
    basis: UUID
    expires_at: datetime
    items: tuple[tuple[UUID, int], ...]

    def __post_init__(self):
        if (
            self.incumbent == self.successor or self.expires_at.utcoffset() is None
            or not 1 <= len(self.items) <= MAX_ITEMS
            or len({ref for ref, _ in self.items}) != len(self.items)
            or any(type(generation) is not int or not 2 <= generation < 2**63 - 1 for _, generation in self.items)
        ):
            raise ValueError("Invalid feedback handoff scope, expiry or generation.")


def _lock_work(connection, scope, expected, incumbent):
    locked = connection.execute(
        """
        SELECT feedback_id FROM thalion.feedback
        WHERE (org_id, space_id) = (%s, %s) AND feedback_id = ANY(%s)
        ORDER BY feedback_id FOR UPDATE
        """, (*scope, list(expected)),
    ).fetchall()
    if len(locked) != len(expected):
        raise FeedbackConflict("The selected feedback is no longer eligible for handoff.")
    current = connection.execute(
        """
        SELECT feedback_id, generation FROM thalion.current_feedback
        WHERE (org_id, space_id, assignee_id) = (%s, %s, %s)
          AND state = 'pending' AND feedback_id = ANY(%s)
        """, (*scope, incumbent, list(expected)),
    ).fetchall()
    if dict(current) != expected:
        raise FeedbackConflict("The selected feedback is no longer eligible for handoff.")


def _has_handoff_delegation(connection: Connection, org_id: int, space_id: int, principal_id: int) -> bool:
    if not connection.execute(
        "SELECT to_regprocedure('thalion.has_active_space_delegation(bigint,bigint,bigint,text)') IS NOT NULL",
    ).fetchone()[0]:
        return False
    return bool(connection.execute(
        "SELECT thalion.has_active_space_delegation(%s, %s, %s, 'feedback_handoff_management')",
        (org_id, space_id, principal_id),
    ).fetchone()[0])


def authorize(connection: Connection, call: OperationsCall, spec: HandoffSpec) -> dict:
    scope = (call.org_id, call.space_id)
    deadline = spec.expires_at.astimezone(UTC)
    items = sorted(spec.items)
    command = command_for(call, AUTHORIZE, (
        str(spec.incumbent), str(spec.successor), str(spec.basis), deadline.isoformat(),
        [[str(ref), generation] for ref, generation in items],
    ))
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        owner = require_scope(connection, call, AUTHORIZE)
        is_delegate = owner != call.principal_id and _has_handoff_delegation(
            connection, call.org_id, call.space_id, call.principal_id,
        )
        if owner != call.principal_id and not is_delegate:
            raise OperationsNotAdmitted("Only the current space owner or active delegate can authorize a feedback handoff.")
        incumbent = resolve_assignee(connection, call.org_id, spec.incumbent)
        successor = resolve_assignee(connection, call.org_id, spec.successor)
        if successor in (call.principal_id, incumbent) or not _active_employee(connection, call.org_id, successor):
            raise OperationsNotAdmitted("The successor must be another current employee.")

        def apply(transaction):
            by_ref = dict(transaction.execute(
                """
                SELECT public_id, object_id FROM thalion.object_identity
                WHERE (org_id, space_id, object_type) = (%s, %s, 'feedback') AND public_id = ANY(%s)
                """, (*scope, [ref for ref, _ in items]),
            ).fetchall())
            if len(by_ref) != len(items):
                raise FeedbackConflict("The selected feedback is no longer eligible for handoff.")
            expected = {by_ref[ref]: generation for ref, generation in items}
            _lock_work(transaction, scope, expected, incumbent)
            now, = transaction.execute("SELECT clock_timestamp()").fetchone()
            if deadline <= now:
                raise FeedbackConflict("The feedback handoff has expired.")
            if deadline > now + MAX_WINDOW:
                raise ValueError("The feedback handoff expiry cannot exceed fifteen minutes.")
            grant, = transaction.execute(
                """
                INSERT INTO thalion.feedback_handoff (
                    org_id, space_id, authorizer_id, incumbent_id, successor_id, request_id, basis_ref,
                    issued_at, expires_at, item_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING handoff_ref
                """, (*scope, call.principal_id, incumbent, successor, call.request_id, spec.basis, now, deadline, len(expected)),
            ).fetchone()
            with transaction.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO thalion.feedback_handoff_item (org_id, space_id, handoff_ref, feedback_id, expected_generation)
                    VALUES (%s, %s, %s, %s, %s)
                    """, [(*scope, grant, feedback_id, generation) for feedback_id, generation in expected.items()],
                )
            append_space_event(transaction, call, "operations.feedback.handoff_authorized")
            return grant

        grant = execute_command(connection, command, apply).result_ref
        return {"handoff_id": str(grant), "state": "authorized", "item_count": len(items)}


def resolve(connection: Connection, call: OperationsCall, grant: UUID, *, accept: bool) -> dict:
    scope = (call.org_id, call.space_id)
    operation, outcome = (ACCEPT, "accepted") if accept else (REVOKE, "revoked")
    command = command_for(call, operation, (str(grant),))
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        owner = require_scope(connection, call, operation)
        approved = connection.execute(
            """
            SELECT authorizer_id, incumbent_id, successor_id, expires_at, item_count
            FROM thalion.feedback_handoff WHERE (org_id, space_id, handoff_ref) = (%s, %s, %s) FOR UPDATE
            """, (*scope, grant),
        ).fetchone()
        if approved is None:
            raise OperationsNotAdmitted("No feedback handoff is available to this employee.")
        authorizer, incumbent, successor, deadline, count = approved
        can_revoke = call.principal_id == owner or (
            call.principal_id == authorizer
            and _has_handoff_delegation(connection, call.org_id, call.space_id, call.principal_id)
        )
        authorizer_valid = (
            (owner == authorizer and _active_employee(connection, call.org_id, owner))
            or _has_handoff_delegation(connection, call.org_id, call.space_id, authorizer)
        )
        if (
            (accept and (call.principal_id != successor or not authorizer_valid))
            or (not accept and not can_revoke)
        ):
            raise OperationsNotAdmitted("No feedback handoff is available to this employee.")

        def apply(transaction):
            if transaction.execute(
                "SELECT 1 FROM thalion.feedback_handoff_resolution WHERE handoff_ref = %s", (grant,),
            ).fetchone() is not None:
                raise FeedbackConflict("The feedback handoff already has a final decision.")
            if accept:
                expected = dict(transaction.execute(
                    """
                    SELECT feedback_id, expected_generation FROM thalion.feedback_handoff_item
                    WHERE (org_id, space_id, handoff_ref) = (%s, %s, %s)
                    """, (*scope, grant),
                ).fetchall())
                if len(expected) != count:
                    raise FeedbackConflict("The feedback handoff no longer matches its sealed scope.")
                _lock_work(transaction, scope, expected, incumbent)
            now, = transaction.execute("SELECT clock_timestamp()").fetchone()
            if accept and now >= deadline:
                raise FeedbackConflict("The feedback handoff has expired.")
            transaction.execute(
                """
                INSERT INTO thalion.feedback_handoff_resolution (
                    org_id, space_id, handoff_ref, actor_id, request_id, outcome, recorded_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (*scope, grant, call.principal_id, call.request_id, outcome, now),
            )
            if accept:
                refs = transaction.execute(
                    """
                    INSERT INTO thalion.feedback_decision (
                        org_id, space_id, feedback_id, generation, action, actor_id, assignee_id, request_id, handoff_ref
                    )
                    SELECT org_id, space_id, feedback_id, expected_generation + 1, 'accept_handoff', %s, %s, %s, handoff_ref
                    FROM thalion.feedback_handoff_item WHERE handoff_ref = %s
                    RETURNING feedback_id
                    """, (successor, successor, call.request_id, grant),
                ).fetchall()
                for (ref,) in transaction.execute(
                    """
                    SELECT public_id FROM thalion.object_identity
                    WHERE (org_id, space_id, object_type) = (%s, %s, 'feedback') AND object_id = ANY(%s)
                    """, (*scope, [entry[0] for entry in refs]),
                ).fetchall():
                    append_event(transaction, call.org_id, "operations.feedback.transitioned", ref, space_id=call.space_id)
            append_space_event(transaction, call, f"operations.feedback.handoff_{outcome}")
            return grant

        execute_command(connection, command, apply)
        return {"handoff_id": str(grant), "state": outcome, "item_count": count}
