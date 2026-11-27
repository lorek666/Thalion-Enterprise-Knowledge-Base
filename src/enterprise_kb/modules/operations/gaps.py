from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, append_space_event, command_for, require_scope
from enterprise_kb.runtime.commands import execute_command


RECORD = "record_gap"
QUEUE = "read_gap_queue"
RECLASSIFY = "reclassify_gap"
REVIEW_CLASSES = frozenset({"permission_review", "conditions_missing"})
PAGE_SIZE = 20


class GapConflict(Exception):
    pass


def note_search_scope(
    connection: Connection, org_id: int, space_id: int, request_id: UUID, visibility_limited: bool,
    *, empty_fingerprint: bytes | None = None,
):
    connection.execute(
        """
        INSERT INTO thalion.search_scope_observation (org_id, space_id, request_id, visibility_limited, empty_fingerprint)
        VALUES (%s, %s, %s, %s, %s)
        """, (org_id, space_id, request_id, visibility_limited, empty_fingerprint),
    )


def capture_gap(connection: Connection, call: OperationsCall, origin: UUID, *, feedback_id: int | None = None) -> UUID:
    row = connection.execute(
        """
        SELECT CASE
            WHEN request.outcome IN ('dependency_unavailable', 'input_changed') THEN request.outcome
            WHEN scope.request_id IS NULL THEN 'scope_unverified'
            WHEN scope.visibility_limited THEN 'visibility_limited'
            WHEN request.outcome = 'no_evidence' THEN 'no_visible_match'
            ELSE 'reported_missing'
        END
        FROM thalion.request_record AS request
        LEFT JOIN thalion.search_scope_observation AS scope USING (org_id, request_id)
        WHERE (request.org_id, request.scope_space_id, request.principal_id, request.request_id) =
              (%(org)s, %(space)s, %(principal)s, %(origin)s)
          AND request.operation = 'search' AND request.destination = 'employee' AND request.delegated_principal_id IS NULL
          AND (%(feedback)s::bigint IS NULL OR EXISTS (
              SELECT 1 FROM thalion.feedback AS report
              WHERE (report.org_id, report.space_id, report.reporter_id, report.origin_request_id) =
                    (request.org_id, request.scope_space_id, request.principal_id, request.request_id)
                AND report.feedback_id = %(feedback)s AND report.category = 'missing_evidence'
                AND report.created_request_id = %(recorded)s
          ))
          AND (request.outcome IN ('no_evidence', 'dependency_unavailable', 'input_changed') OR (
              request.outcome = 'succeeded' AND %(feedback)s IS NOT NULL AND EXISTS (
                  SELECT 1 FROM thalion.delivery_record AS delivery
                  WHERE (delivery.org_id, delivery.request_id) = (request.org_id, request.request_id)
                    AND request.completed_at < delivery.valid_until
              )
          ))
        """, {"org": call.org_id, "space": call.space_id, "principal": call.principal_id, "origin": origin,
              "feedback": feedback_id, "recorded": call.request_id},
    ).fetchone()
    if row is None:
        raise OperationsNotAdmitted("A scoped search outcome or related missing-evidence feedback is required.")
    identity = (call.org_id, call.space_id, origin)
    inserted = connection.execute(
        """
        INSERT INTO thalion.gap_event (org_id, space_id, origin_request_id, recorded_request_id, observation, feedback_id)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (org_id, space_id, origin_request_id) DO NOTHING RETURNING gap_ref
        """, (*identity, call.request_id, row[0], feedback_id),
    ).fetchone()
    if inserted is not None:
        append_space_event(connection, call, "operations.gap.recorded")
        return inserted[0]
    ref, original_feedback = connection.execute(
        "SELECT gap_ref, feedback_id FROM thalion.gap_event WHERE (org_id, space_id, origin_request_id) = (%s, %s, %s)", identity,
    ).fetchone()
    if feedback_id is not None and original_feedback is None:
        linked = connection.execute(
            """
            INSERT INTO thalion.gap_feedback_link (org_id, space_id, gap_ref, feedback_id)
            VALUES (%s, %s, %s, %s) ON CONFLICT (gap_ref) DO NOTHING RETURNING gap_ref
            """, (call.org_id, call.space_id, ref, feedback_id),
        ).fetchone()
        if linked is not None:
            append_space_event(connection, call, "operations.gap.feedback_linked")
    return ref


def record_gap(connection: Connection, call: OperationsCall, origin: UUID) -> UUID:
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        require_scope(connection, call, RECORD)
        command = command_for(call, RECORD, (str(origin),))
        return execute_command(connection, command, lambda transaction: capture_gap(transaction, call, origin)).result_ref


def _require_owner(connection: Connection, call: OperationsCall, operation: str):
    if require_scope(connection, call, operation) != call.principal_id:
        raise OperationsNotAdmitted("The current space owner is required for gap review.")


def list_gap_work(connection: Connection, call: OperationsCall, after: UUID | None) -> dict:
    with connection.transaction():
        _require_owner(connection, call, QUEUE)
        rows = connection.execute(
            """
            SELECT gap_ref, classification, generation FROM thalion.open_gap_candidate
            WHERE (org_id, space_id) = (%s, %s) AND (%s::uuid IS NULL OR gap_ref > %s)
            ORDER BY gap_ref LIMIT %s
            """, (call.org_id, call.space_id, after, after, PAGE_SIZE + 1),
        ).fetchall()
        items = [{"gap_id": str(ref), "classification": category, "generation": generation}
                 for ref, category, generation in rows[:PAGE_SIZE]]
        return {"items": items, "next_cursor": items[-1]["gap_id"] if len(rows) > PAGE_SIZE else None}


def reclassify_gap(connection: Connection, call: OperationsCall, ref: UUID, expected: int, classification: str) -> dict:
    if type(expected) is not int or not 1 <= expected < 2**63 - 1 or classification not in REVIEW_CLASSES:
        raise ValueError("Invalid gap review classification or generation.")
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        _require_owner(connection, call, RECLASSIFY)
        command = command_for(call, RECLASSIFY, (str(ref), classification), expected)
        scope = (call.org_id, call.space_id, ref)

        def apply(transaction):
            if transaction.execute(
                "SELECT gap_ref FROM thalion.gap_event WHERE (org_id, space_id, gap_ref) = (%s, %s, %s) FOR UPDATE", scope,
            ).fetchone() is None:
                raise OperationsNotAdmitted("No gap is available in this space.")
            current = transaction.execute(
                "SELECT generation FROM thalion.open_gap_candidate WHERE (org_id, space_id, gap_ref) = (%s, %s, %s)",
                scope,
            ).fetchone()
            if current != (expected,):
                raise GapConflict("The candidate is not current for this review.")
            transaction.execute(
                """
                INSERT INTO thalion.gap_review (org_id, space_id, gap_ref, generation, classification, actor_id, request_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (*scope, expected + 1, classification, call.principal_id, call.request_id),
            )
            append_space_event(transaction, call, "operations.gap.reclassified")
            return ref

        execute_command(connection, command, apply)
        return {"gap_id": str(ref), "classification": classification, "generation": expected + 1}
