from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.operations import gaps
from enterprise_kb.modules.operations.context import DESTINATION, OperationsCall as FeedbackCall
from enterprise_kb.modules.operations.context import OperationsNotAdmitted as FeedbackNotAdmitted
from enterprise_kb.modules.operations.context import command_for as _command, require_scope as _scope
from enterprise_kb.modules.sources.registry import SourceWrite, sql_admitted_issuer
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


RECORD = "record_feedback"
TRANSITION = "transition_feedback"
STATUS = "read_feedback_status"
NOTICES = "read_feedback_notices"
QUEUE = "read_feedback_queue"
EVIDENCE = "read_feedback_evidence"
QUARANTINE = "quarantine_feedback_evidence"
PAGE_SIZE = 20
Transition = Literal["assign", "mark_corrected", "explain", "verify_correction"]
ACTION_STATES = {
    "assign": "pending", "mark_corrected": "awaiting_retest", "explain": "explained",
    "verify_correction": "closed",
}
EXPLANATION_CODES = frozenset({"source_text_confirmed", "applicability_confirmed"})


class FeedbackConflict(Exception):
    pass


@dataclass(frozen=True)
class FeedbackSpec:
    origin_request_id: UUID
    category: Literal["incorrect_evidence", "missing_evidence"]
    passage_ref: UUID | None = None
    note: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if (self.category, self.passage_ref is not None) not in {
            ("incorrect_evidence", True), ("missing_evidence", False),
        } or (self.note is not None and (
            not self.note.strip() or "\x00" in self.note or len(self.note.encode("utf-8")) > 2048
        )):
            raise ValueError("Invalid feedback category, citation or note.")


@dataclass(frozen=True)
class FeedbackProgress:
    feedback_ref: UUID
    state: str
    generation: int
    conclusion_code: str | None = None


@dataclass(frozen=True)
class FeedbackEvidence:
    feedback_id: int
    generation: int
    passage_ref: UUID
    excerpt_revision: int
    state: str


def _record_origin(connection: Connection, call: FeedbackCall, spec: FeedbackSpec):
    origin = connection.execute(
        """
        SELECT request.operation, request.outcome, citation.check_id, citation.position
        FROM thalion.request_record AS request
        LEFT JOIN LATERAL (
            SELECT delivery.check_id, displayed.position FROM thalion.delivery_record AS delivery
            JOIN thalion.delivery_citation AS displayed USING (check_id)
            JOIN thalion.delivery_dependency AS part USING (check_id, position)
            WHERE (delivery.org_id, delivery.request_id) = (request.org_id, request.request_id)
              AND part.space_id = request.scope_space_id AND part.passage_ref = %s
              AND request.completed_at < delivery.valid_until
        ) AS citation ON true
        WHERE (request.org_id, request.scope_space_id, request.request_id, request.principal_id) = (%s, %s, %s, %s)
          AND request.destination = 'employee' AND request.delegated_principal_id IS NULL
        """, (spec.passage_ref, call.org_id, call.space_id, spec.origin_request_id, call.principal_id),
    ).fetchone()
    if origin is not None:
        operation, outcome, check_id, position = origin
        if spec.passage_ref is not None and operation in {"search", "read_passage"} and outcome == "succeeded" and check_id:
            return check_id, position
        if spec.passage_ref is None and operation == "search" and outcome in {"succeeded", "no_evidence"}:
            return None, None
    raise FeedbackNotAdmitted("The original request or displayed citation is not available to this reporter.")


def record_feedback(connection: Connection, call: FeedbackCall, spec: FeedbackSpec) -> UUID:
    command = _command(call, RECORD, (
        str(spec.origin_request_id), spec.category, str(spec.passage_ref) if spec.passage_ref else None, spec.note,
    ))
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        _scope(connection, call, RECORD)
        check_id, position = _record_origin(connection, call, spec)

        def apply(transaction):
            feedback_id = transaction.execute(
                """
                INSERT INTO thalion.feedback (
                    org_id, space_id, reporter_id, created_request_id, origin_request_id,
                    origin_check_id, citation_position, category
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING feedback_id
                """,
                (call.org_id, call.space_id, call.principal_id, call.request_id, spec.origin_request_id,
                 check_id, position, spec.category),
            ).fetchone()[0]
            ref = transaction.execute(
                """
                INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id)
                VALUES (%s, %s, 'feedback', %s) RETURNING public_id
                """, (call.org_id, call.space_id, feedback_id),
            ).fetchone()[0]
            if spec.note is not None:
                transaction.execute(
                    "INSERT INTO thalion.feedback_note (feedback_id, note) VALUES (%s, %s)", (feedback_id, spec.note),
                )
            if spec.category == "missing_evidence":
                gaps.capture_gap(transaction, call, spec.origin_request_id, feedback_id=feedback_id)
            append_event(transaction, call.org_id, "operations.feedback.recorded", ref, space_id=call.space_id)
            return ref

        return execute_command(connection, command, apply).result_ref


def get_feedback_progress(connection: Connection, call: FeedbackCall, ref: UUID) -> FeedbackProgress:
    with connection.transaction():
        _scope(connection, call, STATUS)
        row = connection.execute(
            """
            SELECT report.state, report.generation, CASE decision.action
                WHEN 'mark_corrected' THEN 'correction_recorded'
                WHEN 'explain' THEN coalesce(decision.conclusion_code, 'basis_reviewed')
                WHEN 'verify_correction' THEN 'correction_verified'
            END
            FROM thalion.current_feedback AS report
            LEFT JOIN thalion.feedback_decision AS decision ON (decision.feedback_id, decision.generation) =
                (report.feedback_id, report.generation)
            WHERE (report.org_id, report.space_id, report.feedback_ref, report.reporter_id) = (%s, %s, %s, %s)
            """, (call.org_id, call.space_id, ref, call.principal_id),
        ).fetchone()
        if row is None:
            raise FeedbackNotAdmitted("No feedback progress is available to this reporter.")
        return FeedbackProgress(ref, *row)


def list_feedback_notices(connection: Connection, call: FeedbackCall, after: UUID | None) -> dict:
    with connection.transaction():
        _scope(connection, call, NOTICES)
        rows = connection.execute(
            """
            WITH eligible AS NOT MATERIALIZED (
                SELECT report.feedback_id, decision.action, decision.decision_ref, decision.recorded_at
                FROM thalion.feedback AS report
                JOIN thalion.feedback_decision AS decision USING (org_id, space_id, feedback_id)
                WHERE (report.org_id, report.space_id, report.reporter_id) = (%s, %s, %s)
                  AND decision.action IN ('mark_corrected', 'explain', 'verify_correction')
            )
            SELECT eligible.decision_ref, identity.public_id, eligible.action FROM eligible
            JOIN thalion.object_identity AS identity ON (identity.object_type, identity.object_id) =
                ('feedback', eligible.feedback_id)
            WHERE (%s::uuid IS NULL OR (eligible.recorded_at, eligible.decision_ref) < (
                SELECT anchor.recorded_at, anchor.decision_ref FROM eligible AS anchor WHERE anchor.decision_ref = %s
            ))
            ORDER BY eligible.recorded_at DESC, eligible.decision_ref DESC LIMIT %s
            """, (call.org_id, call.space_id, call.principal_id, after, after, PAGE_SIZE + 1),
        ).fetchall()
        items = [
            {"notice_id": str(notice), "feedback_id": str(ref), "state": ACTION_STATES[action]}
            for notice, ref, action in rows[:PAGE_SIZE]
        ]
        return {"items": items, "next_cursor": items[-1]["notice_id"] if len(rows) > PAGE_SIZE else None}


def list_feedback_work(connection: Connection, call: FeedbackCall, after: UUID | None) -> dict:
    with connection.transaction():
        owner = _scope(connection, call, QUEUE) == call.principal_id
        scope = (call.org_id, call.space_id, owner, call.principal_id)
        locked = connection.execute(
            """
            WITH candidates AS MATERIALIZED (
                SELECT feedback_id FROM thalion.current_feedback
                WHERE (org_id, space_id) = (%s, %s) AND (%s OR assignee_id = %s)
                  AND state IN ('pending', 'awaiting_retest') AND (%s::uuid IS NULL OR feedback_ref > %s)
                ORDER BY feedback_ref LIMIT %s
            )
            SELECT report.feedback_id FROM candidates
            JOIN thalion.feedback AS report USING (feedback_id)
            ORDER BY report.feedback_id FOR SHARE OF report
            """, (*scope, after, after, PAGE_SIZE + 1),
        ).fetchall()
        rows = connection.execute(
            """
            SELECT feedback_ref, state, generation, category, assignee_id IS NOT NULL, passage_ref IS NOT NULL
            FROM thalion.current_feedback
            WHERE (org_id, space_id) = (%s, %s) AND (%s OR assignee_id = %s)
              AND state IN ('pending', 'awaiting_retest') AND feedback_id = ANY(%s)
            ORDER BY feedback_ref
            """, (*scope, [entry[0] for entry in locked]),
        ).fetchall()
        items = [
            {"feedback_id": str(ref), "state": state, "generation": generation, "category": category,
             "assigned": assigned, "has_citation": has_citation}
            for ref, state, generation, category, assigned, has_citation in rows[:PAGE_SIZE]
        ]
        return {
            "role": "owner" if owner else "assignee", "items": items,
            "next_cursor": items[-1]["feedback_id"] if len(rows) > PAGE_SIZE else None,
        }


def get_feedback_evidence(connection: Connection, call: FeedbackCall, ref: UUID) -> FeedbackEvidence | None:
    owner = _scope(connection, call, "read_passage", destination="employee")
    return _lock_feedback_evidence(connection, call, ref, owner=owner == call.principal_id)


def _lock_feedback_evidence(
    connection: Connection, call: FeedbackCall, ref: UUID, *, owner: bool,
) -> FeedbackEvidence | None:
    scope = (call.org_id, call.space_id, ref)
    locked = connection.execute(
        """
        SELECT report.feedback_id FROM thalion.object_identity AS identity
        JOIN thalion.feedback AS report ON (report.org_id, report.space_id, report.identity_type, report.feedback_id) =
                                          (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s) FOR SHARE OF report
        """, scope,
    ).fetchone()
    if locked is None:
        return None
    row = connection.execute(
        """
        SELECT feedback_id, generation, passage_ref, excerpt_revision, state FROM thalion.current_feedback
        WHERE (org_id, space_id, feedback_id) = (%s, %s, %s) AND passage_ref IS NOT NULL
          AND state IN ('pending', 'awaiting_retest') AND (%s OR assignee_id = %s)
        """, (call.org_id, call.space_id, locked[0], owner, call.principal_id),
    ).fetchone()
    return FeedbackEvidence(*row) if row is not None else None


def seal_feedback_evidence(connection: Connection, call: FeedbackCall, target: FeedbackEvidence, check_id: UUID):
    connection.execute(
        """
        INSERT INTO thalion.feedback_evidence_read (org_id, space_id, request_id, check_id, feedback_id, generation)
        VALUES (%s, %s, %s, %s, %s, %s)
        """, (call.org_id, call.space_id, call.request_id, check_id, target.feedback_id, target.generation),
    )


def quarantine_feedback_evidence(
    connection: Connection, call: FeedbackCall, ref: UUID, expected: int, basis_id: UUID,
) -> UUID:
    if type(expected) is not int or not 1 <= expected < 2**63:
        raise ValueError("Invalid feedback generation.")
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        if _scope(connection, call, processing.QUALITY_OPERATION) != call.principal_id:
            raise FeedbackNotAdmitted("Only the current space owner can request feedback quarantine.")
        target = _lock_feedback_evidence(connection, call, ref, owner=True)
        if target is None:
            raise FeedbackNotAdmitted("No feedback evidence is available for this action.")
        if target.generation != expected or target.state != "pending":
            raise FeedbackConflict("Feedback changed before quarantine.")
        basis = connection.execute(
            """
            SELECT 1 FROM thalion.feedback_evidence_read AS work
            JOIN thalion.request_record AS request USING (org_id, request_id)
            JOIN thalion.delivery_record AS delivery ON (delivery.org_id, delivery.check_id) = (work.org_id, work.check_id)
            JOIN thalion.delivery_citation AS shown ON shown.check_id = work.check_id
            JOIN thalion.delivery_dependency AS part ON (part.check_id, part.position) = (shown.check_id, shown.position)
            WHERE (work.org_id, work.space_id, work.feedback_id, work.generation, work.request_id) = (%s, %s, %s, %s, %s)
              AND request.principal_id = %s AND request.operation = 'read_passage' AND request.delegated_principal_id IS NULL
              AND request.destination = 'employee' AND request.outcome = 'succeeded' AND request.completed_at < delivery.valid_until
              AND (part.space_id, part.passage_ref, part.excerpt_revision) = (work.space_id, %s, %s)
            """, (call.org_id, call.space_id, target.feedback_id, target.generation, basis_id, call.principal_id,
                  target.passage_ref, target.excerpt_revision),
        ).fetchone()
        if basis is None:
            raise FeedbackConflict("Quarantine requires the owner's own work-bound evidence receipt.")
        context = SourceWrite(call.org_id, call.principal_id, call.request_id, call.key)
        try:
            return processing.quarantine_exact_excerpt(
                connection, context, call.space_id, target.passage_ref, target.excerpt_revision, basis_id,
            )
        except processing.ProcessingNotAdmitted as error:
            raise FeedbackNotAdmitted("The current source does not authorize this quality action.") from error
        except processing.QualityConflict as error:
            raise FeedbackConflict("The exact evidence batch no longer admits quarantine.") from error


def _active_employee(connection: Connection, org_id: int, principal_id: int) -> bool:
    return connection.execute(
        f"""
        SELECT 1 FROM thalion.principal WHERE (org_id, principal_id) = (%s, %s)
          AND principal_type = 'employee' AND {sql_admitted_issuer('authority_issuer')} AND NOT disabled FOR SHARE
        """, (org_id, principal_id),
    ).fetchone() is not None


def resolve_assignee(connection: Connection, org_id: int, employee_ref: UUID | None) -> int | None:
    if employee_ref is None:
        return None
    row = connection.execute(
        """
        SELECT object_id FROM thalion.object_identity
        WHERE (org_id, object_type, public_id) = (%s, 'principal', %s)
        """, (org_id, employee_ref),
    ).fetchone()
    if row is None:
        raise FeedbackNotAdmitted("The requested assignee is unavailable.")
    return row[0]


def seal_search_match(
    connection: Connection, org_id: int, space_id: int, request_id: UUID, check_id: UUID, fingerprint: bytes,
):
    connection.execute(
        """
        INSERT INTO thalion.feedback_search_match (org_id, space_id, request_id, check_id, fingerprint)
        VALUES (%s, %s, %s, %s, %s)
        """, (org_id, space_id, request_id, check_id, fingerprint),
    )


def _has_evidence_receipt(connection: Connection, feedback_id: int, request_id: UUID, *, corrected: bool) -> bool:
    return connection.execute(
        """
        SELECT 1 FROM thalion.current_feedback AS report
        JOIN thalion.request_record AS origin ON (origin.org_id, origin.request_id) = (report.org_id, report.origin_request_id)
        JOIN thalion.request_record AS retry ON (retry.org_id, retry.scope_space_id) = (report.org_id, report.space_id)
        JOIN thalion.delivery_record AS delivery ON (delivery.org_id, delivery.request_id) = (retry.org_id, retry.request_id)
        JOIN thalion.delivery_citation AS displayed USING (check_id)
        JOIN thalion.delivery_dependency AS part USING (check_id, position)
        LEFT JOIN thalion.feedback_evidence_read AS work ON (work.org_id, work.request_id) = (retry.org_id, retry.request_id)
        LEFT JOIN thalion.feedback_origin_transcription AS original ON original.feedback_id = report.feedback_id
        LEFT JOIN thalion.feedback_decision AS decision
          ON (decision.feedback_id, decision.generation) = (report.feedback_id, report.generation)
        LEFT JOIN thalion.feedback_correction_candidate AS correction
          ON (correction.feedback_id, correction.check_id, correction.position) =
             (report.feedback_id, decision.correction_check_id, decision.correction_position)
        WHERE report.feedback_id = %s AND retry.request_id = %s
          AND retry.destination = origin.destination AND retry.destination = 'employee' AND retry.delegated_principal_id IS NULL
          AND retry.outcome = 'succeeded'
          AND thalion.feedback_request_follows(retry.feedback_order, retry.started_at, decision.feedback_order, report.decided_at)
          AND retry.completed_at < delivery.valid_until
          AND (work.request_id IS NULL OR (work.feedback_id, work.generation) = (report.feedback_id, report.generation))
          AND part.space_id = report.space_id
          AND CASE WHEN %s THEN
              retry.operation = origin.operation AND retry.principal_id = report.reporter_id
              AND retry.client_id = origin.client_id AND retry.business_date = origin.business_date
              AND CASE WHEN decision.correction_check_id IS NOT NULL THEN
                  (part.passage_ref, part.excerpt_revision) = (correction.passage_ref, correction.excerpt_revision)
                  AND NOT EXISTS (
                      SELECT 1 FROM thalion.delivery_citation AS shown
                      JOIN thalion.delivery_dependency AS old USING (check_id, position)
                      WHERE shown.check_id = delivery.check_id AND old.passage_ref = report.passage_ref
                  )
              ELSE NOT original.quarantined AND part.passage_ref = report.passage_ref
                   AND part.excerpt_revision > report.excerpt_revision END
              AND (retry.operation = 'read_passage' OR (retry.operation = 'search' AND EXISTS (
                  SELECT 1 FROM thalion.feedback_search_match AS initial
                  JOIN thalion.feedback_search_match AS repeated USING (org_id, space_id, fingerprint)
                  WHERE (initial.org_id, initial.space_id, initial.request_id, initial.check_id) =
                        (report.org_id, report.space_id, origin.request_id, report.origin_check_id)
                    AND (repeated.request_id, repeated.check_id) = (retry.request_id, delivery.check_id)
              )))
          ELSE retry.operation = 'read_passage' AND retry.principal_id = report.assignee_id
              AND (part.passage_ref, part.excerpt_revision) = (report.passage_ref, report.excerpt_revision) END
        """, (feedback_id, request_id, corrected),
    ).fetchone() is not None


def _lock_correction_origin(connection: Connection, feedback_id: int):
    connection.execute(
        """
        SELECT document.document_id FROM thalion.feedback_origin_transcription AS original
        JOIN thalion.document_version AS version USING (version_id)
        JOIN thalion.document AS document USING (document_id)
        JOIN thalion.source AS source ON source.source_id = version.source_id
        WHERE original.feedback_id = %s FOR SHARE OF source, document
        """, (feedback_id,),
    ).fetchone()


def _lock_gap_supplement(connection: Connection, call: FeedbackCall, feedback_id: int, read_id: UUID | None):
    connection.execute(
        """
        SELECT event.gap_ref FROM thalion.gap_feedback_attachment AS attachment
        JOIN thalion.gap_event AS event USING (org_id, space_id, gap_ref)
        WHERE (attachment.org_id, attachment.space_id, attachment.feedback_id) = (%s, %s, %s)
        FOR UPDATE OF event
        """, (call.org_id, call.space_id, feedback_id),
    ).fetchone()
    connection.execute(
        """
        SELECT document.document_id FROM thalion.current_feedback AS report
        LEFT JOIN thalion.feedback_decision AS decision
          ON (decision.feedback_id, decision.generation) = (report.feedback_id, report.generation)
        JOIN thalion.delivery_record AS receipt ON receipt.org_id = report.org_id
        JOIN thalion.delivery_dependency AS part ON (part.org_id, part.check_id) = (receipt.org_id, receipt.check_id)
        JOIN thalion.rule_effectivity AS rule ON (rule.org_id, rule.space_id, rule.decision_ref) =
                                                (part.org_id, part.space_id, part.effectivity_ref)
        JOIN thalion.source AS source ON source.source_id = rule.source_id
        JOIN thalion.document AS document ON document.document_id = rule.document_id
        WHERE report.feedback_id = %s AND part.space_id = report.space_id AND receipt.dependency_count = 1
          AND CASE WHEN %s::uuid IS NULL THEN receipt.check_id = decision.correction_check_id
                   ELSE receipt.request_id = %s END
        FOR SHARE OF source, document
        """, (feedback_id, read_id, read_id),
    ).fetchone()


def _correction_receipt(connection: Connection, feedback_id: int, request_id: UUID | None, *, gap: bool):
    if request_id is None:
        if gap or connection.execute(
            "SELECT 1 FROM thalion.feedback_origin_transcription WHERE feedback_id = %s AND quarantined",
            (feedback_id,),
        ).fetchone() is not None:
            raise FeedbackConflict("This feedback requires exact correction evidence.")
        return None, None
    receipt = connection.execute(
        """
        SELECT candidate.check_id, candidate.position FROM thalion.feedback_work_correction_candidate AS candidate
        JOIN thalion.current_feedback AS report USING (feedback_id)
        JOIN thalion.feedback_decision AS previous
          ON (previous.feedback_id, previous.generation) = (report.feedback_id, report.generation)
        WHERE (candidate.feedback_id, candidate.request_id, candidate.principal_id) = (%s, %s, report.assignee_id)
          AND thalion.feedback_request_follows(candidate.feedback_order, candidate.started_at, previous.feedback_order, report.decided_at)
        """, (feedback_id, request_id),
    ).fetchone()
    if receipt is None:
        raise FeedbackConflict("Correction requires the assignee's own read of the independently approved replacement.")
    return receipt


def transition_feedback(
    connection: Connection, call: FeedbackCall, ref: UUID, expected: int, action: Transition, *,
    assignee_id: int | None = None, retest_id: UUID | None = None, basis_id: UUID | None = None,
    conclusion_code: str | None = None, correction_id: UUID | None = None,
) -> FeedbackProgress:
    if (
        type(expected) is not int or not 1 <= expected < 2**63 - 1 or action not in ACTION_STATES
        or (action == "assign") != (assignee_id is not None) or (action == "verify_correction") != (retest_id is not None)
        or (action == "explain") != (basis_id is not None)
        or (correction_id is not None and action != "mark_corrected")
        or (conclusion_code is not None and (
            action != "explain" or not isinstance(conclusion_code, str) or conclusion_code not in EXPLANATION_CODES
        ))
    ):
        raise ValueError("Invalid feedback transition, generation or evidence.")
    values = (
        str(ref), action, assignee_id, str(retest_id) if retest_id else None, str(basis_id) if basis_id else None,
    )
    if conclusion_code is not None:
        values += (conclusion_code,)
    if correction_id is not None:
        values += (str(correction_id),)
    command = _command(call, TRANSITION, values, expected)
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        owner = _scope(connection, call, TRANSITION)
        report = connection.execute(
            """
            SELECT report.feedback_id, report.category FROM thalion.feedback AS report
            JOIN thalion.object_identity AS identity
              ON (report.org_id, report.space_id, report.identity_type, report.feedback_id) =
                 (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
            WHERE (report.org_id, report.space_id, identity.public_id) = (%s, %s, %s) FOR UPDATE OF report
            """, (call.org_id, call.space_id, ref),
        ).fetchone()
        if report is None:
            raise FeedbackNotAdmitted("No feedback transition is available to this employee.")
        feedback_id, category = report
        gap = category == "missing_evidence"
        state, generation, current_assignee = connection.execute(
            "SELECT state, generation, assignee_id FROM thalion.current_feedback WHERE feedback_id = %s",
            (feedback_id,),
        ).fetchone()
        owner_action = action in {"assign", "verify_correction"}
        if call.principal_id != (owner if owner_action else current_assignee):
            raise FeedbackNotAdmitted("No feedback transition is available to this employee.")
        if action == "assign":
            if assignee_id == owner or not _active_employee(connection, call.org_id, assignee_id):
                raise FeedbackNotAdmitted("Assignment requires another current employee in this organization.")
        else:
            assignee_id = current_assignee
        if action == "verify_correction" and owner == current_assignee:
            raise FeedbackNotAdmitted("Correction requires independent verification.")

        def apply(transaction):
            required = {"awaiting_retest"} if action == "verify_correction" else {"pending"}
            if correction_id is not None:
                required.add("awaiting_retest")
            if generation != expected or state not in required or assignee_id is None:
                raise FeedbackConflict("The feedback state or generation does not admit this transition.")
            if action == "explain" and not _has_evidence_receipt(transaction, feedback_id, basis_id, corrected=False):
                raise FeedbackConflict("An explanation requires the assignee's exact reread after assignment.")
            correction_check, correction_position = None, None
            if action in {"mark_corrected", "verify_correction"}:
                if gap:
                    _lock_gap_supplement(transaction, call, feedback_id, correction_id)
                else:
                    _lock_correction_origin(transaction, feedback_id)
            if action == "mark_corrected":
                correction_check, correction_position = _correction_receipt(transaction, feedback_id, correction_id, gap=gap)
            if action == "verify_correction":
                matched = transaction.execute(
                    "SELECT thalion.feedback_gap_retest_matches(%s, %s)", (feedback_id, retest_id),
                ).fetchone()[0] if gap else _has_evidence_receipt(transaction, feedback_id, retest_id, corrected=True)
                if not matched:
                    raise FeedbackConflict("A matching post-correction delivery is required before closing.")
            decision_ref = transaction.execute(
                """
                INSERT INTO thalion.feedback_decision (
                    org_id, space_id, feedback_id, generation, action, actor_id, assignee_id, request_id,
                    retest_request_id, basis_request_id, conclusion_code, correction_check_id, correction_position
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING decision_ref
                """,
                (call.org_id, call.space_id, feedback_id, generation + 1, action, call.principal_id, assignee_id,
                 call.request_id, retest_id, basis_id, conclusion_code, correction_check, correction_position),
            ).fetchone()[0]
            append_event(transaction, call.org_id, "operations.feedback.transitioned", ref, space_id=call.space_id)
            return decision_ref

        execute_command(connection, command, apply)
        return FeedbackProgress(ref, ACTION_STATES[action], expected + 1)
