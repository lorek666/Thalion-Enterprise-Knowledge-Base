from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, append_space_event, command_for, require_scope
from enterprise_kb.runtime.commands import execute_command


EMIT = "emit_finding"
CONFLICT_RULES = frozenset({"statement_conflict", "unit_mismatch"})


def emit_finding(
    connection: Connection, call: OperationsCall, observations: tuple[tuple[UUID, UUID], tuple[UUID, UUID]], rule: str,
) -> UUID:
    origins = [origin for origin, _ in observations]
    if rule not in CONFLICT_RULES or len(origins) != 2 or len(set(origins)) != 2:
        raise ValueError("A conflict requires a supported rule and two different requests.")

    command = command_for(call, EMIT, (rule, *sorted((str(origin), str(revision)) for origin, revision in observations)))
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        owner_id = require_scope(connection, call, EMIT)
        if call.principal_id != owner_id:
            raise OperationsNotAdmitted("The current space owner must report this conflict.")
        observed = connection.execute(
            """
            SELECT request_id, business_date, revision_ref FROM thalion.lint_search_receipt
            WHERE (org_id, space_id, principal_id) = (%s, %s, %s) AND request_id = ANY(%s)
            ORDER BY revision_ref
            """, (call.org_id, call.space_id, call.principal_id, origins),
        ).fetchall()
        if (
            {(origin, revision) for origin, _, revision in observed} != set(observations)
            or observed[0][1] != observed[1][1] or observed[0][2] == observed[1][2]
        ):
            raise OperationsNotAdmitted("Two different revisions from the reporter's same-day searches are required.")
        (first_origin, business_date, first_revision), (second_origin, _, second_revision) = observed

        def apply(transaction):
            scope = (call.org_id, call.space_id)
            signature = (*scope, business_date, rule, first_revision, second_revision)
            row = transaction.execute(
                """
                INSERT INTO thalion.lint_finding (
                    org_id, space_id, business_date, rule, first_revision_ref, second_revision_ref, initial_owner_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (org_id, space_id, business_date, rule, first_revision_ref, second_revision_ref)
                DO NOTHING RETURNING finding_ref
                """, (*signature, owner_id),
            ).fetchone()
            if row is None:
                row = transaction.execute(
                    """
                    SELECT finding_ref FROM thalion.lint_finding
                    WHERE (org_id, space_id, business_date, rule, first_revision_ref, second_revision_ref) =
                          (%s, %s, %s, %s, %s, %s)
                    """, signature,
                ).fetchone()
            finding_ref = row[0]
            saved = transaction.execute(
                """
                INSERT INTO thalion.lint_finding_observation (
                    org_id, space_id, finding_ref, report_request_id, reporter_id, first_origin, second_origin
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (finding_ref, first_origin, second_origin) DO NOTHING RETURNING report_request_id
                """, (*scope, finding_ref, call.request_id, call.principal_id, first_origin, second_origin),
            ).fetchone()
            if saved is not None:
                append_space_event(transaction, call, "operations.finding.observed")
            return finding_ref

        return execute_command(connection, command, apply).result_ref
