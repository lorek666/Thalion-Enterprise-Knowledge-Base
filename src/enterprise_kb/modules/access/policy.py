from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Literal
from uuid import UUID

from psycopg import Connection, errors

from enterprise_kb.modules.sources.registry import (
    SourceWrite, _digest, sql_admitted_admission, sql_issuer_matches_admission, sql_issuer_matches_value,
)
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed

from .rules import require_aware


class PolicyNotAdmitted(Exception):
    pass


class PolicyConflict(Exception):
    pass


PASSAGE_FIELDS = frozenset({"excerpt", "citation", "title", "location", "version"})
EMPLOYEE_SOURCE_OPTIONS_ACCESS = ("list_employee_sources", "employee_evidence", "employee")
EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS = ("list_employee_departments", "employee_evidence", "employee")
EMPLOYEE_TITLE_SUGGESTIONS_ACCESS = ("list_employee_title_suggestions", "employee_evidence", "employee")
ORIGINAL_DOWNLOAD_ACCESS = ("download_original", "employee_evidence", "employee")
ORIGINAL_FIELDS = frozenset({"original"})
WORKSPACE_EVIDENCE_FIELDS = frozenset({"excerpt", "location"})
MAX_LOCAL_POLICY_RULES = 500
READ = "read_local_policy"
REPLACE = "replace_local_policy"
READ_MODEL = "read_model_policy"
REPLACE_MODEL = "replace_model_policy"
WRITE_OPERATIONS = frozenset({REPLACE, REPLACE_MODEL})
OPERATIONS = WRITE_OPERATIONS | {READ, READ_MODEL}
MODEL_RULE_OPERATION = "send_model_evidence"
MODEL_RULE_PURPOSES = frozenset({"model_answer", "wiki_compilation", "model_review"})
SYNTHETIC_MODEL_DESTINATION = "synthetic-gateway"
DESTINATION = "internal_access"
WIKI_INPUT_ACCESS = ("assemble_wiki_inputs", "wiki_compilation", "local_workspace")
WIKI_CANDIDATE_ACCESS = ("create_wiki_candidate", "wiki_compilation", "local_workspace")
WIKI_REVIEW_ACCESS = ("review_wiki_revision", "wiki_review", "local_workspace")
WIKI_PREVIEW_ACCESS = ("read_wiki_candidate", "wiki_review", "local_workspace")
WIKI_PUBLISH_ACCESS = ("publish_wiki_revision", "wiki_publication", "local_workspace")
WIKI_ROLLBACK_ACCESS = ("rollback_wiki_topic", "wiki_publication", "local_workspace")
WIKI_READ_ACCESS = ("read_published_wiki", "employee_evidence", "employee")
REPAIR_PREVIEW_ACCESS = ("preview_evidence_repair", "evidence_quality_review", "local_workspace")
DOCX_PREVIEW_ACCESS = ("preview_docx_quality", "evidence_quality_review", "local_workspace")
PDF_PAGE_PREVIEW_ACCESS = ("preview_pdf_original_page", "evidence_quality_review", "local_workspace")
PDF_PAGE_FIELDS = frozenset({"original_page"})
WIKI_DERIVED_ACCESS = (
    WIKI_INPUT_ACCESS, WIKI_CANDIDATE_ACCESS, WIKI_REVIEW_ACCESS, WIKI_PREVIEW_ACCESS,
    WIKI_PUBLISH_ACCESS, WIKI_ROLLBACK_ACCESS, WIKI_READ_ACCESS,
)


@dataclass(frozen=True)
class LocalRule:
    subject_id: int | UUID
    operation: str
    effect: Literal["allow", "deny"]
    purpose: str
    destination: str
    fields: frozenset[str]
    valid_from: datetime
    valid_until: datetime | None = None
    passage_ref: UUID | None = None
    version_ref: UUID | None = None
    allowed_model_destinations: frozenset[str] = field(
        default=frozenset({SYNTHETIC_MODEL_DESTINATION}),
        repr=False,
        compare=False,
    )

    def __post_init__(self):
        object.__setattr__(self, "fields", frozenset(self.fields))
        require_aware(self.valid_from)
        if self.valid_until is not None:
            require_aware(self.valid_until)
            if self.valid_until <= self.valid_from:
                raise ValueError("Policy expiry must follow the start time.")
        access = (self.operation, self.purpose, self.destination)
        employee_read = access == ("read_passage", "employee_evidence", "employee") and self.fields <= PASSAGE_FIELDS
        workspace_read = (
            access in (WIKI_INPUT_ACCESS, WIKI_REVIEW_ACCESS, WIKI_PUBLISH_ACCESS, REPAIR_PREVIEW_ACCESS, DOCX_PREVIEW_ACCESS)
            and self.fields <= WORKSPACE_EVIDENCE_FIELDS
        )
        pdf_original = access == PDF_PAGE_PREVIEW_ACCESS and self.fields == PDF_PAGE_FIELDS and self.passage_ref is None
        full_original = access == ORIGINAL_DOWNLOAD_ACCESS and self.fields == ORIGINAL_FIELDS and self.passage_ref is None
        model_rule = (
            self.operation == MODEL_RULE_OPERATION and self.purpose in MODEL_RULE_PURPOSES
            and self.destination in self.allowed_model_destinations and self.fields <= PASSAGE_FIELDS
            and self.passage_ref is not None and self.valid_until is not None
        )
        if (self.effect not in ("allow", "deny") or not self.fields
                or (self.version_ref is not None) != full_original
                or not (employee_read or workspace_read or pdf_original or model_rule or full_original)):
            raise ValueError("Invalid synthetic evidence policy scope or fields.")


def _scoped_policy(connection: Connection, context: SourceWrite, space_id: int, source_ref: UUID, *, write: bool, model_egress: bool):
    lock = "UPDATE" if write else "SHARE"
    role = ("contract.model_policy_approver_id = actor.principal_id AND source.owner_principal_id <> actor.principal_id"
            if model_egress else "source.owner_principal_id = actor.principal_id")
    selected = connection.execute(
        f"""
        SELECT source.source_id, source.safety_epoch, source.contract_revision,
               source.local_policy_revision, contract.admission
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (source.org_id, %s)
        WHERE identity.org_id = %s AND identity.space_id = %s AND identity.public_id = %s
          AND space.lifecycle = 'active' AND source.lifecycle = 'active'
          AND {sql_admitted_admission('contract.admission')} AND {role}
          AND actor.principal_type = 'employee'
          AND {sql_issuer_matches_admission('actor.authority_issuer', 'contract.admission')}
          AND NOT actor.disabled
        FOR SHARE OF space, actor
        FOR {lock} OF source
        """,
        (context.principal_id, context.org_id, space_id, source_ref),
    ).fetchone()
    if selected is None:
        raise PolicyNotAdmitted("The current policy role matching source admission is required.")
    return selected


def read_synthetic_policy(
    connection: Connection, context: SourceWrite, space_id: int, source_ref: UUID, *, model_egress: bool = False,
) -> dict:
    with connection.transaction():
        _require_read_committed(connection)
        operation = READ_MODEL if model_egress else READ
        require_open_request(connection, context.org_id, context.request_id, context.principal_id, None, operation=operation)
        source_id, epoch, _, revision, _ = _scoped_policy(connection, context, space_id, source_ref, write=False, model_egress=model_egress)
        rows = connection.execute(
            """
            SELECT identity.public_id, binding.passage_ref, binding.operation, binding.effect, binding.purpose,
                   binding.destination, binding.fields, binding.valid_from, binding.valid_until, binding.version_ref
            FROM thalion.permission_binding AS binding
            LEFT JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.object_type, identity.object_id) = (binding.org_id, 'principal', binding.subject_id)
            WHERE (binding.org_id, binding.space_id, binding.source_id, binding.revision) = (%s, %s, %s, %s)
              AND (binding.operation = %s) = %s
            ORDER BY binding.binding_id
            """,
            (context.org_id, space_id, source_id, revision, MODEL_RULE_OPERATION, model_egress),
        ).fetchall() if revision is not None else ()
        rules = []
        for subject, passage, operation, effect, purpose, destination, fields, start, expiry, version in rows:
            if subject is None:
                raise PolicyConflict("A stored rule has no registered subject reference.")
            rules.append({
                "subject_id": str(subject), "operation": operation, "effect": effect, "purpose": purpose,
                "destination": destination, "fields": fields, "valid_from": start.isoformat(),
                **({"valid_until": expiry.isoformat()} if expiry is not None else {}),
                **({"passage_id": str(passage)} if passage is not None else {}),
                **({"version_id": str(version)} if version is not None else {}),
            })
        return {"safety_epoch": epoch, "policy_revision": revision, "rules": rules}


def _resolve_subjects(connection: Connection, org_id: int, rules: tuple[LocalRule, ...]) -> tuple[LocalRule, ...]:
    references = {rule.subject_id for rule in rules if isinstance(rule.subject_id, UUID)}
    if not references:
        return rules
    found = dict(connection.execute(
        """
        SELECT public_id, object_id FROM thalion.object_identity
        WHERE org_id = %s AND object_type = 'principal' AND public_id = ANY(%s)
        """, (org_id, list(references)),
    ).fetchall())
    if found.keys() != references:
        raise PolicyNotAdmitted("A requested policy subject is not registered in this organization.")
    return tuple(replace(rule, subject_id=found[rule.subject_id]) if isinstance(rule.subject_id, UUID) else rule for rule in rules)


def replace_synthetic_policy(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    source_ref: UUID,
    expected_epoch: int,
    rules: tuple[LocalRule, ...],
    basis_ref: UUID,
    *, model_egress: bool = False,
) -> int:
    """Commit a new local policy; this is not an independent recovery acknowledgment."""
    rules = tuple(rules)
    if (not 1 <= expected_epoch < 2**63 - 1 or len(rules) > MAX_LOCAL_POLICY_RULES
            or any((rule.operation == MODEL_RULE_OPERATION) != model_egress for rule in rules)):
        raise ValueError("Invalid expected epoch, rule count, or policy partition.")
    operation = REPLACE_MODEL if model_egress else REPLACE
    with connection.transaction():
        _require_read_committed(connection)
        require_open_request(
            connection, context.org_id, context.request_id, context.principal_id, None, operation=operation,
        )
        source_id, epoch, configuration, current_revision, admission = _scoped_policy(
            connection, context, space_id, source_ref, write=True, model_egress=model_egress,
        )
        rules = _resolve_subjects(connection, context.org_id, rules)
        scope = (context.org_id, space_id, source_id)
        revision = expected_epoch + 1
        command = CommandEnvelope(
            context.org_id, context.principal_id, None, context.request_id, operation,
            context.idempotency_key, _digest(
                space_id, str(source_ref), str(basis_ref),
                [(rule.subject_id, rule.operation, rule.effect, rule.purpose, rule.destination,
                  sorted(rule.fields), rule.valid_from.isoformat(),
                  rule.valid_until.isoformat() if rule.valid_until else None,
                  str(rule.passage_ref) if rule.passage_ref else None,
                  *((str(rule.version_ref),) if rule.version_ref else ())) for rule in rules],
            ), configuration, expected_epoch,
        )

        def apply(transaction):
            if epoch != expected_epoch:
                raise PolicyConflict("The source safety epoch changed before policy replacement.")
            subjects = sorted({rule.subject_id for rule in rules})
            subject_issuer_match = sql_issuer_matches_value("authority_issuer", admission)
            found = transaction.execute(
                f"""
                SELECT principal_id FROM thalion.principal
                WHERE org_id = %s AND principal_id = ANY(%s) AND principal_type IN ('employee', 'group')
                  AND {subject_issuer_match} AND NOT disabled
                ORDER BY principal_id FOR SHARE
                """,
                (context.org_id, subjects),
            ).fetchall()
            if [row[0] for row in found] != subjects:
                raise PolicyNotAdmitted("Policy subjects must be active synthetic employees or groups in scope.")
            retained = (*scope, current_revision, MODEL_RULE_OPERATION, not model_egress)
            preserved, = transaction.execute(
                """
                SELECT count(*) FROM thalion.permission_binding
                WHERE (org_id, space_id, source_id, revision) = (%s, %s, %s, %s) AND (operation = %s) = %s
                """, retained,
            ).fetchone()
            result = transaction.execute(
                """
                INSERT INTO thalion.policy_revision (
                    org_id, space_id, source_id, revision, actor_id, request_id, basis_ref, binding_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING policy_ref
                """,
                (*scope, revision, context.principal_id, context.request_id, basis_ref, len(rules) + preserved),
            ).fetchone()[0]
            if preserved:
                version_column = ", version_ref" if model_egress else ""
                transaction.execute(
                    f"""
                    INSERT INTO thalion.permission_binding (
                        org_id, space_id, source_id, revision, subject_id, passage_ref,
                        operation, effect, purpose, destination, fields, valid_from, valid_until{version_column}
                    ) SELECT org_id, space_id, source_id, %s, subject_id, passage_ref,
                             operation, effect, purpose, destination, fields, valid_from, valid_until{version_column}
                      FROM thalion.permission_binding
                      WHERE (org_id, space_id, source_id, revision) = (%s, %s, %s, %s) AND (operation = %s) = %s
                      ORDER BY binding_id
                    """, (revision, *retained),
                )
            if rules:
                has_versions = any(rule.version_ref is not None for rule in rules)
                version_column = ", version_ref" if has_versions else ""
                version_value = ", %s" if has_versions else ""
                try:
                    with transaction.cursor() as cursor:
                        cursor.executemany(
                            f"""
                            INSERT INTO thalion.permission_binding (
                                org_id, space_id, source_id, revision, subject_id, passage_ref,
                                operation, effect, purpose, destination, fields, valid_from, valid_until{version_column}
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s{version_value})
                            """,
                            [(*scope, revision, rule.subject_id, rule.passage_ref, rule.operation,
                              rule.effect, rule.purpose, rule.destination, sorted(rule.fields),
                              rule.valid_from, rule.valid_until, *((rule.version_ref,) if has_versions else ()))
                             for rule in rules],
                        )
                except (errors.ForeignKeyViolation, errors.CheckViolation):
                    raise PolicyNotAdmitted("A permission binding is outside the admitted source scope.") from None
            changed = transaction.execute(
                """
                UPDATE thalion.source SET local_policy_revision = %s
                WHERE (org_id, space_id, source_id) = (%s, %s, %s) RETURNING safety_epoch
                """,
                (revision, *scope),
            ).fetchone()
            if changed != (revision,):
                raise PolicyConflict("Policy and safety epoch did not advance together.")
            append_event(transaction, context.org_id, "access.policy.replaced", source_ref, space_id=space_id)
            return result

        receipt = execute_command(connection, command, apply)
        if receipt.result_ref is None:
            raise RuntimeError("Policy replacement did not produce a receipt.")
        return revision
