from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
from typing import Literal
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.sources.registry import is_production_issuer, sql_admitted_issuer, sql_issuers_same_mode
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed


class TemplateNotAdmitted(Exception):
    pass


class TemplateConflict(Exception):
    pass


@dataclass(frozen=True)
class TemplateWrite:
    org_id: int
    principal_id: int
    request_id: UUID
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class TemplateSpec:
    template_key: str
    prompt: str = field(repr=False)
    model_profile: str
    max_input_bytes: int
    max_output_tokens: int
    reviewer_id: int

    def __post_init__(self):
        if (
            not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.template_key)
            or not self.prompt.strip() or "\x00" in self.prompt or len(self.prompt.encode("utf-8")) > 16384
            or not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{1,127}", self.model_profile)
            or not 1 <= self.max_input_bytes <= 1048576
            or not 1 <= self.max_output_tokens <= 8192
        ):
            raise ValueError("Invalid template configuration.")


def _command(context, operation, parts, expected_generation=None):
    digest = sha256(json.dumps(parts, separators=(",", ":")).encode("utf-8")).digest()
    return CommandEnvelope(
        context.org_id, context.principal_id, None, context.request_id, operation,
        context.idempotency_key, digest, 1, expected_generation,
    )


def _scope(connection, context, space_id, operation, *, owner):
    _require_read_committed(connection)
    require_open_request(connection, context.org_id, context.request_id, context.principal_id, None, operation=operation)
    selected = connection.execute(
        f"""
        SELECT identity.public_id, actor.authority_issuer
        FROM thalion.space AS space
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (space.org_id, space.space_id, 'space', space.space_id)
        JOIN thalion.principal AS space_owner
          ON (space_owner.org_id, space_owner.principal_id) = (space.org_id, space.owner_principal_id)
        JOIN thalion.principal AS actor ON actor.org_id = space.org_id AND actor.principal_id = %s
        WHERE (space.org_id, space.space_id) = (%s, %s) AND space.lifecycle = 'active'
          AND (NOT %s OR space.owner_principal_id = actor.principal_id)
          AND actor.principal_type = 'employee'
          AND {sql_admitted_issuer('actor.authority_issuer')}
          AND {sql_issuers_same_mode('actor.authority_issuer', 'space_owner.authority_issuer')}
          AND NOT actor.disabled
        FOR SHARE OF space, actor
        """,
        (context.principal_id, context.org_id, space_id, owner),
    ).fetchone()
    if selected is None:
        raise TemplateNotAdmitted("No current template role in this space.")
    return selected[0], selected[1]


def _require_independent_reviewer(connection, context, reviewer_id):
    if context.principal_id == reviewer_id or connection.execute(
        f"""
        SELECT 1 FROM thalion.principal AS reviewer
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (reviewer.org_id, %s)
        WHERE (reviewer.org_id, reviewer.principal_id) = (%s, %s)
          AND reviewer.principal_type = 'employee'
          AND {sql_issuers_same_mode('reviewer.authority_issuer', 'actor.authority_issuer')}
          AND NOT reviewer.disabled
        FOR SHARE OF reviewer
        """,
        (context.principal_id, context.org_id, reviewer_id),
    ).fetchone() is None:
        raise TemplateNotAdmitted("An independent active reviewer matching caller mode is required.")


def register_template_revision(
    connection: Connection, context: TemplateWrite, space_id: int, spec: TemplateSpec,
) -> UUID:
    operation = "register_template_revision"
    config = (spec.prompt, spec.model_profile, spec.max_input_bytes, spec.max_output_tokens)
    family = (context.org_id, space_id, spec.template_key)
    command = _command(context, operation, (space_id, spec.template_key, *config, spec.reviewer_id))
    with connection.transaction():
        _, actor_issuer = _scope(connection, context, space_id, operation, owner=True)
        if is_production_issuer(actor_issuer) and spec.model_profile == "synthetic-local":
            raise TemplateNotAdmitted("Production templates cannot use synthetic-local model_profile.")
        if not is_production_issuer(actor_issuer) and spec.model_profile != "synthetic-local":
            raise TemplateNotAdmitted("Synthetic templates must use synthetic-local model_profile.")
        _require_independent_reviewer(connection, context, spec.reviewer_id)

        def apply(transaction):
            transaction.execute(
                "INSERT INTO thalion.compile_template VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", family,
            )
            return transaction.execute(
                """
                INSERT INTO thalion.compile_template_revision (
                    org_id, space_id, template_key, prompt, model_profile, max_input_bytes, max_output_tokens,
                    author_id, reviewer_id, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING revision_ref
                """,
                (*family, *config, context.principal_id, spec.reviewer_id, context.request_id),
            ).fetchone()[0]

        return execute_command(connection, command, apply).result_ref


def decide_template_admission(
    connection: Connection, context: TemplateWrite, space_id: int, revision_ref: UUID,
    decision: Literal["approved", "rejected"], basis_ref: UUID, reason_code: str,
) -> None:
    if decision not in ("approved", "rejected") or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason_code):
        raise ValueError("Invalid template admission decision or reason code.")
    operation = "decide_template_admission"
    command = _command(context, operation, (space_id, str(revision_ref), decision, str(basis_ref), reason_code))
    with connection.transaction():
        _scope(connection, context, space_id, operation, owner=False)
        selected = connection.execute(
            """
            SELECT template_key FROM thalion.compile_template_revision
            WHERE (org_id, space_id, revision_ref, reviewer_id) = (%s, %s, %s, %s)
            """,
            (context.org_id, space_id, revision_ref, context.principal_id),
        ).fetchone()
        if selected is None:
            raise TemplateNotAdmitted("Only the designated reviewer may decide this revision.")

        def apply(transaction):
            written = transaction.execute(
                """
                INSERT INTO thalion.compile_template_admission (
                    org_id, space_id, template_key, revision_ref, reviewer_id, decision, reason_code, basis_ref, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (revision_ref) DO NOTHING RETURNING revision_ref
                """,
                (context.org_id, space_id, selected[0], revision_ref, context.principal_id, decision,
                 reason_code, basis_ref, context.request_id),
            ).fetchone()
            if written is None:
                raise TemplateConflict("Template admission has already been decided.")
            return revision_ref

        execute_command(connection, command, apply)


def activate_template_revision(
    connection: Connection, context: TemplateWrite, space_id: int, revision_ref: UUID, expected_generation: int,
) -> int:
    if not 0 <= expected_generation < 2 ** 63 - 1:
        raise ValueError("Invalid template activation generation.")
    operation = "activate_template_revision"
    command = _command(context, operation, (space_id, str(revision_ref)), expected_generation or None)
    with connection.transaction():
        space_ref, _ = _scope(connection, context, space_id, operation, owner=True)
        approval = connection.execute(
            """
            SELECT template_key, reviewer_id FROM thalion.compile_template_admission
            WHERE (org_id, space_id, revision_ref) = (%s, %s, %s) AND decision = 'approved'
            """,
            (context.org_id, space_id, revision_ref),
        ).fetchone()
        if approval is None:
            raise TemplateNotAdmitted("Template revision does not have an approval in this space.")
        _require_independent_reviewer(connection, context, approval[1])
        family = (context.org_id, space_id, approval[0])

        def apply(transaction):
            transaction.execute(
                """
                SELECT 1 FROM thalion.compile_template
                WHERE (org_id, space_id, template_key) = (%s, %s, %s) FOR NO KEY UPDATE
                """,
                family,
            ).fetchone()
            current = transaction.execute(
                """
                SELECT coalesce(max(generation), 0) FROM thalion.compile_template_activation
                WHERE (org_id, space_id, template_key) = (%s, %s, %s)
                """,
                family,
            ).fetchone()[0]
            if current != expected_generation:
                raise TemplateConflict("The expected template generation is no longer current.")
            activation_ref = transaction.execute(
                """
                INSERT INTO thalion.compile_template_activation (
                    org_id, space_id, template_key, generation, revision_ref, activated_by, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING activation_ref
                """,
                (*family, current + 1, revision_ref, context.principal_id, context.request_id),
            ).fetchone()[0]
            append_event(transaction, context.org_id, "wiki.template_activated", space_ref, space_id=space_id)
            return activation_ref

        execute_command(connection, command, apply)
        return expected_generation + 1
