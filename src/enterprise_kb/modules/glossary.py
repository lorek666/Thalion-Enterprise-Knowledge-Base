from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Literal
from uuid import UUID

from psycopg import Connection, errors

from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import _require_read_committed


LIST = "list_glossary"
UPSERT = "upsert_glossary_entry"
SET_STATUS = "set_glossary_status"
OPERATIONS = frozenset({LIST, UPSERT, SET_STATUS})
DESTINATION = "internal_glossary"

GlossaryStatus = Literal["active", "inactive"]
MAX_SYNONYMS = 32
MAX_EXPANDED_TERMS = 64
TERM_TOKEN = re.compile(r"[^\W_]+")


class GlossaryNotAdmitted(Exception):
    pass


class GlossaryNotFound(Exception):
    pass


class GlossaryConflict(Exception):
    pass


@dataclass(frozen=True)
class GlossaryWrite:
    org_id: int
    request_id: UUID
    principal_id: int
    idempotency_key: str


@dataclass(frozen=True)
class GlossaryEntry:
    entry_ref: UUID
    term: str
    synonyms: tuple[str, ...]
    definition: str
    status: GlossaryStatus
    revision: int
    updated_at: datetime

    def to_dict(self) -> dict:
        return {
            "entry_id": str(self.entry_ref),
            "term": self.term,
            "synonyms": list(self.synonyms),
            "definition": self.definition,
            "status": self.status,
            "revision": self.revision,
            "updated_at": self.updated_at.isoformat(),
        }


def _digest(*parts) -> bytes:
    payload = json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return sha256(payload).digest()


def _clean_text(value: str, label: str, max_len: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Invalid {label}.")
    cleaned = value.strip()
    if not 1 <= len(cleaned) <= max_len:
        raise ValueError(f"{label} length must be between 1 and {max_len}.")
    if any(not ch.isprintable() and ch not in "\n\t" for ch in cleaned):
        raise ValueError(f"{label} contains control characters.")
    return cleaned


def _clean_synonyms(raw: list[str] | tuple[str, ...], normalized_term: str) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)) or len(raw) > MAX_SYNONYMS:
        raise ValueError("Invalid synonyms list.")
    seen = {normalized_term}
    cleaned: list[str] = []
    for item in raw:
        text = _clean_text(item, "synonym", 120)
        norm = lexical.normalize_text(text)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        cleaned.append(text)
    return tuple(cleaned)


def _require_space_actor(connection: Connection, org_id: int, space_id: int, principal_id: int, request_id: UUID, operation: str):
    _require_read_committed(connection)
    require_open_request(connection, org_id, request_id, principal_id, None, operation=operation)
    row = connection.execute(
        """
        SELECT org.config_revision, space_id_ref.public_id
        FROM thalion.space AS space
        JOIN thalion.organization AS org USING (org_id)
        JOIN thalion.object_identity AS space_id_ref
          ON (space_id_ref.org_id, space_id_ref.space_id, space_id_ref.object_type, space_id_ref.object_id)
           = (space.org_id, space.space_id, 'space', space.space_id)
        JOIN thalion.principal AS actor ON actor.org_id = space.org_id
        WHERE (space.org_id, space.space_id) = (%s, %s)
          AND space.lifecycle = 'active'
          AND actor.principal_id = %s
          AND actor.principal_type = 'employee'
          AND NOT actor.disabled
        FOR SHARE OF space, org, actor
        """,
        (org_id, space_id, principal_id),
    ).fetchone()
    if row is None:
        raise GlossaryNotAdmitted("An active space and active employee actor are required for glossary operations.")
    return row[0], row[1]


def _row_to_entry(row) -> GlossaryEntry:
    return GlossaryEntry(
        entry_ref=row[0],
        term=row[1],
        synonyms=tuple(row[2] or ()),
        definition=row[3],
        status=row[4],
        revision=row[5],
        updated_at=row[6],
    )


def list_entries(
    connection: Connection,
    org_id: int,
    space_id: int,
    *,
    include_inactive: bool = True,
    query: str | None = None,
) -> tuple[GlossaryEntry, ...]:
    clauses = ["org_id = %s", "space_id = %s"]
    params: list = [org_id, space_id]
    if not include_inactive:
        clauses.append("status = 'active'")
    rows = connection.execute(
        f"""
        SELECT entry_ref, term, synonyms, definition, status, revision, updated_at
        FROM thalion.glossary_entry
        WHERE {' AND '.join(clauses)}
        ORDER BY status ASC, normalized_term ASC, entry_ref ASC
        """,
        tuple(params),
    ).fetchall()
    entries = tuple(_row_to_entry(row) for row in rows)
    if query:
        needle = lexical.normalize_text(query)
        if needle:
            entries = tuple(
                entry for entry in entries
                if needle in lexical.normalize_text(entry.term)
                or needle in lexical.normalize_text(entry.definition)
                or any(needle in lexical.normalize_text(syn) for syn in entry.synonyms)
            )
    return entries


def create_entry(
    connection: Connection,
    context: GlossaryWrite,
    space_id: int,
    *,
    term: str,
    synonyms: list[str] | tuple[str, ...],
    definition: str,
) -> GlossaryEntry:
    cleaned_term = _clean_text(term, "term", 120)
    normalized = lexical.normalize_text(cleaned_term)
    if not normalized or len(normalized) > 120:
        raise ValueError("Invalid normalized term.")
    cleaned_synonyms = _clean_synonyms(synonyms, normalized)
    cleaned_definition = _clean_text(definition, "definition", 2000)

    digest = _digest("glossary.create.v1", space_id, normalized, list(cleaned_synonyms), cleaned_definition)
    with connection.transaction():
        config_rev, space_ref = _require_space_actor(connection, context.org_id, space_id, context.principal_id, context.request_id, UPSERT)

        def apply(tx):
            try:
                row = tx.execute(
                    """
                    INSERT INTO thalion.glossary_entry (
                        org_id, space_id, term, normalized_term, synonyms, definition,
                        status, revision, created_by, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'active', 1, %s, %s)
                    RETURNING entry_ref, term, synonyms, definition, status, revision, updated_at
                    """,
                    (
                        context.org_id, space_id, cleaned_term, normalized, list(cleaned_synonyms),
                        cleaned_definition, context.principal_id, context.principal_id,
                    ),
                ).fetchone()
            except errors.UniqueViolation:
                raise GlossaryConflict("A glossary entry with this normalized term already exists in this space.") from None
            entry = _row_to_entry(row)
            tx.execute(
                """
                INSERT INTO thalion.glossary_audit_event (
                    org_id, space_id, entry_ref, revision, action, term, synonyms,
                    definition, status, actor_id, request_id
                ) VALUES (%s, %s, %s, %s, 'created', %s, %s, %s, %s, %s, %s)
                """,
                (
                    context.org_id, space_id, entry.entry_ref, entry.revision, entry.term,
                    list(entry.synonyms), entry.definition, entry.status, context.principal_id, context.request_id,
                ),
            )
            append_event(tx, context.org_id, "glossary.entry.created", space_ref, space_id=space_id)
            return entry.entry_ref

        receipt = execute_command(
            connection,
            CommandEnvelope(
                context.org_id, context.principal_id, None, context.request_id,
                UPSERT, f"glossary:{space_id}:create:{context.idempotency_key}",
                digest, config_rev, None,
            ),
            apply,
        )
        row = connection.execute(
            """
            SELECT entry_ref, term, synonyms, definition, status, revision, updated_at
            FROM thalion.glossary_entry
            WHERE (org_id, space_id, entry_ref) = (%s, %s, %s)
            """,
            (context.org_id, space_id, receipt.result_ref),
        ).fetchone()
        return _row_to_entry(row)


def update_entry(
    connection: Connection,
    context: GlossaryWrite,
    space_id: int,
    entry_ref: UUID,
    *,
    term: str,
    synonyms: list[str] | tuple[str, ...],
    definition: str,
) -> GlossaryEntry:
    cleaned_term = _clean_text(term, "term", 120)
    normalized = lexical.normalize_text(cleaned_term)
    if not normalized or len(normalized) > 120:
        raise ValueError("Invalid normalized term.")
    cleaned_synonyms = _clean_synonyms(synonyms, normalized)
    cleaned_definition = _clean_text(definition, "definition", 2000)

    digest = _digest("glossary.update.v1", space_id, str(entry_ref), normalized, list(cleaned_synonyms), cleaned_definition)
    with connection.transaction():
        config_rev, space_ref = _require_space_actor(connection, context.org_id, space_id, context.principal_id, context.request_id, UPSERT)

        def apply(tx):
            existing = tx.execute(
                """
                SELECT revision, status FROM thalion.glossary_entry
                WHERE (org_id, space_id, entry_ref) = (%s, %s, %s)
                FOR UPDATE
                """,
                (context.org_id, space_id, entry_ref),
            ).fetchone()
            if existing is None:
                raise GlossaryNotFound("Glossary entry not found.")
            try:
                row = tx.execute(
                    """
                    UPDATE thalion.glossary_entry
                    SET term = %s, normalized_term = %s, synonyms = %s, definition = %s,
                        revision = revision + 1, updated_by = %s, updated_at = clock_timestamp()
                    WHERE (org_id, space_id, entry_ref) = (%s, %s, %s)
                    RETURNING entry_ref, term, synonyms, definition, status, revision, updated_at
                    """,
                    (
                        cleaned_term, normalized, list(cleaned_synonyms), cleaned_definition,
                        context.principal_id, context.org_id, space_id, entry_ref,
                    ),
                ).fetchone()
            except errors.UniqueViolation:
                raise GlossaryConflict("Another glossary entry already uses this term.") from None
            entry = _row_to_entry(row)
            tx.execute(
                """
                INSERT INTO thalion.glossary_audit_event (
                    org_id, space_id, entry_ref, revision, action, term, synonyms,
                    definition, status, actor_id, request_id
                ) VALUES (%s, %s, %s, %s, 'updated', %s, %s, %s, %s, %s, %s)
                """,
                (
                    context.org_id, space_id, entry.entry_ref, entry.revision, entry.term,
                    list(entry.synonyms), entry.definition, entry.status, context.principal_id, context.request_id,
                ),
            )
            append_event(tx, context.org_id, "glossary.entry.updated", space_ref, space_id=space_id)
            return entry.entry_ref

        execute_command(
            connection,
            CommandEnvelope(
                context.org_id, context.principal_id, None, context.request_id,
                UPSERT, f"glossary:{space_id}:update:{entry_ref}:{context.idempotency_key}",
                digest, config_rev, None,
            ),
            apply,
        )
        row = connection.execute(
            """
            SELECT entry_ref, term, synonyms, definition, status, revision, updated_at
            FROM thalion.glossary_entry
            WHERE (org_id, space_id, entry_ref) = (%s, %s, %s)
            """,
            (context.org_id, space_id, entry_ref),
        ).fetchone()
        return _row_to_entry(row)


def set_entry_status(
    connection: Connection,
    context: GlossaryWrite,
    space_id: int,
    entry_ref: UUID,
    status: GlossaryStatus,
) -> GlossaryEntry:
    if status not in ("active", "inactive"):
        raise ValueError("Glossary status must be 'active' or 'inactive'.")
    digest = _digest("glossary.status.v1", space_id, str(entry_ref), status)
    with connection.transaction():
        config_rev, space_ref = _require_space_actor(connection, context.org_id, space_id, context.principal_id, context.request_id, SET_STATUS)

        def apply(tx):
            existing = tx.execute(
                """
                SELECT status FROM thalion.glossary_entry
                WHERE (org_id, space_id, entry_ref) = (%s, %s, %s)
                FOR UPDATE
                """,
                (context.org_id, space_id, entry_ref),
            ).fetchone()
            if existing is None:
                raise GlossaryNotFound("Glossary entry not found.")
            row = tx.execute(
                """
                UPDATE thalion.glossary_entry
                SET status = %s, revision = revision + 1, updated_by = %s, updated_at = clock_timestamp()
                WHERE (org_id, space_id, entry_ref) = (%s, %s, %s)
                RETURNING entry_ref, term, synonyms, definition, status, revision, updated_at
                """,
                (status, context.principal_id, context.org_id, space_id, entry_ref),
            ).fetchone()
            entry = _row_to_entry(row)
            action = "deactivated" if status == "inactive" else "reactivated"
            tx.execute(
                """
                INSERT INTO thalion.glossary_audit_event (
                    org_id, space_id, entry_ref, revision, action, term, synonyms,
                    definition, status, actor_id, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    context.org_id, space_id, entry.entry_ref, entry.revision, action, entry.term,
                    list(entry.synonyms), entry.definition, entry.status, context.principal_id, context.request_id,
                ),
            )
            append_event(tx, context.org_id, f"glossary.entry.{action}", space_ref, space_id=space_id)
            return entry.entry_ref

        execute_command(
            connection,
            CommandEnvelope(
                context.org_id, context.principal_id, None, context.request_id,
                SET_STATUS, f"glossary:{space_id}:status:{entry_ref}:{context.idempotency_key}",
                digest, config_rev, None,
            ),
            apply,
        )
        row = connection.execute(
            """
            SELECT entry_ref, term, synonyms, definition, status, revision, updated_at
            FROM thalion.glossary_entry
            WHERE (org_id, space_id, entry_ref) = (%s, %s, %s)
            """,
            (context.org_id, space_id, entry_ref),
        ).fetchone()
        return _row_to_entry(row)


def expand_query_terms(
    connection: Connection,
    org_id: int,
    space_id: int,
    raw_query: str,
    base_terms: frozenset[str],
    *,
    max_terms: int = MAX_EXPANDED_TERMS,
) -> tuple[frozenset[str], str]:
    rows = connection.execute(
        """
        SELECT term, normalized_term, synonyms
        FROM thalion.glossary_entry
        WHERE (org_id, space_id, status) = (%s, %s, 'active')
        ORDER BY normalized_term ASC
        """,
        (org_id, space_id),
    ).fetchall()
    if not rows:
        return base_terms, raw_query

    normalized_query = lexical.normalize_text(raw_query)
    expanded: set[str] = set(base_terms)
    added_phrases: list[str] = []
    seen_phrases: set[str] = set()

    for term, normalized_term, synonyms in rows:
        variants = [term, *(synonyms or ())]
        normalized_variants = [normalized_term] + [lexical.normalize_text(s) for s in (synonyms or ())]
        matched = False
        for norm_var in normalized_variants:
            if not norm_var:
                continue
            if norm_var in base_terms or norm_var in normalized_query:
                matched = True
                break
        if not matched:
            continue
        for variant in variants:
            norm_var = lexical.normalize_text(variant)
            if norm_var and norm_var not in seen_phrases and norm_var not in normalized_query:
                seen_phrases.add(norm_var)
                added_phrases.append(variant)
            for token in TERM_TOKEN.findall(norm_var):
                if len(expanded) >= max_terms:
                    break
                expanded.add(token)
        if len(expanded) >= max_terms:
            break

    if not added_phrases and expanded == base_terms:
        return base_terms, raw_query
    enriched_query = f"{raw_query} {' '.join(added_phrases)}".strip() if added_phrases else raw_query
    return frozenset(expanded), enriched_query
