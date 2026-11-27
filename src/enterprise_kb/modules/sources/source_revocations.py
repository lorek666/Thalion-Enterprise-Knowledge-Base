from collections.abc import Callable
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from psycopg import Connection, Error

from enterprise_kb.database import rehearsal_marker
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.sources.restriction_log import _log_ref, _require_idle


RevocationUse = Literal["evidence", "archive"]
MAX_REVOCATIONS = 1000


@dataclass(frozen=True)
class SourceRevocation:
    generation: int
    decision_ref: UUID
    employee_ref: UUID
    object_ref: UUID
    access_use: RevocationUse
    basis_ref: UUID
    recorded_at: datetime


@dataclass(frozen=True)
class SourceRevocationSnapshot:
    authority_ref: UUID
    space_ref: UUID
    stream_ref: UUID
    generation: int
    decisions: tuple[SourceRevocation, ...] = field(repr=False)

    def denied_objects(self, employee_ref: UUID, access_use: RevocationUse) -> frozenset[UUID]:
        return frozenset(
            event.object_ref for event in self.decisions
            if (event.employee_ref, event.access_use) == (employee_ref, access_use)
        )


def _check_authority(connection: Connection, authority_ref: UUID):
    if (
        connection.info.hostaddr not in {"127.0.0.1", "::1"}
        or rehearsal_marker(connection) is not None or _log_ref(connection) != authority_ref
        or connection.execute("SELECT 1 FROM thalion.organization LIMIT 1").fetchone() is not None
    ):
        raise AuthorizationUnavailable("The distinct synthetic source authority could not be verified.")


def enroll_space(connection: Connection, authority_ref: UUID, space_ref: UUID) -> UUID:
    """Enroll a space on the separate operator-controlled synthetic authority."""
    _require_idle(connection)
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        _check_authority(connection, authority_ref)
        connection.execute("""
            INSERT INTO thalion.source_revocation_stream (space_ref) VALUES (%s) ON CONFLICT (space_ref) DO NOTHING
            """, (space_ref,))
        return connection.execute(
            "SELECT stream_ref FROM thalion.source_revocation_stream WHERE space_ref = %s", (space_ref,),
        ).fetchone()[0]


def revoke(
    connection: Connection, authority_ref: UUID, space_ref: UUID,
    employee_ref: UUID, object_ref: UUID, access_use: RevocationUse, *, basis_ref: UUID,
) -> SourceRevocation:
    """Record an absorbing scoped denial. This interface never grants any rights."""
    if access_use not in {"evidence", "archive"}:
        raise ValueError("Unsupported synthetic source revocation scope.")
    _require_idle(connection)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        _check_authority(connection, authority_ref)
        head = connection.execute("""
            SELECT generation FROM thalion.source_revocation_stream WHERE space_ref = %s FOR UPDATE
            """, (space_ref,)).fetchone()
        if head is None:
            raise AuthorizationUnavailable("The requested source authority scope is not enrolled.")
        existing = connection.execute("""
            SELECT generation, decision_ref, employee_ref, object_ref, access_use, basis_ref, recorded_at
            FROM thalion.source_revocation_event
            WHERE (space_ref, employee_ref, object_ref, access_use) = (%s, %s, %s, %s)
            """, (space_ref, employee_ref, object_ref, access_use)).fetchone()
        if existing is not None:
            return SourceRevocation(*existing)
        return SourceRevocation(*connection.execute("""
            INSERT INTO thalion.source_revocation_event
                (space_ref, generation, employee_ref, object_ref, access_use, basis_ref)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING generation, decision_ref, employee_ref, object_ref, access_use, basis_ref, recorded_at
            """, (space_ref, head[0] + 1, employee_ref, object_ref, access_use, basis_ref)).fetchone())


@dataclass(frozen=True)
class SourceRevocationAuthority:
    connect: Callable[[], Connection] = field(repr=False)
    authority_ref: UUID

    def validate(self):
        try:
            with self.connect() as connection:
                _require_idle(connection)
                _check_authority(connection, self.authority_ref)
                connection.execute("SELECT generation FROM thalion.source_revocation_stream LIMIT 0")
        except (Error, RuntimeError):
            raise AuthorizationUnavailable("The configured synthetic source authority is unavailable.") from None

    def snapshot(self, space_ref: UUID) -> SourceRevocationSnapshot:
        try:
            with self.pinned_snapshot(space_ref) as snapshot:
                return snapshot
        except (Error, RuntimeError):
            raise AuthorizationUnavailable("Current synthetic source revocations could not be verified.") from None

    @contextmanager
    def pinned_snapshot(self, space_ref: UUID):
        with ExitStack() as stack:
            try:
                connection = stack.enter_context(self.connect())
                _require_idle(connection)
                stack.enter_context(connection.transaction())
                connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                connection.execute("SET LOCAL lock_timeout = '3s'")
                _check_authority(connection, self.authority_ref)
                head = connection.execute("""
                    SELECT stream_ref, generation FROM thalion.source_revocation_stream
                    WHERE space_ref = %s FOR SHARE
                    """, (space_ref,)).fetchone()
                if head is None or head[1] > MAX_REVOCATIONS:
                    raise AuthorizationUnavailable("The synthetic source revocation history is missing or exceeds its limit.")
                stream_ref, generation = head
                rows = connection.execute("""
                    SELECT generation, decision_ref, employee_ref, object_ref, access_use, basis_ref, recorded_at
                    FROM thalion.source_revocation_event WHERE space_ref = %s ORDER BY generation LIMIT %s
                    """, (space_ref, generation + 1)).fetchall()
                if len(rows) != generation or any(row[0] != sequence for sequence, row in enumerate(rows, 1)):
                    raise AuthorizationUnavailable("The synthetic source revocation history is incomplete.")
            except (Error, RuntimeError):
                raise AuthorizationUnavailable("Current synthetic source revocations could not be verified.") from None
            yield SourceRevocationSnapshot(
                self.authority_ref, space_ref, stream_ref, generation, tuple(SourceRevocation(*row) for row in rows),
            )
