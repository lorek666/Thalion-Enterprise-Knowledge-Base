from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import re
from secrets import token_urlsafe
from threading import Lock
from uuid import UUID

import psycopg

from enterprise_kb.ports.contracts import IdentityVerifierPort, VerifiedIdentity
from enterprise_kb.runtime.config import ConfigValidationError

from .evidence import CLIENT_PATTERN, CREDENTIAL_OPERATIONS, parse_ref
from .oidc_sso import OidcSsoError


SESSION_PREFIX = "thalion_sso_"
MAX_SESSIONS = 4096
SESSION_LIFETIME = timedelta(minutes=5)


@dataclass(frozen=True)
class _GroupGrant:
    space_ref: UUID
    operations: frozenset[str]


class OidcBrowserAccess:
    admission = "production_approved"

    def __init__(self, connect: Callable[[], psycopg.Connection], identity: IdentityVerifierPort, mapping: dict):
        self.issuer = identity.issuer
        self.audience = identity.audience
        self._connect = connect
        self._identity = identity
        if not isinstance(mapping, dict) or set(mapping) != {"issuer", "client_id", "group_claim", "groups"}:
            raise ConfigValidationError("OIDC access map must define issuer, client_id, group_claim and groups.")
        if mapping["issuer"] != self.issuer:
            raise ConfigValidationError("OIDC access map issuer must match the configured identity issuer.")
        client_id = mapping["client_id"]
        group_claim = mapping["group_claim"]
        if not isinstance(client_id, str) or not CLIENT_PATTERN.fullmatch(client_id):
            raise ConfigValidationError("OIDC access map has an invalid application client_id.")
        if not isinstance(group_claim, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}(?:\.[A-Za-z0-9_-]{1,64}){0,4}", group_claim):
            raise ConfigValidationError("OIDC access map has an invalid group claim path.")
        groups = mapping["groups"]
        if not isinstance(groups, dict) or not 1 <= len(groups) <= 1024:
            raise ConfigValidationError("OIDC access map must contain between 1 and 1024 groups.")
        grants = {}
        for group, grant in groups.items():
            if (
                not isinstance(group, str) or not 1 <= len(group) <= 255 or not group.strip()
                or not isinstance(grant, dict) or set(grant) != {"space_ref", "operations"}
            ):
                raise ConfigValidationError("OIDC access map contains an invalid group grant.")
            operations = grant["operations"]
            if (
                not isinstance(operations, list) or not operations
                or not all(isinstance(operation, str) and operation in CREDENTIAL_OPERATIONS for operation in operations)
                or not isinstance(grant["space_ref"], str)
            ):
                raise ConfigValidationError("OIDC access map must grant explicit, supported operations and a space UUID.")
            grants[group] = _GroupGrant(parse_ref(grant["space_ref"]), frozenset(operations))
        self._client_id = client_id
        self._claim_path = group_claim.split(".")
        self._grants = grants
        self._lock = Lock()
        self._sessions: dict[str, VerifiedIdentity] = {}

    def issue(self, claims: dict, _access_token: str | None) -> tuple[str, datetime]:
        subject = claims.get("sub")
        group_values = claims
        for segment in self._claim_path:
            group_values = group_values.get(segment) if isinstance(group_values, dict) else None
        refused = OidcSsoError("oidc_access_denied", "该企业账号没有知识库权限，请联系管理员。", 403)
        if (
            claims.get("iss") != self.issuer or not isinstance(subject, str) or not 1 <= len(subject) <= 255
            or not subject.isprintable() or not isinstance(group_values, list) or len(group_values) > 2048
            or not all(isinstance(group, str) for group in group_values)
        ):
            raise refused
        grants = [self._grants[group] for group in set(group_values) if group in self._grants]
        if not grants:
            raise refused
        try:
            with self._connect() as connection:
                rows = connection.execute("""
                    SELECT employee_ref.public_id, space_ref.public_id
                    FROM thalion.principal AS employee
                    JOIN thalion.object_identity AS employee_ref
                      ON (employee_ref.org_id, employee_ref.object_type, employee_ref.object_id)
                       = (employee.org_id, employee.identity_type, employee.principal_id)
                    JOIN thalion.space AS space ON space.org_id = employee.org_id
                    JOIN thalion.object_identity AS space_ref
                      ON (space_ref.org_id, space_ref.object_type, space_ref.object_id)
                       = (space.org_id, space.identity_type, space.space_id)
                    WHERE employee.authority_issuer = %s AND employee.authority_subject_key = %s
                      AND employee.principal_type = 'employee' AND NOT employee.disabled
                      AND space.lifecycle = 'active' AND space_ref.public_id = ANY(%s)
                    """, (self.issuer, subject, list({grant.space_ref for grant in grants}))).fetchall()
        except psycopg.Error:
            raise OidcSsoError("oidc_access_unavailable", "暂时无法核对知识库权限，请稍后再试。", 503) from None
        if len(rows) != 1:
            raise refused
        subject_ref, space_ref = rows[0]
        operations = frozenset(operation for grant in grants if grant.space_ref == space_ref for operation in grant.operations)
        now = datetime.now(UTC)
        expires_at = min(datetime.fromtimestamp(float(claims["exp"]), UTC), now + SESSION_LIFETIME)
        if expires_at <= now:
            raise OidcSsoError("oidc_invalid_token", "企业登录凭据已过期，请重新登录。", 401)
        token = SESSION_PREFIX + token_urlsafe(32)
        with self._lock:
            for expired in [key for key, session in self._sessions.items() if session.expires_at <= now]:
                del self._sessions[expired]
            if len(self._sessions) >= MAX_SESSIONS:
                raise OidcSsoError("sso_busy", "登录人数过多，请稍后重试。", 503)
            self._sessions[token] = VerifiedIdentity(self.issuer, subject_ref, space_ref, self._client_id, operations, expires_at)
        return token, expires_at

    def verify_bearer_token(self, token: str) -> VerifiedIdentity | None:
        if not token.startswith(SESSION_PREFIX):
            return self._identity.verify_bearer_token(token)
        with self._lock:
            session = self._sessions.get(token)
            if session is not None and session.expires_at <= datetime.now(UTC):
                del self._sessions[token]
                return None
            return session
