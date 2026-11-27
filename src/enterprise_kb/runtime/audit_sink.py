from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from typing import Any
from uuid import UUID

from enterprise_kb.ports.contracts import SecurityAuditLogPort, SecurityLogReceipt, SecurityLogUnavailable


FORBIDDEN_AUDIT_KEYS = frozenset({
    "content", "excerpt", "markdown", "password", "payload", "query", "secret", "text", "token",
})


@dataclass(frozen=True)
class SecurityAuditEvent:
    event_type: str
    request_id: UUID
    org_id: int
    space_ref: UUID
    actor_principal_id: int
    operation: str
    outcome: str
    resource_ref: str | None = None
    detail_digest: str | None = None
    occurred_at: datetime | None = None

    def to_sanitized_payload(self) -> dict[str, Any]:
        when = (self.occurred_at or datetime.now(UTC)).astimezone(UTC)
        payload: dict[str, Any] = {
            "event_type": self.event_type,
            "request_id": str(self.request_id),
            "org_id": self.org_id,
            "space_ref": str(self.space_ref),
            "actor_principal_id": self.actor_principal_id,
            "operation": self.operation,
            "outcome": self.outcome,
            "occurred_at": when.isoformat(),
        }
        if self.resource_ref is not None:
            payload["resource_ref"] = self.resource_ref
        if self.detail_digest is not None:
            payload["detail_digest"] = self.detail_digest
        if FORBIDDEN_AUDIT_KEYS & set(payload):
            raise ValueError("Forbidden sensitive field detected in security audit payload.")
        return payload


def metadata_digest(*parts: object) -> str:
    encoded = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
    return sha256(encoded).hexdigest()


class SecurityAuditDispatcher:
    """Dispatches metadata-only security events to an external SecurityAuditLogPort."""

    def __init__(self, port: SecurityAuditLogPort | None, *, strict: bool = False):
        if strict and port is None:
            raise SecurityLogUnavailable("Strict security audit dispatch requires a configured SecurityAuditLogPort.")
        self._port = port
        self._strict = strict
        self.last_receipt: SecurityLogReceipt | None = None
        self.failure_count: int = 0

    @property
    def enabled(self) -> bool:
        return self._port is not None

    @property
    def strict(self) -> bool:
        return self._strict

    def emit(self, event: SecurityAuditEvent) -> SecurityLogReceipt | None:
        if self._port is None:
            if self._strict:
                raise SecurityLogUnavailable("Security audit log port is missing in strict mode.")
            return None
        payload = event.to_sanitized_payload()
        try:
            receipt = self._port.append_restriction_receipt(event.space_ref, payload)
        except SecurityLogUnavailable:
            self.failure_count += 1
            if self._strict:
                raise
            return None
        self.last_receipt = receipt
        return receipt

    def verify_checkpoint(self, space_ref: UUID, expected_generation: int) -> bool:
        if self._port is None:
            if self._strict:
                raise SecurityLogUnavailable("Security audit log port is missing in strict mode.")
            return False
        return self._port.verify_checkpoint(space_ref, expected_generation)
