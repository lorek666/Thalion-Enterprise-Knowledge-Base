import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
import psycopg
from psycopg.pq import TransactionStatus
from sqlalchemy.exc import ArgumentError

from .database import local_connection_factory
from .ports.adapters import resolve_secret_ref
from .ports.contracts import PortUnavailable
from .runtime.config import _validate_https_url
from .runtime.events import OutboxEvent, append_event, consume_event
from .runtime.job_backlog import read_job_backlog


BLOCKERS = frozenset({"awaiting_external", "external_budget_blocked", "inconsistent", "lease_expired"})
STALL_AGE_MS = 3_600_000
_WEBHOOK_EVENTS = {
    f"runtime.backlog.{reason}.{state}": (reason, state)
    for reason in (*BLOCKERS, "stalled") for state in ("raised", "cleared")
}
_CONSUMER = "thalion-runtime-alert-webhook"


class AlertWebhook:
    def __init__(self, url: str, *, token: str | None = None, transport: httpx2.BaseTransport | None = None):
        self._url = _validate_https_url(url, "Alert webhook")
        if urlsplit(self._url).fragment or "#" in self._url:
            raise ValueError("Alert webhook URL cannot contain a fragment.")
        if token is not None and not re.fullmatch(r"[A-Za-z0-9_.~+/-]{1,512}={0,2}", token):
            raise ValueError("Alert webhook bearer token is invalid.")
        self._token = token
        self._transport = transport

    @classmethod
    def from_env(cls, env):
        url_ref = (env.get("THALION_ALERT_WEBHOOK_URL_REF") or "").strip()
        token_ref = (env.get("THALION_ALERT_WEBHOOK_TOKEN_REF") or "").strip()
        if not url_ref:
            if token_ref:
                raise ValueError("Alert webhook authentication requires a webhook URL reference.")
            return None
        return cls(
            resolve_secret_ref(url_ref, environ=env),
            token=resolve_secret_ref(token_ref, environ=env) if token_ref else None,
        )

    def send(self, event: OutboxEvent) -> None:
        reason, state = _WEBHOOK_EVENTS[event.event_type]
        event_id = str(event.event_id)
        headers = {"Idempotency-Key": event_id}
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            with httpx2.Client(timeout=4, follow_redirects=False, transport=self._transport, trust_env=False) as client:
                with client.stream("POST", self._url, headers=headers, json={
                    "event_id": event_id, "space_id": str(event.object_ref), "reason": reason,
                    "state": state, "occurred_at": event.occurred_at.isoformat(),
                }) as response:
                    if not 200 <= response.status_code < 300:
                        raise PortUnavailable("Alert webhook did not accept the event.")
        except (httpx2.HTTPError, ValueError):
            raise PortUnavailable("Alert webhook is unavailable.") from None


def deliver_pending(connection: psycopg.Connection, org_id: int, space_ref: UUID, webhook: AlertWebhook) -> int:
    if not connection.autocommit or connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Alert delivery requires an idle autocommit connection.")
    events = connection.execute("""
        SELECT event.event_id FROM thalion.outbox_event AS event
        WHERE event.org_id = %s AND event.object_ref = %s AND event.event_type = ANY(%s)
          AND NOT EXISTS (
            SELECT 1 FROM thalion.event_consumption AS receipt
            WHERE (receipt.org_id, receipt.event_id, receipt.consumer) = (event.org_id, event.event_id, %s)
          )
        ORDER BY event.occurred_at, event.event_id LIMIT 10
        """, (org_id, space_ref, list(_WEBHOOK_EVENTS), _CONSUMER)).fetchall()
    return sum(
        consume_event(connection, org_id, event_id, _CONSUMER, lambda _, event: webhook.send(event))
        for event_id, in events
    )


def _active_reasons(snapshot: dict) -> set[str]:
    succeeded = {row["stage"]: row["succeeded"] for row in snapshot["job_throughput_by_stage"]}
    reasons = set()
    for row in snapshot["job_backlog_by_stage"]:
        reasons.update(BLOCKERS.intersection(row["states"]))
        age = row["oldest_known_age_ms"]
        if age is not None and age >= STALL_AGE_MS and not succeeded.get(row["stage"], 0):
            reasons.add("stalled")
    return reasons


def poll(connection: psycopg.Connection, space_ref: UUID) -> dict:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Polling requires an independent write transaction.")
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        scope = connection.execute("""
            SELECT org_id, space_id FROM thalion.object_identity
            WHERE object_type = 'space' AND public_id = %s
        """, (space_ref,)).fetchone()
        if scope is None:
            raise ValueError("The alert scope is not registered.")
        org_id, space_id = scope
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"thalion.runtime.backlog:{space_ref}",),
        )
        snapshot = read_job_backlog(connection, org_id, space_id)
        active = _active_reasons(snapshot)
        previous = {row[0] for row in connection.execute("""
            SELECT reason FROM thalion.runtime_backlog_alert WHERE (org_id, space_id) = (%s, %s)
        """, scope)}
        raised, cleared = sorted(active - previous), sorted(previous - active)
        for reason in raised:
            connection.execute("""
                INSERT INTO thalion.runtime_backlog_alert (org_id, space_id, reason) VALUES (%s, %s, %s)
            """, (*scope, reason))
            append_event(connection, org_id, f"runtime.backlog.{reason}.raised", space_ref, space_id=space_id)
        if cleared:
            connection.execute("""
                DELETE FROM thalion.runtime_backlog_alert
                WHERE (org_id, space_id) = (%s, %s) AND reason = ANY(%s)
            """, (*scope, cleared))
            for reason in cleared:
                append_event(connection, org_id, f"runtime.backlog.{reason}.cleared", space_ref, space_id=space_id)
    return {
        "scope": "synthetic_space", "space_id": str(space_ref), "observed_at": snapshot["observed_at"],
        "active": sorted(active), "transitions": {"raised": raised, "cleared": cleared},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="巡检本机合成空间，将告警变化写入本地发件箱")
    parser.add_argument("--space-id", type=UUID, required=True)
    parser.add_argument("--synthetic", action="store_true", required=True)
    arguments = parser.parse_args()
    try:
        connect = local_connection_factory(os.environ.get("THALION_DATABASE_URL", ""))
        with connect() as connection:
            detail = poll(connection, arguments.space_id)
    except (ValueError, ArgumentError, psycopg.Error):
        print("FAIL 巡检未确认告警变化。请核对本机数据库、写入权限和空间。", file=sys.stderr)
        return 1
    print(json.dumps(detail, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
