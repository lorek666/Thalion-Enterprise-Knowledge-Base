from hmac import compare_digest
from time import monotonic

import psycopg
from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest

from enterprise_kb.database import current_revisions, expected_head_revisions


LIVE = "/health/live"
READY = "/health/ready"
METRICS = "/metrics"
_EXCLUDED = frozenset({LIVE, READY, METRICS})
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_HEALTH_HEADERS = {"Cache-Control": "no-store"}


class RequestMetrics:
    def __init__(self):
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "thalion_http_requests_total", "Completed Thalion HTTP requests.", ("method", "route", "status"),
            registry=self.registry,
        )
        self.duration = Histogram(
            "thalion_http_request_duration_seconds", "Time to complete a Thalion HTTP response.", ("method", "route"),
            registry=self.registry,
        )


class MeasureRequests:
    def __init__(self, app, metrics: RequestMetrics):
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] in _EXCLUDED:
            await self.app(scope, receive, send)
            return
        method = scope["method"] if scope["method"] in _METHODS else "OTHER"
        status = 500
        started = monotonic()

        async def observed_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
        finally:
            route = getattr(scope.get("route"), "path", "unmatched")
            self.metrics.requests.labels(method, route, str(status)).inc()
            self.metrics.duration.labels(method, route).observe(monotonic() - started)


def register_observability(app, connect, *, metrics_token: str | None) -> None:
    expected = expected_head_revisions()

    @app.get(LIVE, include_in_schema=False)
    def live():
        return Response('{"status":"live"}', media_type="application/json", headers=_HEALTH_HEADERS)

    @app.get(READY, include_in_schema=False)
    def ready():
        try:
            with connect() as connection:
                is_ready = current_revisions(connection) == expected
        except psycopg.Error:
            is_ready = False
        return Response(
            '{"status":"ready"}' if is_ready else '{"status":"not_ready"}',
            status_code=200 if is_ready else 503, media_type="application/json", headers=_HEALTH_HEADERS,
        )

    if metrics_token is None:
        return
    expected_authorization = f"Bearer {metrics_token}".encode("ascii")
    metrics = RequestMetrics()
    app.add_middleware(MeasureRequests, metrics=metrics)

    @app.get(METRICS, include_in_schema=False)
    def scrape(request: Request):
        authorization = request.headers.getlist("authorization")
        if len(authorization) != 1 or not compare_digest(authorization[0].encode("latin-1"), expected_authorization):
            return Response(status_code=401, headers={**_HEALTH_HEADERS, "WWW-Authenticate": "Bearer"})
        return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST, headers=_HEALTH_HEADERS)
