from dataclasses import dataclass
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
import psycopg

from enterprise_kb.database import local_connection_factory
from enterprise_kb.transport.api import create_app
from enterprise_kb.transport.evidence import EvidenceReply

from test_runtime import runtime_db


def test_readiness_reports_connection_failure_and_schema_mismatch(runtime_db, independent_database_url):
    _, _, database_url = runtime_db
    service = SimpleNamespace(connect=local_connection_factory(database_url))
    with TestClient(create_app(service), base_url="http://127.0.0.1") as client:
        assert client.get("/health/ready").status_code == 200
        service.connect = local_connection_factory(independent_database_url)
        assert client.get("/health/ready").status_code == 503

        def unavailable():
            raise psycopg.OperationalError("private database configuration")

        service.connect = unavailable
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert "private database" not in response.text
        assert client.get("/health/live").status_code == 200
        assert client.get("/").status_code == 200


def test_metrics_use_route_templates_and_separate_scrape_token():
    token = "test-metrics-authentication-token-only"

    @dataclass(frozen=True)
    class Caller:
        ingress: str | None = None

    app = create_app(SimpleNamespace(
        identify=lambda _: Caller(), execute=lambda *_: EvidenceReply(uuid4(), 200, b"{}"),
    ), metrics_token=token)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/v1/passages/private-document?token=hidden-token", headers={
            "Authorization": f"Bearer {'a' * 40}",
        }).status_code == 200
        assert client.get("/unknown-private-path").status_code == 404
        metrics = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
        assert metrics.status_code == 200
        assert 'thalion_http_requests_total{method="GET",route="/v1/passages/{citation}",status="200"} 1.0' in metrics.text
        assert 'thalion_http_request_duration_seconds_count{method="GET",route="/v1/passages/{citation}"} 1.0' in metrics.text
        assert 'route="unmatched",status="404"' in metrics.text
        assert all(secret not in metrics.text for secret in (token, "private-document", "hidden-token", "unknown-private-path"))


def test_metrics_are_disabled_without_a_scrape_token():
    with TestClient(create_app(SimpleNamespace()), base_url="http://127.0.0.1") as client:
        assert client.get("/metrics").status_code == 404
