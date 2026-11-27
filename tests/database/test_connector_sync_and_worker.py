from base64 import b64encode
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
import subprocess
import sys
from threading import Event
from uuid import UUID, uuid4

import httpx2
import pytest

from enterprise_kb.modules.retrieval import vector
from enterprise_kb.modules.sources import connector_sync, source_revocations
from enterprise_kb.ports.adapters import HttpSecurityAuditLogAdapter, HttpSourceConnectorAdapter
from enterprise_kb.ports.contracts import ConnectorDeltaPage
from enterprise_kb.runtime.config import AuthenticatedEndpointConfig
from enterprise_kb.worker import WorkerConfig, run_worker_cycle, run_worker_loop

from enterprise_kb.modules.evidence import processing
from test_evidence import create_evidence_db
from test_sources import request_for
from test_runtime import open_database, runtime_db
from test_source_revocations import independent_authority


DOC_ONE = "# 差旅制度一\n\n上海住宿上限 600 元/晚。\n".encode("utf-8")
DOC_TWO = "# 差旅制度二\n\n北京高铁二等座按实报销。\n".encode("utf-8")


@pytest.fixture
def sync_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    return create_evidence_db(connection, tenant, database_url, tmp_path)


def test_connector_resumes_the_exact_vendor_cursor_on_a_fresh_connection(sync_db):
    connection, _, database_url, source_ref, store = sync_db
    calls = []

    class Connector:
        admission = "synthetic_local"

        def fetch_delta_page(self, ref, cursor):
            assert ref == source_ref
            calls.append(cursor)
            if len(calls) == 1:
                return ConnectorDeltaPage(None, "vendor-page=A+1/2", (), True)
            assert cursor == "vendor-page=A+1/2"
            return ConnectorDeltaPage(cursor, "vendor-page=B+2/3", (), False)

    before = connector_sync.sync_source_from_connector(connection, source_ref, Connector(), store, max_pages=1)
    assert before.pages_committed == 1
    with open_database(database_url) as fresh:
        after = connector_sync.sync_source_from_connector(fresh, source_ref, Connector(), store)
    assert calls == [None, "vendor-page=A+1/2"]
    assert after.pages_committed == 1
    assert after.content_position != before.content_position
    assert "vendor-page" not in json.dumps(after.to_dict())


def test_connector_keeps_the_page_pending_until_removal_is_confirmed(sync_db):
    connection, _, _, source_ref, store = sync_db
    event_ref, decision_ref = uuid4(), uuid4()

    class Connector:
        admission = "synthetic_local"

        def fetch_delta_page(self, ref, cursor):
            assert cursor is None
            return ConnectorDeltaPage(None, "vendor-unconfirmed-removal", ({
                "action": "deleted", "object_key": "doc-1", "version_key": "v1",
                "event_ref": str(event_ref), "decision_ref": str(decision_ref),
            },), False)

    for attempt in range(2):
        result = connector_sync.sync_source_from_connector(connection, source_ref, Connector(), store)
        assert result.status == "rejected" and result.pages_committed == 0
        assert result.content_position is None


def test_connector_sync_and_worker_full_automated_pipeline(sync_db, independent_authority, monkeypatch):
    monkeypatch.setenv("THALION_CONN_CRED", "conn-secret")
    monkeypatch.setenv("THALION_AUDIT_CRED", "audit-secret")

    connection, tenant, database_url, source_ref, store = sync_db
    cursor_1 = str(uuid4())
    cursor_2 = str(uuid4())
    snap_1 = str(uuid4())
    state = {
        "mode": "normal",
        "inventory_complete": True,
        "delta_calls": 0,
        "audit_events": [],
    }
    log_ref = uuid4()

    def connector_handler(request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path.endswith("/deltas"):
            state["delta_calls"] += 1
            if state["mode"] == "down":
                return httpx2.Response(503)
            cursor = request.url.params.get("cursor")
            if state["mode"] == "tampered":
                return httpx2.Response(
                    200,
                    json={
                        "through_cursor": str(uuid4()),
                        "has_more": False,
                        "items": [
                            {
                                "action": "upsert",
                                "object_key": "bad-doc",
                                "incarnation": "v1",
                                "source_version_key": "rev-bad",
                                "display_name": "篡改文档",
                                "version_label": "v1",
                                "media_type": "text/markdown",
                                "content_sha256": sha256(DOC_ONE).hexdigest(),
                                "content_base64": b64encode(b"tampered payload").decode("ascii"),
                            }
                        ],
                    },
                )
            if cursor is None:
                return httpx2.Response(
                    200,
                    json={
                        "through_cursor": cursor_1,
                        "has_more": True,
                        "items": [
                            {
                                "action": "upsert",
                                "object_key": "travel-doc-1",
                                "incarnation": "v1",
                                "source_version_key": "rev-1",
                                "display_name": "差旅制度一",
                                "version_label": "1.0",
                                "media_type": "text/markdown",
                                "content_sha256": sha256(DOC_ONE).hexdigest(),
                                "content_base64": b64encode(DOC_ONE).decode("ascii"),
                            }
                        ],
                    },
                )
            if cursor == cursor_1:
                return httpx2.Response(
                    200,
                    json={
                        "through_cursor": cursor_2,
                        "has_more": False,
                        "items": [
                            {
                                "action": "upsert",
                                "object_key": "travel-doc-2",
                                "incarnation": "v1",
                                "source_version_key": "rev-1",
                                "display_name": "差旅制度二",
                                "version_label": "1.0",
                                "media_type": "text/markdown",
                                "content_sha256": sha256(DOC_TWO).hexdigest(),
                                "download_ref": "obj-doc-2",
                            }
                        ],
                    },
                )
            return httpx2.Response(200, json={"through_cursor": cursor_2, "has_more": False, "items": []})

        if path.endswith("/objects/obj-doc-2"):
            return httpx2.Response(200, content=DOC_TWO)

        if path.endswith("/inventory"):
            return httpx2.Response(
                200,
                json={
                    "snapshot_ref": snap_1,
                    "observed_at": datetime.now(UTC).isoformat(),
                    "complete": state["inventory_complete"],
                    "stable_object_keys": ["travel-doc-1", "travel-doc-2"],
                    "entries": [
                        {
                            "object_key": "travel-doc-1",
                            "incarnation": "v1",
                            "source_version_key": "rev-1",
                            "content_sha256": sha256(DOC_ONE).hexdigest(),
                        },
                        {
                            "object_key": "travel-doc-2",
                            "incarnation": "v1",
                            "source_version_key": "rev-1",
                            "content_sha256": sha256(DOC_TWO).hexdigest(),
                        },
                    ],
                },
            )
        return httpx2.Response(404)

    def audit_handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        state["audit_events"].append(body)
        return httpx2.Response(
            200,
            json={
                "log_ref": str(log_ref),
                "stream_ref": str(uuid4()),
                "generation": len(state["audit_events"]),
                "recorded_at": datetime.now(UTC).isoformat(),
                "digest": sha256(request.content).hexdigest(),
            },
        )

    class _SyntheticHttpConnector(HttpSourceConnectorAdapter):
        admission = "synthetic_local"

    prod_connector = HttpSourceConnectorAdapter(
        AuthenticatedEndpointConfig("https://connector.corp.example/v1", "env:THALION_CONN_CRED"),
        source_system="corp-wiki",
        transport=httpx2.MockTransport(connector_handler),
    )
    with open_database(database_url) as conn:
        blocked = connector_sync.sync_source_from_connector(conn, source_ref, prod_connector, store)
    assert blocked.status == "source_not_admitted"

    connector = _SyntheticHttpConnector(
        AuthenticatedEndpointConfig("https://connector.corp.example/v1", "env:THALION_CONN_CRED"),
        source_system="corp-wiki",
        transport=httpx2.MockTransport(connector_handler),
    )
    audit_port = HttpSecurityAuditLogAdapter(
        AuthenticatedEndpointConfig("https://audit.corp.example/v1", "env:THALION_AUDIT_CRED"),
        log_ref=log_ref,
        transport=httpx2.MockTransport(audit_handler),
    )
    authority_conn, authority_url, authority_ref = independent_authority
    source_revocations.enroll_space(authority_conn, authority_ref, tenant.space_ref)
    revocation_authority = source_revocations.SourceRevocationAuthority(
        lambda: open_database(authority_url), authority_ref
    )
    embedding_provider = vector.resolve_synthetic_embedding_provider(vector.DEFAULT_MODEL_ID)

    # 1. Fail-closed on connector outage (503)
    state["mode"] = "down"
    with open_database(database_url) as conn:
        down_report = connector_sync.sync_source_from_connector(conn, source_ref, connector, store)
    assert down_report.status == "dependency_unavailable"
    assert down_report.pages_committed == 0
    assert down_report.content_position is None

    # 2. Fail-closed on tampered SHA-256 digest (cursor does NOT advance)
    state["mode"] = "tampered"
    with open_database(database_url) as conn:
        tampered_report = connector_sync.sync_source_from_connector(conn, source_ref, connector, store)
    assert tampered_report.status == "rejected"
    assert tampered_report.pages_committed == 0
    assert tampered_report.content_position is None

    # 3. Incomplete inventory rejected fail-closed while delta sync succeeds
    state["mode"] = "normal"
    state["inventory_complete"] = False
    worker_cfg = WorkerConfig(
        connect=lambda: open_database(database_url),
        store=store,
        connector=connector,
        revocation_authority=revocation_authority,
        embedding_provider=embedding_provider,
        security_audit_log=audit_port,
        reconcile_on_sync=True,
        interval_seconds=0.1,
    )
    cycle_1 = run_worker_cycle(worker_cfg)
    assert len(cycle_1.synced_sources) == 1
    sync_1 = cycle_1.synced_sources[0]
    assert sync_1["pages_committed"] == 2
    assert len(sync_1["versions_registered"]) == 2
    assert sync_1["reconciliation_status"] == "incomplete_inventory"
    assert sync_1["permission_checkpoint_id"] is not None
    # Both newly synced versions were automatically claimed & parsed in the same cycle!
    assert len(cycle_1.parsed_jobs) == 2
    assert all(j["outcome"] == "pending_review" for j in cycle_1.parsed_jobs)
    assert len(cycle_1.alerts) == 1

    # 4. Now complete inventory succeeds + record a revocation and verify catch-up + checkpoint advances
    state["inventory_complete"] = True
    employee_ref = connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = %s AND object_id = %s",
        ("principal", tenant.actor_id),
    ).fetchone()[0]
    first_version_ref = UUID(sync_1["versions_registered"][0])
    source_revocations.revoke(
        authority_conn,
        authority_ref,
        tenant.space_ref,
        employee_ref,
        first_version_ref,
        "evidence",
        basis_ref=uuid4(),
    )

    # Approve quality for both parsed runs so Cycle 2 automatically builds lexical + vector indices
    run_rows = connection.execute(
        "SELECT run_ref, manifest_digest FROM thalion.processing_run WHERE org_id = %s ORDER BY run_ref",
        (tenant.org_id,),
    ).fetchall()
    assert len(run_rows) == 2
    for run_ref, manifest_digest in run_rows:
        q_ctx = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "decide_evidence_quality")
        processing.decide_quality(
            connection, q_ctx, tenant.space_id, run_ref, bytes(manifest_digest), "approved", uuid4()
        )

    cycle_2 = run_worker_cycle(worker_cfg)
    assert cycle_2.errors == ()
    sync_2 = cycle_2.synced_sources[0]
    assert sync_2["pages_committed"] == 0
    assert len(sync_2["restrictions_acknowledged"]) == 1
    assert sync_2["permission_generation"] == 1
    assert sync_2["reconciliation_status"] == "reconciled"
    assert sync_2["reconciliation_matched"] == 2
    assert sync_2["reconciliation_differences"] == 0
    # Zero duplicate parse jobs
    assert cycle_2.parsed_jobs == ()
    # Both versions automatically indexed in lexical AND vector tables!
    assert len([x for x in cycle_2.lexical_indexed if x["status"] == "indexed"]) == 2
    assert len([x for x in cycle_2.vector_indexed if x["status"] == "indexed"]) == 2

    # 5. Cycle 3 via run_worker_loop(max_cycles=1) is 100% idempotent
    loop_reports = run_worker_loop(worker_cfg, stop_event=Event(), max_cycles=1)
    assert len(loop_reports) == 1
    rep3 = loop_reports[0]
    assert rep3.errors == ()
    assert rep3.synced_sources[0]["status"] == "up_to_date"
    assert rep3.synced_sources[0]["reconciliation_status"] == "up_to_date"
    assert rep3.parsed_jobs == ()
    assert rep3.lexical_indexed == ()
    assert rep3.vector_indexed == ()

    # 6. CLI `python -m enterprise_kb.worker --once` works end-to-end
    cli = subprocess.run(
        [
            sys.executable,
            "-m",
            "enterprise_kb.worker",
            "--once",
            "--originals",
            str(store.root),
            "--embedding-synthetic-model",
            vector.DEFAULT_MODEL_ID,
        ],
        env=os.environ | {"THALION_DATABASE_URL": database_url},
        capture_output=True,
        text=True,
        check=False,
    )
    assert cli.returncode == 0, cli.stderr
    cli_json = json.loads(cli.stdout)
    assert cli_json["errors"] == []
    assert len(cli_json["alerts"]) == 1
