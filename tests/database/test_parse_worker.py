from datetime import timedelta
import json
import subprocess
import sys
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.evidence.processing import ProcessingNotAdmitted, process_registered_version
from enterprise_kb.runtime.jobs import JobSpec, claim_job, enqueue_job

from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, transport
from test_feedback_work import admit
from test_holds import CAPABILITY as HOLD, decide
from test_ingest import MARKDOWN, item, run
from test_ingest_transport import DOCX, PDF, file, processing_status, upload
from test_runtime import runtime_db
from test_travel_search import corpus


def principal_ref(connection, principal_id):
    return connection.execute("""
        SELECT public_id FROM thalion.object_identity WHERE object_type = 'principal' AND object_id = %s
        """, (principal_id,)).fetchone()[0]


def invoke(database_url, root, version_ref, worker_ref, monkeypatch):
    monkeypatch.setenv("THALION_DATABASE_URL", database_url)
    return subprocess.run(
        [sys.executable, "-I", "-m", "enterprise_kb.parse_worker", "--originals", str(root),
         "--version-id", str(version_ref), "--processor-id", str(worker_ref)],
        capture_output=True, text=True, timeout=20, check=False,
    )


@pytest.fixture
def enrolled(evidence_db):
    connection, tenant, database_url, source_ref, store = evidence_db
    first, second = run(
        (connection, tenant, source_ref, store),
        item(MARKDOWN), item(MARKDOWN, object_key="synthetic-other"),
    )
    return connection, tenant, database_url, store, first, second


def test_runs_only_the_selected_registered_version_and_does_not_approve_it(enrolled, monkeypatch):
    connection, tenant, database_url, store, first, second = enrolled
    worker_ref = principal_ref(connection, tenant.other_worker_id)
    repair = enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, first.version_ref, "parse", first.digest, 2))
    result = invoke(database_url, store.root, first.version_ref, worker_ref, monkeypatch)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["state"] == "pending_review"
    assert connection.execute(
        "SELECT run_ref::text, outcome FROM thalion.processing_run",
    ).fetchall() == [(receipt["run_id"], "pending_review")]
    assert connection.execute("SELECT state, generation FROM thalion.job WHERE job_id = %s", (repair,)).fetchone() == ("queued", 0)
    assert connection.execute(
        "SELECT state, generation FROM thalion.job WHERE target_ref = %s", (second.version_ref,),
    ).fetchone() == ("queued", 0)
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
    repeated = invoke(database_url, store.root, first.version_ref, worker_ref, monkeypatch)
    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(repeated.stdout) == {"state": "already_processed", "run_id": receipt["run_id"]}
    assert connection.execute("SELECT count(*) FROM thalion.job_attempt").fetchone() == (1,)


@pytest.mark.parametrize("condition", ["wrong_processor", "disabled_processor", "unknown_version", "live_lease"])
def test_refuses_unadmitted_versions_and_never_steals_a_live_lease(enrolled, monkeypatch, condition):
    connection, tenant, database_url, store, first, _ = enrolled
    version_ref, processor_id = first.version_ref, tenant.other_worker_id
    if condition == "unknown_version":
        version_ref = uuid4()
    elif condition == "disabled_processor":
        connection.execute("UPDATE thalion.principal SET disabled = true WHERE principal_id = %s", (processor_id,))
    elif condition == "wrong_processor":
        processor_id = tenant.worker_id
    else:
        lease = claim_job(connection, tenant.org_id, "parse", processor_id, timedelta(minutes=1))
        version_ref = lease.spec.target_ref
    result = invoke(database_url, store.root, version_ref, principal_ref(connection, processor_id), monkeypatch)
    assert result.returncode == (2 if condition == "live_lease" else 1), result.stderr
    assert result.stderr.startswith("RETRY " if condition == "live_lease" else "FAIL ")
    assert result.stdout == ""
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.job_attempt").fetchone() == (int(condition == "live_lease"),)


def test_missing_registered_bytes_requeue_without_accepting_a_run(enrolled, monkeypatch):
    connection, tenant, database_url, store, first, _ = enrolled
    for entry in store.root.iterdir():
        entry.unlink()
    result = invoke(
        database_url, store.root, first.version_ref, principal_ref(connection, tenant.other_worker_id), monkeypatch,
    )
    assert result.returncode == 2, result.stderr
    assert connection.execute("""
        SELECT state, available_at > clock_timestamp() FROM thalion.job WHERE target_ref = %s
        """, (first.version_ref,)).fetchone() == ("queued", True)
    assert connection.execute("SELECT outcome FROM thalion.job_attempt").fetchone() == ("retry",)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)


@pytest.mark.parametrize(("suffix", "payload"), [("md", MARKDOWN), ("docx", DOCX), ("pdf", PDF)])
def test_uploaded_version_transitions_to_pending_review_through_the_worker(transport, monkeypatch, suffix, payload):
    if suffix == "pdf":
        pytest.importorskip("pypdfium2")
    client, db, (owner, _), credentials, *_ = transport
    connection, tenant, database_url, source_ref, store = db
    admit(credentials, owner, "upload_source_batch", "read_source_processing_status")
    opened = upload(client, owner, source_ref, [file(f"travel.{suffix}", "Travel rules", "A", "uploaded", payload)])
    assert opened.status_code == 200, opened.text
    version_id = opened.json()["files"][0]["version_id"]
    assert processing_status(client, owner, version_id).json()["state"] == "queued"
    result = invoke(database_url, store.root, version_id, principal_ref(connection, tenant.other_worker_id), monkeypatch)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state"] == "pending_review"
    assert processing_status(client, owner, version_id).json()["state"] == "pending_review"


def test_current_hold_blocks_a_queued_markdown_version_before_claiming(transport, monkeypatch):
    client, db, (owner, custodian), credentials, *_ = transport
    connection, tenant, database_url, source_ref, store = db
    admit(credentials, owner, "upload_source_batch", "read_source_processing_status")
    admit(credentials, custodian, HOLD)
    opened = upload(client, owner, source_ref, [file("travel.md", "Travel rules", "A", "held-upload", MARKDOWN)])
    assert opened.status_code == 200, opened.text
    version_id = opened.json()["files"][0]["version_id"]
    assert decide(client, custodian, version_id).status_code == 200
    assert processing_status(client, owner, version_id).json()["state"] == "blocked"
    worker_ref = principal_ref(connection, tenant.other_worker_id)
    refused = invoke(database_url, store.root, version_id, worker_ref, monkeypatch)
    assert refused.returncode == 1 and refused.stderr.startswith("FAIL ") and refused.stdout == ""
    assert connection.execute(
        "SELECT state, generation FROM thalion.job WHERE target_ref = %s", (version_id,),
    ).fetchone() == ("queued", 0)
    assert decide(client, custodian, version_id, action="release", generation=1).status_code == 200
    result = invoke(database_url, store.root, version_id, worker_ref, monkeypatch)
    assert result.returncode == 0, result.stderr
    assert processing_status(client, owner, version_id).json()["state"] == "pending_review"


def test_hold_established_during_original_read_prevents_accepting_a_run(transport, monkeypatch):
    client, db, (owner, custodian), credentials, *_ = transport
    connection, tenant, _, source_ref, store = db
    admit(credentials, owner, "upload_source_batch", "read_source_processing_status")
    admit(credentials, custodian, HOLD)
    opened = upload(client, owner, source_ref, [file("travel.md", "Travel rules", "A", "held-during-read", MARKDOWN)])
    assert opened.status_code == 200, opened.text
    version_ref = UUID(opened.json()["files"][0]["version_id"])
    worker_ref = principal_ref(connection, tenant.other_worker_id)
    read = store.read

    def establish_hold(asset):
        payload = read(asset)
        assert decide(client, custodian, version_ref).status_code == 200
        return payload

    monkeypatch.setattr(store, "read", establish_hold)
    with pytest.raises(ProcessingNotAdmitted, match="held original"):
        process_registered_version(connection, version_ref, worker_ref, store)
    assert connection.execute("""
        SELECT job.state, job.result_ref, attempt.outcome
        FROM thalion.job AS job JOIN thalion.job_attempt AS attempt USING (org_id, job_id)
        WHERE job.target_ref = %s
        """, (version_ref,)).fetchone() == ("queued", None, "retry")
    assert processing_status(client, owner, version_ref).json()["state"] == "blocked"
