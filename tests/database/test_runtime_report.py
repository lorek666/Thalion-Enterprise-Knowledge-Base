from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
import subprocess
import sys
from uuid import uuid4

import psycopg
import pytest

from enterprise_kb import runtime_report
from enterprise_kb.database import upgrade
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity, registry
from enterprise_kb.modules.wiki import management
from enterprise_kb.runtime import external
from enterprise_kb.runtime.audit import finish_request
from enterprise_kb.runtime.jobs import JobSpec, claim_job, complete_job, enqueue_job, retry_job

from test_effectivity import BEGIN, approve, record
from test_evidence import claim, create_evidence_db, evidence_db, review
from test_evidence_transport import evidence_transport, transport
from test_external_calls import dispatch, expire, reserve
from test_feedback_work import admit
from test_holds import decide
from test_identity import migrate_to_revision, space
from test_pdf_correction import TRANSCRIPT, propose, view
from test_pdf_correction_review import decide as decide_correction, preview as preview_correction, stage_review
from test_pdf_repair import repair_lease
from test_pdf_review import EmptyScan, pdf_review
from test_persisted_access import set_rules
from test_runtime import LEASE_FOR, open_database, register_tenant, runtime_db, spec_for
from test_sources import register, request_for
from test_travel_search import corpus, publish
from test_wiki_drafts import candidate, preview, submit, workspace
from test_wiki_inputs import assemble, compile_rule
from test_wiki_invalidation import version_ref
from test_wiki_publication import approve as approve_wiki, authorize, configure


def run_report(database_url, space_ref, start, end):
    return subprocess.run([
        sys.executable, "-I", "-m", "enterprise_kb.runtime_report", "--space-id", str(space_ref),
        "--start", start.isoformat(), "--end", end.isoformat(),
    ], env=os.environ | {"THALION_DATABASE_URL": database_url}, capture_output=True, text=True, check=False)


def report(database_url, tenant, start, end):
    result = run_report(database_url, tenant.space_ref, start, end)
    assert result.returncode == 0 and not result.stderr, result.stderr
    return json.loads(result.stdout)


def backlog_states(snapshot):
    rows = snapshot["job_backlog_by_stage"]
    assert all(row["unknown_enqueue_time"] == 0 and row["oldest_known_age_ms"] >= 0 for row in rows)
    return [{key: row[key] for key in ("stage", "unfinished", "states", "next_retry_at")} for row in rows]


def register_request(connection, tenant, space_id, started_at, outcome=None, elapsed_ms=None, *, ingress="http"):
    request_id = uuid4()
    connection.execute("""
        INSERT INTO thalion.request_record (
            org_id, request_id, principal_id, client_id, operation, destination,
            business_date, configuration_revision, scope_space_id, started_at, ingress
        )
        VALUES (%s, %s, %s, 'synthetic-private-client', 'search', 'employee', '2026-11-21', 1, %s, %s, %s)
    """, (tenant.org_id, request_id, tenant.actor_id, space_id, started_at, ingress))
    if outcome is not None:
        assert finish_request(connection, tenant.org_id, request_id, outcome, elapsed_ms)
    return request_id


def test_report_counts_scoped_request_cohort_and_only_success_latencies(runtime_db):
    connection, tenant, url = runtime_db
    other = register_tenant(connection, "Other organization")
    with connection.transaction():
        other_space, _ = space(connection, tenant.org_id, tenant.actor_id)
    end, = connection.execute("SELECT clock_timestamp() - interval '1 minute'").fetchone()
    start = end - timedelta(minutes=20)
    request_id = register_request(connection, tenant, tenant.space_id, start, "succeeded", 3)
    register_request(connection, tenant, tenant.space_id, start, "succeeded", 200)
    register_request(connection, tenant, tenant.space_id, start, "dependency_unavailable", 9000)
    register_request(connection, tenant, tenant.space_id, start, "no_evidence", 700)
    register_request(connection, tenant, tenant.space_id, start)
    register_request(connection, tenant, tenant.space_id, start, "rejected", 7, ingress="mcp")
    register_request(connection, tenant, tenant.space_id, start, "failed", 8, ingress="unknown")
    register_request(connection, tenant, tenant.space_id, end, "succeeded", 999)
    register_request(connection, tenant, tenant.space_id, start - timedelta(microseconds=1))
    register_request(connection, tenant, other_space, start)
    register_request(connection, tenant, None, start)
    register_request(connection, other, other.space_id, start)

    result = report(url, tenant, start, end)
    assert result["scope"] == "synthetic_space"
    assert result["registered_requests"] == 7
    assert result["unfinished_requests"] == 1
    http, mcp, unknown = result["requests_by_ingress_operation_destination"]
    assert http["operation"] == "search" and http["destination"] == "employee" and http["ingress"] == "http"
    assert http["registered"] == 5
    assert http["outcomes"] == {"succeeded": 2, "dependency_unavailable": 1, "no_evidence": 1, "unfinished": 1}
    assert http["success_ledger_elapsed_ms"] == {"p50": 3, "p95": 200, "p99": 200}
    assert http["oldest_unfinished_age_ms"] >= 21 * 60 * 1000
    assert mcp == {
        "operation": "search", "destination": "employee", "ingress": "mcp",
        "registered": 1, "outcomes": {"rejected": 1},
        "success_ledger_elapsed_ms": None, "oldest_unfinished_age_ms": None,
    }
    assert unknown["ingress"] == "unknown" and unknown["outcomes"] == {"failed": 1}
    assert result["external_calls_by_currency"] == []
    assert result["job_backlog_by_stage"] == []
    assert result["quality_review_backlog"] == {"pending_review": 0}
    assert result["ocr_correction_backlog"] == {"pending_pages": 0}
    assert result["wiki_review_backlog"] == {"awaiting_review": 0, "approved": 0, "rejected": 0, "stale": 0}
    assert str(request_id) not in json.dumps(result) and "synthetic-private-client" not in json.dumps(result)
    assert report(url, tenant, start - timedelta(hours=1), start - timedelta(minutes=1))["registered_requests"] == 0


def external_reservation(connection, tenant, label, currency="CNY"):
    external.enqueue_external_job(connection, spec_for(tenant, label), external.CallBudget(currency, 500, 2))
    lease = claim_job(connection, tenant.org_id, label, tenant.worker_id, LEASE_FOR)
    return lease, reserve(connection, lease, maximum=100)


def seed_job(connection, spec, enqueued_at):
    return connection.execute("""
        INSERT INTO thalion.job (org_id, space_id, target_ref, stage, input_digest, configuration_revision, enqueued_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING job_id
    """, (spec.org_id, spec.space_id, spec.target_ref, spec.stage, spec.input_digest,
          spec.configuration_revision, enqueued_at)).fetchone()[0]


def test_job_enqueue_timestamp_survives_upgrade_deduplication_and_retry(database_url):
    migrate_to_revision(database_url, "0094_request_ingress")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Pre-migration jobs")
        old = enqueue_job(connection, spec_for(tenant, "legacy"))
        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        spec = spec_for(tenant)
        before, = connection.execute("SELECT clock_timestamp()").fetchone()
        job_id = enqueue_job(connection, spec)
        assert enqueue_job(connection, spec) == job_id
        lease = claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR)
        retry_job(connection, lease, delay=timedelta(hours=2))
        recorded, available = connection.execute("""
            SELECT enqueued_at, available_at FROM thalion.job WHERE job_id = %s
        """, (job_id,)).fetchone()
        assert before <= recorded < available - timedelta(hours=1)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            connection.execute("UPDATE thalion.job SET enqueued_at = NULL WHERE job_id = %s", (job_id,))
        end, = connection.execute("SELECT clock_timestamp()").fetchone()
        snapshot = runtime_report.observe(connection, tenant.space_ref, before, end)
        assert connection.execute("SELECT enqueued_at FROM thalion.job WHERE job_id = %s", (old,)).fetchone() == (None,)
        legacy, pending = snapshot["job_backlog_by_stage"]
        assert legacy["unknown_enqueue_time"] == 1 and legacy["oldest_known_age_ms"] is None
        assert pending["unknown_enqueue_time"] == 0 and 0 <= pending["oldest_known_age_ms"] < 60_000
        assert snapshot["job_throughput_by_stage"] == [{"stage": "parse", "enqueued": 1, "succeeded": 0}]


def test_job_throughput_uses_event_windows_and_current_success_only(runtime_db):
    connection, tenant, _ = runtime_db
    outsider = register_tenant(connection, "Other throughput tenant")
    with connection.transaction():
        other_space, other_ref = space(connection, tenant.org_id, tenant.actor_id)
    other = replace(tenant, space_id=other_space, space_ref=other_ref)
    end, = connection.execute("SELECT clock_timestamp() - interval '5 minutes'").fetchone()
    start = end - timedelta(hours=1)
    earlier = start - timedelta(microseconds=1)
    spec = spec_for(tenant)

    def complete_at(owner, task, enqueued, finished, *, retry=False):
        job_id = seed_job(connection, task, enqueued)
        lease = claim_job(connection, owner.org_id, task.stage, owner.worker_id, LEASE_FOR, job_id=job_id)
        if retry:
            retry_job(connection, lease, delay=timedelta(0))
            connection.execute("""
                UPDATE thalion.job_attempt SET outcome = 'succeeded', finished_at = %s WHERE attempt_id = %s
            """, (start, lease.attempt_id))
            lease = claim_job(connection, owner.org_id, task.stage, owner.worker_id, LEASE_FOR, job_id=job_id)
        complete_job(connection, lease, lambda tx: owner.space_ref)
        connection.execute("UPDATE thalion.job_attempt SET finished_at = %s WHERE attempt_id = %s",
                           (finished, lease.attempt_id))

    seed_job(connection, spec, start)
    seed_job(connection, replace(spec, configuration_revision=2), end)
    complete_at(tenant, replace(spec, configuration_revision=3), earlier, start, retry=True)
    complete_at(tenant, replace(spec, configuration_revision=4), earlier, end)
    complete_at(tenant, replace(spec, configuration_revision=5), earlier, earlier)
    complete_at(tenant, spec_for(tenant, "completed-only"), earlier, end - timedelta(microseconds=1))
    complete_at(tenant, spec_for(tenant, "legacy-completion"), None, start)
    complete_at(other, spec_for(other), start, start)
    complete_at(outsider, spec_for(outsider), start, start)
    enqueue_job(connection, spec_for(tenant, "not-finished"))
    running = claim_job(connection, tenant.org_id, "not-finished", tenant.worker_id, LEASE_FOR)
    connection.execute("""
        UPDATE thalion.job_attempt SET outcome = 'expired', finished_at = %s WHERE attempt_id = %s
    """, (start, running.attempt_id))

    result = runtime_report.observe(connection, tenant.space_ref, start, end)
    assert result["job_throughput_by_stage"] == [
        {"stage": "completed-only", "enqueued": 0, "succeeded": 1},
        {"stage": "legacy-completion", "enqueued": 0, "succeeded": 1},
        {"stage": "parse", "enqueued": 1, "succeeded": 1},
    ]
    pending = next(stage for stage in result["job_backlog_by_stage"] if stage["stage"] == "parse")
    age = (datetime.fromisoformat(result["observed_at"]) - start) // timedelta(milliseconds=1)
    assert pending["unfinished"] == 2
    assert pending["oldest_known_age_ms"] == age and pending["unknown_enqueue_time"] == 0


def test_report_separates_reconciled_usage_from_unsettled_and_unsent_calls(runtime_db):
    connection, tenant, url = runtime_db
    other = register_tenant(connection, "Other organization")
    with connection.transaction():
        other_space, other_ref = space(connection, tenant.org_id, tenant.actor_id)
    start, = connection.execute("SELECT clock_timestamp()").fetchone()
    lease, settled = external_reservation(connection, tenant, "settled")
    assert dispatch(connection, lease, settled)
    receipt = external.UsageReceipt(uuid4(), "private-provider-reference", False, 10, 5, 60)
    assert external.record_call_receipt(connection, tenant.org_id, settled, receipt)
    assert external.record_call_receipt(connection, tenant.org_id, settled, external.UsageReceipt(
        uuid4(), receipt.provider_request_id, False, 11, 6, 70, receipt.receipt_id,
    ))
    lease, unknown = external_reservation(connection, tenant, "unknown")
    assert dispatch(connection, lease, unknown)
    external.mark_call_unknown(connection, tenant.org_id, unknown)
    external_reservation(connection, tenant, "unsent")
    lease, zero = external_reservation(connection, tenant, "zero", "USD")
    assert dispatch(connection, lease, zero)
    assert external.record_call_receipt(connection, tenant.org_id, zero, external.UsageReceipt(
        uuid4(), "synthetic-zero", True, 0, 0, 0,
    ))
    lease, pending = external_reservation(connection, tenant, "pending", "EUR")
    assert dispatch(connection, lease, pending)
    external_reservation(connection, other, "unrelated", "GBP")
    external_reservation(connection, replace(tenant, space_id=other_space, space_ref=other_ref), "other-space", "CHF")
    end, = connection.execute("SELECT clock_timestamp()").fetchone()
    external_reservation(connection, tenant, "outside-window", "JPY")

    result = report(url, tenant, start, end)
    cny, eur, usd = result["external_calls_by_currency"]
    assert cny == {
        "currency": "CNY", "registered": 3, "dispatched": 2, "settled": 1, "unsettled": 1,
        "open_unsent": 1, "reserved_microunits": 200, "receipted_microunits": 70,
        "receipted_input_tokens": 11, "receipted_output_tokens": 6,
    }
    assert eur["currency"] == "EUR" and eur["unsettled"] == 1 and eur["receipted_microunits"] is None
    assert usd["currency"] == "USD" and usd["settled"] == 1 and usd["receipted_microunits"] == 0
    assert "private-provider-reference" not in json.dumps(result) and str(unknown) not in json.dumps(result)


def test_report_counts_current_backlog_outside_history_window(runtime_db):
    connection, tenant, url = runtime_db
    other = register_tenant(connection, "Other organization")
    with connection.transaction():
        other_space, other_ref = space(connection, tenant.org_id, tenant.actor_id)
    end, = connection.execute("SELECT clock_timestamp() - interval '5 minutes'").fetchone()
    start = end - timedelta(minutes=10)
    spec = spec_for(tenant)

    ready = enqueue_job(connection, spec)
    connection.execute(
        "UPDATE thalion.job SET available_at = clock_timestamp() + interval '1 hour' WHERE job_id = %s", (ready,),
    )
    leases = []
    for revision in range(2, 8):
        job_id = enqueue_job(connection, replace(spec, configuration_revision=revision))
        leases.append(claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR, job_id=job_id))
    delayed, expired, leased, complete, due, missing = leases
    retry_job(connection, delayed, delay=timedelta(hours=1))
    retry_job(connection, due, delay=timedelta(0))
    retry_at, = connection.execute(
        "SELECT available_at FROM thalion.job WHERE job_id = %s", (delayed.job_id,),
    ).fetchone()
    expire(connection, expired)
    complete_job(connection, complete, lambda tx: tenant.space_ref)
    connection.execute("DELETE FROM thalion.job_attempt WHERE attempt_id = %s", (missing.attempt_id,))
    enqueue_job(connection, spec_for(tenant, "local-rebuild"))
    enqueue_job(connection, spec_for(other, "other-org"))
    enqueue_job(connection, spec_for(replace(tenant, space_id=other_space, space_ref=other_ref), "other-space"))

    result = report(url, tenant, start, end)
    assert result["registered_requests"] == 0 and result["external_calls_by_currency"] == []
    assert backlog_states(result) == [
        {"stage": "local-rebuild", "unfinished": 1, "states": {"ready": 1}, "next_retry_at": None},
        {
            "stage": "parse", "unfinished": 6, "next_retry_at": retry_at.astimezone(UTC).isoformat(),
            "states": {"ready": 2, "retry_delayed": 1, "lease_expired": 1, "leased": 1, "inconsistent": 1},
        },
    ]
    assert str(leased.job_id) not in json.dumps(result) and str(leased.attempt_id) not in json.dumps(result)


def test_backlog_rechecks_parked_jobs_against_current_budget_without_claiming(runtime_db):
    connection, tenant, url = runtime_db
    start, = connection.execute("SELECT clock_timestamp()").fetchone()
    waiting, unresolved = external_reservation(connection, tenant, "model-wait")
    assert dispatch(connection, waiting, unresolved)
    expire(connection, waiting)
    assert claim_job(connection, tenant.org_id, waiting.spec.stage, tenant.worker_id, LEASE_FOR) is None

    capped_spec = spec_for(tenant, "model-capped")
    external.enqueue_external_job(connection, capped_spec, external.CallBudget("CNY", 500, 1))
    capped = claim_job(connection, tenant.org_id, capped_spec.stage, tenant.worker_id, LEASE_FOR)
    exhausted = reserve(connection, capped)
    assert dispatch(connection, capped, exhausted)
    assert external.record_call_receipt(connection, tenant.org_id, exhausted, external.UsageReceipt(
        uuid4(), "synthetic-cap", False, 0, 0, 50,
    ))
    expire(connection, capped)
    assert claim_job(connection, tenant.org_id, capped_spec.stage, tenant.worker_id, LEASE_FOR) is None

    end, = connection.execute("SELECT clock_timestamp()").fetchone()
    before = report(url, tenant, start, end)
    assert backlog_states(before) == [
        {"stage": "model-capped", "unfinished": 1, "states": {"external_budget_blocked": 1}, "next_retry_at": None},
        {"stage": "model-wait", "unfinished": 1, "states": {"awaiting_external": 1}, "next_retry_at": None},
    ]
    assert external.record_call_receipt(connection, tenant.org_id, unresolved, external.UsageReceipt(
        uuid4(), "synthetic-reconciled", False, 0, 0, 50,
    ))
    reconciled = report(url, tenant, start, end)
    assert backlog_states(reconciled) == [
        backlog_states(before)[0],
        {"stage": "model-wait", "unfinished": 1, "states": {"ready": 1}, "next_retry_at": None},
    ]
    assert connection.execute("""
        SELECT state, generation FROM thalion.job WHERE job_id = %s
    """, (waiting.job_id,)).fetchone() == ("awaiting_external", 1)
    resumed = claim_job(connection, tenant.org_id, waiting.spec.stage, tenant.worker_id, LEASE_FOR)
    assert (resumed.job_id, resumed.generation) == (waiting.job_id, 2)


def process_quality_candidate(db, label, payload=b"# Synthetic pending evidence\n\nRetain written approval.\n"):
    connection, tenant, _, source, store = db
    version = register(
        connection, tenant, source, store, key=label, object_key=label, display_name=label,
        payload=payload, digest=sha256(payload).digest(),
    )
    lease = claim(db)
    assert lease.spec.target_ref == version.version_ref
    return version, processing.process_markdown_job(connection, lease, store)


def test_quality_backlog_keeps_only_current_completed_undecided_runs(evidence_db, tmp_path):
    connection, tenant, url, _, store = evidence_db
    end, = connection.execute("SELECT clock_timestamp() - interval '1 minute'").fetchone()
    start = end - timedelta(minutes=10)
    version, first = process_quality_candidate(evidence_db, "private-quality-candidate")
    other = register_tenant(connection, "Other organization")
    with connection.transaction():
        other_space, other_ref = space(connection, tenant.org_id, tenant.actor_id)
    other_tenant = replace(tenant, space_id=other_space, space_ref=other_ref)
    process_quality_candidate(create_evidence_db(connection, other, url, tmp_path), "other-org-quality")
    other_source = registry.register_synthetic_source(
        connection, request_for(connection, tenant, tenant.actor_id, "other-source", "register_source_contract"),
        other_space, registry.SyntheticSource(
            "other-travel", "other-archive", tenant.worker_id, processor_id=tenant.other_worker_id,
            quality_reviewer_id=tenant.actor_id,
        ),
    )
    process_quality_candidate((connection, other_tenant, url, other_source, store), "other-space-quality")
    _, failed = process_quality_candidate(evidence_db, "invalid-quality", b"# Heading only\n")
    assert failed.outcome == "quarantined"
    connection.execute("""
        INSERT INTO thalion.processing_config_revision
            (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
    """)
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 2))

    waiting = report(url, tenant, start, end)
    assert waiting["registered_requests"] == 0
    assert waiting["quality_review_backlog"] == {"pending_review": 1}
    replacement = processing.process_markdown_job(connection, claim(evidence_db), store)
    assert report(url, tenant, start, end)["quality_review_backlog"] == {"pending_review": 1}
    review(evidence_db, replacement)
    after = report(url, tenant, start, end)
    assert after["quality_review_backlog"] == {"pending_review": 0}
    review(evidence_db, replacement, decision="quarantined")
    assert report(url, tenant, start, end)["quality_review_backlog"] == {"pending_review": 0}
    assert connection.execute(
        "SELECT count(*) FROM thalion.quality_decision WHERE run_ref = %s", (first.run_ref,),
    ).fetchone() == (0,)
    assert all(secret not in json.dumps(waiting) for secret in (
        str(first.run_ref), str(version.version_ref), "private-quality-candidate", "Retain written approval",
    ))


def test_quality_backlog_excludes_withdrawn_and_currently_held_versions(transport):
    client, db, (_, custodian), credentials, *_ = transport
    connection, tenant, url, *_ = db
    end, = connection.execute("SELECT clock_timestamp() - interval '1 minute'").fetchone()
    start = end - timedelta(minutes=10)
    retired, _ = process_quality_candidate(db, "retired-quality")
    held, _ = process_quality_candidate(db, "held-quality")
    assert report(url, tenant, start, end)["quality_review_backlog"] == {"pending_review": 2}

    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "stop-quality"), tenant.space_id,
        retired.version_ref, "withdrawn", uuid4(),
    )
    admit(credentials, custodian, "decide_hold")
    assert decide(client, custodian, held.version_ref).status_code == 200
    assert report(url, tenant, start, end)["quality_review_backlog"] == {"pending_review": 0}
    assert decide(client, custodian, held.version_ref, action="release", generation=1).status_code == 200
    assert report(url, tenant, start, end)["quality_review_backlog"] == {"pending_review": 1}


def test_wiki_backlog_uses_recorded_review_stages_across_all_topics(workspace, tmp_path, monkeypatch):
    db, _, _, second = workspace
    connection, tenant, url, *_ = db
    end, = connection.execute("SELECT clock_timestamp() - interval '1 minute'").fetchone()
    start = end - timedelta(minutes=10)
    configure(db, 2)
    published = approve_wiki(workspace)
    approve_wiki(workspace)
    assert authorize(db, *published).status == "succeeded"
    approve_wiki(workspace)
    rejected = candidate(workspace)
    assert submit(db, rejected.ref, preview(db, rejected.ref), decision="rejected").status == "succeeded"
    drafts = [candidate(workspace, topic=f"private-draft-{index}") for index in range(3)]
    assert all(draft.status == "succeeded" for draft in drafts)
    effectivity.stop_synthetic_rule(
        connection, record(connection, tenant, "stop_rule_use", "stop-wiki-backlog"), tenant.space_id,
        version_ref(connection, second), "withdrawn", uuid4(),
    )

    other = register_tenant(connection, "Other organization")
    other_db = create_evidence_db(connection, other, url, tmp_path)
    version, part, _ = publish(other_db, "other-wiki-source", "Other Wiki evidence", b"# Other\n\nRetain approval.\n")
    approve(connection, other, version, BEGIN)
    set_rules(other_db, compile_rule(other.actor_id))
    other_workspace = (other_db, assemble(other_db, (part,)), part, part)
    assert candidate(other_workspace, topic="private-other-draft").status == "succeeded"

    monkeypatch.setattr(management, "PAGE_SIZE", 1)
    first_page, next_page = management.list_topic_status(connection, tenant.org_id, tenant.space_id, None)
    assert len(first_page) == 1 and next_page is not None
    result = runtime_report.observe(connection, tenant.space_ref, start, end)
    assert result["wiki_review_backlog"] == {"awaiting_review": 3, "approved": 1, "rejected": 1, "stale": 1}
    assert result["registered_requests"] == 0
    assert all(secret not in json.dumps(result) for secret in (
        "private-draft", "private-other-draft", str(drafts[0].ref), str(published[0]), "本地差旅",
    ))


def test_ocr_backlog_counts_pages_not_proposals_and_separates_page_from_batch_review(pdf_review):
    db = pdf_review[0]
    connection, tenant, version, run, client, reviewer, author, first = stage_review(pdf_review)
    url = db[2]
    end, = connection.execute("SELECT clock_timestamp() - interval '1 minute'").fetchone()
    start = end - timedelta(minutes=10)
    author_preview = view(client, run, author)
    alternative = propose(client, run, author, author_preview, transcript="Keep the signed synthetic receipt.")
    assert alternative.status_code == 200, alternative.text
    alternative_id = alternative.json()["correction_id"]
    waiting = report(url, tenant, start, end)
    assert waiting["registered_requests"] == 0
    assert waiting["ocr_correction_backlog"] == {"pending_pages": 1}
    assert waiting["quality_review_backlog"] == {"pending_review": 0}
    assert all(secret not in json.dumps(waiting) for secret in (
        first, alternative_id, str(run.run_ref), str(version.version_ref), TRANSCRIPT, "signed synthetic receipt",
    ))

    compared = preview_correction(client, first, reviewer)
    assert compared.status_code == 200, compared.text
    assert decide_correction(
        client, first, reviewer, compared.json()["request_id"], outcome="rejected",
    ).status_code == 200
    assert report(url, tenant, start, end)["ocr_correction_backlog"] == {"pending_pages": 1}
    compared = preview_correction(client, alternative_id, reviewer)
    assert compared.status_code == 200, compared.text
    assert decide_correction(
        client, alternative_id, reviewer, compared.json()["request_id"], outcome="rejected",
    ).status_code == 200
    assert report(url, tenant, start, end)["ocr_correction_backlog"] == {"pending_pages": 0}

    accepted = []
    for transcript in ("Synthetic correction A.", "Synthetic correction B."):
        response = propose(client, run, author, author_preview, transcript=transcript)
        assert response.status_code == 200, response.text
        accepted.append(response.json()["correction_id"])
    compared = preview_correction(client, accepted[0], reviewer)
    assert compared.status_code == 200, compared.text
    assert decide_correction(client, accepted[0], reviewer, compared.json()["request_id"]).status_code == 200
    after_approval = report(url, tenant, start, end)
    assert after_approval["ocr_correction_backlog"] == {"pending_pages": 0}
    assert after_approval["quality_review_backlog"] == {"pending_review": 0}
    processing.repair_pdf_job(
        connection, repair_lease(db, version), db[-1], replaces=run.run_ref, basis_ref=uuid4(),
    )
    after_repair = report(url, tenant, start, end)
    assert after_repair["ocr_correction_backlog"] == {"pending_pages": 0}
    assert after_repair["quality_review_backlog"] == {"pending_review": 1}
    assert connection.execute("SELECT count(*) FROM thalion.pdf_ocr_review_decision").fetchone() == (3,)


@pytest.mark.parametrize("change", ["held", "withdrawn", "replaced"])
def test_ocr_backlog_excludes_blocked_or_replaced_batches(pdf_review, change):
    db = pdf_review[0]
    connection, tenant, version, _, client, _, author, _ = stage_review(pdf_review)
    url = db[2]
    end, = connection.execute("SELECT clock_timestamp() - interval '1 minute'").fetchone()
    start = end - timedelta(minutes=10)
    assert report(url, tenant, start, end)["ocr_correction_backlog"] == {"pending_pages": 1}
    with connection.transaction():
        _, other_ref = space(connection, tenant.org_id, tenant.actor_id)
    other = run_report(url, other_ref, start, end)
    assert other.returncode == 0 and json.loads(other.stdout)["ocr_correction_backlog"] == {"pending_pages": 0}

    if change == "held":
        assert decide(client, author, version.version_ref).status_code == 200
    elif change == "withdrawn":
        approve(connection, tenant, version, BEGIN)
        effectivity.stop_synthetic_rule(
            connection, record(connection, tenant, "stop_rule_use", "stop-ocr-backlog"), tenant.space_id,
            version.version_ref, "withdrawn", uuid4(),
        )
    else:
        replacing = repair_lease(db, version)
        assert report(url, tenant, start, end)["ocr_correction_backlog"] == {"pending_pages": 1}
        processing.process_evidence_job(connection, replacing, db[-1], pdf_ocr=EmptyScan())

    assert report(url, tenant, start, end)["ocr_correction_backlog"] == {"pending_pages": 0}
    assert connection.execute("SELECT count(*) FROM thalion.pdf_ocr_review_decision").fetchone() == (0,)


def test_report_reads_one_snapshot_before_a_concurrent_completion(evidence_db, monkeypatch):
    connection, tenant, url, source, store = evidence_db
    end, = connection.execute("SELECT clock_timestamp()").fetchone()
    start = end - timedelta(minutes=2)
    request_id = register_request(connection, tenant, tenant.space_id, start)
    _, awaiting = process_quality_candidate(evidence_db, "concurrent-quality")
    spec = spec_for(tenant)
    enqueue_job(connection, spec)
    lease = claim_job(connection, tenant.org_id, spec.stage, tenant.worker_id, LEASE_FOR)
    read_requests = runtime_report._requests

    def complete_then_read(tx, *args):
        assert tx.execute("SHOW transaction_read_only").fetchone() == ("on",)
        assert tx.execute("SHOW transaction_isolation").fetchone() == ("repeatable read",)
        with open_database(url) as independent:
            assert finish_request(independent, tenant.org_id, request_id, "succeeded", 25)
            assert complete_job(independent, lease, lambda job_tx: tenant.space_ref) == tenant.space_ref
            review((independent, tenant, url, source, store), awaiting)
        return read_requests(tx, *args)

    monkeypatch.setattr(runtime_report, "_requests", complete_then_read)
    before = runtime_report.observe(connection, tenant.space_ref, start, end)
    assert before["unfinished_requests"] == 1
    assert before["quality_review_backlog"] == {"pending_review": 1}
    assert backlog_states(before) == [
        {"stage": "parse", "unfinished": 1, "states": {"leased": 1}, "next_retry_at": None},
    ]
    after = report(url, tenant, start, end)
    assert after["unfinished_requests"] == 0
    assert after["quality_review_backlog"] == {"pending_review": 0}
    assert after["job_backlog_by_stage"] == []
    assert after["requests_by_ingress_operation_destination"][0]["success_ledger_elapsed_ms"]["p95"] == 25


@pytest.mark.parametrize("invalid", ["unknown_space", "inverted", "wide", "naive", "future"])
def test_report_refuses_unbounded_or_unknown_scope(runtime_db, invalid):
    connection, tenant, url = runtime_db
    end, = connection.execute("SELECT clock_timestamp()").fetchone()
    start = end - timedelta(minutes=10)
    if invalid == "inverted":
        start = end
    elif invalid == "wide":
        start = end - timedelta(days=1, microseconds=1)
    elif invalid == "naive":
        start = start.replace(tzinfo=None)
    elif invalid == "future":
        end += timedelta(minutes=1)
    result = run_report(url, uuid4() if invalid == "unknown_space" else tenant.space_ref, start, end)
    assert result.returncode == 1 and not result.stdout and "FAIL" in result.stderr
    assert url not in result.stderr
