from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import pdf_review as pdf_review_module, processing
from enterprise_kb.modules.sources import effectivity
from enterprise_kb.runtime.audit import RequestStart, start_request
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job
from enterprise_kb.transport import api

from test_effectivity import BEGIN, approve, record
from test_evidence import claim, evidence_db
from test_evidence_transport import bearer, private_json
from test_pdf_correction import TRANSCRIPT, fixture_page, propose, view
from test_pdf_review import EmptyScan, pdf_review
from test_runtime import runtime_db


PREVIEW = "preview_pdf_ocr_correction"
DECIDE = "decide_pdf_ocr_correction"


def correction_path(correction):
    return f"/internal/evidence/pdf-corrections/{correction}"


def stage_review(pdf_review):
    _, _, _, _, _, credentials = pdf_review
    connection, tenant, version, run, client, reviewer, author = fixture_page(pdf_review, b"")
    for token in (reviewer, author):
        credentials[token] = replace(credentials[token], operations=credentials[token].operations | {PREVIEW, DECIDE})
    proposed = propose(client, run, author, view(client, run, author))
    assert proposed.status_code == 200, proposed.text
    return connection, tenant, version, run, client, reviewer, author, proposed.json()["correction_id"]


def preview(client, correction, token):
    return client.get(f"{correction_path(correction)}/preview", headers=bearer(token))


def decide(client, correction, token, preview_id, *, outcome="approved", basis=None, key=None):
    return client.post(
        f"{correction_path(correction)}/decision", headers=bearer(token) | {"Idempotency-Key": key or uuid4().hex},
        json={"preview_request_id": preview_id, "outcome": outcome, "basis_id": str(basis or uuid4())},
    )


def test_ocr_reviewer_compares_exact_page_and_records_decision_without_activation(pdf_review):
    connection, tenant, version, run, client, reviewer, author, correction = stage_review(pdf_review)
    compared = preview(client, correction, reviewer)
    assert compared.status_code == 200, compared.text
    assert compared.headers["cache-control"] == "no-store"
    payload = compared.json()
    assert (payload["version_id"], payload["run_id"], payload["page_number"], payload["correction_id"]) == (
        str(version.version_ref), str(run.run_ref), 1, correction,
    )
    assert payload["png_base64"].startswith("iVBORw0KGgo")
    assert payload["previous_transcript"] is None
    assert payload["proposed_transcript"] == TRANSCRIPT
    assert connection.execute("""
        SELECT payload_digest FROM thalion.pdf_page_preview WHERE request_id = %s
    """, (payload["request_id"],)).fetchone() == (sha256(compared.content).digest(),)
    assert preview(client, correction, author).status_code == 403
    assert decide(client, correction, author, payload["request_id"]).status_code == 403
    assert decide(client, correction, reviewer, view(client, run, reviewer)).status_code == 409

    basis, key = uuid4(), uuid4().hex
    accepted = decide(client, correction, reviewer, payload["request_id"], basis=basis, key=key)
    assert accepted.status_code == 200, accepted.text
    assert set(accepted.json()) == {"decision_id", "outcome", "request_id"}
    assert accepted.json()["outcome"] == "approved" and TRANSCRIPT not in accepted.text
    again = decide(client, correction, reviewer, payload["request_id"], basis=basis, key=key)
    assert again.json()["decision_id"] == accepted.json()["decision_id"]
    assert decide(client, correction, reviewer, payload["request_id"], outcome="rejected", basis=basis, key=key).status_code == 409
    assert connection.execute("""
        SELECT reviewer_id, preview_request_id::text, outcome, basis_ref FROM thalion.pdf_ocr_review_decision
    """).fetchall() == [(tenant.actor_id, payload["request_id"], "approved", basis)]
    assert connection.execute("SELECT outcome FROM thalion.processing_run").fetchall() == [("quarantined",)]
    for table in ("quality_decision", "passage_excerpt"):
        assert connection.execute(f"SELECT count(*) FROM thalion.{table}").fetchone() == (0,)


@pytest.mark.parametrize("restriction", ["revoked", "client_changed", "expired", "held", "withdrawn", "replaced"])
def test_ocr_decision_rejects_stale_review_context(pdf_review, monkeypatch, restriction):
    db, profile, _, _, _, credentials = pdf_review
    connection, tenant, version, _, client, reviewer, author, correction = stage_review(pdf_review)
    compared = preview(client, correction, reviewer)
    assert compared.status_code == 200, compared.text
    if restriction == "revoked":
        private_json(profile.root / "pdf-page-grants.json", {})
        expected = 403
    elif restriction == "client_changed":
        credentials[reviewer] = replace(credentials[reviewer], client_id="changed-review-client")
        expected = 409
    elif restriction == "expired":
        monkeypatch.setattr(pdf_review_module, "CORRECTION_PREVIEW_WINDOW", timedelta(seconds=-1))
        expected = 409
    elif restriction == "held":
        held = client.post(
            api.HOLD_PATH, headers=bearer(author) | {"Idempotency-Key": uuid4().hex},
            json={"version_id": str(version.version_ref), "action": "establish",
                  "expected_generation": 0, "basis_id": str(uuid4())},
        )
        assert held.status_code == 200, held.text
        expected = 403
    elif restriction == "withdrawn":
        approve(connection, tenant, version, BEGIN)
        effectivity.stop_synthetic_rule(
            connection, record(connection, tenant, "stop_rule_use", "withdraw-ocr-review"),
            tenant.space_id, version.version_ref, "withdrawn", uuid4(),
        )
        expected = 403
    else:
        newer, = connection.execute("""
            INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
            SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
                   parser_version, profile, locator_revision
            FROM thalion.processing_config_revision WHERE profile = 'pdf_pages_v1'
            RETURNING configuration_revision
        """).fetchone()
        enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, newer))
        processing.process_evidence_job(connection, claim(db), db[-1], pdf_ocr=EmptyScan())
        expected = 409
    refused = decide(client, correction, reviewer, compared.json()["request_id"])
    assert refused.status_code == expected and TRANSCRIPT not in refused.text
    assert connection.execute("SELECT count(*) FROM thalion.pdf_ocr_review_decision").fetchone() == (0,)


def test_ocr_comparison_and_decision_recheck_source_after_read(pdf_review, monkeypatch):
    db, profile, _, _, _, credentials = pdf_review
    connection, _, version, _, client, reviewer, _, correction = stage_review(pdf_review)
    compared = preview(client, correction, reviewer)
    assert compared.status_code == 200, compared.text
    store = db[-1]
    read = store.read

    def revoke(asset):
        original = read(asset)
        private_json(profile.root / "pdf-page-grants.json", {})
        return original

    monkeypatch.setattr(store, "read", revoke)
    for request in (
        lambda: preview(client, correction, reviewer),
        lambda: decide(client, correction, reviewer, compared.json()["request_id"]),
    ):
        private_json(profile.root / "pdf-page-grants.json", {str(credentials[reviewer].employee_ref): [str(version.version_ref)]})
        refused = request()
        assert refused.status_code == 403 and TRANSCRIPT not in refused.text
    assert connection.execute("SELECT count(*) FROM thalion.pdf_ocr_review_decision").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.pdf_page_preview WHERE correction_ref IS NOT NULL").fetchone() == (1,)


def test_sql_requires_exact_recent_comparison_and_rejection_is_final(pdf_review):
    connection, tenant, _, run, client, reviewer, _, correction = stage_review(pdf_review)
    request = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request, tenant.actor_id, None, "synthetic-pdf-review", DECIDE,
        "local_workspace", datetime.now(UTC).date(), 1, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation, match="recent preview by its independent reviewer"):
        connection.execute("""
            INSERT INTO thalion.pdf_ocr_review_decision (
                correction_ref, org_id, space_id, version_id, run_ref, page_number, reviewer_id,
                preview_request_id, request_id, basis_ref, outcome, proof_digest
            )
            SELECT correction_ref, org_id, space_id, version_id, run_ref, page_number, %s, %s, %s, %s, 'approved', %s
            FROM thalion.pdf_ocr_correction WHERE correction_ref = %s
        """, (tenant.actor_id, view(client, run, reviewer), request, uuid4(), bytes(32), correction))
    compared = preview(client, correction, reviewer)
    assert compared.status_code == 200, compared.text
    preview_id = compared.json()["request_id"]
    rejected = decide(client, correction, reviewer, preview_id, outcome="rejected")
    assert rejected.status_code == 200 and rejected.json()["outcome"] == "rejected"
    assert decide(client, correction, reviewer, preview_id).status_code == 409
    assert connection.execute("SELECT outcome FROM thalion.pdf_ocr_review_decision").fetchall() == [("rejected",)]


def test_competing_reviews_cannot_both_approve_one_physical_page(pdf_review):
    connection, _, _, run, client, reviewer, author, first = stage_review(pdf_review)
    second = propose(client, run, author, view(client, run, author), transcript="Travel allowance 500 CNY.")
    assert second.status_code == 200, second.text
    corrections = (first, second.json()["correction_id"])
    pending = []
    for correction in corrections:
        compared = preview(client, correction, reviewer)
        assert compared.status_code == 200, compared.text
        pending.append((correction, compared.json()["request_id"]))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda pair: decide(client, pair[0], reviewer, pair[1]), pending))
    assert sorted(response.status_code for response in results) == [200, 409]
    assert connection.execute("SELECT outcome FROM thalion.pdf_ocr_review_decision").fetchall() == [("approved",)]
