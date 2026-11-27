from dataclasses import replace
from datetime import datetime, timedelta, UTC
from hashlib import sha256
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.sources import effectivity
from enterprise_kb.runtime.audit import RequestStart, start_request

from test_effectivity import BEGIN, approve, record
from test_evidence import evidence_db, review
from test_evidence_transport import bearer, private_json
from test_pdf_processing import PAGE_TEXT, text_page
from test_pdf_review import original_rule, path, pdf_review, stage_pdf
from test_persisted_access import set_rules
from test_runtime import runtime_db


TRANSCRIPT = "Travel allowance 600 CNY."


def propose(client, run, token, preview_id, *, page=1, transcript=TRANSCRIPT, basis=None, key=None):
    return client.post(
        f"{path(run, page)}/corrections", headers=bearer(token) | {"Idempotency-Key": key or uuid4().hex},
        json={"preview_request_id": preview_id, "basis_id": str(basis or uuid4()), "transcript": transcript},
    )


def fixture_page(pdf_review, *pages):
    db, profile, _, client, (reviewer, author), credentials = pdf_review
    connection, tenant, *_ = db
    version, run = stage_pdf(db, *pages)
    for token in (reviewer, author):
        credentials[token] = replace(
            credentials[token], operations=credentials[token].operations | {"submit_pdf_ocr_correction"},
        )
    set_rules(db, original_rule(tenant.actor_id), original_rule(tenant.other_actor_id))
    private_json(profile.root / "pdf-page-grants.json", {
        str(credentials[token].employee_ref): [str(version.version_ref)] for token in (reviewer, author)
    })
    return connection, tenant, version, run, client, reviewer, author


def view(client, run, token, page=1):
    response = client.get(path(run, page), headers=bearer(token))
    assert response.status_code == 200, response.text
    return response.json()["request_id"]


def test_ocr_proposal_binds_failed_physical_page_to_author_and_basis(pdf_review):
    connection, tenant, _, run, client, _, author = fixture_page(pdf_review, b"")
    assert run.outcome == "quarantined"
    preview = view(client, run, author)
    basis, key = uuid4(), uuid4().hex
    first = propose(client, run, author, preview, basis=basis, key=key)
    assert first.status_code == 200, first.text
    assert set(first.json()) == {"correction_id", "request_id"}
    assert TRANSCRIPT not in first.text
    repeated = propose(client, run, author, preview, basis=basis, key=key)
    assert repeated.status_code == 200
    assert repeated.json()["correction_id"] == first.json()["correction_id"]
    assert propose(client, run, author, preview, basis=basis, key=key, transcript="Another value").status_code == 409
    assert connection.execute("""
        SELECT correction_ref::text, run_ref, page_number, author_id, preview_request_id::text,
               basis_ref, proposed_transcript, proposed_digest
        FROM thalion.pdf_ocr_correction
    """).fetchall() == [
        (first.json()["correction_id"], run.run_ref, 1, tenant.other_actor_id, preview, basis,
         TRANSCRIPT.encode(), sha256(TRANSCRIPT.encode()).digest()),
    ]
    assert connection.execute("SELECT transcript FROM thalion.pdf_page_observation").fetchall() == [(None,)]
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.passage_excerpt").fetchone() == (0,)
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.pdf_ocr_correction SET proposed_transcript = %s", (b"altered",))


def test_ocr_proposal_refuses_self_review_wrong_page_and_live_batch(pdf_review):
    db = pdf_review[0]
    connection, _, _, run, client, reviewer, author = fixture_page(pdf_review, text_page(PAGE_TEXT), b"", b"")
    author_preview = view(client, run, author, 2)
    reviewer_preview = view(client, run, reviewer, 2)
    assert propose(client, run, reviewer, reviewer_preview, page=2).status_code == 403
    assert propose(client, run, author, author_preview, page=2).status_code == 409
    review(db, run, decision="quarantined")
    assert propose(client, run, author, reviewer_preview, page=2).status_code == 409
    assert propose(client, run, author, author_preview, page=3).status_code == 409
    assert propose(client, run, author, view(client, run, author)).status_code == 409
    assert propose(client, run, author, author_preview, page=2, transcript=" \n").status_code == 400
    for invalid_body in (42, ["page_number"], {"page_number": "3"}):
        assert client.post(
            f"{path(run, 2)}/corrections", headers=bearer(author) | {"Idempotency-Key": uuid4().hex}, json=invalid_body,
        ).status_code == 400
    assert connection.execute("SELECT count(*) FROM thalion.pdf_ocr_correction").fetchone() == (0,)
    assert propose(client, run, author, author_preview, page=2).status_code == 200


@pytest.mark.parametrize("restriction", ["revoked", "withdrawn", "changed_client", "expired"])
def test_ocr_proposal_rechecks_authority_and_preview(pdf_review, monkeypatch, restriction):
    db, profile, _, _, _, credentials = pdf_review
    connection, tenant, version, run, client, _, author = fixture_page(pdf_review, b"")
    preview = view(client, run, author)
    expected = 403
    if restriction == "revoked":
        private_json(profile.root / "pdf-page-grants.json", {})
    elif restriction == "withdrawn":
        approve(connection, tenant, version, BEGIN)
        effectivity.stop_synthetic_rule(
            connection, record(connection, tenant, "stop_rule_use", "stop-ocr"),
            tenant.space_id, version.version_ref, "withdrawn", uuid4(),
        )
    elif restriction == "changed_client":
        credentials[author] = replace(credentials[author], client_id="other-review-client")
        expected = 409
    else:
        from enterprise_kb.modules.evidence import pdf_review as pdf_review_module

        monkeypatch.setattr(pdf_review_module, "CORRECTION_PREVIEW_WINDOW", timedelta(seconds=-1))
        expected = 409
    refused = propose(client, run, author, preview)
    assert refused.status_code == expected and TRANSCRIPT not in refused.text
    assert connection.execute("SELECT count(*) FROM thalion.pdf_ocr_correction").fetchone() == (0,)


def test_ocr_proposal_discarded_when_source_revokes_during_read(pdf_review, monkeypatch):
    db, profile, _, _, _, _ = pdf_review
    store = db[-1]
    connection, _, _, run, client, _, author = fixture_page(pdf_review, b"")
    preview = view(client, run, author)
    read = store.read

    def revoke(asset):
        original = read(asset)
        private_json(profile.root / "pdf-page-grants.json", {})
        return original

    monkeypatch.setattr(store, "read", revoke)
    assert propose(client, run, author, preview).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.pdf_ocr_correction").fetchone() == (0,)
    assert connection.execute("""
        SELECT count(*) FROM thalion.outbox_event WHERE event_type = 'evidence.pdf_correction.submitted'
    """).fetchone() == (0,)


def test_ocr_database_guard_rejects_reviewer_as_author_and_mismatched_preview(pdf_review):
    connection, tenant, _, run, client, reviewer, author = fixture_page(pdf_review, b"", b"")
    reviewer_preview = view(client, run, reviewer, 1)
    author_preview = view(client, run, author, 2)
    for actor, preview in ((tenant.actor_id, reviewer_preview), (tenant.other_actor_id, author_preview)):
        request = uuid4()
        start_request(connection, RequestStart(
            tenant.org_id, request, actor, None, "synthetic-pdf-review", "submit_pdf_ocr_correction",
            "local_workspace", datetime.now(UTC).date(), 1, space_id=tenant.space_id,
        ))
        with pytest.raises(errors.CheckViolation, match="recent preview by an independent author"):
            connection.execute("""
                INSERT INTO thalion.pdf_ocr_correction (
                    org_id, space_id, version_id, run_ref, page_number, author_id, preview_request_id, request_id, basis_ref,
                    proposed_transcript, proof_digest
                )
                SELECT org_id, space_id, version_id, run_ref, 1, %s, %s, %s, %s, %s, %s
                FROM thalion.processing_run WHERE run_ref = %s
            """, (actor, preview, request, uuid4(), TRANSCRIPT.encode(), bytes(32), run.run_ref))
