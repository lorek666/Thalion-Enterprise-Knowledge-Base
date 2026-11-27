from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import processing
from enterprise_kb.runtime.audit import RequestStart, start_request
from enterprise_kb.transport import api

from test_evidence import evidence_db, review
from test_evidence_transport import bearer, private_json
from test_pdf_correction import TRANSCRIPT, fixture_page, view
from test_pdf_processing import PAGE_TEXT, text_page
from test_pdf_repair import approve_page, repair_lease
from test_pdf_review import original_rule, pdf_review
from test_persisted_access import set_rules
from test_runtime import runtime_db


PREVIEW = "preview_pdf_repair_page"
APPROVE = "approve_pdf_repair"


def stage_batch(pdf_review):
    db = pdf_review[0]
    connection, _, version, original, client, reviewer, author = fixture_page(pdf_review, text_page(PAGE_TEXT), b"")
    review(db, original, decision="quarantined")
    approve_page(pdf_review, original, client, reviewer, author, 2)
    repaired = processing.repair_pdf_job(
        connection, repair_lease(db, version), db[-1], replaces=original.run_ref, basis_ref=uuid4(),
    )
    return connection, version, original, repaired, client, reviewer, author


def permit_review(pdf_review, *tokens):
    credentials = pdf_review[-1]
    for token in tokens:
        credentials[token] = replace(credentials[token], operations=credentials[token].operations | {PREVIEW, APPROVE})


def compare_page(client, repaired, token, page):
    return client.get(
        f"{api.REPAIR_PATH}/{repaired.run_ref}/pdf-pages/{page}/review", headers=bearer(token),
    )


def approve_batch(client, repaired, token, previews, *, basis=None, key=None):
    return client.post(
        f"{api.REPAIR_PATH}/{repaired.run_ref}/pdf-approval",
        headers=bearer(token) | {"Idempotency-Key": key or uuid4().hex},
        json={"preview_request_ids": previews, "basis_id": str(basis or uuid4())},
    )


def compare_batch(client, repaired, reviewer):
    previews = []
    for physical_page in (1, 2):
        response = compare_page(client, repaired, reviewer, physical_page)
        assert response.status_code == 200, response.text
        previews.append(response.json()["request_id"])
    return previews


def test_whole_pdf_approval_requires_distinct_current_receipts_for_all_pages(pdf_review):
    connection, version, original, repaired, client, reviewer, author = stage_batch(pdf_review)
    assert compare_page(client, repaired, reviewer, 2).status_code == 403
    permit_review(pdf_review, reviewer, author)
    assert compare_page(client, repaired, author, 2).status_code == 403
    first = compare_page(client, repaired, reviewer, 1)
    corrected = compare_page(client, repaired, reviewer, 2)
    assert first.status_code == corrected.status_code == 200, corrected.text
    assert corrected.headers["cache-control"] == "no-store"
    first_page, corrected_page = first.json(), corrected.json()
    assert (first_page["transcript"], corrected_page["transcript"]) == (PAGE_TEXT.decode(), TRANSCRIPT)
    assert corrected_page["version_id"] == str(version.version_ref)
    assert corrected_page["replaces_run_id"] == str(original.run_ref)
    assert corrected_page["manifest_sha256"] == repaired.manifest_digest.hex()
    assert corrected_page["page_count"] == 2
    assert corrected_page["png_base64"].startswith("iVBORw0KGgo")
    assert connection.execute(
        "SELECT payload_digest FROM thalion.pdf_page_preview WHERE request_id = %s", (corrected_page["request_id"],),
    ).fetchone() == (sha256(corrected.content).digest(),)

    previews = [first_page["request_id"], corrected_page["request_id"]]
    assert approve_batch(client, repaired, reviewer, previews[:1]).status_code == 409
    assert approve_batch(client, repaired, reviewer, [previews[0], previews[0]]).status_code == 400
    assert approve_batch(client, repaired, reviewer, previews[::-1]).status_code == 409
    assert approve_batch(client, repaired, reviewer, [previews[0], view(client, repaired, reviewer, 2)]).status_code == 409
    assert approve_batch(client, repaired, author, previews).status_code == 403
    basis, key = uuid4(), uuid4().hex
    accepted = approve_batch(client, repaired, reviewer, previews, basis=basis, key=key)
    assert accepted.status_code == 200, accepted.text
    assert set(accepted.json()) == {"decision_id", "outcome", "request_id"}
    assert accepted.json()["outcome"] == "approved"
    replayed = approve_batch(client, repaired, reviewer, previews, basis=basis, key=key)
    assert replayed.status_code == 200 and replayed.json()["decision_id"] == accepted.json()["decision_id"]
    assert approve_batch(client, repaired, reviewer, previews).status_code == 409
    assert set(connection.execute(
        "SELECT run_ref, outcome FROM thalion.quality_decision",
    ).fetchall()) == {(original.run_ref, "quarantined"), (repaired.run_ref, "approved")}
    assert connection.execute("""
        SELECT pdf_repair_page_requests, octet_length(pdf_repair_proof_digest)
        FROM thalion.quality_decision WHERE run_ref = %s
    """, (repaired.run_ref,)).fetchone() == ([UUID(request) for request in previews], 32)
    _, tenant, *_ = pdf_review[0]
    assert processing.list_approved_passages(connection, tenant.org_id, tenant.space_id, version.version_ref) == ()


@pytest.mark.parametrize("change", ["source_revokes_during_read", "client_changes", "policy_changes", "quarantined", "held"])
def test_pdf_repair_approval_rejects_changed_authority_even_with_every_receipt(pdf_review, monkeypatch, change):
    connection, version, _, repaired, client, reviewer, author = stage_batch(pdf_review)
    permit_review(pdf_review, reviewer)
    previews = compare_batch(client, repaired, reviewer)
    db, profile, _, _, _, credentials = pdf_review
    if change == "source_revokes_during_read":
        store = db[-1]
        read = store.read

        def revoke(asset):
            payload = read(asset)
            private_json(profile.root / "pdf-page-grants.json", {})
            return payload

        monkeypatch.setattr(store, "read", revoke)
        expected = 403
    elif change == "client_changes":
        credentials[reviewer] = replace(credentials[reviewer], client_id="renewed-review-client")
        expected = 409
    elif change == "policy_changes":
        tenant = db[1]
        set_rules(db, original_rule(tenant.actor_id), original_rule(tenant.other_actor_id), expected=2)
        expected = 409
    elif change == "quarantined":
        review(db, repaired, decision="quarantined")
        expected = 409
    else:
        held = client.post(
            api.HOLD_PATH, headers=bearer(author) | {"Idempotency-Key": uuid4().hex},
            json={"version_id": str(version.version_ref), "action": "establish",
                  "expected_generation": 0, "basis_id": str(uuid4())},
        )
        assert held.status_code == 200, held.text
        expected = 403
    refused = approve_batch(client, repaired, reviewer, previews)
    assert refused.status_code == expected and TRANSCRIPT not in refused.text
    assert connection.execute("""
        SELECT count(*) FROM thalion.quality_decision WHERE (run_ref, outcome) = (%s, 'approved')
    """, (repaired.run_ref,)).fetchone() == (0,)


def test_database_does_not_accept_mismatched_page_receipts_on_pdf_approval(pdf_review):
    connection, _, _, repaired, client, reviewer, _ = stage_batch(pdf_review)
    permit_review(pdf_review, reviewer)
    ordered = [UUID(request) for request in compare_batch(client, repaired, reviewer)]
    tenant = pdf_review[0][1]
    request = uuid4()
    start_request(connection, RequestStart(
        tenant.org_id, request, tenant.actor_id, None, "synthetic-pdf-review", APPROVE,
        "local_workspace", datetime.now(UTC).date(), 1, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation, match="require every recent page receipt"):
        connection.execute("""
            INSERT INTO thalion.quality_decision (
                org_id, space_id, version_id, run_ref, reviewer_id, request_id, basis_ref,
                outcome, pdf_repair_page_requests, pdf_repair_proof_digest
            )
            SELECT org_id, space_id, version_id, run_ref, %s, %s, %s, 'approved', %s, %s
            FROM thalion.processing_run WHERE run_ref = %s
        """, (tenant.actor_id, request, uuid4(), ordered[::-1], bytes(32), repaired.run_ref))


def test_competing_whole_batch_approvals_only_record_one_decision(pdf_review):
    connection, _, _, repaired, client, reviewer, _ = stage_batch(pdf_review)
    permit_review(pdf_review, reviewer)
    previews = compare_batch(client, repaired, reviewer)
    with ThreadPoolExecutor(max_workers=2) as pool:
        submissions = [pool.submit(approve_batch, client, repaired, reviewer, previews) for _ in range(2)]
        assert sorted(submission.result().status_code for submission in submissions) == [200, 409]
    assert connection.execute("""
        SELECT count(*) FROM thalion.quality_decision WHERE (run_ref, outcome) = (%s, 'approved')
    """, (repaired.run_ref,)).fetchone() == (1,)
