from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from secrets import token_urlsafe
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from psycopg import errors
import pytest

from enterprise_kb.database import upgrade
from enterprise_kb.modules.access import governance, policy
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.operations import feedback, handoffs
from enterprise_kb.modules.sources import effectivity, registry, responsibility
from enterprise_kb.transport import api

from test_effectivity import BEGIN, approve
from test_employee_portal import browser, portal, screenshot
from test_evidence import approved, claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, rpc
from test_feedback import present
from test_feedback_work import EVIDENCE_CAPABILITY, QUEUE_CAPABILITY, admit, assign, submit as submit_feedback
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import open_database, runtime_db
from test_sources import register, request_for
from test_travel_search import SEARCH_FIELDS, corpus


GOV_PATH = "/internal/governance"
GOV_OPS = frozenset({
    "search", "read_passage", "download_original",
    governance.READ_GOVERNANCE, governance.MANAGE_SHARED_GROUP,
    governance.MANAGE_DELEGATION, governance.ARCHIVE_SPACE, governance.HANDOFF_TRANSITION,
    responsibility.READ, responsibility.SET,
    handoffs.AUTHORIZE, handoffs.ACCEPT, handoffs.REVOKE,
    QUEUE_CAPABILITY, EVIDENCE_CAPABILITY,
})


def _headers(token: str, key: str | None = None) -> dict[str, str]:
    base = bearer(token)
    if key is not None:
        base["Idempotency-Key"] = key
    return base


def _add_employee(connection, org_id: int) -> tuple[int, UUID]:
    with connection.transaction():
        principal_id, = connection.execute(
            """
            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
            VALUES (%s, 'employee', 'https://synthetic.invalid', %s) RETURNING principal_id
            """,
            (org_id, f"emp-{uuid4()}"),
        ).fetchone()
        public_ref, = connection.execute(
            """
            INSERT INTO thalion.object_identity (object_type, object_id, org_id)
            VALUES ('principal', %s, %s) RETURNING public_id
            """,
            (principal_id, org_id),
        ).fetchone()
    return principal_id, public_ref


def _add_space(connection, org_id: int, name: str, classification: str, owner_id: int) -> tuple[int, UUID]:
    with connection.transaction():
        space_id, = connection.execute(
            """
            INSERT INTO thalion.space (org_id, name, classification, owner_principal_id)
            VALUES (%s, %s, %s, %s) RETURNING space_id
            """,
            (org_id, name, classification, owner_id),
        ).fetchone()
        space_ref, = connection.execute(
            """
            INSERT INTO thalion.object_identity (object_type, object_id, org_id, space_id)
            VALUES ('space', %s, %s, %s) RETURNING public_id
            """,
            (space_id, org_id, space_id),
        ).fetchone()
    return space_id, space_ref


def _cred_for(template, *, employee_ref: UUID, space_ref: UUID | None = None, ops=GOV_OPS):
    return replace(
        template,
        employee_ref=employee_ref,
        space_ref=space_ref or template.space_ref,
        operations=frozenset(ops),
    )


def test_governance_migration_and_db_guards(database_url, evidence_db):
    assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
    connection, tenant, *_ = evidence_db
    now = datetime.now(UTC)
    ctx = request_for(connection, tenant, tenant.actor_id, "gov-guard-req", governance.MANAGE_DELEGATION)

    # Self-delegation must be rejected by CHECK constraint.
    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.space_delegation (
                    org_id, space_id, delegator_id, delegate_id, scopes, purpose,
                    basis_ref, request_id, starts_at, review_at, expires_at
                ) VALUES (%s, %s, %s, %s, ARRAY['responsibility_management'], 'self_del',
                          %s, %s, %s, %s, %s)
                """,
                (
                    tenant.org_id, tenant.space_id, tenant.actor_id, tenant.actor_id,
                    uuid4(), ctx.request_id, now - timedelta(minutes=1),
                    now + timedelta(minutes=5), now + timedelta(minutes=10),
                ),
            )

    # Creating a valid delegation and checking immutability trigger.
    with connection.transaction():
        del_ref, = connection.execute(
            """
            INSERT INTO thalion.space_delegation (
                org_id, space_id, delegator_id, delegate_id, scopes, purpose,
                basis_ref, request_id, starts_at, review_at, expires_at
            ) VALUES (%s, %s, %s, %s, ARRAY['responsibility_management'], 'valid_del',
                      %s, %s, %s, %s, %s)
            RETURNING delegation_ref
            """,
            (
                tenant.org_id, tenant.space_id, tenant.actor_id, tenant.other_actor_id,
                uuid4(), ctx.request_id, now - timedelta(minutes=1),
                now + timedelta(minutes=5), now + timedelta(minutes=10),
            ),
        ).fetchone()
    assert connection.execute(
        "SELECT thalion.has_active_space_delegation(%s, %s, %s, 'responsibility_management')",
        (tenant.org_id, tenant.space_id, tenant.other_actor_id),
    ).fetchone()[0] is True
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        with connection.transaction():
            connection.execute(
                "UPDATE thalion.space_delegation SET purpose = 'tampered' WHERE delegation_ref = %s",
                (del_ref,),
            )


def test_three_spaces_time_bounded_shared_group_expiry_transfer_and_project_archive(evidence_transport):
    service, db, (owner, other), credentials, live, first, second = evidence_transport
    connection, tenant, _, finance_source, store = db

    # Space 1 (existing): Finance space (tenant.space_id); Space 2: Business; Space 3: Cross-department Project.
    _, biz_space_ref = _add_space(connection, tenant.org_id, "business-ops", "internal", tenant.actor_id)
    proj_space_id, proj_space_ref = _add_space(connection, tenant.org_id, "cross-dept-project", "restricted", tenant.actor_id)

    admin_only_id, admin_only_ref = _add_employee(connection, tenant.org_id)
    member_a_id, member_a_ref = _add_employee(connection, tenant.org_id)
    member_b_id, member_b_ref = _add_employee(connection, tenant.org_id)
    member_c_id, member_c_ref = _add_employee(connection, tenant.org_id)

    # Grant source authority to members (to prove local shared group controls local scope, and source revoke still blocks).
    live.update({member_a_id, member_b_id, member_c_id})

    owner_proj_tok = token_urlsafe(32)
    admin_only_tok = token_urlsafe(32)
    member_a_tok = token_urlsafe(32)
    member_b_tok = token_urlsafe(32)
    member_c_tok = token_urlsafe(32)

    credentials[owner] = replace(credentials[owner], operations=GOV_OPS)
    credentials[owner_proj_tok] = _cred_for(credentials[owner], employee_ref=credentials[owner].employee_ref, space_ref=proj_space_ref)
    credentials[admin_only_tok] = _cred_for(credentials[owner], employee_ref=admin_only_ref)
    credentials[member_a_tok] = _cred_for(credentials[owner], employee_ref=member_a_ref, ops={"search", "read_passage", "download_original"})
    credentials[member_b_tok] = _cred_for(credentials[owner], employee_ref=member_b_ref, ops={"search", "read_passage", "download_original"})
    credentials[member_c_tok] = _cred_for(credentials[owner], employee_ref=member_c_ref, ops={"search", "read_passage", "download_original"})

    with TestClient(api.create_app(service), base_url="http://127.0.0.1:8765") as client:
        # MCP must never expose any governance tools.
        mcp_tools = {t["name"] for t in rpc(client, owner, "tools/list").json()["result"]["tools"]}
        assert not (mcp_tools & governance.OPERATIONS)

        now, = connection.execute("SELECT clock_timestamp()").fetchone()

        # Admin-only employee gets delegation for shared_group_management but ZERO read rights.
        del_resp = client.post(
            f"{GOV_PATH}/delegations",
            headers=_headers(owner, "del-admin-only"),
            json={
                "delegate_id": str(admin_only_ref),
                "scopes": ["shared_group_management"],
                "purpose": "project_admin_only",
                "starts_at": (now - timedelta(minutes=1)).isoformat(),
                "review_at": (now + timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
                "basis_id": str(uuid4()),
            },
        )
        assert del_resp.status_code == 200
        # Admin-only can inspect governance overview, but cannot read content or search passages!
        assert client.get(GOV_PATH, headers=bearer(admin_only_tok)).status_code == 200
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(admin_only_tok)).status_code == 404
        admin_search = client.post(
            "/v1/search", headers=bearer(admin_only_tok),
            json={"query": "上海住宿", "business_date": BEGIN.isoformat()},
        )
        assert admin_search.status_code == 200 and admin_search.json()["passages"] == []

        # Create cross-space time-bounded shared group owned by Project space targeting Finance source!
        grp_resp = client.post(
            f"{GOV_PATH}/shared-groups",
            headers=_headers(owner_proj_tok, "create-cross-space-group"),
            json={
                "target_source_id": str(finance_source),
                "name": "跨部门差旅核对组",
                "purpose": "cross_dept_audit",
                "scope_summary": "finance_allowance_row_only",
                "starts_at": (now - timedelta(minutes=1)).isoformat(),
                "review_at": (now + timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(minutes=15)).isoformat(),
                "basis_id": str(uuid4()),
            },
        )
        assert grp_resp.status_code == 200, grp_resp.text
        group_id = grp_resp.json()["group_id"]
        group_principal_ref = UUID(grp_resp.json()["group_principal_id"])

        # Grant the shared group ONLY passage `first` (partial row/passage scope), and explicitly DENY `second`.
        current_epoch, = connection.execute(
            "SELECT safety_epoch FROM thalion.source WHERE (org_id, space_id) = (%s, %s)",
            (tenant.org_id, tenant.space_id),
        ).fetchone()
        set_rules(
            db,
            replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
            replace(binding(group_principal_ref), fields=SEARCH_FIELDS, passage_ref=first.passage_ref),
            replace(binding(group_principal_ref), effect="deny", fields=SEARCH_FIELDS, passage_ref=second.passage_ref),
            expected=current_epoch,
        )

        # Before joining shared group, member_a cannot read `first`.
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_a_tok)).status_code == 404

        # Add member_a with short 2.5s window (expiry test), member_b and member_c with longer windows.
        short_expiry, = connection.execute("SELECT clock_timestamp() + interval '2.5 seconds'").fetchone()
        for tok_key, emp_ref, exp in (
            ("add-a", member_a_ref, short_expiry),
            ("add-b", member_b_ref, now + timedelta(minutes=10)),
            ("add-c", member_c_ref, now + timedelta(minutes=10)),
        ):
            add_resp = client.post(
                f"{GOV_PATH}/shared-groups/{group_id}/members",
                headers=_headers(owner_proj_tok, tok_key),
                json={
                    "member_id": str(emp_ref),
                    "starts_at": (now - timedelta(seconds=10)).isoformat(),
                    "expires_at": exp.isoformat(),
                    "basis_id": str(uuid4()),
                },
            )
            assert add_resp.status_code == 200, add_resp.text

        # Verify member_a can search, see source option, get title suggestion, and read `first`,
        # while `second` (explicit deny) and full original download remain blocked!
        a_search = client.post(
            "/v1/search", headers=bearer(member_a_tok),
            json={"query": "上海住宿", "business_date": BEGIN.isoformat()},
        )
        assert a_search.status_code == 200
        assert [p["passage_id"] for p in a_search.json()["passages"]] == [str(first.passage_ref)]
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_a_tok)).status_code == 200
        assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(member_a_tok)).status_code == 404
        opts = client.get(f"/employee/source-options?business_date={BEGIN.isoformat()}", headers=bearer(member_a_tok))
        assert opts.status_code == 200 and len(opts.json()["options"]) == 1
        sug = client.post(
            "/employee/search-suggestions",
            headers=bearer(member_a_tok),
            json={"business_date": BEGIN.isoformat(), "prefix": "住"},
        )
        assert sug.status_code == 200 and len(sug.json()["suggestions"]) >= 1
        # Partial reader has no full original download permission.
        ver_ref, = connection.execute(
            """
            SELECT oi.public_id FROM thalion.passage p
            JOIN thalion.object_identity oi
              ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (p.org_id, p.space_id, 'document_version', p.version_id)
            JOIN thalion.object_identity po
              ON (po.org_id, po.space_id, po.object_type, po.object_id) = (p.org_id, p.space_id, 'passage', p.passage_id)
            WHERE po.public_id = %s
            """,
            (first.passage_ref,),
        ).fetchone()
        assert client.get(
            f"/employee/originals/{ver_ref}",
            headers=bearer(member_a_tok),
        ).status_code == 404

        # Source-side revocation STILL blocks even when member_a is in the local shared group!
        live.discard(member_a_id)
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_a_tok)).status_code == 404
        live.add(member_a_id)

        # 1) Wait for member_a's time-bounded membership to expire -> access stops immediately and never revives.
        connection.execute(
            "SELECT pg_sleep(greatest(0, extract(epoch FROM %s::timestamptz - clock_timestamp()) + 0.1))",
            (short_expiry,),
        )
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_a_tok)).status_code == 404
        expired_search = client.post(
            "/v1/search", headers=bearer(member_a_tok),
            json={"query": "上海住宿", "business_date": BEGIN.isoformat()},
        )
        assert expired_search.status_code == 200 and expired_search.json()["passages"] == []
        expired_sug = client.post(
            "/employee/search-suggestions",
            headers=bearer(member_a_tok),
            json={"business_date": BEGIN.isoformat(), "prefix": "住"},
        )
        assert expired_sug.status_code == 200 and expired_sug.json()["suggestions"] == []

        # 2) Employee transfer for member_b -> transition handoff revokes shared group membership immediately!
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_b_tok)).status_code == 200
        transfer_resp = client.post(
            f"{GOV_PATH}/transitions/{member_b_ref}/handoff",
            headers=_headers(owner, "transfer-member-b"),
            json={
                "transition_kind": "transfer",
                "review_at": (now + timedelta(days=7)).isoformat(),
                "basis_id": str(uuid4()),
            },
        )
        assert transfer_resp.status_code == 200, transfer_resp.text
        assert transfer_resp.json()["revoked_group_member_count"] == 1
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_b_tok)).status_code == 404
        b_opts = client.get(f"/employee/source-options?business_date={BEGIN.isoformat()}", headers=bearer(member_b_tok))
        assert b_opts.status_code == 200 and b_opts.json()["options"] == []

        # 3) Project space archive -> immediately invalidates cross-space shared group for member_c!
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_c_tok)).status_code == 200
        archive_resp = client.post(
            f"{GOV_PATH}/spaces/archive",
            headers=_headers(owner_proj_tok, "archive-proj-space"),
            json={"reason_code": "project_completed", "basis_id": str(uuid4())},
        )
        assert archive_resp.status_code == 200, archive_resp.text
        assert archive_resp.json()["lifecycle"] == "archived"
        assert archive_resp.json()["disabled_shared_groups"] == 1
        # Further requests against an archived space are blocked at ingress (403).
        assert client.post(
            f"{GOV_PATH}/spaces/archive",
            headers=_headers(owner_proj_tok, "archive-proj-space"),
            json={"reason_code": "project_completed", "basis_id": str(uuid4())},
        ).status_code == 403
        assert client.get(GOV_PATH, headers=bearer(owner_proj_tok)).status_code == 403
        # member_c immediately loses access across all endpoints!
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(member_c_tok)).status_code == 404
        c_search = client.post(
            "/v1/search", headers=bearer(member_c_tok),
            json={"query": "上海住宿", "business_date": BEGIN.isoformat()},
        )
        assert c_search.status_code == 200 and c_search.json()["passages"] == []
        assert biz_space_ref != proj_space_ref


def test_delegation_proxy_handoff_departure_and_acceptance_receipt(evidence_transport):
    service, db, (owner, incumbent), credentials, live, first, _ = evidence_transport
    connection, tenant, _, source, _ = db

    delegate_id, delegate_ref = _add_employee(connection, tenant.org_id)
    successor_id, successor_ref = _add_employee(connection, tenant.org_id)
    delegate_tok = token_urlsafe(32)
    successor_tok = token_urlsafe(32)
    credentials[owner] = replace(credentials[owner], operations=GOV_OPS)
    credentials[incumbent] = replace(credentials[incumbent], operations=GOV_OPS)
    credentials[delegate_tok] = _cred_for(credentials[owner], employee_ref=delegate_ref)
    credentials[successor_tok] = _cred_for(credentials[owner], employee_ref=successor_ref)

    # Grant incumbent & successor read rights so they can read original passages in feedback workflow;
    # delegate has NO read rights (A06).
    live.update({tenant.other_actor_id, successor_id})
    current_epoch, = connection.execute(
        "SELECT safety_epoch FROM thalion.source WHERE (org_id, space_id) = (%s, %s)",
        (tenant.org_id, tenant.space_id),
    ).fetchone()
    set_rules(
        db,
        replace(binding(tenant.actor_id), fields=SEARCH_FIELDS),
        replace(binding(tenant.other_actor_id), fields=SEARCH_FIELDS),
        replace(binding(successor_id), fields=SEARCH_FIELDS),
        expected=current_epoch,
    )

    doc_ref, = connection.execute(
        """
        SELECT oi.public_id FROM thalion.passage p
        JOIN thalion.document_version v USING (org_id, space_id, version_id)
        JOIN thalion.object_identity oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (v.org_id, v.space_id, 'document', v.document_id)
        JOIN thalion.object_identity po
          ON (po.org_id, po.space_id, po.object_type, po.object_id) = (p.org_id, p.space_id, 'passage', p.passage_id)
        WHERE po.public_id = %s
        """,
        (first.passage_ref,),
    ).fetchone()

    with TestClient(api.create_app(service), base_url="http://127.0.0.1:8765") as client:
        now, = connection.execute("SELECT clock_timestamp()").fetchone()

        # Delegate cannot manage document responsibility before delegation is issued.
        assert client.get(f"/internal/sources/documents/{doc_ref}/responsibility", headers=bearer(delegate_tok)).status_code == 403

        # Space owner issues delegation (responsibility_management + feedback_handoff_management) to delegate.
        del_resp = client.post(
            f"{GOV_PATH}/delegations",
            headers=_headers(owner, "delegate-proxy-1"),
            json={
                "delegate_id": str(delegate_ref),
                "scopes": ["responsibility_management", "feedback_handoff_management"],
                "purpose": "operations_proxy",
                "starts_at": (now - timedelta(minutes=1)).isoformat(),
                "review_at": (now + timedelta(days=3)).isoformat(),
                "expires_at": (now + timedelta(days=14)).isoformat(),
                "basis_id": str(uuid4()),
            },
        )
        assert del_resp.status_code == 200, del_resp.text
        delegation_id = del_resp.json()["delegation_id"]

        # Delegate assigns document responsibility to incumbent via delegated authority (still cannot read body!).
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(delegate_tok)).status_code == 404
        assign_doc = client.post(
            f"/internal/sources/documents/{doc_ref}/responsibility",
            headers=_headers(delegate_tok, "delegate-assign-doc"),
            json={
                "expected_generation": 0,
                "responsible_id": str(credentials[incumbent].employee_ref),
                "basis_id": str(uuid4()),
            },
        )
        assert assign_doc.status_code == 200, assign_doc.text

        # Open a feedback ticket assigned to incumbent.
        origin = present(client, owner, first)
        fb_ref = submit_feedback(connection, tenant, origin, first)
        assign(connection, tenant, fb_ref)

        # Delegate (under feedback_handoff_management delegation) authorizes feedback handoff to successor,
        # but CANNOT self-assign to self (403)!
        self_handoff = client.post(
            "/internal/feedback/handoffs",
            headers=_headers(delegate_tok, "delegate-self-handoff"),
            json={
                "from_employee_ref": str(credentials[incumbent].employee_ref),
                "to_employee_ref": str(delegate_ref),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "basis_id": str(uuid4()),
                "items": [{"feedback_id": str(fb_ref), "expected_generation": 2}],
            },
        )
        assert self_handoff.status_code == 403

        fb_handoff = client.post(
            "/internal/feedback/handoffs",
            headers=_headers(delegate_tok, "delegate-fb-handoff"),
            json={
                "from_employee_ref": str(credentials[incumbent].employee_ref),
                "to_employee_ref": str(successor_ref),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "basis_id": str(uuid4()),
                "items": [{"feedback_id": str(fb_ref), "expected_generation": 2}],
            },
        )
        assert fb_handoff.status_code == 200, fb_handoff.text
        fb_handoff_id = fb_handoff.json()["handoff_id"]

        # Successor accepts handoff and reads evidence under own identity.
        accepted = client.post(
            f"/internal/feedback/handoffs/{fb_handoff_id}/accept",
            headers=_headers(successor_tok, "successor-accept-fb"),
            json={},
        )
        assert accepted.status_code == 200, accepted.text
        assert client.get(f"/internal/feedback/{fb_ref}/evidence", headers=bearer(successor_tok)).status_code == 200

        # Incumbent departs: loses read rights & disabled in directory -> cannot read passage anymore!
        live.discard(tenant.other_actor_id)
        connection.execute("UPDATE thalion.principal SET disabled = true WHERE principal_id = %s", (tenant.other_actor_id,))
        assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(incumbent)).status_code in (401, 403, 404)

        # Inspect incumbent transition items and record formal departure handoff acceptance receipt.
        inspected = client.get(
            f"{GOV_PATH}/transitions/{credentials[incumbent].employee_ref}",
            headers=bearer(delegate_tok),
        )
        assert inspected.status_code == 200, inspected.text
        assert len(inspected.json()["active_document_responsibilities"]) == 1
        assert inspected.json()["employee_active"] is False
        assert inspected.json()["open_feedback_items"] == []

        review_day = (now + timedelta(days=30)).isoformat()
        basis_id = str(uuid4())
        handoff_body = {
            "transition_kind": "departure",
            "successor_id": str(successor_ref),
            "delegation_id": delegation_id,
            "review_at": review_day,
            "basis_id": basis_id,
            "accepted_feedback_handoff_ids": [fb_handoff_id],
        }
        receipt_resp = client.post(
            f"{GOV_PATH}/transitions/{credentials[incumbent].employee_ref}/handoff",
            headers=_headers(delegate_tok, "departure-receipt-1"),
            json=handoff_body,
        )
        assert receipt_resp.status_code == 200, receipt_resp.text
        rec = receipt_resp.json()
        assert rec["delegation_id"] == delegation_id
        assert rec["reassigned_document_count"] == 1
        assert rec["remaining_open_feedback_count"] == 0
        assert rec["accepted_feedback_handoff_ids"] == [fb_handoff_id]
        assert rec["handed_off_at"] and rec["review_at"]

        # Idempotent replay returns exact receipt; conflicting payload returns 409 governance_conflict.
        replay = client.post(
            f"{GOV_PATH}/transitions/{credentials[incumbent].employee_ref}/handoff",
            headers=_headers(delegate_tok, "departure-receipt-1"),
            json=handoff_body,
        )
        assert replay.status_code == 200 and replay.json()["receipt_id"] == rec["receipt_id"]
        conflict = client.post(
            f"{GOV_PATH}/transitions/{credentials[incumbent].employee_ref}/handoff",
            headers=_headers(delegate_tok, "departure-receipt-1"),
            json={**handoff_body, "transition_kind": "transfer"},
        )
        assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "governance_conflict"

        # Document responsibility now belongs to successor.
        doc_state = client.get(f"/internal/sources/documents/{doc_ref}/responsibility", headers=bearer(owner)).json()
        assert doc_state["responsible_id"] == str(successor_ref) and doc_state["state"] == "assigned"

        # Revoking delegation immediately revokes delegate's ability to manage document responsibility.
        rev_del = client.post(
            f"{GOV_PATH}/delegations/{delegation_id}/revoke",
            headers=_headers(owner, "revoke-proxy-del"),
            json={"reason_code": "handoff_complete", "basis_id": str(uuid4())},
        )
        assert rev_del.status_code == 200
        assert client.get(f"/internal/sources/documents/{doc_ref}/responsibility", headers=bearer(delegate_tok)).status_code == 403


def test_governance_management_portal_desktop_and_mobile(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, other), credentials, *_ = portal
    connection, tenant, _, source, _ = db
    credentials[owner] = replace(credentials[owner], operations=GOV_OPS)
    now, = connection.execute("SELECT clock_timestamp()").fetchone()

    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/manage/governance")
    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="载入治理凭据").click()
    expect(page.locator("#gov-status")).to_contain_text("已载入治理总览")

    # Create a time-bounded shared group via UI.
    page.get_by_label("目标来源编号").fill(str(source))
    page.get_by_label("共享组名称").fill("财务复核项目组")
    page.locator("#gov-group-start").fill((now - timedelta(minutes=1)).isoformat())
    page.locator("#gov-group-review").fill((now + timedelta(days=3)).isoformat())
    page.locator("#gov-group-expiry").fill((now + timedelta(days=7)).isoformat())
    page.get_by_label("共享依据编号").fill(str(uuid4()))
    page.get_by_role("button", name="创建限时共享组").click()
    expect(page.locator("#gov-group-result")).to_contain_text("已创建限时共享组")

    # Issue delegation via UI.
    page.get_by_label("代理人员工编号").fill(str(credentials[other].employee_ref))
    page.locator("#gov-del-start").fill((now - timedelta(minutes=1)).isoformat())
    page.locator("#gov-del-review").fill((now + timedelta(days=3)).isoformat())
    page.locator("#gov-del-expiry").fill((now + timedelta(days=7)).isoformat())
    page.get_by_label("委派依据编号").fill(str(uuid4()))
    page.get_by_role("button", name="签发空间委派").click()
    expect(page.locator("#gov-delegation-result")).to_contain_text("已签发空间委派")

    # Inspect and submit transition handoff receipt via UI.
    page.get_by_label("待交接员工编号").fill(str(credentials[other].employee_ref))
    page.get_by_role("button", name="核查交接项").click()
    expect(page.locator("#gov-transition-summary")).to_contain_text("员工状态")
    page.locator("#gov-handoff-review").fill((now + timedelta(days=14)).isoformat())
    page.locator("#gov-handoff-basis").fill(str(uuid4()))
    page.get_by_role("button", name="执行交接并签发验收单").click()
    expect(page.locator("#gov-handoff-result")).to_contain_text("已签发交接验收单")

    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-governance-desktop.png")

    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "management-governance-mobile.png")

    page.get_by_role("button", name="更换凭据").click()
    assert page.locator("#gov-status").inner_text() == ""
    assert page.locator("#gov-handoff-result").inner_text() == ""
