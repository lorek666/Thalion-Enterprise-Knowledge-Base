from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.access.policy import LocalRule
from enterprise_kb.modules.evidence import docx_review as review_service, processing, quality_restrictions
from enterprise_kb.modules.sources import registry
from enterprise_kb.modules.sources.originals import OriginalIntegrityError
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from docx_fixture import DOCUMENT, docx_package
from test_archive_rule_checkpoint import rule_log
from test_docx_processing import docx_locators, register_docx
from test_docx_tables import AMOUNT_COLUMNS, COMPLETE, HEADERS, grid, table_package
from test_effectivity import BEGIN, approve
from test_employee_portal import browser, loopback_page
from test_evidence import claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_pdf_repair_management import load_reviewer
from test_persisted_access import authority_for, binding, set_rules
from test_quality_replay import replay
from test_rule_replay import rehearsal_clone
from test_runtime import runtime_db
from test_sources import request_for
from test_travel_search import SEARCH_FIELDS, corpus


PREVIEW = "preview_docx_quality"
DECIDE = "decide_docx_quality"
FIELDS = frozenset({"excerpt", "location"})
TEXT = "不得报销\t除非书面批准\n按实际金额。"


def path(run):
    return f"/internal/evidence/repairs/{run.run_ref}/docx"


def open_preview(client, token, run, *, tables=False):
    return client.get(path(run) + "-preview", headers=bearer(token),
                      params={"format": "table-batch-v1"} if tables else None)


def decide(client, token, run, preview, outcome="approved", *, key=None, basis=None):
    return client.post(path(run) + "-decision", headers=command_headers(token, key), json={
        "preview_id": str(preview), "outcome": outcome, "basis_id": str(basis or uuid4()),
    })


def locate(connection, run):
    return connection.execute("""
        SELECT identity.public_id FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.passage AS passage USING (org_id, space_id, passage_id)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
           = (passage.org_id, passage.space_id, 'passage', passage.passage_id)
        WHERE excerpt.run_ref = %s ORDER BY passage.docx_paragraph
    """, (run.run_ref,)).fetchall()


def grant(tenant, ref, fields=FIELDS, *, principal=None):
    return LocalRule(principal or tenant.actor_id, PREVIEW, "allow", "evidence_quality_review", "local_workspace",
                     fields, datetime.now(UTC) - timedelta(minutes=1), passage_ref=ref)


@pytest.fixture
def docx_review(evidence_transport):
    service, db, tokens, credentials, *_ = evidence_transport
    connection, tenant, _, _, store = db
    version = register_docx(db, docx_package(), key="pending-docx", object_key="pending-docx")
    run = processing.process_evidence_job(connection, claim(db), store)
    approve(connection, tenant, version, BEGIN)
    for token in tokens:
        admit(credentials, token, PREVIEW, DECIDE)
    return service, db, tokens, version, run


@pytest.fixture
def docx_table_review(evidence_transport):
    service, db, tokens, credentials, *_ = evidence_transport
    connection, tenant, database_url, _, store = db
    source = registry.register_synthetic_source(connection, request_for(
        connection, tenant, tenant.actor_id, "docx-review-source", "register_source_contract",
    ), tenant.space_id, registry.SyntheticSource(
        "docx-table-reviews", "docx-table-archive", tenant.worker_id, approver_id=tenant.other_actor_id,
        processor_id=tenant.other_worker_id, quality_reviewer_id=tenant.actor_id, docx_amount_columns=AMOUNT_COLUMNS,
        model_policy_approver_id=tenant.other_actor_id,
    ))
    table_db = (connection, tenant, database_url, source, store)
    package = table_package(grid((HEADERS, COMPLETE, ("非正式员工", "800", "", "另行审批"))))
    version = register_docx(table_db, package, key="docx-table-review", object_key="docx-table-review")
    run = processing.process_evidence_job(connection, claim(table_db), store)
    approve(connection, tenant, version, BEGIN)
    for token in tokens:
        admit(credentials, token, PREVIEW, DECIDE)
    return service, table_db, tokens, version, run


def test_docx_table_preview_returns_literal_rows_and_does_not_enable_employee_delivery(transport, docx_table_review):
    client, *_ = transport
    _, db, (owner, _), version, run = docx_table_review
    connection, tenant, *_ = db
    refs = {ref for ref, in locate(connection, run)}
    set_rules(db, *(grant(tenant, ref) for ref in refs), replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))

    assert open_preview(client, owner, run).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.docx_quality_preview").fetchone() == (0,)
    response = open_preview(client, owner, run, tables=True)

    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    preview = response.json()
    table, = preview["batch"]["tables"]
    assert (table["table_number"], table["heading_path"], table["headers"]) == (1, ["差旅", "住宿"], list(HEADERS))
    included, incomplete = table["rows"]
    assert (included["row_number"], included["reason"]) == (2, None)
    assert (incomplete["row_number"], incomplete["reason"]) == (3, "missing_value")
    assert tuple(cell["excerpt"] for cell in included["cells"]) == COMPLETE
    assert [cell["role"] for cell in included["cells"]] == ["condition", "amount", "unit", "exception"]
    assert [cell["column_number"] for cell in included["cells"]] == [1, 2, 3, 4]
    assert all(cell["role"] is None for cell in incomplete["cells"]) and incomplete["cells"][2]["excerpt"] == ""
    assert refs == {UUID(part["passage_id"]) for part in preview["batch"]["paragraphs"] + included["cells"] + incomplete["cells"]}
    assert decide(client, owner, run, preview["preview_id"]).status_code == 200
    assert docx_locators(db, version) == ()
    assert all(client.get(f"/v1/passages/{ref}", headers=bearer(owner)).status_code == 404 for ref in refs)


def test_docx_table_preview_requires_every_cell_before_opening_and_at_decision(transport, docx_table_review, monkeypatch):
    client, *_ = transport
    service, db, (owner, _), _, run = docx_table_review
    connection, tenant, _, _, store = db
    refs = [ref for ref, in locate(connection, run)]
    missing, = connection.execute("""
        SELECT identity.public_id FROM thalion.object_identity AS identity
        JOIN thalion.passage AS passage ON passage.passage_id = identity.object_id AND identity.object_type = 'passage'
        JOIN thalion.passage_excerpt AS excerpt USING (passage_id)
        WHERE excerpt.run_ref = %s AND (passage.docx_table, passage.docx_row, passage.docx_column) = (1, 3, 3)
    """, (run.run_ref,)).fetchone()
    set_rules(db, grant(tenant, None), *(grant(tenant, ref) for ref in refs if ref != missing))
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *_: pytest.fail("Must not open a partly authorized batch."))
        assert open_preview(client, owner, run, tables=True).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.docx_quality_preview").fetchone() == (0,)

    set_rules(db, *(grant(tenant, ref) for ref in refs), expected=2)
    response = open_preview(client, owner, run, tables=True)
    assert response.status_code == 200
    source_check = authority_for({tenant.actor_id})
    checks = []

    def revoke_at_final_check(credential, probe):
        checks.append({scope.object_id for scope in probe.scopes})
        result = source_check(probe)
        if len(checks) == 2:
            return replace(result, permitted_fields={scope: frozenset() if scope.object_id == missing else fields
                                                     for scope, fields in result.permitted_fields.items()})
        return result

    service.check_source = revoke_at_final_check
    assert decide(client, owner, run, response.json()["preview_id"]).status_code == 403
    assert checks == [set(refs), set(refs)]
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision WHERE run_ref = %s", (run.run_ref,)).fetchone() == (0,)


def test_docx_approved_table_projection_keeps_exact_complete_units_and_checks_the_original(transport, docx_table_review):
    client, *_ = transport
    _, db, (owner, _), version, run = docx_table_review
    connection, tenant, _, _, store = db
    scope = (connection, tenant.org_id, tenant.space_id, version.version_ref)
    assert processing.list_approved_docx_units(*scope) == ()
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)))
    preview = open_preview(client, owner, run, tables=True).json()
    assert decide(client, owner, run, preview["preview_id"]).status_code == 200

    unit, = processing.list_approved_docx_units(*scope)
    assert (unit.table_number, unit.row_number, unit.amount_columns) == (1, 2, AMOUNT_COLUMNS)
    assert [(member.role, member.cell.column_number) for member in unit.members] == [
        ("condition", 1), ("amount", 2), ("unit", 3), ("exception", 4),
    ]
    included, incomplete = preview["batch"]["tables"][0]["rows"]
    assert {str(member.cell.passage_ref) for member in unit.members} == {cell["passage_id"] for cell in included["cells"]}
    assert processing.list_approved_docx_units(*scope, passage_ref=unit.members[1].cell.passage_ref) == (unit,)
    assert processing.list_approved_docx_units(*scope, passage_ref=UUID(incomplete["cells"][1]["passage_id"])) == ()
    assert processing.list_approved_docx_units(connection, tenant.org_id, tenant.space_id + 1000, version.version_ref) == ()

    asset = connection.execute("SELECT storage_key FROM thalion.asset WHERE content_digest = %s", (version.digest,)).fetchone()[0]
    payload = (store.root / asset).read_bytes()
    material = processing.resolve_docx_units(payload, (unit,))
    assert [material[member.cell] for member in unit.members] == list(zip(HEADERS, COMPLETE))
    rewritten = table_package(grid((HEADERS, (COMPLETE[0], "600.50", *COMPLETE[2:]))))
    with pytest.raises(OriginalIntegrityError):
        processing.resolve_docx_units(rewritten, (unit,))
    with pytest.raises(OriginalIntegrityError):
        processing.resolve_docx_units(payload, (replace(unit, members=unit.members[:-1]),))
    review(db, run, decision="quarantined")
    assert processing.list_approved_docx_units(*scope) == ()


def test_docx_management_routes_reject_an_employee_credential_without_review_capability(transport):
    client, _, (owner, _), *_ = transport
    assert client.get(f"/internal/evidence/repairs/{uuid4()}/docx-preview").status_code == 401
    assert client.get(f"/internal/evidence/repairs/{uuid4()}/docx-preview", headers=bearer(owner)).status_code == 403


def test_docx_review_seals_the_whole_batch_and_uses_the_same_reviewer_and_client(transport, docx_review):
    client, db, (owner, other), credentials, *_ = transport
    _, _, _, version, run = docx_review
    connection, tenant, *_ = db
    (first,), (second,) = locate(connection, run)
    direct = f"/v1/passages/{first}"
    assert client.get(direct, headers=bearer(owner)).status_code == 404
    assert decide(client, owner, run, uuid4()).status_code == 409
    set_rules(db, grant(tenant, first), grant(tenant, second),
              grant(tenant, first, principal=tenant.other_actor_id), grant(tenant, second, principal=tenant.other_actor_id),
              expected=2)
    assert open_preview(client, other, run).status_code == 403
    preview = open_preview(client, owner, run)
    assert preview.status_code == 200 and preview.headers["cache-control"] == "no-store"
    data = preview.json()
    assert data["batch"]["version_id"] == str(version.version_ref)
    assert data["batch"]["manifest_sha256"] == run.manifest_digest.hex()
    assert [(item["passage_id"], item["document_paragraph"], item["excerpt"]) for item in data["batch"]["paragraphs"]] == [
        (str(first), 3, TEXT), (str(second), 5, "仅限正式员工。"),
    ]
    assert all(item["location"] == {"heading_path": ["差旅", "住宿"], "paragraph": 1}
               for item in data["batch"]["paragraphs"])
    assert client.get(direct, headers=bearer(owner)).status_code == 404
    assert decide(client, other, run, data["preview_id"]).status_code == 403
    saved = credentials[owner]
    credentials[owner] = replace(saved, client_id="other-client")
    assert decide(client, owner, run, data["preview_id"]).status_code == 409
    credentials[owner] = saved
    result = decide(client, owner, run, data["preview_id"])
    assert result.status_code == 200 and result.json()["outcome"] == "approved"
    assert connection.execute("""
        SELECT quality.reviewer_id, quality.docx_preview_request, preview.proof_digest
        FROM thalion.quality_decision AS quality JOIN thalion.docx_quality_preview AS preview
          ON (quality.org_id, quality.docx_preview_request) = (preview.org_id, preview.request_id)
        WHERE decision_ref = %s
    """, (UUID(result.json()["decision_id"]),)).fetchone()[:2] == (tenant.actor_id, UUID(data["preview_id"]))
    assert client.get(direct, headers=bearer(owner)).status_code == 404


def test_docx_preview_requires_all_exact_grants_before_any_original_read(transport, docx_review, monkeypatch):
    client, db, (owner, _), *_ = transport
    _, _, _, _, run = docx_review
    connection, tenant, _, _, store = db
    (first,), (second,) = locate(connection, run)
    set_rules(db, grant(tenant, None), grant(tenant, first), grant(tenant, second, frozenset({"excerpt"})), expected=2)

    def no_read(*_):
        pytest.fail("The original must not be opened for a partial DOCX approval scope.")

    monkeypatch.setattr(store, "read", no_read)
    response = open_preview(client, owner, run)
    assert response.status_code == 403 and "batch" not in response.json()
    assert connection.execute("SELECT count(*) FROM thalion.docx_quality_preview").fetchone() == (0,)


def test_docx_review_rechecks_source_rights_at_preview_and_decision(transport, docx_review):
    client, db, (owner, _), *_ = transport
    service, _, _, _, run = docx_review
    connection, tenant, *_ = db
    refs = [ref for ref, in locate(connection, run)]
    set_rules(db, *(grant(tenant, ref) for ref in refs), expected=2)
    live = authority_for({tenant.actor_id})
    seen = []
    deny_at = {2}

    def check(credential, probe):
        seen.append(probe)
        assert {(scope.object_id, scope.revision, scope.fields) for scope in probe.scopes} == {
            (ref, 1, FIELDS) for ref in refs
        }
        decision = live(probe)
        if len(seen) in deny_at:
            return replace(decision, permitted_fields={
                scope: fields if scope.object_id == refs[0] else fields - {"location"}
                for scope, fields in decision.permitted_fields.items()
            })
        return decision

    service.check_source = check
    assert open_preview(client, owner, run).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.docx_quality_preview").fetchone() == (0,)
    preview = open_preview(client, owner, run)
    assert preview.status_code == 200
    deny_at.add(6)
    denied = decide(client, owner, run, preview.json()["preview_id"])
    assert denied.status_code == 403 and "decision_id" not in denied.json()
    assert len(seen) == 6
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision WHERE run_ref = %s", (run.run_ref,)).fetchone() == (0,)


def test_docx_new_run_invalidates_old_review_and_uses_a_new_receipt(transport, docx_review):
    client, db, (owner, _), *_ = transport
    _, _, _, version, run = docx_review
    connection, tenant, _, _, store = db
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)), expected=2)
    preview = open_preview(client, owner, run)
    assert preview.status_code == 200
    revision, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
               parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE profile = 'docx_literal_paragraphs_v1'
        RETURNING configuration_revision
    """).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, revision))
    current = processing.process_evidence_job(connection, claim(db), store)
    assert decide(client, owner, run, preview.json()["preview_id"]).status_code == 409
    assert decide(client, owner, current, preview.json()["preview_id"]).status_code == 409
    replacement = open_preview(client, owner, current)
    assert {item["excerpt_revision"] for item in replacement.json()["batch"]["paragraphs"]} == {2}
    assert decide(client, owner, current, replacement.json()["preview_id"], "quarantined").status_code == 200
    assert open_preview(client, owner, current).status_code == 409


def test_docx_expired_preview_cannot_be_used(transport, docx_review, monkeypatch):
    client, db, (owner, _), *_ = transport
    _, _, _, _, run = docx_review
    connection, tenant, *_ = db
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)), expected=2)
    monkeypatch.setattr(review_service, "PREVIEW_WINDOW", timedelta(microseconds=1))
    preview = open_preview(client, owner, run)
    assert preview.status_code == 200
    assert decide(client, owner, run, preview.json()["preview_id"]).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision WHERE run_ref = %s", (run.run_ref,)).fetchone() == (0,)


def test_docx_policy_replacement_requires_a_new_preview_even_with_identical_grants(transport, docx_review):
    client, db, (owner, _), *_ = transport
    _, _, _, _, run = docx_review
    connection, tenant, *_ = db
    grants = [grant(tenant, ref) for ref, in locate(connection, run)]
    set_rules(db, *grants, expected=2)
    previous = open_preview(client, owner, run)
    assert previous.status_code == 200
    set_rules(db, *grants, expected=3)
    assert decide(client, owner, run, previous.json()["preview_id"]).status_code == 409
    current = open_preview(client, owner, run)
    assert current.status_code == 200
    assert decide(client, owner, run, current.json()["preview_id"]).status_code == 200


def test_docx_existing_decision_allows_only_an_authorized_identical_command_replay(transport, docx_review):
    client, db, (owner, _), *_ = transport
    _, _, _, _, run = docx_review
    connection, tenant, *_ = db
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)), expected=2)
    initial, alternate = [open_preview(client, owner, run).json()["preview_id"] for _ in range(2)]
    key, basis = str(uuid4()), uuid4()
    first = decide(client, owner, run, initial, key=key, basis=basis)
    replay = decide(client, owner, run, initial, key=key, basis=basis)
    assert first.status_code == replay.status_code == 200
    assert first.json()["decision_id"] == replay.json()["decision_id"]
    assert decide(client, owner, run, initial, key=key).status_code == 409
    assert decide(client, owner, run, initial, "quarantined").status_code == 409
    assert decide(client, owner, run, alternate, "quarantined").status_code == 409
    assert connection.execute("SELECT outcome FROM thalion.quality_decision WHERE run_ref = %s", (run.run_ref,)).fetchall() == [
        ("approved",),
    ]


def test_docx_review_authority_failure_returns_no_content_or_decision(transport, docx_review):
    client, db, (owner, _), *_ = transport
    service, _, _, _, run = docx_review
    connection, tenant, *_ = db
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)), expected=2)
    preview = open_preview(client, owner, run)
    assert preview.status_code == 200

    def unavailable(*_):
        raise AuthorizationUnavailable("Synthetic source authority is temporarily unavailable.")

    service.check_source = unavailable
    blocked_preview = open_preview(client, owner, run)
    blocked_decision = decide(client, owner, run, preview.json()["preview_id"])
    assert blocked_preview.status_code == blocked_decision.status_code == 503
    assert "batch" not in blocked_preview.json() and "decision_id" not in blocked_decision.json()
    assert connection.execute("SELECT count(*) FROM thalion.docx_quality_preview").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision WHERE run_ref = %s", (run.run_ref,)).fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.command_receipt WHERE operation = %s", (DECIDE,)).fetchone() == (0,)


def test_docx_review_does_not_offer_partial_previews_above_the_policy_capacity(transport, docx_review, monkeypatch):
    client, db, (owner, _), *_ = transport
    connection, _, _, _, store = db
    body = "<w:p><w:r><w:t>合成段落</w:t></w:r></w:p>" * 501
    payload = docx_package(DOCUMENT[:DOCUMENT.index("<w:body>")] + f"<w:body>{body}</w:body></w:document>")
    register_docx(db, payload, key="long-docx", object_key="long-docx")
    run = processing.process_evidence_job(connection, claim(db), store)
    assert run.passage_count == 501 and run.outcome == "pending_review"

    def no_read(*_):
        pytest.fail("The original must not be opened for an unreviewable DOCX batch.")

    monkeypatch.setattr(store, "read", no_read)
    blocked = open_preview(client, owner, run)
    assert blocked.status_code == 409 and "batch" not in blocked.json()
    assert connection.execute("SELECT count(*) FROM thalion.docx_quality_preview").fetchone() == (0,)


@pytest.mark.parametrize("variant", ["docx_review", "docx_table_review"])
def test_docx_managed_quarantine_replays_without_restoring_the_preview(transport, request, variant, rule_log, postgres_server):
    client, *_ = transport
    _, db, (owner, _), _, run = request.getfixturevalue(variant)
    connection, tenant, database_url, *_ = db
    tables = variant == "docx_table_review"
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)), expected=1 if tables else 2)

    with rehearsal_clone(connection, database_url, postgres_server) as (primary, staged, _):
        preview = open_preview(client, owner, run, tables=tables)
        assert preview.status_code == 200
        response = decide(client, owner, run, preview.json()["preview_id"], "quarantined")
        assert response.status_code == 200
        decision = UUID(response.json()["decision_id"])
        assert quality_restrictions.deliver_pending(primary, rule_log, tenant.org_id).confirmed == (decision,)
        result = replay(primary, rule_log, staged, tenant.org_id)
        assert (result.status, result.applied) == ("replayed", (decision,))
        assert staged.execute("""
            SELECT outcome, request_id, docx_preview_request FROM thalion.quality_decision WHERE decision_ref = %s
        """, (decision,)).fetchone() == ("quarantined", None, None)
        assert staged.execute("SELECT count(*) FROM thalion.docx_quality_preview").fetchone() == (0,)


def test_docx_management_workflow_clears_preview_after_deciding(browser, docx_review):
    from playwright.sync_api import expect

    service, db, (owner, _), _, run = docx_review
    connection, tenant, *_ = db
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)), expected=2)
    with loopback_page(browser, service, "/manage/repairs") as (page, _, _):
        load_reviewer(page, owner)
        page.get_by_role("radio", name="DOCX 批次审核").check()
        page.get_by_label("待审批次编号").fill(str(run.run_ref))
        page.get_by_role("button", name="查看待审批次").click()
        expect(page.get_by_text("已载入 2 段待审核材料", exact=True)).to_be_visible()
        expect(page.get_by_text("差旅 / 住宿 / 第 1 段 · 主文档第 3 段 · 转录 1", exact=True)).to_be_visible()
        expect(page.get_by_text("仅限正式员工。", exact=True)).to_be_visible()
        page.get_by_label("审核依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="批准 DOCX 批次").click()
        expect(page.get_by_text("DOCX 批次已批准。", exact=True)).to_be_visible()
        expect(page.get_by_text("仅限正式员工。", exact=True)).to_have_count(0)


def test_docx_management_displays_the_full_table_and_clears_it_after_approval(browser, docx_table_review):
    from playwright.sync_api import expect

    service, db, (owner, _), _, run = docx_table_review
    connection, tenant, *_ = db
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, run)))
    with loopback_page(browser, service, "/manage/repairs") as (page, _, _):
        load_reviewer(page, owner)
        page.get_by_role("radio", name="DOCX 批次审核").check()
        page.get_by_label("待审批次编号").fill(str(run.run_ref))
        page.get_by_role("button", name="查看待审批次").click()
        table = page.get_by_role("table", name="差旅 / 住宿 / 第 1 表")
        expect(table.get_by_role("columnheader", name="上限")).to_be_visible()
        expect(table.get_by_text("0600.50", exact=True)).to_be_visible()
        expect(table.get_by_text("缺少必需值", exact=True)).to_be_visible()
        expect(page.get_by_text("已载入 2 段、1 张表待审核", exact=True)).to_be_visible()
        page.get_by_label("审核依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="批准 DOCX 批次").click()
        expect(page.get_by_text("DOCX 批次已批准。", exact=True)).to_be_visible()
        expect(table).to_have_count(0)
