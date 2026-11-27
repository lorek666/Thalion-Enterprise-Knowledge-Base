from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from enterprise_kb.modules.evidence import docx_evidence, processing
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job
from enterprise_kb.transport.evidence import REPAIR_OPERATIONS

from docx_fixture import docx_package
from test_docx_processing import docx_locators, register_docx
from test_docx_review import decide, docx_table_review, grant, locate, open_preview
from test_docx_tables import COMPLETE
from test_employee_portal import browser, loopback_page, portal
from test_evidence import claim, evidence_db, review
from test_evidence_transport import evidence_transport, transport
from test_feedback_work import admit
from test_markdown_repair import client_for, get_preview, repair_rule, repair_service, submit_review
from test_pdf_repair_management import load_reviewer
from test_persisted_access import authority_for, set_rules
from test_runtime import runtime_db
from test_travel_search import corpus


def queue(db, version):
    connection, tenant, *_ = db
    configuration, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
               parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE profile = %s
        ORDER BY configuration_revision DESC LIMIT 1 RETURNING configuration_revision
    """, (docx_evidence.PROFILE,)).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, configuration))
    return claim(db)


def replace_run(db, lease, previous, basis=None, rollback=None):
    return processing.repair_docx_job(
        db[0], lease, db[-1], replaces=previous.run_ref, basis_ref=basis or uuid4(),
        rollback_to=rollback.run_ref if rollback else None,
    )


def incomplete_run(db, monkeypatch):
    connection, _, _, _, store = db
    version = register_docx(db, docx_package(), key="repair-docx", object_key="repair-docx")
    baseline = processing.process_evidence_job(connection, claim(db), store)
    review(db, baseline)
    original_positions = docx_locators(db, version)
    lease = queue(db, version)
    parse = docx_evidence.parse_docx

    def omit_last(payload, **options):
        candidate = parse(payload, **options)
        return replace(candidate, passages=candidate.passages[:-1])

    with monkeypatch.context() as patch:
        patch.setattr(docx_evidence, "parse_docx", omit_last)
        previous = processing.process_evidence_job(connection, lease, store)
    assert previous.passage_count == 1
    review(db, previous, decision="quarantined")
    return version, baseline, previous, original_positions


@pytest.mark.parametrize("use_baseline", [False, True], ids=["repair", "rollback"])
def test_docx_repair_recovers_missing_text_through_an_exact_independent_review(evidence_db, monkeypatch, use_baseline):
    db = evidence_db
    connection, tenant, _, _, store = db
    version, baseline, previous, original_positions = incomplete_run(db, monkeypatch)
    missing = original_positions[-1]
    basis = uuid4()
    replacement = replace_run(db, queue(db, version), previous, basis, baseline if use_baseline else None)
    assert replacement.passage_count == 2 and docx_locators(db, version) == ()
    assert connection.execute("""
        SELECT replaces_run_ref, rollback_run_ref, repair_basis_ref FROM thalion.processing_run WHERE run_ref = %s
        """, (replacement.run_ref,)).fetchone() == (previous.run_ref, baseline.run_ref if use_baseline else None, basis)
    with pytest.raises(processing.QualityConflict, match="preview"):
        review(db, replacement)

    set_rules(db, repair_rule(tenant.actor_id))
    service, (reviewer, other), allowed = repair_service(db)
    with client_for(service) as client:
        with monkeypatch.context() as patch:
            patch.setattr(store, "read", lambda *args: pytest.fail("A broad grant must not open the DOCX repair original."))
            assert get_preview(client, reviewer, replacement).status_code == 403
        set_rules(db, replace(repair_rule(tenant.actor_id), passage_ref=missing.passage_ref), expected=2)
        assert get_preview(client, other, replacement).status_code == 403
        preview = get_preview(client, reviewer, replacement)
        assert preview.status_code == 200, preview.text
        change, = preview.json()["difference"]["changes"]
        assert change == {
            "passage_id": str(missing.passage_ref),
            "before": None,
            "after": {
                "revision": 2, "paragraph": 1, "document_paragraph": 5, "heading_path": ["差旅", "住宿"],
                "excerpt": processing.resolve_docx_paragraph(docx_package(), missing).decode(),
            },
        }
        preview_id = preview.json()["preview_id"]
        allowed.clear()
        assert submit_review(client, reviewer, replacement, preview_id).status_code == 403
        assert docx_locators(db, version) == ()
        allowed.add(tenant.actor_id)
        assert submit_review(client, reviewer, replacement, preview_id).status_code == 200

    current = docx_locators(db, version)
    assert [(part.passage_ref, part.digest) for part in current] == [
        (part.passage_ref, part.digest) for part in original_positions
    ]
    assert [part.revision for part in current] == [3, 2]
    assert connection.execute("""
        SELECT outcome FROM thalion.quality_decision WHERE run_ref = %s
        """, (previous.run_ref,)).fetchall() == [("quarantined",)]


def test_docx_repair_requires_current_quarantine_and_rejects_identical_output(evidence_db, monkeypatch):
    db = evidence_db
    connection, _, _, _, store = db
    version = register_docx(db, docx_package())
    original = processing.process_evidence_job(connection, claim(db), store)
    lease = queue(db, version)
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *args: pytest.fail("A non-quarantined batch must not open the original."))
        with pytest.raises(processing.QualityConflict):
            replace_run(db, lease, original)
    review(db, original, decision="quarantined")
    with pytest.raises(processing.QualityConflict):
        replace_run(db, lease, original)
    assert connection.execute("SELECT run_ref FROM thalion.processing_run").fetchall() == [(original.run_ref,)]
    assert docx_locators(db, version) == ()


def test_docx_paragraph_repair_refuses_a_table_batch_before_opening_the_original(docx_table_review, monkeypatch):
    _, db, _, version, previous = docx_table_review
    review(db, previous, decision="quarantined")
    lease = queue(db, version)
    monkeypatch.setattr(db[-1], "read", lambda *args: pytest.fail("A DOCX table batch must not enter paragraph repair."))
    with pytest.raises(processing.QualityConflict):
        replace_run(db, lease, previous)
    assert db[0].execute("SELECT run_ref FROM thalion.processing_run WHERE replaces_run_ref = %s", (previous.run_ref,)).fetchone() is None


@pytest.mark.parametrize("use_baseline", [False, True], ids=["repair", "rollback"])
def test_docx_table_repair_requires_a_complete_current_batch_receipt(
    transport, docx_table_review, monkeypatch, use_baseline,
):
    client, _, _, credentials, *_ = transport
    service, db, (reviewer, other), version, baseline = docx_table_review
    connection, tenant, _, _, store = db
    refs = {ref for ref, in locate(connection, baseline)}
    set_rules(db, *(grant(tenant, ref) for ref in refs))
    baseline_preview = open_preview(client, reviewer, baseline, tables=True)
    assert baseline_preview.status_code == 200
    assert decide(client, reviewer, baseline, baseline_preview.json()["preview_id"]).status_code == 200
    scope = (connection, tenant.org_id, tenant.space_id, version.version_ref)
    initial, = processing.list_approved_docx_units(*scope)
    excluded = UUID(baseline_preview.json()["batch"]["tables"][0]["rows"][1]["cells"][2]["passage_id"])
    previous = quarantine_misclassified_row(db, version, monkeypatch)
    assert processing.list_approved_docx_units(*scope) == ()
    basis = uuid4()
    lease = queue(db, version)
    if use_baseline:
        parse = docx_evidence.parse_docx

        def omit_paragraph(payload, **options):
            candidate = parse(payload, **options)
            return replace(candidate, passages=candidate.passages[:-1])

        with monkeypatch.context() as patch:
            patch.setattr(docx_evidence, "parse_docx", omit_paragraph)
            with pytest.raises(processing.QualityConflict, match="baseline"):
                processing.repair_docx_job(
                    connection, lease, store, replaces=previous.run_ref, basis_ref=basis,
                    rollback_to=baseline.run_ref, allow_tables=True,
                )
        assert processing.list_approved_docx_units(*scope) == ()
    replacement = processing.repair_docx_job(
        connection, lease, store, replaces=previous.run_ref, basis_ref=basis,
        rollback_to=baseline.run_ref if use_baseline else None, allow_tables=True,
    )
    assert replacement.passage_count == baseline.passage_count
    with pytest.raises(processing.QualityConflict, match="preview"):
        review(db, replacement)
    admit(credentials, reviewer, "preview_evidence_repair")
    assert get_preview(client, reviewer, replacement).status_code == 409
    assert open_preview(client, other, replacement, tables=True).status_code == 403
    assert open_preview(client, reviewer, replacement).status_code == 409
    set_rules(db, *(grant(tenant, ref) for ref in refs - {excluded}), expected=2)
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *_: pytest.fail("A missing non-member cell must block the original read."))
        assert open_preview(client, reviewer, replacement, tables=True).status_code == 403
    set_rules(db, *(grant(tenant, ref) for ref in refs), expected=3)
    response = open_preview(client, reviewer, replacement, tables=True)
    assert response.status_code == 200, response.text
    preview = response.json()
    repair = preview["batch"]["repair"]
    assert {key: repair[key] for key in ("replaces_run_id", "rollback_run_id", "repair_basis_id")} == {
        "replaces_run_id": str(previous.run_ref),
        "rollback_run_id": str(baseline.run_ref) if use_baseline else None,
        "repair_basis_id": str(basis),
    }
    included, incomplete = preview["batch"]["tables"][0]["rows"]
    assert [cell["excerpt"] for cell in included["cells"]] == list(COMPLETE)
    assert incomplete["reason"] == "missing_value" and incomplete["cells"][2]["passage_id"] == str(excluded)
    assert all(cell["excerpt_revision"] == 3 for row in (included, incomplete) for cell in row["cells"])
    changes = repair["changes"]
    assert [change["passage_id"] for change in changes] == [cell["passage_id"] for cell in included["cells"]]
    assert [
        (change["before"]["revision"], change["before"]["reason"], change["before"]["role"],
         change["after"]["revision"], change["after"]["reason"], change["after"]["role"])
        for change in changes
    ] == [(2, "missing_value", None, 3, None, cell["role"]) for cell in included["cells"]]
    assert all(change["before"]["excerpt_sha256"] == change["after"]["excerpt_sha256"] for change in changes)
    assert decide(client, reviewer, replacement, baseline_preview.json()["preview_id"]).status_code == 409
    assert processing.list_approved_docx_units(*scope) == ()
    check = authority_for({tenant.actor_id})
    probes = []

    historical_ref = UUID(changes[0]["passage_id"])

    def withdraw_historical_cell(credential, probe):
        probes.append({(scope.object_id, scope.revision) for scope in probe.scopes})
        decision = check(probe)
        if len(probes) == 2:
            return replace(decision, permitted_fields={
                scope: frozenset() if (scope.object_id, scope.revision) == (historical_ref, 2) else fields
                for scope, fields in decision.permitted_fields.items()
            })
        return decision

    with monkeypatch.context() as patch:
        patch.setattr(service, "check_source", withdraw_historical_cell)
        assert decide(client, reviewer, replacement, preview["preview_id"]).status_code == 403
    exact = {(ref, 3) for ref in refs} | {(UUID(change["passage_id"]), 2) for change in changes}
    assert probes == [exact, exact]
    assert processing.list_approved_docx_units(*scope) == ()
    assert decide(client, reviewer, replacement, preview["preview_id"]).status_code == 200
    current, = processing.list_approved_docx_units(*scope)
    assert [member.cell.passage_ref for member in current.members] == [
        member.cell.passage_ref for member in initial.members
    ]
    assert {member.cell.revision for member in current.members} == {3}
    assert connection.execute(
        "SELECT outcome FROM thalion.quality_decision WHERE run_ref = %s", (previous.run_ref,),
    ).fetchall() == [("quarantined",)]


def quarantine_misclassified_row(db, version, monkeypatch):
    parse = docx_evidence.parse_docx

    def misclassify_row(payload, **options):
        candidate = parse(payload, **options)
        table, = candidate.tables
        complete, incomplete = table.units
        broken = replace(complete, columns=(), reason="missing_value")
        return replace(candidate, tables=(replace(table, units=(broken, incomplete)),))

    with monkeypatch.context() as patch:
        patch.setattr(docx_evidence, "parse_docx", misclassify_row)
        previous = processing.process_evidence_job(db[0], queue(db, version), db[-1])
    review(db, previous, decision="quarantined")
    return previous


def test_docx_table_repair_management_shows_lineage_in_the_whole_batch(browser, docx_table_review, monkeypatch):
    from playwright.sync_api import expect

    service, db, (reviewer, _), version, _ = docx_table_review
    connection, tenant, _, _, store = db
    previous = quarantine_misclassified_row(db, version, monkeypatch)
    basis = uuid4()
    replacement = processing.repair_docx_job(
        connection, queue(db, version), store, replaces=previous.run_ref, basis_ref=basis, allow_tables=True,
    )
    set_rules(db, *(grant(tenant, ref) for ref, in locate(connection, replacement)))
    with loopback_page(browser, service, "/manage/repairs") as (page, _, _):
        page.set_viewport_size({"width": 390, "height": 820})
        load_reviewer(page, reviewer)
        page.get_by_role("radio", name="DOCX 批次审核").check()
        page.get_by_label("待审批次编号").fill(str(replacement.run_ref))
        page.get_by_role("button", name="查看待审批次").click()
        expect(page.get_by_text(f"隔离批次 {previous.run_ref}", exact=False)).to_be_visible()
        expect(page.get_by_text(f"校订依据 {basis}", exact=False)).to_be_visible()
        changes = page.get_by_role("listitem").filter(has_text="第 1 表 / 第 2 行 / 第 2 列")
        expect(changes.get_by_text("校订前 缺少必需值 · 修订 2")).to_be_visible()
        expect(changes.get_by_text("校订后 金额 · 修订 3")).to_be_visible()
        table = page.get_by_role("table", name="差旅 / 住宿 / 第 1 表")
        expect(table.get_by_text("0600.50", exact=True)).to_be_visible()
        expect(table.get_by_text("缺少必需值", exact=True)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.get_by_label("审核依据编号").fill(str(uuid4()))
        page.get_by_role("button", name="批准 DOCX 批次").click()
        expect(page.get_by_text("DOCX 批次已批准。", exact=True)).to_be_visible()
        expect(table).to_have_count(0)
        expect(page.get_by_text(str(basis), exact=False)).to_have_count(0)


def test_docx_repair_management_shows_native_location_and_clears_text_after_approval(portal, monkeypatch):
    from playwright.sync_api import expect

    page, _, db, (reviewer, _), credentials, *_ = portal
    version, _, previous, positions = incomplete_run(db, monkeypatch)
    replacement = replace_run(db, queue(db, version), previous)
    connection, tenant, *_ = db
    credentials[reviewer] = replace(credentials[reviewer], operations=REPAIR_OPERATIONS)
    set_rules(db, replace(repair_rule(tenant.actor_id), passage_ref=positions[-1].passage_ref), expected=2)
    page.set_viewport_size({"width": 390, "height": 820})
    page.goto("/manage/repairs")
    page.get_by_label("管理测试凭据").fill(reviewer)
    page.get_by_role("button", name="载入审核凭据").click()
    page.get_by_role("radio", name="文本校订差异").check()
    page.get_by_label("校订批次编号").fill(str(replacement.run_ref))
    page.get_by_role("button", name="查看差异").click()
    position = page.get_by_text("差旅 / 住宿 / 文档第 5 段", exact=False)
    expect(position).to_be_visible()
    assert "undefined" not in position.inner_text()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.get_by_label("审核依据编号").fill(str(uuid4()))
    page.get_by_role("button", name="批准校订").click()
    expect(page.get_by_text("校订已批准。", exact=True)).to_be_visible()
    expect(position).to_have_count(0)
    assert connection.execute("""
        SELECT outcome FROM thalion.quality_decision WHERE run_ref = %s
        """, (replacement.run_ref,)).fetchone() == ("approved",)
