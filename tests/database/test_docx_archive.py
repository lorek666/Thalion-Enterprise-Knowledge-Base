from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import pytest

from enterprise_kb.modules.evidence import docx_evidence, docx_review, processing
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.lifecycle import docx_transcripts
from enterprise_kb.modules.lifecycle.disposition import PLAN
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.modules.wiki.drafts import WikiStatement
from enterprise_kb.transport.local import LocalProfile

from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import confirm_unrelated_stop, endpoint, restore_source_authority, rule_log
from test_csv_wiki import exact, role_rules
from test_disposition import plan
from test_docx_processing import DOCX_TYPE, register_docx
from test_docx_repair import incomplete_run, quarantine_misclassified_row, queue, replace_run
from test_docx_review import decide as decide_docx, docx_table_review, grant, locate, open_preview
from test_docx_table_delivery import ready_docx_table
from test_docx_tables import COMPLETE, HEADERS, grid, table_package
from test_docx_wiki import wiki_row
from test_effectivity import BEGIN, approve as approve_effectivity
from test_evidence import evidence_db, review
from test_evidence_transport import evidence_transport, private_json, transport
from test_feedback_work import admit
from test_holds import CAPABILITY as HOLD, decide
from test_markdown_repair import get_preview, repair_rule, submit_review
from test_original_export import APPROVE, EXPORT, REQUEST, approve, command, request
from test_persisted_access import set_rules
from test_rule_replay import rehearsal_clone
from test_rule_restriction_log import stop
from test_runtime import runtime_db
from test_source_revocations import independent_authority, revocation_authority
from test_travel_search import corpus, publish
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble
from test_wiki_publication import authorize


@pytest.fixture
def docx_archive(transport, evidence_transport, revocation_authority):
    client, db, (owner, reviewer), credentials, *_ = transport
    service, *_ = evidence_transport
    profile = revocation_authority[2]
    admit(credentials, owner, REQUEST, APPROVE, EXPORT, PLAN)
    admit(credentials, reviewer, REQUEST, APPROVE, EXPORT, HOLD)
    payload = table_package(grid((HEADERS, COMPLETE)))
    version = register_docx(db, payload, key="archive-docx", object_key="archive-docx")
    employee = credentials[owner].employee_ref
    private_json(profile.root / "source-grants.json", {str(employee): [str(version.version_ref)]})
    service.check_archive_source = profile.check_archive_source
    return client, db, owner, reviewer, service, profile, employee, version, payload


def request_approved(case):
    client, _, owner, reviewer, *_, version, _ = case
    opened = request(client, owner, version)
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert approve(client, owner, export_id).status_code == 403
    assert approve(client, reviewer, export_id).status_code == 200
    return export_id


def grant_archive(profile, employee, version):
    private_json(profile.root / "archive-grants.json", {str(employee): [str(version.version_ref)]})


def test_docx_archive_requires_a_separate_grant_and_seals_only_the_exact_original(
    docx_archive, postgres_server, tmp_path_factory, monkeypatch,
):
    client, db, owner, reviewer, service, profile, employee, version, original = docx_archive
    connection, tenant, url, _, store = db
    assert request(client, reviewer, version).status_code == 403
    for scope in ("original_and_transcript", "original_and_rebuild", "original_and_wiki", "wiki_rebuild"):
        args = {"wiki_revision_id": str(uuid4())} if "wiki" in scope else {}
        denied = request(client, owner, version, scope=scope, **args)
        assert denied.status_code == 409 and denied.json()["error"]["code"] == "original_archive_conflict"
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_request").fetchone() == (0,)
    before = plan(client, owner, version.version_ref).json()
    export_id = request_approved(docx_archive)
    uri = f"/{export_id}/seal"
    assert command(client, reviewer, uri).status_code == 403

    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *args: pytest.fail("A missing archive grant must not open the DOCX."))
        assert command(client, owner, uri).status_code == 403
        private_json(profile.root / "archive-grants.json", [])
        assert command(client, owner, uri).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)

    grant_archive(profile, employee, version)
    checks = []

    def observe(credential, probe):
        checks.append(probe)
        return profile.check_archive_source(credential, probe)

    service.check_archive_source = observe
    key = str(uuid4())
    sealed = command(client, owner, uri, key=key)
    assert sealed.status_code == 200 and sealed.headers["cache-control"] == "no-store"
    body = sealed.json()
    assert body["scope"] == "original_only" and body["restorable"] is False
    payload, digest = connection.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    assert sha256(payload).digest() == digest == bytes.fromhex(body["archive_sha256"])
    assert len(checks) == 2 and checks[-1].payload_sha256 == digest.hex()
    assert all({(scope.object_id, scope.fields) for scope in probe.scopes} == {
        (version.version_ref, frozenset({"original_bytes", "version_manifest"}))
    } for probe in checks)
    with ZipFile(BytesIO(payload)) as archive:
        assert archive.namelist() == ["manifest.json", "original.docx"]
        assert archive.read("original.docx") == original
        manifest = json.loads(archive.read("manifest.json"))
        assert (manifest["version_id"], manifest["format_media_type"], manifest["byte_length"], manifest["original_sha256"]) == (
            str(version.version_ref), DOCX_TYPE, len(original), sha256(original).hexdigest(),
        )
    assert "0600.50" not in sealed.text
    after = plan(client, owner, version.version_ref).json()
    assert before["inventory_snapshot"] != after["inventory_snapshot"]
    assert any(copy["kind"] == "export" for copy in after["copies"])
    assert command(client, owner, uri, key=key).json()["package_id"] == body["package_id"]
    private_json(profile.root / "archive-grants.json", {})
    assert command(client, owner, uri, key=key).status_code == 403

    scratch = tmp_path_factory.mktemp("docx-archive-stage")
    pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, UUID(body["package_id"]), digest)
    with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(connection, pin, payload, scratch):
        pytest.fail("An active database must not provide rehearsal staging.")
    with rehearsal_clone(connection, url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as result:
            assert (result.version_ref, result.scope, result.store.read(result.asset)) == (version.version_ref, "original_only", original)
        stop(staged, tenant, version.version_ref)
        with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(staged, pin, payload, scratch):
            pytest.fail("A withdrawal must block staging.")
    assert list(scratch.iterdir()) == []


def test_docx_archive_rechecks_independent_revocation_on_the_actual_bytes(docx_archive, revocation_authority):
    client, db, owner, _, service, profile, employee, version, _ = docx_archive
    connection, tenant, *_ = db
    writer, authority, _ = revocation_authority
    export_id = request_approved(docx_archive)
    grant_archive(profile, employee, version)
    checks = []

    def revoke_before_seal(credential, probe):
        checks.append(probe.payload_sha256)
        if len(checks) == 2:
            source_revocations.revoke(writer, authority.authority_ref, tenant.space_ref, employee, version.version_ref,
                                      "archive", basis_ref=uuid4())
        return profile.check_archive_source(credential, probe)

    service.check_archive_source = revoke_before_seal
    reply = command(client, owner, f"/{export_id}/seal")
    assert reply.status_code == 403
    assert len(checks) == len(set(checks)) == 2
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_docx_archive_hold_blocks_the_approved_request(docx_archive):
    client, db, owner, reviewer, _, profile, employee, version, _ = docx_archive
    export_id = request_approved(docx_archive)
    grant_archive(profile, employee, version)
    assert decide(client, reviewer, version.version_ref).status_code == 200
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert db[0].execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_docx_transcript_archive_seals_all_exact_positions_and_rechecks_current_permission(
    transport, docx_table_review, revocation_authority, postgres_server, tmp_path_factory, monkeypatch,
):
    client, _, (owner, approver), credentials, *_ = transport
    service, db, _, version, run = docx_table_review
    connection, tenant, url, _, store = db
    writer, authority, profile = revocation_authority
    employee = credentials[owner].employee_ref
    admit(credentials, owner, REQUEST, EXPORT)
    admit(credentials, approver, APPROVE)
    refs = [ref for ref, in locate(connection, run)]
    set_rules(db, *(grant(tenant, ref) for ref in refs))
    private_json(profile.root / "source-grants.json", {str(employee): list(map(str, refs))})
    preview = open_preview(client, owner, run, tables=True)
    assert preview.status_code == 200
    batch = preview.json()["batch"]
    assert decide_docx(client, owner, run, preview.json()["preview_id"]).status_code == 200
    opened = request(client, owner, version, scope="original_and_transcript")
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, approver, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    grant_archive(profile, employee, version)
    service.check_archive_source = profile.check_archive_source
    table, = batch["tables"]
    parts = batch["paragraphs"] + [cell for row in table["rows"] for cell in row["cells"]]
    revisions = {part["passage_id"]: part["excerpt_revision"] for part in parts}
    excluded = table["rows"][1]["cells"][2]["passage_id"]
    grants = profile.root / "transcript-archive-grants.json"
    private_json(grants, {str(employee): {ref: revision for ref, revision in revisions.items() if ref != excluded}})
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *_: pytest.fail("A missing exact transcript grant must block the original read."))
        assert command(client, owner, uri).status_code == 403

    private_json(grants, {str(employee): revisions})
    parse = docx_evidence.parse_docx

    def inconsistent_parse(payload, **options):
        candidate = parse(payload, **options)
        return replace(candidate, passages=candidate.passages[:-1])

    with monkeypatch.context() as patch:
        patch.setattr(docx_evidence, "parse_docx", inconsistent_parse)
        assert command(client, owner, uri).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    probes = []

    def observe(credential, probe):
        probes.append(probe)
        return profile.check_archive_source(credential, probe)

    service.check_archive_source = observe
    key = str(uuid4())
    sealed = command(client, owner, uri, key=key)
    assert sealed.status_code == 200 and sealed.json()["scope"] == "original_and_transcript"
    payload, digest = connection.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    assert len(probes) == 2 and probes[-1].payload_sha256 == digest.hex()
    for probe in probes:
        assert {str(scope.object_id): scope.revision for scope in probe.scopes if scope.revision is not None} == revisions
    with ZipFile(BytesIO(payload)) as archive:
        assert set(archive.namelist()) == {"manifest.json", "original.docx", "transcription.json"} | {
            f"transcript/{ref}.txt" for ref in revisions
        }
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-docx-transcript-archive.v1"
        transcription = archive.read("transcription.json")
        assert sha256(transcription).hexdigest() == manifest["transcription_sha256"]
        content = json.loads(transcription)
        assert content["run_id"] == str(run.run_ref) and content["manifest_sha256"] == run.manifest_digest.hex()
        sealed_table, = content["tables"]
        assert sealed_table["headers"] == table["headers"]
        assert [row["reason"] for row in sealed_table["rows"]] == [None, "missing_value"]
        for part in parts:
            assert archive.read(f"transcript/{part['passage_id']}.txt") == part["excerpt"].encode()
        assert sha256(archive.read("original.docx")).digest() == version.digest

    def revoke_at_final_check(credential, probe):
        if probe.payload_sha256 == digest.hex():
            source_revocations.revoke(writer, authority.authority_ref, tenant.space_ref, employee, UUID(excluded),
                                      "archive", basis_ref=uuid4())
        return profile.check_archive_source(credential, probe)

    with monkeypatch.context() as patch:
        patch.setattr(service, "check_archive_source", revoke_at_final_check)
        assert command(client, owner, uri, key=key).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (1,)
    pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, UUID(sealed.json()["package_id"]), digest)
    scratch = tmp_path_factory.mktemp("docx-transcript-stage")
    with rehearsal_clone(connection, url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as result:
            assert result.scope == "original_and_transcript" and result.version_ref == version.version_ref
        review((staged, *db[1:]), run, decision="quarantined")
        with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(staged, pin, payload, scratch):
            pytest.fail("A quarantined transcription must not pass archive staging.")


def test_docx_repaired_archive_pins_quarantine_and_rollback_read_permissions(
    transport, docx_table_review, revocation_authority, postgres_server, tmp_path_factory, monkeypatch,
):
    client, _, (owner, approver), credentials, *_ = transport
    service, db, _, version, baseline = docx_table_review
    connection, tenant, url, _, store = db
    _, _, profile = revocation_authority
    employee = credentials[owner].employee_ref
    refs = [ref for ref, in locate(connection, baseline)]
    set_rules(db, *(grant(tenant, ref) for ref in refs))
    private_json(profile.root / "source-grants.json", {str(employee): list(map(str, refs))})
    baseline_preview = open_preview(client, owner, baseline, tables=True)
    assert baseline_preview.status_code == 200
    assert decide_docx(client, owner, baseline, baseline_preview.json()["preview_id"]).status_code == 200
    parse = docx_evidence.parse_docx

    def extra_paragraph(payload, **options):
        candidate = parse(payload, **options)
        last = candidate.passages[-1]
        extra = replace(last, document_paragraph=last.document_paragraph + 1, paragraph=last.paragraph + 1)
        return replace(candidate, passages=(*candidate.passages, extra))

    with monkeypatch.context() as patch:
        patch.setattr(docx_evidence, "parse_docx", extra_paragraph)
        previous = quarantine_misclassified_row(db, version, patch)
    historical_only, = {ref for ref, in locate(connection, previous)} - set(refs)
    set_rules(db, *(grant(tenant, ref) for ref in (*refs, historical_only)), expected=2)
    private_json(profile.root / "source-grants.json", {str(employee): list(map(str, (*refs, historical_only)))})
    basis = uuid4()
    run = processing.repair_docx_job(
        connection, queue(db, version), store, replaces=previous.run_ref,
        rollback_to=baseline.run_ref, basis_ref=basis, allow_tables=True,
    )
    admit(credentials, owner, REQUEST, EXPORT)
    admit(credentials, approver, APPROVE)
    assert request(client, owner, version, scope="original_and_transcript").status_code == 409
    preview = open_preview(client, owner, run, tables=True)
    assert preview.status_code == 200
    assert decide_docx(client, owner, run, preview.json()["preview_id"]).status_code == 200
    with monkeypatch.context() as patch:
        patch.setattr(docx_transcripts, "MAX_REPAIR_RUNS", 2)
        assert request(client, owner, version, scope="original_and_transcript").status_code == 409
    opened = request(client, owner, version, scope="original_and_transcript")
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, approver, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    grant_archive(profile, employee, version)
    private_json(profile.root / "transcript-archive-grants.json", {str(employee): {str(ref): 3 for ref in refs}})
    service.check_archive_source = profile.check_archive_source
    history_grants = profile.root / "repair-history-archive-grants.json"
    other_grants = list(map(str, (version.version_ref, *refs)))
    private_json(history_grants, {str(employee): other_grants})
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *_: pytest.fail("A missing historical-only grant must block the original read."))
        assert command(client, owner, uri).status_code == 403
    full_grants = {str(employee): [*other_grants, str(historical_only)]}
    private_json(history_grants, full_grants)
    check_count = 0

    def revoke_history(credential, probe):
        nonlocal check_count
        check_count += 1
        if check_count == 2:
            private_json(history_grants, {str(employee): other_grants})
        return profile.check_archive_source(credential, probe)

    with monkeypatch.context() as patch:
        patch.setattr(service, "check_archive_source", revoke_history)
        assert command(client, owner, uri).status_code == 403
    assert check_count == 2
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(history_grants, full_grants)
    seal = command(client, owner, uri)
    assert seal.status_code == 200, seal.text
    payload, digest = connection.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-docx-transcript-archive.v2"
        raw_history = archive.read("repair-history.json")
        assert sha256(raw_history).hexdigest() == manifest["repair_history_sha256"]
        original, isolated, current = json.loads(raw_history)["runs"]
        assert original["run_id"] == str(baseline.run_ref)
        assert isolated["run_id"] == str(previous.run_ref)
        assert isolated["decisions"][0]["outcome"] == "quarantined"
        assert str(historical_only) in {part["passage_id"] for part in isolated["locations"]}
        assert f"transcript/{historical_only}.txt" not in archive.namelist()
        assert current["rollback_run_id"] == str(baseline.run_ref)
        assert current["repair_basis_id"] == str(basis)
        assert current["decisions"][0]["preview_id"] == preview.json()["preview_id"]
        assert b"0600.50" not in raw_history
    scratch = tmp_path_factory.mktemp("docx-history-stage")
    pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, UUID(seal.json()["package_id"]), digest)
    with rehearsal_clone(connection, url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as result:
            assert result.scope == "original_and_transcript" and result.version_ref == version.version_ref
    private_json(history_grants, {})
    assert command(client, owner, uri).status_code == 403


def test_docx_paragraph_repair_archive_keeps_the_exact_difference_receipt(
    transport, evidence_transport, revocation_authority, monkeypatch,
):
    client, db, (owner, approver), credentials, *_ = transport
    service, *_ = evidence_transport
    connection, tenant, *_ = db
    _, _, profile = revocation_authority
    employee = credentials[owner].employee_ref
    version, baseline, previous, positions = incomplete_run(db, monkeypatch)
    run = replace_run(db, queue(db, version), previous, rollback=baseline)
    admit(credentials, owner, REQUEST, EXPORT, "preview_evidence_repair", "decide_evidence_quality")
    admit(credentials, approver, APPROVE)
    refs = [str(part.passage_ref) for part in positions]
    private_json(profile.root / "source-grants.json", {str(employee): refs})
    set_rules(db, replace(repair_rule(tenant.actor_id), passage_ref=positions[-1].passage_ref), expected=2)
    preview = get_preview(client, owner, run)
    assert preview.status_code == 200, preview.text
    preview_id = preview.json()["preview_id"]
    basis = uuid4()
    assert submit_review(client, owner, run, preview_id, basis=basis).status_code == 200
    receipt, = connection.execute(
        "SELECT difference_digest FROM thalion.repair_review_preview WHERE preview_ref = %s", (preview_id,),
    ).fetchone()
    opened = request(client, owner, version, scope="original_and_transcript")
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, approver, export_id).status_code == 200
    grant_archive(profile, employee, version)
    private_json(profile.root / "transcript-archive-grants.json", {str(employee): dict(zip(refs, (3, 2), strict=True))})
    private_json(profile.root / "repair-history-archive-grants.json", {str(employee): [str(version.version_ref), *refs]})
    service.check_archive_source = profile.check_archive_source
    sealed = command(client, owner, f"/{export_id}/seal")
    assert sealed.status_code == 200, sealed.text
    payload, = connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    with ZipFile(BytesIO(payload)) as archive:
        original, isolated, current = json.loads(archive.read("repair-history.json"))["runs"]
        assert (original["run_id"], isolated["run_id"], current["run_id"]) == tuple(
            str(batch.run_ref) for batch in (baseline, previous, run)
        )
        decision, = current["decisions"]
        assert {key: value for key, value in decision.items() if key != "decision_id"} == {
            "outcome": "approved", "basis_id": str(basis), "preview_id": preview_id, "difference_sha256": receipt.hex(),
        }
        assert json.loads(archive.read("transcription.json"))["tables"] == []


@pytest.fixture
def docx_wiki_bundle(
    wiki_row, transport, ready_docx_table, restore_source_authority, tmp_path,
):
    db, cells = wiki_row
    client, _, (owner, approver), credentials, *_ = transport
    service, _, version, _ = ready_docx_table
    writer, authority, _ = restore_source_authority
    profile_root = tmp_path / "wiki-archive-profile"
    profile_root.mkdir(mode=0o700)
    private_json(profile_root / "credentials.json", [])
    private_json(profile_root / "source-grants.json", {})
    profile = LocalProfile(profile_root, revocations=authority)
    employee = credentials[owner].employee_ref
    connection, tenant, url, _, store = db
    admit(credentials, owner, REQUEST, EXPORT, PLAN)
    admit(credentials, approver, APPROVE)
    markdown_version, markdown, _ = publish(db, "wiki-archive-note", "Archive note", b"# Travel\n\nSynthetic note.\n")
    approve_effectivity(connection, tenant, markdown_version, BEGIN)
    set_rules(db, *role_rules(db, (*cells, markdown)), expected=2)
    parent = assemble(db, cells)
    assert parent.status == "succeeded"
    sealed = assemble(db, (markdown,), (parent.manifest_ref,))
    assert sealed.status == "succeeded"
    statement = WikiStatement("Synthetic note.", (exact((markdown,)),))
    draft = candidate((db, sealed, markdown, cells[-1]), statements=(statement,))
    assert draft.status == "succeeded"
    reviewed = preview(db, draft.ref)
    approval = submit(db, draft.ref, reviewed)
    published = authorize(db, draft.ref, approval.ref)
    assert published.status == "succeeded"
    grant_archive(profile, employee, version)
    private_json(profile.root / "wiki-archive-grants.json", {str(employee): [str(draft.ref)]})
    service.check_archive_source = profile.check_archive_source
    return db, version, markdown_version, markdown, cells, draft, parent, profile, writer, authority, employee


def test_docx_wiki_archive_checks_unquoted_inherited_cells_before_opening_and_at_seal(
    docx_wiki_bundle, transport, ready_docx_table, postgres_server, tmp_path, monkeypatch,
):
    db, version, markdown_version, markdown, cells, draft, parent, profile, writer, authority, employee = docx_wiki_bundle
    client, _, (owner, approver), *_ = transport
    service, *_ = ready_docx_table
    connection, tenant, url, _, store = db
    opened = request(client, owner, version, scope="original_and_wiki", wiki_revision_id=str(draft.ref))
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, approver, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    grants_path = profile.root / "transcript-archive-grants.json"
    missing = cells[-1]
    incomplete = {str(ref): revision for ref, revision in exact((markdown, *cells[:-1]))}
    complete = incomplete | {str(missing.passage_ref): missing.revision}
    private_json(grants_path, {str(employee): incomplete})
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *_: pytest.fail("An unlicensed inherited cell must block the DOCX original read."))
        assert command(client, owner, uri).status_code == 403
    private_json(grants_path, {str(employee): complete})
    probes = []

    def deny_after_preflight(credential, probe):
        probes.append(probe.payload_sha256)
        if len(probes) == 2:
            private_json(grants_path, {str(employee): incomplete})
        return profile.check_archive_source(credential, probe)

    with monkeypatch.context() as patch:
        patch.setattr(service, "check_archive_source", deny_after_preflight)
        assert command(client, owner, uri).status_code == 403
    assert len(probes) == len(set(probes)) == 2
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(grants_path, {str(employee): complete})
    result = command(client, owner, uri)
    assert result.status_code == 200, result.text
    assert result.json()["scope"] == "original_and_wiki" and result.json()["restorable"] is False
    payload, digest = connection.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    with ZipFile(BytesIO(payload)) as archive:
        assert set(archive.namelist()) == {
            "manifest.json", "original.docx", "wiki/content.md", "wiki/dependencies.json", "wiki/revision.json",
        }
        dependencies = json.loads(archive.read("wiki/dependencies.json"))
        assert dependencies["parent_manifest_ids"] == [str(parent.manifest_ref)]
        assert {item["passage_id"]: item["excerpt_revision"] for item in dependencies["inputs"]} == complete
        assert json.loads(archive.read("wiki/revision.json"))["citations"] == [[str(markdown.passage_ref), markdown.revision]]
        assert sha256(archive.read("original.docx")).digest() == version.digest
    for included in (version, markdown_version):
        response = plan(client, owner, included.version_ref)
        assert response.status_code == 200 and [copy["kind"] for copy in response.json()["copies"]].count("export") == 1
    pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, UUID(result.json()["package_id"]), digest)
    scratch = tmp_path / "wiki-staging"
    scratch.mkdir(mode=0o700)
    with rehearsal_clone(connection, url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as material:
            assert material.scope == "original_and_wiki" and material.version_ref == version.version_ref
    source_revocations.revoke(writer, authority.authority_ref, tenant.space_ref, employee, missing.passage_ref,
                              "archive", basis_ref=uuid4())
    assert command(client, owner, uri).status_code == 403


@pytest.mark.parametrize("revoke", [False, True], ids=["verified", "revoked-non-member"])
def test_docx_wiki_rebuild_checks_all_transcripts_including_unreferenced_cells(
    docx_wiki_bundle, transport, docx_table_review, empty_rehearsal, rule_log, corpus, tmp_path, monkeypatch, revoke,
):
    db, version, markdown_version, markdown, cells, draft, parent, profile, writer, authority, employee = docx_wiki_bundle
    client, _, (owner, approver), *_ = transport
    connection, tenant, _, _, store = db
    _, _, _, _, run = docx_table_review
    version_id, count = connection.execute(
        "SELECT version_id, passage_count FROM thalion.processing_run WHERE run_ref = %s", (run.run_ref,),
    ).fetchone()
    locations = docx_review.batch_locations(connection, tenant.org_id, tenant.space_id, version_id, run.run_ref, count)
    wiki_refs = {cell.passage_ref for cell in cells}
    not_in_wiki = next(part[0] for part in locations if part[1] == "docx_cell" and part[11] and part[0] not in wiki_refs)
    opened = request(client, owner, markdown_version, scope="wiki_rebuild", wiki_revision_id=str(draft.ref))
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, approver, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    version_refs = [str(version.version_ref), str(markdown_version.version_ref)]
    for file_name in ("archive-grants.json", "rebuild-archive-grants.json"):
        private_json(profile.root / file_name, {str(employee): version_refs})
    grants = {str(part[0]): part[5] for part in locations}
    grants[str(markdown.passage_ref)] = markdown.revision
    grants_path = profile.root / "transcript-archive-grants.json"
    private_json(grants_path, {str(employee): {ref: number for ref, number in grants.items() if ref != str(not_in_wiki)}})
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *_: pytest.fail("A missing transcript grant must block the nested original read."))
        assert command(client, owner, uri).status_code == 403
    private_json(grants_path, {str(employee): grants})
    result = command(client, owner, uri)
    assert result.status_code == 200, result.text
    payload, digest = connection.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    pin = archive_rehearsal.WikiArchivePermit(
        tenant.org_id, tenant.space_id, UUID(export_id), markdown_version.version_ref, draft.ref, digest,
    )
    target, _ = empty_rehearsal
    permit = archive_rehearsal.WikiRebuildPermit(pin, target.info.dbname)
    scratch = tmp_path / "wiki-rebuild"
    scratch.mkdir(mode=0o700)
    confirm_unrelated_stop(db, rule_log, version_ref=corpus[1].version_ref)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="checkpoint"):
        archive_rehearsal.rebuild_wiki(target, permit, payload, scratch)
    options = dict(authority=connection, log=rule_log, authority_ref=endpoint(connection),
                   log_ref=endpoint(rule_log), source_authority=authority)
    if revoke:
        source_revocations.revoke(writer, authority.authority_ref, tenant.space_ref, employee, not_in_wiki,
                                  "archive", basis_ref=uuid4())
        with pytest.raises(archive_rehearsal.ArchiveRejected, match="source revocation"):
            archive_rehearsal.rebuild_wiki_with_rule_checkpoint(target, permit, payload, scratch, **options)
        assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
        assert not any(scratch.iterdir())
        return
    rebuilt = archive_rehearsal.rebuild_wiki_with_rule_checkpoint(target, permit, payload, scratch, **options)
    assert rebuilt.revision_ref == draft.ref
    assert {ref: sha256(rebuilt.store.read(asset)).digest() for ref, asset in rebuilt.originals} == {
        version.version_ref: version.digest, markdown_version.version_ref: markdown_version.digest,
    }
    with ZipFile(BytesIO(payload)) as archive:
        with ZipFile(BytesIO(archive.read(f"versions/{version.version_ref}.zip"))) as embedded:
            transcript = json.loads(embedded.read("transcription.json"))
            ordered = transcript["paragraphs"] + [
                cell for table in transcript["tables"] for row in table["rows"] for cell in row["cells"]
            ]
            exact_bytes = [embedded.read(part["member"]) for part in ordered]
    assert {part["passage_id"] for part in ordered} == grants.keys() - {str(markdown.passage_ref)}
    assert target.execute("""
        SELECT version_ref, run_ref, transcription, transcript_bytes FROM thalion.archive_docx_rebuild
        """).fetchone() == (version.version_ref, run.run_ref, transcript, exact_bytes)
    graph, = target.execute("SELECT manifest_graph FROM thalion.archive_wiki_rebuild").fetchone()
    assert str(parent.manifest_ref) in {node["manifest_id"] for node in graph["manifests"]}
    assert target.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
    assert target.execute("SELECT count(*) FROM thalion.available_wiki_publication").fetchone() == (0,)
