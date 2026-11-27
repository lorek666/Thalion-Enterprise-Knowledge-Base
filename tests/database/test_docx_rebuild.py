from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import psycopg
from psycopg import sql
import pytest

from enterprise_kb.database import local_connection_factory
from enterprise_kb.modules.evidence import docx_evidence, processing, quality_restrictions
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.transport.local import LocalProfile

from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import assert_empty, confirm_unrelated_stop, rebuild, restore_source_authority, rule_log
from test_docx_archive import grant_archive
from test_docx_processing import DOCX_TYPE
from test_docx_repair import quarantine_misclassified_row, queue
from test_docx_review import decide, docx_table_review, grant, locate, open_preview
from test_docx_tables import AMOUNT_COLUMNS
from test_evidence import evidence_db, review
from test_evidence_transport import evidence_transport, private_json, transport
from test_feedback_work import admit
from test_original_export import APPROVE, EXPORT, REQUEST, approve, command, request as request_export
from test_persisted_access import set_rules
from test_runtime import runtime_db
from test_travel_search import corpus


@pytest.fixture
def docx_rebuild_bundle(
    request, transport, docx_table_review, restore_source_authority, empty_rehearsal, rule_log, corpus, tmp_path, monkeypatch,
):
    client, _, (owner, approver), credentials, *_ = transport
    service, db, _, version, run = docx_table_review
    authority, tenant, _, _, store = db
    writer, source, _ = restore_source_authority
    tmp_path.chmod(0o700)
    employee = credentials[owner].employee_ref
    refs = {ref for ref, in locate(authority, run)}
    set_rules(db, *(grant(tenant, ref) for ref in refs))
    private_json(tmp_path / "credentials.json", [])
    private_json(tmp_path / "source-grants.json", {str(employee): list(map(str, refs))})
    profile = LocalProfile(tmp_path, revocations=source)
    service.check_source = profile.check_source
    checked = open_preview(client, owner, run, tables=True)
    assert checked.status_code == 200, checked.text
    assert decide(client, owner, run, checked.json()["preview_id"]).status_code == 200
    confirm_unrelated_stop(db, rule_log, version_ref=corpus[1].version_ref)
    repair = getattr(request, "param", None)
    history_only = None
    if repair is not None:
        baseline = run
        parse = docx_evidence.parse_docx

        def historical_parse(payload, **options):
            candidate = parse(payload, **options)
            last = candidate.passages[-1]
            extra = replace(last, document_paragraph=last.document_paragraph + 1, paragraph=last.paragraph + 1)
            if repair == "bad_header":
                table, = candidate.tables
                table = replace(table, headers=(*table.headers[:-1], "Different historical header"))
                candidate = replace(candidate, tables=(table,))
            return replace(candidate, passages=(*candidate.passages, extra))

        with monkeypatch.context() as patch:
            patch.setattr(docx_evidence, "parse_docx", historical_parse)
            previous = quarantine_misclassified_row(db, version, patch)
        history_only, = {ref for ref, in locate(authority, previous)} - refs
        historical = [*refs, history_only]
        set_rules(db, *(grant(tenant, ref) for ref in historical), expected=2)
        private_json(profile.root / "source-grants.json", {str(employee): list(map(str, historical))})
        run = processing.repair_docx_job(
            authority, queue(db, version), store, replaces=previous.run_ref,
            rollback_to=baseline.run_ref, basis_ref=uuid4(), allow_tables=True,
        )
        preview = open_preview(client, owner, run, tables=True)
        assert preview.status_code == 200, preview.text
        assert decide(client, owner, run, preview.json()["preview_id"]).status_code == 200
        private_json(profile.root / "repair-history-archive-grants.json", {
            str(employee): list(map(str, [version.version_ref, *historical])),
        })
    admit(credentials, owner, REQUEST, EXPORT)
    admit(credentials, approver, APPROVE)
    opened = request_export(client, owner, version, scope="original_and_rebuild")
    assert opened.status_code == 200, opened.text
    export = opened.json()["export_id"]
    assert approve(client, approver, export).status_code == 200
    uri = f"/{export}/seal"
    grant_archive(profile, employee, version)
    revision = 3 if repair is not None else 1
    private_json(profile.root / "transcript-archive-grants.json", {str(employee): {str(ref): revision for ref in refs}})
    service.check_archive_source = profile.check_archive_source
    with monkeypatch.context() as patch:
        patch.setattr(store, "read", lambda *_: pytest.fail("Missing rebuild permission must block the original read."))
        assert command(client, owner, uri).status_code == 403
    private_json(profile.root / "rebuild-archive-grants.json", {str(employee): [str(version.version_ref)]})
    sealed = command(client, owner, uri)
    assert sealed.status_code == 200, sealed.text
    assert sealed.json()["restorable"] is False
    payload, digest = authority.execute("SELECT archive_bytes, archive_digest FROM thalion.synthetic_export_package").fetchone()
    assert digest == sha256(payload).digest() == bytes.fromhex(sealed.json()["archive_sha256"])
    target, url = empty_rehearsal
    permit = archive_rehearsal.RebuildPermit(
        tenant.org_id, tenant.space_id, UUID(export), version.version_ref, digest, target.info.dbname,
    )
    scratch = tmp_path / "rebuild"
    scratch.mkdir(mode=0o700)
    return (target, url, permit, payload, scratch, source, rule_log), db, writer, employee, version, run, history_only


def test_docx_rebuild_keeps_exact_cells_without_restoring_business_access(docx_rebuild_bundle):
    bundle, db, _, _, version, run, _ = docx_rebuild_bundle
    target, url, permit, payload, scratch, *_ = bundle
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-docx-version-rebuild.v1"
        assert manifest["rebuild"]["docx_amount_columns"] == list(AMOUNT_COLUMNS)
        original = archive.read("original.docx")
        transcript = json.loads(archive.read("transcription.json"))
        table, = transcript["tables"]
        assert [row["reason"] for row in table["rows"]] == [None, "missing_value"]
        parts = transcript["paragraphs"] + [cell for row in table["rows"] for cell in row["cells"]]
        excerpts = [archive.read(f"transcript/{part['passage_id']}.txt") for part in parts]
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(target, permit, payload, scratch)
    assert_empty(bundle)

    restored = rebuild(bundle, db[0])

    assert restored.store.read(restored.asset) == original
    assert target.execute("SELECT media_type FROM thalion.asset").fetchone() == (DOCX_TYPE,)
    assert dict(target.execute("""
        SELECT object_type, public_id FROM thalion.object_identity
        WHERE object_type IN ('source', 'document', 'document_version')
        """).fetchall()) == {"source": db[3], "document": version.document_ref, "document_version": version.version_ref}
    assert target.execute("""
        SELECT version_ref, run_ref, amount_columns, transcription, transcript_bytes FROM thalion.archive_docx_rebuild
        """).fetchone() == (version.version_ref, run.run_ref, list(AMOUNT_COLUMNS), transcript, excerpts)
    assert target.execute("SELECT lifecycle FROM thalion.space").fetchone() == ("archived",)
    assert target.execute("SELECT version_ref, archive_digest FROM thalion.archive_rebuild_rule_check").fetchone() == (
        version.version_ref, permit.digest,
    )
    for table_name in (
        "processing_run", "quality_decision", "passage_excerpt", "permission_binding", "rule_effectivity",
        "wiki_publication_event", "synthetic_export_approval",
    ):
        assert target.execute(sql.SQL("SELECT count(*) FROM thalion.{}").format(sql.Identifier(table_name))).fetchone() == (0,)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        target.execute("UPDATE thalion.archive_docx_rebuild SET transcription = '{}'::jsonb")
    with pytest.raises(psycopg.OperationalError, match="rehearsal"):
        local_connection_factory(url)()


@pytest.mark.parametrize("restriction", ["revoked_non_member", "quarantined"])
def test_docx_rebuild_rechecks_current_restrictions_without_leaving_state(docx_rebuild_bundle, restriction):
    bundle, db, writer, employee, _, run, _ = docx_rebuild_bundle
    _, _, _, payload, _, source, _ = bundle
    if restriction == "revoked_non_member":
        with ZipFile(BytesIO(payload)) as archive:
            table, = json.loads(archive.read("transcription.json"))["tables"]
        non_member = UUID(table["rows"][1]["cells"][2]["passage_id"])
        source_revocations.revoke(
            writer, source.authority_ref, db[1].space_ref, employee, non_member, "archive", basis_ref=uuid4(),
        )
    else:
        review(db, run, decision="quarantined")
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        rebuild(bundle, db[0])
    assert_empty(bundle)


@pytest.mark.parametrize(("docx_rebuild_bundle", "expected_rejection"), [
    ("repair", None),
    ("revoked_history", "source revocation"),
    ("bad_header", "historical DOCX table headers"),
], indirect=["docx_rebuild_bundle"])
def test_docx_repair_rebuild_requires_current_exact_and_independent_history(docx_rebuild_bundle, expected_rejection):
    bundle, db, writer, employee, version, run, history_only = docx_rebuild_bundle
    target, _, permit, payload, scratch, source, log = bundle
    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "thalion.synthetic-docx-version-rebuild.v2"
        original = archive.read("original.docx")
        history = json.loads(archive.read("repair-history.json"))
        initial, isolated, current = history["runs"]
        assert current["rollback_run_id"] == initial["run_id"]
        assert current["replaces_run_id"] == isolated["run_id"]
        assert current["decisions"][0]["batch_sha256"]
        assert str(history_only) in {part["passage_id"] for part in isolated["locations"]}
        assert f"transcript/{history_only}.txt" not in archive.namelist()
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_version(target, permit, payload, scratch)
    if expected_rejection != "historical DOCX table headers":
        with pytest.raises(archive_rehearsal.ArchiveRejected, match="independent quality history"):
            rebuild(bundle, db[0])
        assert_empty(bundle)
    delivered = quality_restrictions.deliver_pending(db[0], log, db[1].org_id)
    assert delivered.status == "ok" and len(delivered.confirmed) == 1

    if expected_rejection == "source revocation":
        source_revocations.revoke(writer, source.authority_ref, db[1].space_ref, employee, history_only,
                                  "archive", basis_ref=uuid4())
    if expected_rejection is not None:
        with pytest.raises(archive_rehearsal.ArchiveRejected, match=expected_rejection):
            rebuild(bundle, db[0])
        assert_empty(bundle)
    else:
        restored = rebuild(bundle, db[0])
        assert restored.store.read(restored.asset) == original
        assert target.execute("SELECT version_ref, run_ref, repair_history FROM thalion.archive_docx_rebuild").fetchone() == (
            version.version_ref, run.run_ref, history,
        )
        assert target.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
