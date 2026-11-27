from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import pytest

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.lifecycle import archive_rehearsal, transcripts
from enterprise_kb.transport.local import LocalProfile

from test_disposition_cases import candidate
from test_evidence import approved, claim, evidence_db, review
from test_evidence_transport import evidence_transport, private_json, transport
from test_markdown_repair import PAYLOAD, client_for, get_preview, initial_run, queue
from test_markdown_repair import repair, repair_rule, repair_service, submit_review
from test_original_export import approve, archive_fixture, command, request
from test_persisted_access import set_rules
from test_rule_replay import rehearsal_clone
from test_runtime import runtime_db
from test_travel_search import corpus


SCOPE = "original_and_transcript"


def correct(db, version, failed, *, configuration, baseline=None):
    _, tenant, *_ = db
    quarantine = review(db, failed, decision="quarantined")
    queue(db, version, configuration)
    basis = uuid4()
    current = repair(db, claim(db), failed, basis, baseline)
    service, (actor, _), _ = repair_service(db)
    with client_for(service) as client:
        preview = get_preview(client, actor, current)
        assert preview.status_code == 200, preview.json()
        decision = submit_review(client, actor, current, preview.json()["preview_id"])
        assert decision.status_code == 200, decision.json()
    return current, {
        "quarantine": str(quarantine), "basis": str(basis), "preview": preview.json()["preview_id"],
        "approval": decision.json()["decision_id"],
    }


@pytest.fixture
def repaired_archive(archive_fixture, monkeypatch):
    client, db, owner, reviewer, service, _, _ = archive_fixture
    _, tenant, *_ = db
    version, baseline = initial_run(db)
    parse = processing.parse_markdown

    def miss_exception_and_shorten_locator(payload):
        parsed = parse(payload)
        first = parsed.passages[0]
        stop = first.byte_end - 1
        return replace(parsed, passages=(
            replace(first, byte_end=stop, digest=sha256(payload[first.byte_start:stop]).digest()),
        ))

    queue(db, version, 10)
    with monkeypatch.context() as patch:
        patch.setattr(processing, "parse_markdown", miss_exception_and_shorten_locator)
        failed = processing.process_markdown_job(db[0], claim(db), db[-1])
    set_rules(db, repair_rule(tenant.actor_id), expected=2)
    current, refs = correct(db, version, failed, configuration=11, baseline=baseline)
    return client, db, owner, reviewer, service, version, current, failed, baseline, refs


def test_archive_seals_exact_repair_history_only_with_explicit_grant(repaired_archive, tmp_path_factory, postgres_server):
    client, db, owner, reviewer, service, version, current, failed, baseline, refs = repaired_archive
    connection, tenant, url, *_ = db
    root = tmp_path_factory.mktemp("repair-archive-profile")
    root.chmod(0o700)
    employee = str(service.verify_token(owner).employee_ref)
    private_json(root / "credentials.json", [])
    private_json(root / "source-grants.json", {})
    private_json(root / "archive-grants.json", {employee: [str(version.version_ref)]})
    grants = root / "transcript-archive-grants.json"
    passages = approved(db, version)
    current_grants = {str(part.passage_ref): part.revision for part in passages}
    historic_only, = connection.execute("""
        SELECT identity.public_id::text FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (excerpt.org_id, excerpt.space_id, 'passage', excerpt.passage_id)
        WHERE excerpt.run_ref = %s
    """, (failed.run_ref,)).fetchone()
    assert historic_only not in current_grants
    private_json(grants, {employee: current_grants})
    service.check_archive_source = LocalProfile(root).check_archive_source

    requested = request(client, owner, version, scope=SCOPE)
    assert requested.status_code == 200, requested.json()
    rebuild_request = request(client, owner, version, scope="original_and_rebuild")
    assert rebuild_request.status_code == 200, rebuild_request.json()
    rebuild_id = rebuild_request.json()["export_id"]
    assert approve(client, reviewer, rebuild_id).status_code == 200
    export_id = requested.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    path = f"/{export_id}/seal"
    key = str(uuid4())
    assert command(client, owner, path, key=key).status_code == 403
    history_grants = root / "repair-history-archive-grants.json"
    private_json(history_grants, {employee: [str(version.version_ref), *current_grants]})
    assert command(client, owner, path, key=key).status_code == 403
    private_json(history_grants, {employee: [str(version.version_ref), historic_only, *current_grants]})
    private_json(grants, {employee: dict(list(current_grants.items())[:1])})
    assert command(client, owner, path, key=key).status_code == 403
    private_json(grants, {employee: current_grants})
    sealed = command(client, owner, path, key=key)
    assert sealed.status_code == 200, sealed.json()
    summary = sealed.json()
    assert summary["restorable"] is False and summary["scope"] == SCOPE
    assert not (set(refs.values()) & set(summary.values()))
    payload, = connection.execute(
        "SELECT archive_bytes FROM thalion.synthetic_export_package WHERE export_ref = %s", (export_id,),
    ).fetchone()

    with ZipFile(BytesIO(payload)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        history_bytes = archive.read("repair-history.json")
        history = json.loads(history_bytes)
        assert archive.read("original.md") == PAYLOAD
        assert manifest["format"] == "thalion.synthetic-transcript-archive.v2"
        assert manifest["repair_history_sha256"] == sha256(history_bytes).hexdigest()
        assert history["run_id"] == str(current.run_ref)
        past, before, after = history["runs"]
        assert [run["run_id"] for run in (past, before, after)] == [
            str(baseline.run_ref), str(failed.run_ref), str(current.run_ref),
        ]
        assert [run["manifest_sha256"] for run in (past, before, after)] == [
            run.manifest_digest.hex() for run in (baseline, failed, current)
        ]
        assert after["replaces_run_id"] == before["run_id"] and after["rollback_run_id"] == past["run_id"]
        assert after["repair_basis_id"] == refs["basis"]
        assert {item["outcome"]: item["decision_id"] for item in before["decisions"]} == {"quarantined": refs["quarantine"]}
        approval, = after["decisions"]
        assert approval["decision_id"] == refs["approval"] and approval["preview_id"] == refs["preview"]
        assert len(bytes.fromhex(approval["difference_sha256"])) == 32
        assert [[part["excerpt_revision"] for part in run["passages"]] for run in (past, before, after)] == [
            [1, 1], [1], [2, 2],
        ]
        assert before["passages"][0]["passage_id"] == historic_only
        assert not any(name.startswith("history/") for name in archive.namelist())
        assert b"Meeting accommodation" not in history_bytes

    pin = archive_rehearsal.ArchivePin(
        tenant.org_id, tenant.space_id, UUID(summary["package_id"]), bytes.fromhex(summary["archive_sha256"]),
    )
    scratch = tmp_path_factory.mktemp("repair-transcript-stage")
    with rehearsal_clone(connection, url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as material:
            assert (material.version_ref, material.scope) == (version.version_ref, SCOPE)
            assert material.store.read(material.asset) == PAYLOAD
        changed = BytesIO()
        with ZipFile(BytesIO(payload)) as sealed_zip, ZipFile(changed, "w") as altered_zip:
            for name in sealed_zip.namelist():
                altered_zip.writestr(name, b"{}" if name == "repair-history.json" else sealed_zip.read(name))
        modified = changed.getvalue()
        alternate = replace(pin, digest=sha256(modified).digest())
        staged.execute("ALTER TABLE thalion.synthetic_export_package DISABLE TRIGGER USER")
        staged.execute("UPDATE thalion.synthetic_export_package SET archive_bytes = %s", (modified,))
        with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(
            staged, alternate, modified, scratch,
        ):
            pytest.fail("A mismatched repair history was staged.")
    assert list(scratch.iterdir()) == []
    rebuild_path = f"/{rebuild_id}/seal"
    assert command(client, owner, rebuild_path).status_code == 403
    private_json(root / "rebuild-archive-grants.json", {employee: [str(version.version_ref)]})
    assert command(client, owner, rebuild_path).status_code == 200
    private_json(history_grants, {})
    assert command(client, owner, path, key=key).status_code == 403
    assert command(client, owner, rebuild_path).status_code == 403


def test_quarantine_during_sealing_rejects_repaired_package(repaired_archive):
    client, db, owner, reviewer, service, version, current, *_ = repaired_archive
    connection, *_ = db
    requested = request(client, owner, version, scope=SCOPE)
    assert requested.status_code == 200, requested.json()
    export_id = requested.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    original_check = service.check_archive_source

    def isolate(credential, probe):
        review(db, current, decision="quarantined")
        return original_check(credential, probe)

    service.check_archive_source = isolate
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    assert request(client, owner, version, scope=SCOPE).status_code == 409


def test_archive_rejects_unbounded_repair_history_instead_of_truncating(repaired_archive, monkeypatch):
    client, db, owner, _, _, version, *_ = repaired_archive
    monkeypatch.setattr(transcripts, "MAX_REPAIR_RUNS", 2)
    assert request(client, owner, version, scope=SCOPE).status_code == 409
    assert db[0].execute("SELECT count(*) FROM thalion.synthetic_export_request").fetchone() == (0,)


def test_archive_preserves_transitive_repair_lineage(repaired_archive, monkeypatch):
    client, db, owner, reviewer, _, version, repaired, failed, baseline, _ = repaired_archive
    parse = processing.parse_markdown

    def omit_exception(payload):
        parsed = parse(payload)
        return replace(parsed, passages=parsed.passages[:1])

    queue(db, version, 12)
    with monkeypatch.context() as patch:
        patch.setattr(processing, "parse_markdown", omit_exception)
        next_failed = processing.process_markdown_job(db[0], claim(db), db[-1])
    current, refs = correct(db, version, next_failed, configuration=13, baseline=repaired)
    requested = request(client, owner, version, scope=SCOPE)
    assert requested.status_code == 200, requested.json()
    export_id = requested.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    assert command(client, owner, f"/{export_id}/seal").status_code == 200
    payload, = db[0].execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    with ZipFile(BytesIO(payload)) as archive:
        runs = json.loads(archive.read("repair-history.json"))["runs"]
        assert [entry["run_id"] for entry in runs] == [
            str(run.run_ref) for run in (baseline, failed, repaired, next_failed, current)
        ]
        assert runs[-1]["rollback_run_id"] == str(repaired.run_ref)
        assert runs[-1]["decisions"][0]["decision_id"] == refs["approval"]
        assert runs[-1]["contract_revision"] == 1
        assert runs[-1]["parser"] == {
            "version": processing.PARSER_VERSION, "profile": processing.PROFILE,
            "locator_revision": processing.LOCATOR_REVISION,
        }
