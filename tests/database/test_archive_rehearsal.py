from hashlib import sha256
from io import BytesIO
from uuid import UUID, uuid4
from zipfile import ZipFile

import pytest

from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.sources import restriction_log

from test_disposition_cases import candidate
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, transport
from test_original_export import approve, archive_fixture, command, pdf_archive_fixture, request as request_archive
from test_persisted_access import authority_for, read
from test_rule_replay import rehearsal_clone
from test_rule_restriction_log import independent_log, stop
from test_runtime import runtime_db
from test_transcript_export import transcript
from test_travel_search import corpus
from test_wiki_archive import wiki_archive


def sealed_payload(client, db, owner, reviewer, version, **archive_args):
    opened = request_archive(client, owner, version, **archive_args)
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    sealed = command(client, owner, f"/{export_id}/seal")
    assert sealed.status_code == 200, sealed.text
    summary = sealed.json()
    payload, = db[0].execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    return UUID(summary["package_id"]), bytes.fromhex(summary["archive_sha256"]), payload


@pytest.fixture(params=["original_only", "pdf_original_only", "original_and_transcript", "original_and_wiki"])
def sealed_archive(request):
    scope = "original_only" if request.param == "pdf_original_only" else request.param
    archive_args = {"scope": scope}
    if request.param == "pdf_original_only":
        client, db, owner, reviewer, _, _, version = request.getfixturevalue("pdf_archive_fixture")
    elif scope == "original_only":
        client, db, owner, reviewer, _, _, version = request.getfixturevalue("archive_fixture")
    elif scope == "original_and_transcript":
        (client, db, owner, reviewer, *_), version, *_ = request.getfixturevalue("transcript")
    else:
        client, db, owner, reviewer, _, _, version, _, _, revision, *_ = request.getfixturevalue("wiki_archive")
        archive_args["wiki_revision_id"] = str(revision)
    package, digest, payload = sealed_payload(client, db, owner, reviewer, version, **archive_args)
    return db, version, package, digest, payload, scope


def test_approved_archive_rehydrates_original_in_private_stage_only(sealed_archive, postgres_server, tmp_path_factory):
    db, version, package, digest, payload, scope = sealed_archive
    source, tenant, source_url, _, store = db
    expected = original(db, version).read_bytes()
    scratch = tmp_path_factory.mktemp("archive-stage")
    pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, package, digest)
    with rehearsal_clone(source, source_url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as result:
            assert (result.version_ref, result.scope) == (version.version_ref, scope)
            assert result.store.root != store.root and result.store.root.parent == scratch.resolve()
            assert result.store.read(result.asset) == expected
            assert result.store.root.stat().st_mode & 0o077 == 0
            assert staged.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (1,)
            assert staged.execute("SELECT count(*) FROM thalion.rule_use_stop").fetchone() == (0,)
        assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("fixture", ["archive_fixture", "pdf_archive_fixture"])
def test_archive_stage_rejects_wrong_package_pin_scope_and_known_withdrawal(
    request, fixture, postgres_server, tmp_path_factory,
):
    client, db, owner, reviewer, _, _, version = request.getfixturevalue(fixture)
    source, tenant, source_url, *_ = db
    package, digest, payload = sealed_payload(client, db, owner, reviewer, version)
    scratch = tmp_path_factory.mktemp("archive-stage-refused")
    pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, package, digest)
    with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(source, pin, payload, scratch):
        pytest.fail("Unmarked primary database staged an archive.")

    with rehearsal_clone(source, source_url, postgres_server) as (_, staged, _):
        invalid_pins = [
            archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id + 1, package, digest),
            archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, uuid4(), digest),
            archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, package, b"x" * 32),
        ]
        for invalid in invalid_pins:
            with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(
                staged, invalid, payload, scratch,
            ):
                pytest.fail("Archive was staged outside its approved pin.")
        stop(staged, tenant, version.version_ref)
        with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(staged, pin, payload, scratch):
            pytest.fail("Known withdrawn archive was staged.")
    assert list(scratch.iterdir()) == []


def test_rehydrated_original_supports_the_same_citation_until_independent_withdrawal_replays(
    wiki_archive, independent_log, postgres_server, tmp_path_factory,
):
    client, db, owner, reviewer, _, _, version, citation, _, revision, *_ = wiki_archive
    source, tenant, source_url, source_ref, _ = db
    package, digest, payload = sealed_payload(
        client, db, owner, reviewer, version, scope="original_and_wiki", wiki_revision_id=str(revision),
    )
    pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, package, digest)
    scratch = tmp_path_factory.mktemp("archive-with-replay")
    current_authority = authority_for({tenant.actor_id})
    with rehearsal_clone(source, source_url, postgres_server) as (primary, staged, staged_url):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as result:
            staged_db = (staged, tenant, staged_url, source_ref, result.store)
            raw = result.store.read(result.asset)
            before = read(staged_db, citation, tenant.actor_id, current_authority)
            assert before.payload == raw[citation.byte_start:citation.byte_end]
            decision = stop(primary, tenant, version.version_ref)
            assert restriction_log.deliver_pending(primary, independent_log, tenant.org_id).confirmed == (decision,)
            assert restriction_log.rehearse_replay(primary, independent_log, staged, tenant.org_id).applied == (decision,)
            assert read(staged_db, citation, tenant.actor_id, current_authority).payload is None
            assert result.store.read(result.asset) == raw
        with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(
            staged, pin, payload, scratch,
        ):
            pytest.fail("Withdrawal was not respected by a subsequent staging attempt.")
    assert list(scratch.iterdir()) == []


def test_approved_pin_cannot_substitute_mismatched_member_bytes(sealed_archive, postgres_server, tmp_path_factory):
    db, _, package, _, payload, scope = sealed_archive
    source, tenant, source_url, *_ = db
    replaced = {
        "original_only": "manifest.json",
        "original_and_transcript": "transcription.json",
        "original_and_wiki": "wiki/dependencies.json",
    }[scope]
    changed = BytesIO()
    with ZipFile(BytesIO(payload)) as sealed, ZipFile(changed, "w") as rebuilt:
        if "original.pdf" in sealed.namelist():
            replaced = "original.pdf"
        for name in sealed.namelist():
            content = sealed.read(name)
            if name == replaced:
                content = b"!" + content[1:] if name == "original.pdf" else b"{}"
            rebuilt.writestr(name, content)
    changed_payload = changed.getvalue()
    new_pin = archive_rehearsal.ArchivePin(tenant.org_id, tenant.space_id, package, sha256(changed_payload).digest())
    scratch = tmp_path_factory.mktemp("archive-stage-mismatch")
    with rehearsal_clone(source, source_url, postgres_server) as (_, staged, _):
        staged.execute("ALTER TABLE thalion.synthetic_export_package DISABLE TRIGGER USER")
        updated = staged.execute(
            "UPDATE thalion.synthetic_export_package SET archive_bytes = %s WHERE package_ref = %s RETURNING archive_digest",
            (changed_payload, package),
        ).fetchone()
        assert updated == (new_pin.digest,)
        with pytest.raises(archive_rehearsal.ArchiveRejected), archive_rehearsal.stage_original(
            staged, new_pin, changed_payload, scratch,
        ):
            pytest.fail("The staged archive did not agree with the exact registered package scope.")
    assert list(scratch.iterdir()) == []
