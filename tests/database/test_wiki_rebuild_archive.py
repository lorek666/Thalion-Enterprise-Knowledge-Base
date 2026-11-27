from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import psycopg
from psycopg import sql
import pytest

from enterprise_kb.database import local_connection_factory, rehearsal_marker
from enterprise_kb.modules.evidence import quality_restrictions
from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.lifecycle.wiki_rebuild import canonical_json
from enterprise_kb.modules.sources import restriction_log, source_revocations
from enterprise_kb.modules.sources.originals import OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.modules.wiki.drafts import WikiStatement
from enterprise_kb.transport.local import LocalProfile

from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import (
    archive_subject, confirm_unrelated_stop, endpoint, restore_source_authority, rule_log,
)
from test_disposition_cases import candidate
from test_disposition_verification import original
from test_effectivity import BEGIN, approve as approve_effectivity
from test_evidence import approved, evidence_db, review
from test_evidence_transport import evidence_transport, private_json, transport
from test_holds import decide
from test_original_export import approve, archive_fixture, command, request
from test_rule_restriction_log import stop
from test_runtime import runtime_db
from test_travel_search import corpus, publish
from test_wiki_archive import wiki_archive
from test_wiki_drafts import candidate as create_wiki, preview, submit
from test_wiki_inputs import assemble
from test_wiki_invalidation import version_ref
from test_wiki_publication import authorize


SCOPE = "wiki_rebuild"


def enroll(wiki_archive):
    client, _, owner, reviewer, _, _, anchor, _, _, revision, *_ = wiki_archive
    opened = request(client, owner, anchor, scope=SCOPE, wiki_revision_id=str(revision))
    assert opened.status_code == 200, opened.text
    export_id = opened.json()["export_id"]
    approved = approve(client, reviewer, export_id)
    assert approved.status_code == 200, approved.text
    return UUID(export_id)


def sealed(wiki_archive, export_id):
    client, db, owner, *_ = wiki_archive
    response = command(client, owner, f"/{export_id}/seal")
    assert response.status_code == 200, response.text
    assert (response.json()["scope"], response.json()["restorable"]) == (SCOPE, False)
    payload, = db[0].execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    assert response.json()["archive_sha256"] == sha256(payload).hexdigest()
    return payload


def permit_for(wiki_archive, export_id, payload):
    _, db, _, _, _, _, anchor, _, _, revision, *_ = wiki_archive
    return archive_rehearsal.WikiArchivePermit(
        db[1].org_id, db[1].space_id, export_id, anchor.version_ref, revision, sha256(payload).digest(),
    )


def test_package_contains_exact_version_material_and_parent_closure_without_querying_source(wiki_archive):
    _, db, _, _, _, _, anchor, cited, inherited, revision, _, parent, manifest = wiki_archive
    connection, *_ = db
    inherited_version = version_ref(connection, inherited)
    export_id = enroll(wiki_archive)
    payload = sealed(wiki_archive, export_id)
    permit = permit_for(wiki_archive, export_id, payload)
    anchor_bytes = original(db, anchor).read_bytes()
    connection.close()

    verified = archive_rehearsal.verify_wiki_rebuild(permit, payload)

    assert verified.revision_ref == revision
    assert set(verified.version_refs) == {anchor.version_ref, inherited_version}
    assert set(verified.manifest_refs) == {manifest.manifest_ref, parent}
    with ZipFile(BytesIO(payload)) as archive:
        assert json.loads(archive.read("manifest.json"))["format"] == "thalion.synthetic-wiki-rebuild.v1"
        originals = {}
        for ref in verified.version_refs:
            with ZipFile(BytesIO(archive.read(f"versions/{ref}.zip"))) as embedded:
                originals[ref] = embedded.read("original.md")
                transcription = json.loads(embedded.read("transcription.json"))
                part = transcription["passages"][0]
                expected = cited if ref == anchor.version_ref else inherited
                assert (part["passage_id"], part["excerpt_revision"]) == (str(expected.passage_ref), expected.revision)
                assert embedded.read(part["member"]) == originals[ref][expected.byte_start:expected.byte_end]
        assert originals[anchor.version_ref] == anchor_bytes
        assert originals[inherited_version] == "# 差旅\n\n上海住宿超标需审批。\n".encode()


def test_embedded_versions_require_separate_original_and_metadata_grants(wiki_archive, tmp_path):
    client, db, owner, _, service, _, anchor, cited, inherited, revision, *_ = wiki_archive
    connection, *_ = db
    inherited_ref = str(version_ref(connection, inherited))
    archive_root = tmp_path / "wiki-rebuild-profile"
    archive_root.mkdir(mode=0o700)
    employee = str(service.verify_token(owner).employee_ref)
    private_json(archive_root / "credentials.json", [])
    private_json(archive_root / "source-grants.json", {})
    private_json(archive_root / "wiki-archive-grants.json", {employee: [str(revision)]})
    private_json(archive_root / "transcript-archive-grants.json", {employee: {
        str(cited.passage_ref): cited.revision, str(inherited.passage_ref): inherited.revision,
    }})
    private_json(archive_root / "archive-grants.json", {employee: [str(anchor.version_ref)]})
    private_json(archive_root / "rebuild-archive-grants.json", {employee: [str(anchor.version_ref)]})
    service.check_archive_source = LocalProfile(archive_root).check_archive_source
    export_id = enroll(wiki_archive)
    uri = f"/{export_id}/seal"
    assert command(client, owner, uri).status_code == 403
    private_json(archive_root / "archive-grants.json", {employee: [str(anchor.version_ref), inherited_ref]})
    assert command(client, owner, uri).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(archive_root / "rebuild-archive-grants.json", {employee: [str(anchor.version_ref), inherited_ref]})
    sealed(wiki_archive, export_id)


def test_enrolled_metadata_for_inherited_version_cannot_change_before_sealing(wiki_archive):
    client, db, owner, _, _, _, _, _, inherited, *_ = wiki_archive
    connection, *_ = db
    export_id = enroll(wiki_archive)
    connection.execute("""
        UPDATE thalion.document SET display_name = 'Changed after approval'
        WHERE document_id = (
            SELECT document_id FROM thalion.document_version AS version
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_id, identity.object_type) =
                 (version.org_id, version.space_id, version.version_id, 'document_version')
            WHERE identity.public_id = %s
        )
        """, (version_ref(connection, inherited),))
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_complete_transcript_requires_grant_for_a_passage_outside_the_wiki_input_graph(wiki_archive, tmp_path):
    client, db, owner, _, service, _, anchor, cited, *_ = wiki_archive
    connection, tenant, *_ = db
    version, inherited, _ = publish(
        db, "larger-wiki-dependency", "Larger synthetic policy",
        b"# Travel\n\nAn inherited condition.\n\nA paragraph not used by the Wiki.\n",
    )
    approve_effectivity(connection, tenant, version, BEGIN)
    _, unused = approved(db, version)
    grandparent = assemble(db, (inherited,))
    parent = assemble(db, (), (grandparent.manifest_ref,))
    root = assemble(db, (cited,), (parent.manifest_ref,))
    revision = create_wiki((db, root, cited, inherited), topic="archive-with-ancestor")
    assert revision.status == "succeeded"
    review = submit(db, revision.ref, preview(db, revision.ref))
    assert authorize(db, revision.ref, review.ref).status == "succeeded"
    bundle = (*wiki_archive[:8], inherited, revision.ref, None, parent.manifest_ref, root)
    export_id = enroll(bundle)

    profile_dir = tmp_path / "full-transcript"
    profile_dir.mkdir(mode=0o700)
    employee = str(service.verify_token(owner).employee_ref)
    private_json(profile_dir / "credentials.json", [])
    private_json(profile_dir / "source-grants.json", {})
    private_json(profile_dir / "wiki-archive-grants.json", {employee: [str(revision.ref)]})
    for key in ("archive-grants.json", "rebuild-archive-grants.json"):
        private_json(profile_dir / key, {employee: [str(anchor.version_ref), str(version.version_ref)]})
    exact = {str(part.passage_ref): part.revision for part in (cited, inherited)}
    grants = profile_dir / "transcript-archive-grants.json"
    private_json(grants, {employee: exact})
    service.check_archive_source = LocalProfile(profile_dir).check_archive_source
    assert command(client, owner, f"/{export_id}/seal").status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(grants, {employee: exact | {str(unused.passage_ref): unused.revision}})
    payload = sealed(bundle, export_id)
    verified = archive_rehearsal.verify_wiki_rebuild(permit_for(bundle, export_id, payload), payload)
    assert set(verified.manifest_refs) == {root.manifest_ref, parent.manifest_ref, grandparent.manifest_ref}


@pytest.mark.parametrize("missing", ["version", "parent"])
def test_independent_verifier_rejects_incomplete_archives_even_with_corrected_package_digest(wiki_archive, missing):
    _, db, _, _, _, _, _, _, inherited, _, _, parent, _ = wiki_archive
    export_id = enroll(wiki_archive)
    payload = sealed(wiki_archive, export_id)
    permit = permit_for(wiki_archive, export_id, payload)
    missing_bundle = f"versions/{version_ref(db[0], inherited)}.zip"
    altered = BytesIO()
    with ZipFile(BytesIO(payload)) as source, ZipFile(altered, "w") as output:
        graph = source.read("wiki/manifests.json")
        manifest = json.loads(source.read("manifest.json"))
        if missing == "parent":
            nodes = json.loads(graph)
            graph = json.dumps({"manifests": [item for item in nodes["manifests"] if item["manifest_id"] != str(parent)]},
                               sort_keys=True, separators=(",", ":")).encode()
            manifest["manifest_graph_sha256"] = sha256(graph).hexdigest()
        for member in source.namelist():
            if missing == "version" and member == missing_bundle:
                continue
            raw = source.read(member)
            if member == "manifest.json":
                raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            if member == "wiki/manifests.json":
                raw = graph
            output.writestr(member, raw)
    rearranged = altered.getvalue()
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.verify_wiki_rebuild(replace(permit, digest=sha256(rearranged).digest()), rearranged)


@pytest.fixture
def wiki_restore(wiki_archive, empty_rehearsal, tmp_path_factory):
    _, db, _, _, _, _, _, cited, inherited, _, _, parent, _ = wiki_archive
    ancestor = assemble(db, (), (parent,))
    root = assemble(db, (cited,), (ancestor.manifest_ref,))
    statement = WikiStatement("Synthetic allowance", (((cited.passage_ref, cited.revision),),))
    draft = create_wiki((db, root, cited, inherited), topic="archive-restore", statements=(statement,))
    review = submit(db, draft.ref, preview(db, draft.ref))
    publication = authorize(db, draft.ref, review.ref)
    assert publication.status == "succeeded"
    bundle = (*wiki_archive[:9], draft.ref, publication.ref, ancestor.manifest_ref, root)
    export_id = enroll(bundle)
    payload = sealed(bundle, export_id)
    pin = permit_for(bundle, export_id, payload)
    connection, url = empty_rehearsal
    permit = pin, connection.info.dbname
    scratch = tmp_path_factory.mktemp("wiki-rebuild-empty")
    return db, connection, url, permit, payload, scratch


def test_rebuilds_exact_wiki_graph_and_sources_in_an_empty_fenced_database(wiki_restore):
    db, target, url, (pin, database), payload, scratch = wiki_restore
    db[0].close()
    with ZipFile(BytesIO(payload)) as archive:
        content = archive.read("wiki/revision.json")
        graph = json.loads(archive.read("wiki/manifests.json"))
        dependencies = json.loads(archive.read("wiki/dependencies.json"))
        originals = {}
        for ref in {UUID(entry["version_id"]) for entry in dependencies["inputs"]}:
            with ZipFile(BytesIO(archive.read(f"versions/{ref}.zip"))) as embedded:
                originals[ref] = embedded.read("original.md")

    permit = archive_rehearsal.WikiRebuildPermit(pin, database)
    restored = archive_rehearsal.rebuild_wiki(target, permit, payload, scratch)

    assert restored.revision_ref == pin.revision_ref
    assert {ref: restored.store.read(asset) for ref, asset in restored.originals} == originals
    assert target.execute("""
        SELECT revision_ref, content, manifest_graph, dependencies, archive_digest
        FROM thalion.archive_wiki_rebuild
        """).fetchone() == (pin.revision_ref, content, graph, dependencies, pin.digest)
    assert len(graph["manifests"]) == 3
    assert target.execute("""
        SELECT identity.object_type, count(*) FROM thalion.object_identity AS identity
        WHERE identity.object_type IN ('source', 'document', 'document_version', 'passage')
        GROUP BY identity.object_type ORDER BY identity.object_type
        """).fetchall() == [("document", 2), ("document_version", 2), ("passage", 2), ("source", 1)]
    assert set(target.execute("""
        SELECT version.public_id, passage.public_id, excerpt.excerpt_revision, excerpt.run_ref, excerpt.content_digest
        FROM thalion.passage_excerpt AS excerpt
        JOIN thalion.object_identity AS passage
          ON (passage.org_id, passage.space_id, passage.object_type, passage.object_id) =
             (excerpt.org_id, excerpt.space_id, 'passage', excerpt.passage_id)
        JOIN thalion.object_identity AS version
          ON (version.org_id, version.space_id, version.object_type, version.object_id) =
             (excerpt.org_id, excerpt.space_id, 'document_version', excerpt.version_id)
        """).fetchall()) == {
        (UUID(entry["version_id"]), UUID(entry["passage_id"]), entry["excerpt_revision"],
         UUID(entry["run_id"]), bytes.fromhex(entry["excerpt_sha256"])) for entry in dependencies["inputs"]
    }
    assert target.execute("""
        SELECT (SELECT count(*) FROM thalion.wiki_revision), (SELECT count(*) FROM thalion.wiki_review),
               (SELECT count(*) FROM thalion.wiki_publication_event), (SELECT count(*) FROM thalion.input_manifest),
               (SELECT count(*) FROM thalion.quality_decision), (SELECT count(*) FROM thalion.delivery_record),
               (SELECT count(*) FROM thalion.rule_effectivity), (SELECT count(*) FROM thalion.permission_binding),
               (SELECT count(*) FROM thalion.archive_rebuild_rule_check)
        """).fetchone() == (0,) * 9
    assert target.execute("SELECT lifecycle FROM thalion.space").fetchone() == ("archived",)
    assert rehearsal_marker(target) == target.info.dbname
    with pytest.raises(psycopg.OperationalError, match="rehearsal"):
        local_connection_factory(url)()
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        target.execute("UPDATE thalion.archive_wiki_rebuild SET content = %s", (b"{}",))
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="empty"):
        archive_rehearsal.rebuild_wiki(target, permit, payload, scratch)


@pytest.mark.parametrize("change", ["uncited_support", "conflicting_source", "conflicting_document"])
def test_rejects_inconsistent_wiki_rebuild_members_before_writing(wiki_restore, change):
    _, target, _, (pin, database), payload, scratch = wiki_restore
    with ZipFile(BytesIO(payload)) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(members["manifest.json"])
    if change == "uncited_support":
        dependencies = json.loads(members["wiki/dependencies.json"])
        revision = json.loads(members["wiki/revision.json"])
        uncited = dependencies["inputs"][-1]
        revision["statements"][0]["support_groups"] = [[[uncited["passage_id"], uncited["excerpt_revision"]]]]
        raw = json.dumps(revision, ensure_ascii=False, separators=(",", ":")).encode()
        members["wiki/revision.json"] = raw
        dependencies["content_sha256"] = sha256(raw).hexdigest()
        members["wiki/dependencies.json"] = canonical_json(dependencies)
        manifest["wiki_dependencies_sha256"] = sha256(members["wiki/dependencies.json"]).hexdigest()
    else:
        first, second = manifest["versions"]
        first_member, second_member = (f"versions/{entry['version_id']}.zip" for entry in (first, second))
        with ZipFile(BytesIO(members[first_member])) as archive:
            doc_ref = json.loads(archive.read("manifest.json"))["rebuild"]["document_id"]
        repacked = BytesIO()
        with ZipFile(BytesIO(members[second_member])) as original, ZipFile(repacked, "w") as altered:
            for name in original.namelist():
                raw = original.read(name)
                if name == "manifest.json":
                    nested = json.loads(raw)
                    if change == "conflicting_source":
                        nested["rebuild"]["source_key"] = "different-source-key"
                    else:
                        nested["rebuild"]["document_id"] = doc_ref
                    raw = canonical_json(nested)
                altered.writestr(name, raw)
        members[second_member] = repacked.getvalue()
        second["sha256"] = sha256(members[second_member]).hexdigest()
    members["manifest.json"] = canonical_json(manifest)
    repacked = BytesIO()
    with ZipFile(repacked, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    changed = repacked.getvalue()
    permit = archive_rehearsal.WikiRebuildPermit(replace(pin, digest=sha256(changed).digest()), database)
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.verify_wiki_rebuild(permit.pin, changed)
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_wiki(target, permit, changed, scratch)
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert not any(scratch.iterdir())


def test_rebuild_requires_a_database_level_fence_not_a_session_value(wiki_restore):
    _, target, _, (pin, database), payload, scratch = wiki_restore
    target.execute(sql.SQL("ALTER DATABASE {} RESET thalion.restore_rehearsal").format(sql.Identifier(database)))
    target.execute("SELECT set_config('thalion.restore_rehearsal', %s, false)", (database,))
    permit = archive_rehearsal.WikiRebuildPermit(pin, database)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="fenced"):
        archive_rehearsal.rebuild_wiki(target, permit, payload, scratch)
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert not any(scratch.iterdir())


def test_wrong_target_and_later_original_write_failure_leave_no_partial_rebuild(wiki_restore, monkeypatch):
    _, target, _, (pin, database), payload, scratch = wiki_restore
    permit = archive_rehearsal.WikiRebuildPermit(pin, database)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="permit"):
        archive_rehearsal.rebuild_wiki(target, replace(permit, database="other_database"), payload, scratch)

    stage = SyntheticOriginalStore.stage

    def fail_second(store, key, digest, content):
        if any(store.root.iterdir()):
            raise OriginalIntegrityError("Second original unavailable.")
        return stage(store, key, digest, content)

    monkeypatch.setattr(SyntheticOriginalStore, "stage", fail_second)
    with pytest.raises(archive_rehearsal.ArchiveRejected):
        archive_rehearsal.rebuild_wiki(target, permit, payload, scratch)
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert target.execute("SELECT count(*) FROM thalion.archive_wiki_rebuild").fetchone() == (0,)
    assert not any(scratch.iterdir())


def test_records_each_independent_checkpoint_despite_an_unrelated_quarantine(
    wiki_restore, rule_log, candidate, restore_source_authority,
):
    db, target, _, (pin, database), payload, scratch = wiki_restore
    authority, tenant, *_ = db
    stream = confirm_unrelated_stop(db, rule_log)
    _, _, (_, _, unrelated_run) = candidate
    quarantine = review(db, unrelated_run, decision="quarantined")
    assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).confirmed == (quarantine,)
    quality_stream, = authority.execute("""
        SELECT stream_ref FROM thalion.quality_restriction_stream WHERE org_id = %s
        """, (tenant.org_id,)).fetchone()
    _, source_authority, _ = restore_source_authority
    snapshot = source_authority.snapshot(tenant.space_ref)
    permit = archive_rehearsal.WikiRebuildPermit(pin, database)
    rebuilt = archive_rehearsal.rebuild_wiki_with_rule_checkpoint(
        target, permit, payload, scratch,
        authority=authority, log=rule_log, authority_ref=endpoint(authority), log_ref=endpoint(rule_log),
        source_authority=source_authority,
    )
    assert set(target.execute("""
        SELECT version_ref, archive_digest, stream_ref, generation, quality_stream_ref, quality_generation,
               source_authority_ref, source_space_ref, source_stream_ref, source_generation, source_requester_ref
        FROM thalion.archive_rebuild_rule_check
        """).fetchall()) == {
        (ref, pin.digest, stream, 1, quality_stream, 2, source_authority.authority_ref,
         tenant.space_ref, snapshot.stream_ref, 0, archive_subject(db))
        for ref, _ in rebuilt.originals
    }


def test_rule_checkpoint_refuses_stop_on_inherited_uncited_version_before_writes(
    wiki_restore, rule_log, restore_source_authority,
):
    db, target, _, (pin, database), payload, scratch = wiki_restore
    authority, tenant, *_ = db
    confirm_unrelated_stop(db, rule_log)
    verified = archive_rehearsal.verify_wiki_rebuild(pin, payload)
    inherited, = set(verified.version_refs) - {pin.version_ref}
    decision = stop(authority, tenant, inherited)
    permit = archive_rehearsal.WikiRebuildPermit(pin, database)
    kwargs = {
        "authority": authority, "log": rule_log, "authority_ref": endpoint(authority),
        "log_ref": endpoint(rule_log), "source_authority": restore_source_authority[1],
    }

    with pytest.raises(archive_rehearsal.ArchiveRejected, match="could not be verified"):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(target, permit, payload, scratch, **kwargs)
    assert restriction_log.deliver_pending(authority, rule_log, tenant.org_id).confirmed == (decision,)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="rule history blocks"):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(target, permit, payload, scratch, **kwargs)
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert not any(scratch.iterdir())


def test_independent_quality_checkpoint_blocks_quarantine_of_inherited_uncited_version(
    wiki_restore, rule_log, corpus, restore_source_authority,
):
    db, target, _, (pin, database), payload, scratch = wiki_restore
    authority, tenant, *_ = db
    confirm_unrelated_stop(db, rule_log)
    _, _, _, _, inherited_run, _ = corpus
    quarantine = review(db, inherited_run, decision="quarantined")
    permit = archive_rehearsal.WikiRebuildPermit(pin, database)
    kwargs = {
        "authority": authority, "log": rule_log, "authority_ref": endpoint(authority),
        "log_ref": endpoint(rule_log), "source_authority": restore_source_authority[1],
    }

    with pytest.raises(archive_rehearsal.ArchiveRejected, match="independent quality history"):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(target, permit, payload, scratch, **kwargs)
    assert quality_restrictions.deliver_pending(authority, rule_log, tenant.org_id).confirmed == (quarantine,)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="quality history blocks"):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(target, permit, payload, scratch, **kwargs)
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert not any(scratch.iterdir())


@pytest.mark.parametrize("target_kind", ["wiki_revision", "inherited_uncited_passage"])
def test_wiki_rebuild_rejects_current_source_archive_revocation_without_partial_writes(
    wiki_restore, rule_log, corpus, restore_source_authority, target_kind,
):
    db, target, _, (pin, database), payload, scratch = wiki_restore
    authority, tenant, *_ = db
    writer, source_authority, _ = restore_source_authority
    confirm_unrelated_stop(db, rule_log)
    _, _, _, inherited, *_ = corpus
    object_ref = pin.revision_ref if target_kind == "wiki_revision" else inherited.passage_ref
    source_revocations.revoke(
        writer, source_authority.authority_ref, tenant.space_ref, archive_subject(db), object_ref,
        "archive", basis_ref=uuid4(),
    )
    permit = archive_rehearsal.WikiRebuildPermit(pin, database)

    with pytest.raises(archive_rehearsal.ArchiveRejected, match="source revocation blocks"):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(
            target, permit, payload, scratch, authority=authority, log=rule_log, authority_ref=endpoint(authority),
            log_ref=endpoint(rule_log), source_authority=source_authority,
        )
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert target.execute("SELECT count(*) FROM thalion.archive_rebuild_rule_check").fetchone() == (0,)
    assert not any(scratch.iterdir())


def test_rule_checkpoint_blocks_current_hold_of_an_inherited_version(wiki_restore, wiki_archive, rule_log, restore_source_authority):
    db, target, _, (pin, database), payload, scratch = wiki_restore
    authority, *_ = db
    client, _, _, reviewer, *_ = wiki_archive
    confirm_unrelated_stop(db, rule_log)
    inherited, = set(archive_rehearsal.verify_wiki_rebuild(pin, payload).version_refs) - {pin.version_ref}
    held = decide(client, reviewer, inherited)
    assert held.status_code == 200, held.text

    with pytest.raises(archive_rehearsal.ArchiveRejected, match="hold blocks"):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(
            target, archive_rehearsal.WikiRebuildPermit(pin, database), payload, scratch,
            authority=authority, log=rule_log, authority_ref=endpoint(authority), log_ref=endpoint(rule_log),
            source_authority=restore_source_authority[1],
        )
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert not any(scratch.iterdir())
