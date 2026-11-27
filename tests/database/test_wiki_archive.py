from hashlib import sha256
from io import BytesIO
import json
from uuid import uuid4
from zipfile import ZipFile

import pytest

from enterprise_kb.modules.sources import registry
from enterprise_kb.transport.local import LocalProfile

from test_disposition import plan
from test_disposition_cases import candidate
from test_effectivity import BEGIN, approve as approve_effectivity
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, private_json, transport
from test_holds import decide
from test_original_export import approve, archive_fixture, command, request
from test_persisted_access import authority_for
from test_runtime import runtime_db
from test_sources import request_for
from test_travel_search import corpus, publish
from test_wiki_drafts import candidate as create_wiki, preview, submit
from test_wiki_inputs import assemble
from test_wiki_invalidation import version_ref
from test_wiki_publication import authorize, configure


SCOPE = "original_and_wiki"


@pytest.fixture
def wiki_archive(archive_fixture, corpus):
    client, db, owner, reviewer, service, _, unrelated = archive_fixture
    _, allowance, cited, uncited, *_ = corpus
    configure(db, 2)
    parent = assemble(db, (uncited,))
    assert parent.status == "succeeded"
    sealed = assemble(db, (cited,), (parent.manifest_ref,))
    assert sealed.status == "succeeded"
    draft = create_wiki((db, sealed, cited, uncited))
    assert draft.status == "succeeded"
    review = submit(db, draft.ref, preview(db, draft.ref))
    assert review.status == "succeeded"
    publication = authorize(db, draft.ref, review.ref)
    assert publication.status == "succeeded"
    return client, db, owner, reviewer, service, unrelated, allowance, cited, uncited, draft.ref, publication.ref, parent.manifest_ref, sealed


def test_wiki_archive_binds_complete_exact_inputs_and_lists_package_for_every_version(wiki_archive, tmp_path):
    client, db, owner, reviewer, service, unrelated, allowance, cited, uncited, revision, publication, parent, _ = wiki_archive
    connection, *_ = db
    wiki_args = {"scope": SCOPE, "wiki_revision_id": str(revision)}
    assert request(client, owner, unrelated, **wiki_args).status_code == 409
    assert request(client, owner, allowance, **(wiki_args | {"scope": "original_only"})).status_code == 400
    assert request(client, owner, allowance, **(wiki_args | {"wiki_revision_id": str(uuid4())})).status_code == 409
    requested = request(client, owner, allowance, **wiki_args)
    assert requested.status_code == 200, requested.text
    export_id = requested.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    uri = f"/{export_id}/seal"
    profile_dir = tmp_path / "wiki-archive-profile"
    profile_dir.mkdir(mode=0o700)
    employee = str(service.verify_token(owner).employee_ref)
    private_json(profile_dir / "credentials.json", [])
    private_json(profile_dir / "archive-grants.json", {employee: [str(allowance.version_ref)]})
    private_json(profile_dir / "source-grants.json", {employee: [str(uncited.passage_ref)]})
    private_json(profile_dir / "transcript-archive-grants.json", {employee: {str(cited.passage_ref): cited.revision}})
    service.check_archive_source = LocalProfile(profile_dir).check_archive_source
    versions = {part.passage_ref: version_ref(connection, part) for part in (cited, uncited)}
    before = plan(client, owner, versions[uncited.passage_ref]).json()
    assert command(client, owner, uri).status_code == 403
    private_json(profile_dir / "wiki-archive-grants.json", {employee: [str(revision)]})
    assert command(client, owner, uri).status_code == 403
    private_json(profile_dir / "transcript-archive-grants.json", {employee: {
        str(cited.passage_ref): cited.revision, str(uncited.passage_ref): uncited.revision + 1,
    }})
    assert command(client, owner, uri).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(profile_dir / "transcript-archive-grants.json", {employee: {
        str(cited.passage_ref): cited.revision, str(uncited.passage_ref): uncited.revision,
    }})
    response = command(client, owner, uri)
    assert response.status_code == 200, response.text
    assert response.json()["scope"] == SCOPE and response.json()["restorable"] is False
    assert str(uncited.passage_ref) not in response.text
    archive_bytes, = connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    with ZipFile(BytesIO(archive_bytes)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        metadata = archive.read("wiki/dependencies.json")
        assert manifest["wiki_dependencies_sha256"] == sha256(metadata).hexdigest()
        inputs = json.loads(metadata)
        assert (inputs["revision_id"], inputs["publication_id"], inputs["parent_manifest_ids"], inputs["direct_count"]) == (
            str(revision), str(publication), [str(parent)], 1,
        )
        assert [(entry["version_id"], entry["passage_id"], entry["excerpt_revision"]) for entry in inputs["inputs"]] == [
            (str(versions[part.passage_ref]), str(part.passage_ref), part.revision) for part in (cited, uncited)
        ]
        stored_content, = connection.execute("SELECT content FROM thalion.wiki_revision WHERE revision_ref = %s", (revision,)).fetchone()
        assert archive.read("wiki/revision.json") == stored_content
        assert archive.read("wiki/content.md").decode() == json.loads(stored_content)["markdown"]
    after = plan(client, owner, versions[uncited.passage_ref]).json()
    assert after["inventory_snapshot"] != before["inventory_snapshot"]
    assert [item["kind"] for item in after["copies"]].count("export") == 1
    assert decide(client, reviewer, versions[uncited.passage_ref]).status_code == 200
    held = plan(client, owner, versions[uncited.passage_ref]).json()
    assert [item["kind"] for item in held["copies"]].count("export") == 1
    assert command(client, owner, uri).status_code == 409


def test_hold_on_inherited_input_during_authority_check_prevents_sealing(wiki_archive):
    client, db, owner, reviewer, service, _, allowance, _, uncited, revision, *_ = wiki_archive
    connection, tenant, *_ = db
    requested = request(client, owner, allowance, scope=SCOPE, wiki_revision_id=str(revision))
    assert requested.status_code == 200, requested.text
    export_id = requested.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    inherited_version = version_ref(connection, uncited)

    def hold_then_allow(_credential, probe):
        response = decide(client, reviewer, inherited_version, action="establish")
        assert response.status_code == 200, response.text
        return authority_for({tenant.actor_id})(probe)

    service.check_archive_source = hold_then_allow
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_new_publication_does_not_inherit_old_archive_approval(wiki_archive):
    client, db, owner, reviewer, _, _, allowance, cited, uncited, revision, _, _, manifest = wiki_archive
    connection, *_ = db
    requested = request(client, owner, allowance, scope=SCOPE, wiki_revision_id=str(revision))
    assert requested.status_code == 200, requested.text
    export_id = requested.json()["export_id"]
    assert approve(client, reviewer, export_id).status_code == 200
    replacement = create_wiki((db, manifest, cited, uncited))
    assert replacement.status == "succeeded"
    review = submit(db, replacement.ref, preview(db, replacement.ref))
    assert review.status == "succeeded"
    assert authorize(db, replacement.ref, review.ref).status == "succeeded"
    assert command(client, owner, f"/{export_id}/seal").status_code == 409
    assert request(client, owner, allowance, scope=SCOPE, wiki_revision_id=str(revision)).status_code == 409
    updated = request(client, owner, allowance, scope=SCOPE, wiki_revision_id=str(replacement.ref))
    assert updated.status_code == 200 and updated.json()["export_id"] != export_id
    assert command(client, owner, f"/{updated.json()['export_id']}/seal").status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def test_single_source_approval_cannot_include_an_input_from_another_source(wiki_archive):
    client, db, owner, _, _, _, allowance, cited, _, *_ = wiki_archive
    connection, tenant, database_url, _, store = db
    context = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "register_source_contract")
    source = registry.register_synthetic_source(connection, context, tenant.space_id, registry.SyntheticSource(
        "separate-travel", "separate-travel-archive", tenant.worker_id, approver_id=tenant.other_actor_id,
        processor_id=tenant.other_worker_id, quality_reviewer_id=tenant.actor_id,
    ))
    separate_db = (connection, tenant, database_url, source, store)
    configure(separate_db, 1)
    version, uncited, _ = publish(separate_db, "other-source", "另一来源", b"# Travel\n\nSeparate synthetic material.\n")
    approve_effectivity(connection, tenant, version, BEGIN)
    manifest = assemble(db, (cited, uncited))
    assert manifest.status == "succeeded"
    revision = create_wiki((db, manifest, cited, uncited), topic="multi-source")
    assert revision.status == "succeeded"
    review = submit(db, revision.ref, preview(db, revision.ref))
    assert review.status == "succeeded"
    assert authorize(db, revision.ref, review.ref).status == "succeeded"
    assert request(client, owner, allowance, scope=SCOPE, wiki_revision_id=str(revision.ref)).status_code == 409
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_request").fetchone() == (0,)
