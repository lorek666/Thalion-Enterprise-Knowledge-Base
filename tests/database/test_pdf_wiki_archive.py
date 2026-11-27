from dataclasses import replace
from datetime import date
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID, uuid4
from zipfile import ZipFile

import pytest
from psycopg import errors

from enterprise_kb.modules.lifecycle import archive_rehearsal
from enterprise_kb.modules.sources import source_revocations
from enterprise_kb.modules.wiki.drafts import WikiStatement
from enterprise_kb.runtime.audit import RequestStart, start_request
from enterprise_kb.transport.local import LocalProfile

from test_archive_rebuild import empty_rehearsal
from test_archive_rule_checkpoint import confirm_unrelated_stop, endpoint, restore_source_authority, rule_log
from test_disposition import plan
from test_disposition_cases import candidate
from test_disposition_verification import original
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, private_json, transport
from test_holds import decide
from test_original_export import REQUEST, approve, archive_fixture, command, request
from test_pdf_delivery import PRIVATE
from test_pdf_processing import PAGE_TEXT
from test_pdf_wiki import WORKSPACE_FIELDS, pdf_pages
from test_persisted_access import set_rules
from test_rule_replay import rehearsal_clone
from test_runtime import runtime_db
from test_travel_search import corpus
from test_wiki_drafts import candidate as create_wiki, preview, submit
from test_wiki_inputs import assemble, compile_rule
from test_wiki_invalidation import version_ref
from test_wiki_publication import authorize


SCOPE = "original_and_wiki"


@pytest.fixture
def pdf_wiki_bundle(archive_fixture, evidence_transport, restore_source_authority, corpus, tmp_path):
    client, db, owner, reviewer, service, _, _ = archive_fixture
    connection, tenant, *_ = db
    _, markdown_version, markdown, *_ = corpus
    pdf, run, pages = pdf_pages(db)
    rules = []
    for part in (markdown, *pages):
        compile_part = replace(compile_rule(tenant.actor_id), passage_ref=part.passage_ref, fields=WORKSPACE_FIELDS)
        review_part = replace(compile_part, subject_id=tenant.other_actor_id,
                              operation="review_wiki_revision", purpose="wiki_review")
        rules.extend((compile_part, review_part, replace(review_part, operation="publish_wiki_revision", purpose="wiki_publication")))
    assert set_rules(db, *rules, expected=2) == 3
    parent = assemble(db, pages)
    assert parent.status == "succeeded"
    root = assemble(db, (markdown,), (parent.manifest_ref,))
    assert root.status == "succeeded"
    statement = WikiStatement("Synthetic policy summary", (((markdown.passage_ref, markdown.revision),),))
    draft = create_wiki((db, root, markdown, pages[0]), statements=(statement,))
    assert draft.status == "succeeded"
    reviewed = submit(db, draft.ref, preview(db, draft.ref))
    assert reviewed.status == "succeeded"
    publication = authorize(db, draft.ref, reviewed.ref)
    assert publication.status == "succeeded"
    authority, source, _ = restore_source_authority
    profile_root = tmp_path / "archive-profile"
    profile_root.mkdir(mode=0o700)
    private_json(profile_root / "credentials.json", [])
    private_json(profile_root / "source-grants.json", {})
    profile = LocalProfile(profile_root, revocations=source)
    employee = service.verify_token(owner).employee_ref
    service.check_archive_source = profile.check_archive_source
    private_json(profile.root / "archive-grants.json", {str(employee): [str(pdf.version_ref), str(markdown_version.version_ref)]})
    private_json(profile.root / "wiki-archive-grants.json", {str(employee): [str(draft.ref)]})
    grants = {str(part.passage_ref): part.revision for part in (markdown, *pages)}
    private_json(profile.root / "transcript-archive-grants.json", {str(employee): grants})
    return (client, db, owner, reviewer, authority, source, profile, employee, markdown_version, markdown,
            pdf, run, pages, draft, parent, grants, publication)


def open_and_approve(client, owner, reviewer, version, draft, *, scope=SCOPE):
    opened = request(client, owner, version, scope=scope, wiki_revision_id=str(draft.ref))
    assert opened.status_code == 200, opened.text
    export_ref = opened.json()["export_id"]
    assert approve(client, reviewer, export_ref).status_code == 200
    return f"/{export_ref}/seal"


def test_wiki_archive_includes_all_unquoted_inherited_pdf_revisions_and_only_the_selected_original(
    pdf_wiki_bundle, postgres_server, tmp_path_factory,
):
    client, db, owner, reviewer, _, _, profile, employee, markdown_version, markdown, pdf, run, pages, draft, parent, grants, _ = pdf_wiki_bundle
    connection, tenant, database_url, *_ = db
    path = open_and_approve(client, owner, reviewer, pdf, draft)
    partial = grants | {str(pages[-1].passage_ref): pages[-1].revision + 1}
    private_json(profile.root / "transcript-archive-grants.json", {str(employee): partial})
    assert command(client, owner, path).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)
    private_json(profile.root / "transcript-archive-grants.json", {str(employee): grants})
    response = command(client, owner, path)
    assert response.status_code == 200, response.text
    assert (response.json()["scope"], response.json()["restorable"]) == (SCOPE, False)
    payload, = connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    assert response.json()["archive_sha256"] == sha256(payload).hexdigest()
    expected_original = original(db, pdf).read_bytes()
    with ZipFile(BytesIO(payload)) as archive:
        assert set(archive.namelist()) == {
            "manifest.json", "original.pdf", "wiki/content.md", "wiki/dependencies.json", "wiki/revision.json",
        }
        assert archive.read("original.pdf") == expected_original
        metadata = json.loads(archive.read("wiki/dependencies.json"))
        assert metadata["parent_manifest_ids"] == [str(parent.manifest_ref)]
        assert [(item["passage_id"], item["excerpt_revision"], item["version_id"]) for item in metadata["inputs"]] == [
            (str(markdown.passage_ref), markdown.revision, str(markdown_version.version_ref)),
            *((str(page.passage_ref), page.revision, str(pdf.version_ref)) for page in pages),
        ]
        assert {item["run_id"] for item in metadata["inputs"][1:]} == {str(run.run_ref)}
    for version in (pdf, markdown_version):
        inventory = plan(client, owner, version.version_ref)
        assert inventory.status_code == 200
        assert [copy["kind"] for copy in inventory.json()["copies"]].count("export") == 1
    pin = archive_rehearsal.ArchivePin(
        tenant.org_id, tenant.space_id, UUID(response.json()["package_id"]), sha256(payload).digest(),
    )
    scratch = tmp_path_factory.mktemp("wiki-pdf-stage")
    with rehearsal_clone(connection, database_url, postgres_server) as (_, staged, _):
        with archive_rehearsal.stage_original(staged, pin, payload, scratch) as material:
            assert material.scope == SCOPE and material.store.read(material.asset) == expected_original
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("change", ["archive_revocation", "dependent_hold"])
def test_wiki_archive_blocks_changes_to_an_inherited_pdf_even_with_markdown_anchor(pdf_wiki_bundle, change):
    client, db, owner, reviewer, authority, source, _, employee, markdown_version, _, pdf, _, pages, draft, *_ = pdf_wiki_bundle
    connection, tenant, *_ = db
    path = open_and_approve(client, owner, reviewer, markdown_version, draft)
    if change == "archive_revocation":
        source_revocations.revoke(authority, source.authority_ref, tenant.space_ref, employee,
                                  pages[-1].passage_ref, "archive", basis_ref=uuid4())
        expected = 403
    else:
        assert decide(client, reviewer, pdf.version_ref).status_code == 200
        expected = 409
    assert command(client, owner, path).status_code == expected
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_package").fetchone() == (0,)


def seal_mixed_rebuild(bundle, *, pdf_anchor=False):
    client, db, owner, reviewer, _, _, profile, employee, markdown, _, pdf, _, _, draft, *_ = bundle
    connection, tenant, *_ = db
    anchor = pdf if pdf_anchor else markdown
    path = open_and_approve(client, owner, reviewer, anchor, draft, scope="wiki_rebuild")
    private_json(profile.root / "rebuild-archive-grants.json", {str(employee): [str(anchor.version_ref)]})
    assert command(client, owner, path).status_code == 403
    private_json(profile.root / "rebuild-archive-grants.json", {
        str(employee): [str(markdown.version_ref), str(pdf.version_ref)],
    })
    response = command(client, owner, path)
    assert response.status_code == 200, response.text
    assert (response.json()["scope"], response.json()["restorable"]) == ("wiki_rebuild", False)
    export_ref = UUID(path.split("/")[1])
    payload, = connection.execute("SELECT archive_bytes FROM thalion.synthetic_export_package").fetchone()
    assert response.json()["archive_sha256"] == sha256(payload).hexdigest()
    pin = archive_rehearsal.WikiArchivePermit(
        tenant.org_id, tenant.space_id, export_ref, anchor.version_ref, draft.ref, sha256(payload).digest(),
    )
    return pin, payload


@pytest.mark.parametrize("pdf_anchor", [False, True])
def test_mixed_wiki_rebuild_preserves_pdf_pages_only_with_independent_checks(
    pdf_wiki_bundle, empty_rehearsal, rule_log, corpus, tmp_path, pdf_anchor,
):
    _, db, _, _, _, source, _, _, markdown, _, pdf, run, pages, draft, parent, _, _ = pdf_wiki_bundle
    authority, *_ = db
    target, _ = empty_rehearsal
    pin, payload = seal_mixed_rebuild(pdf_wiki_bundle, pdf_anchor=pdf_anchor)
    permit = archive_rehearsal.WikiRebuildPermit(pin, target.info.dbname)
    scratch = tmp_path / "rebuild"
    scratch.mkdir(mode=0o700)
    confirm_unrelated_stop(db, rule_log, version_ref=version_ref(authority, corpus[3]))
    kwargs = dict(authority=authority, log=rule_log, authority_ref=endpoint(authority), log_ref=endpoint(rule_log),
                  source_authority=source)

    with pytest.raises(archive_rehearsal.ArchiveRejected, match="checkpoint"):
        archive_rehearsal.verify_wiki_rebuild(pin, payload)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="checkpoint"):
        archive_rehearsal.rebuild_wiki(target, permit, payload, scratch)
    repacked = BytesIO(payload)
    with ZipFile(repacked, "a") as archive:
        archive.writestr("unexpected", "synthetic")
    forged = repacked.getvalue()
    with pytest.raises(archive_rehearsal.ArchiveRejected, match="exact sealed archive"):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(
            target, replace(permit, pin=replace(pin, digest=sha256(forged).digest())), forged, scratch, **kwargs,
        )
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert not any(scratch.iterdir())

    rebuilt = archive_rehearsal.rebuild_wiki_with_rule_checkpoint(target, permit, payload, scratch, **kwargs)
    assert rebuilt.revision_ref == draft.ref
    assert {ref: rebuilt.store.read(asset) for ref, asset in rebuilt.originals} == {
        version.version_ref: original(db, version).read_bytes() for version in (markdown, pdf)
    }
    ref, rebuilt_run, transcript, texts = target.execute("""
        SELECT version_ref, run_ref, transcription, page_transcripts FROM thalion.archive_pdf_rebuild
        """).fetchone()
    assert (ref, rebuilt_run) == (pdf.version_ref, run.run_ref)
    assert [(page["page"], page["passage_id"], page["excerpt_revision"], page["sha256"]) for page in transcript["pages"]] == [
        (number, str(item.passage_ref), item.revision, sha256(text).hexdigest())
        for number, (item, text) in enumerate(zip(pages, texts, strict=True), 1)
    ]
    assert texts == [PAGE_TEXT, PRIVATE]
    assert target.execute("SELECT run_ref <> %s FROM thalion.processing_run", (run.run_ref,)).fetchall() == [(True,)]
    assert target.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (0,)
    assert target.execute("SELECT count(*) FROM thalion.available_wiki_publication").fetchone() == (0,)
    assert target.execute("SELECT lifecycle FROM thalion.space").fetchone() == ("archived",)
    graph, = target.execute("SELECT manifest_graph FROM thalion.archive_wiki_rebuild").fetchone()
    assert str(parent.manifest_ref) in {node["manifest_id"] for node in graph["manifests"]}
    assert set(target.execute("SELECT version_ref FROM thalion.archive_rebuild_rule_check").fetchall()) == {
        (markdown.version_ref,), (pdf.version_ref,),
    }


@pytest.mark.parametrize(("change", "reason"), [
    ("page_revocation", "source revocation blocks"),
    ("hold", "hold blocks"),
    ("metadata", "metadata changed"),
])
def test_mixed_wiki_rebuild_blocks_changes_to_inherited_pdf(
    pdf_wiki_bundle, empty_rehearsal, rule_log, corpus, tmp_path, change, reason,
):
    client, db, _, reviewer, writer, source, _, employee, _, _, pdf, _, pages, *_ = pdf_wiki_bundle
    authority, tenant, *_ = db
    target, _ = empty_rehearsal
    pin, payload = seal_mixed_rebuild(pdf_wiki_bundle)
    confirm_unrelated_stop(db, rule_log, version_ref=version_ref(authority, corpus[3]))
    if change == "page_revocation":
        source_revocations.revoke(writer, source.authority_ref, tenant.space_ref, employee,
                                  pages[-1].passage_ref, "archive", basis_ref=uuid4())
    elif change == "hold":
        assert decide(client, reviewer, pdf.version_ref).status_code == 200
    else:
        authority.execute("""
            UPDATE thalion.document SET display_name = 'Changed PDF metadata after sealing'
            WHERE document_id = (
                SELECT document_id FROM thalion.synthetic_original_export_target WHERE version_ref = %s
            )
            """, (pdf.version_ref,))
    scratch = tmp_path / "rebuild"
    scratch.mkdir(mode=0o700)
    with pytest.raises(archive_rehearsal.ArchiveRejected, match=reason):
        archive_rehearsal.rebuild_wiki_with_rule_checkpoint(
            target, archive_rehearsal.WikiRebuildPermit(pin, target.info.dbname), payload, scratch,
            authority=authority, log=rule_log, authority_ref=endpoint(authority), log_ref=endpoint(rule_log),
            source_authority=source,
        )
    assert target.execute("SELECT count(*) FROM thalion.archive_pdf_rebuild").fetchone() == (0,)
    assert target.execute("SELECT count(*) FROM thalion.organization").fetchone() == (0,)
    assert not any(scratch.iterdir())


def test_pdf_wiki_rebuild_sql_requires_exact_publication(pdf_wiki_bundle):
    _, db, _, _, _, _, _, _, _, _, pdf, *_ = pdf_wiki_bundle
    connection, tenant, *_ = db
    request_ref = uuid4()
    configuration, = connection.execute(
        "SELECT config_revision FROM thalion.organization WHERE org_id = %s", (tenant.org_id,),
    ).fetchone()
    start_request(connection, RequestStart(
        tenant.org_id, request_ref, tenant.actor_id, None, "synthetic-ui", REQUEST, "internal_lifecycle",
        date(2026, 11, 23), configuration, space_id=tenant.space_id,
    ))
    with pytest.raises(errors.CheckViolation, match="all supported inputs"):
        connection.execute("""
            INSERT INTO thalion.synthetic_export_request (
                org_id, space_id, version_id, requester_id, snapshot, request_id, wiki_publication_ref, wiki_rebuild_digest
            )
            SELECT org_id, space_id, version_id, owner_id, snapshot, %s, %s, %s
            FROM thalion.synthetic_original_export_target WHERE version_ref = %s
            """, (request_ref, uuid4(), bytes(32), pdf.version_ref))
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_request").fetchone() == (0,)
