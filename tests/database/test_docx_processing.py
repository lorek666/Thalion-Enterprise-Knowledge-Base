from dataclasses import replace
from hashlib import sha256

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import registry
from enterprise_kb.modules.sources.originals import OriginalIntegrityError
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from docx_fixture import CORE_REL, DOCUMENT, DOCUMENT_RELS, ROOT_RELS, SETTINGS_REL, STYLES, TEMPLATE_STYLES, docx_package, template_package
from test_disposition_cases import candidate
from test_effectivity import BEGIN, approve
from test_evidence import approved, claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, transport
from test_original_export import archive_fixture, command, request
from test_pdf_delivery import permit
from test_persisted_access import set_rules
from test_runtime import runtime_db
from test_sources import register
from test_travel_search import corpus


DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def register_docx(db, payload, **changes):
    connection, tenant, _, source, store = db
    return register(connection, tenant, source, store, payload=payload, **({
        "digest": sha256(payload).digest(), "media_type": DOCX_TYPE,
    } | changes))


def docx_locators(db, version):
    connection, tenant, *_ = db
    return processing.list_approved_docx_paragraphs(connection, tenant.org_id, tenant.space_id, version.version_ref)


def test_docx_preserves_original_and_only_projects_independently_approved_exact_locations(evidence_db):
    connection, tenant, _, _, store = evidence_db
    payload = docx_package()
    version = register_docx(evidence_db, payload)
    replay = register_docx(evidence_db, payload)
    assert not replay.created and replay.version_ref == version.version_ref
    with pytest.raises(registry.VersionConflict):
        register_docx(evidence_db, payload, media_type="text/markdown", key="conflicting-media")
    media_type, key = connection.execute("SELECT media_type, storage_key FROM thalion.asset").fetchone()
    assert (media_type, (store.root / key).read_bytes()) == (DOCX_TYPE, payload)

    run = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert (run.outcome, run.passage_count) == ("pending_review", 2)
    assert docx_locators(evidence_db, version) == ()
    with pytest.raises(processing.ProcessingNotAdmitted):
        review(evidence_db, run, principal_id=tenant.other_actor_id)
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, run, digest=bytes(32))
    review(evidence_db, run)
    first, second = docx_locators(evidence_db, version)
    assert (first.heading_path, first.paragraph, first.document_paragraph, first.revision) == (("差旅", "住宿"), 1, 3, 1)
    assert (second.heading_path, second.paragraph, second.document_paragraph) == (("差旅", "住宿"), 1, 5)
    assert first.passage_ref != second.passage_ref
    assert processing.resolve_docx_paragraph(payload, first) == "不得报销\t除非书面批准\n按实际金额。".encode()
    with pytest.raises(OriginalIntegrityError):
        processing.resolve_docx_paragraph(payload, replace(first, document_paragraph=5))
    assert approved(evidence_db, version) == ()
    assert processing.list_approved_docx_paragraphs(connection, tenant.org_id, tenant.space_id + 1000, version.version_ref) == ()
    with pytest.raises(errors.CheckViolation, match="format does not match"):
        connection.execute("""
            INSERT INTO thalion.passage (
                org_id, space_id, version_id, locator_revision, heading_path, paragraph, kind, byte_start, byte_end
            )
            SELECT org_id, space_id, version_id, 1, ARRAY['Wrong format'], 1, 'paragraph', 1, 2
            FROM thalion.document_version
        """)


def test_docx_reprocessing_reuses_only_locator_identity_and_requires_review(evidence_db):
    connection, tenant, _, _, store = evidence_db
    version = register_docx(evidence_db, docx_package())
    first = processing.process_evidence_job(connection, claim(evidence_db), store)
    review(evidence_db, first)
    before = docx_locators(evidence_db, version)
    configuration, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT (SELECT max(configuration_revision) + 1 FROM thalion.processing_config_revision),
               parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE configuration_revision = (
            SELECT configuration_revision FROM thalion.processing_run WHERE run_ref = %s
        ) RETURNING configuration_revision
    """, (first.run_ref,)).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, configuration))
    second = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert docx_locators(evidence_db, version) == ()
    review(evidence_db, second)
    assert docx_locators(evidence_db, version) == tuple(replace(part, revision=2) for part in before)
    review(evidence_db, second, decision="quarantined")
    assert docx_locators(evidence_db, version) == ()


def test_docx_default_template_relations_and_equal_outline_effects_are_admitted(evidence_db):
    connection, _, _, _, store = evidence_db
    version = register_docx(evidence_db, template_package())
    run = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert (run.outcome, run.passage_count) == ("pending_review", 2)
    review(evidence_db, run)
    assert [part.heading_path for part in docx_locators(evidence_db, version)] == [("差旅", "住宿"), ("差旅", "住宿")]


def test_docx_candidate_and_exact_identity_roll_back_with_the_outbox(evidence_db):
    connection, _, _, _, store = evidence_db
    version = register_docx(evidence_db, docx_package())
    lease = claim(evidence_db)
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_docx_event
        CHECK (event_type <> 'evidence.candidate.recorded') NOT VALID
    """)
    with pytest.raises(errors.CheckViolation):
        processing.process_evidence_job(connection, lease, store)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.object_identity WHERE object_type = 'passage'").fetchone() == (0,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_docx_event")
    run = processing.process_evidence_job(connection, lease, store)
    review(evidence_db, run)
    assert len(docx_locators(evidence_db, version)) == 2


def test_docx_employee_read_grant_does_not_grant_archive_access(archive_fixture):
    client, db, owner, _, _, _, _ = archive_fixture
    connection, tenant, _, _, store = db
    version = register_docx(db, docx_package(), key="isolated-docx", object_key="isolated-docx")
    run = processing.process_evidence_job(connection, claim(db), store)
    review(db, run)
    approve(connection, tenant, version, BEGIN)
    first, _ = docx_locators(db, version)
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).status_code == 404
    reply = client.post("/v1/search", headers=bearer(owner), json={"query": "书面批准"})
    assert reply.status_code == 200 and reply.json()["passages"] == []
    set_rules(db, permit(tenant.actor_id, first.passage_ref), expected=2)
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).status_code == 200
    opened = request(client, owner, version)
    assert opened.status_code == 200
    assert command(client, owner, f"/{opened.json()['export_id']}/seal").status_code == 409


@pytest.mark.parametrize(("payload", "reason"), [
    (b"Not a Word document", "unsupported_structure"),
    (docx_package(DOCUMENT.replace("<w:sectPr/>", "<w:tbl><w:tr/></w:tbl><w:sectPr/>")), "unsupported_structure"),
    (docx_package(DOCUMENT.replace("<w:t>不得", "<w:rPr><w:vanish/></w:rPr><w:t>不得")), "unsupported_structure"),
    (docx_package(styles=STYLES.replace('<w:outlineLvl w:val="1"/>', '<w:numPr/>')), "unsupported_structure"),
    (docx_package(document_rels=DOCUMENT_RELS.replace('Target="styles.xml"', 'Target="https://example.invalid/styles.xml" TargetMode="External"')), "unsupported_structure"),
    (docx_package("<!DOCTYPE doc>" + DOCUMENT), "unsupported_structure"),
    (docx_package(extra={"WORD/DOCUMENT.XML": "ambiguous"}), "unsupported_structure"),
    (docx_package(extra={"word/oversized.xml": " " * (8 * 1024 * 1024)}), "size_limit"),
    (docx_package(root_rels=ROOT_RELS.replace("</Relationships>", CORE_REL + "</Relationships>")), "unsupported_structure"),
    (docx_package(document_rels=DOCUMENT_RELS.replace("</Relationships>", SETTINGS_REL + "</Relationships>"),
                  extra={"word/settings.xml": "not XML"}), "unsupported_structure"),
    (template_package(effects=TEMPLATE_STYLES.replace('outlineLvl w:val="1"', 'outlineLvl w:val="2"')), "unsupported_structure"),
], ids=["corrupt", "table", "hidden-run", "inherited-numbering", "external-part", "xml-dtd", "duplicate-part", "expanded-size",
        "missing-related-part", "malformed-related-part", "conflicting-outline"])
def test_docx_invalid_or_unsupported_content_is_quarantined_as_a_whole(evidence_db, payload, reason):
    connection, _, _, _, store = evidence_db
    version = register_docx(evidence_db, payload)
    run = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert (run.outcome, run.reason, run.passage_count) == ("quarantined", reason, 0)
    assert connection.execute("SELECT count(*) FROM thalion.passage").fetchone() == (0,)
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, run)
    assert docx_locators(evidence_db, version) == ()
