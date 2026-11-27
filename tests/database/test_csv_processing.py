from hashlib import sha256
import json
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import registry
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from test_disposition_cases import candidate
from test_effectivity import BEGIN, approve
from test_evidence import approved, claim, create_evidence_db, evidence_db, register_markdown, review
from test_evidence_transport import bearer, evidence_transport, transport
from test_identity import migrate_to_revision
from test_original_export import archive_fixture, request
from test_runtime import open_database, register_tenant, runtime_db
from test_sources import register
from test_travel_search import corpus


CSV = (
    '编号,限额（元/人·晚）,例外\r\n'
    '0017,600,"会议统一安排\r\n不得补报"\r\n'
    '17,0,\r\n'
).encode("utf-8")


def register_csv(db, payload=CSV, **changes):
    connection, tenant, _, source, store = db
    return register(connection, tenant, source, store, payload=payload, **({
        "digest": sha256(payload).digest(), "media_type": "text/csv",
    } | changes))


def csv_cells(db, version):
    connection, tenant, *_ = db
    return processing.list_approved_csv_cells(connection, tenant.org_id, tenant.space_id, version.version_ref)


def test_csv_original_and_logical_cells_are_pinned_to_an_independent_review(evidence_db):
    connection, tenant, _, _, store = evidence_db
    version = register_csv(evidence_db)
    replay = register_csv(evidence_db)
    assert not replay.created and replay.version_ref == version.version_ref
    with pytest.raises(registry.VersionConflict):
        register_csv(evidence_db, media_type="text/markdown", key="conflicting-original-type")

    media_type, storage_key = connection.execute("SELECT media_type, storage_key FROM thalion.asset").fetchone()
    assert (media_type, (store.root / storage_key).read_bytes()) == ("text/csv", CSV)
    lease = claim(evidence_db)
    with pytest.raises(processing.ProcessingNotAdmitted):
        processing.process_markdown_job(connection, lease, store)
    result = processing.process_evidence_job(connection, lease, store)
    assert (result.outcome, result.passage_count) == ("pending_review", 6)
    assert csv_cells(evidence_db, version) == ()
    with pytest.raises(processing.ProcessingNotAdmitted):
        review(evidence_db, result, principal_id=tenant.other_actor_id)
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, result, digest=bytes(32))

    review(evidence_db, result)
    cells = csv_cells(evidence_db, version)
    assert [(cell.record_number, cell.column_number, cell.revision) for cell in cells] == [
        (2, 1, 1), (2, 2, 1), (2, 3, 1), (3, 1, 1), (3, 2, 1), (3, 3, 1),
    ]
    material = json.dumps(("csv_cell.v1", "例外", "会议统一安排\r\n不得补报"), separators=(",", ":")).encode()
    assert cells[2].digest == sha256(material).digest()
    assert connection.execute("""
        SELECT count(*) FROM thalion.passage
        WHERE byte_start IS NULL AND byte_end IS NULL AND heading_path IS NULL AND paragraph IS NULL
    """).fetchone() == (6,)
    assert approved(evidence_db, version) == ()
    assert processing.list_approved_csv_cells(connection, tenant.org_id, tenant.space_id + 1000, version.version_ref) == ()
    with pytest.raises(errors.CheckViolation, match="format does not match"):
        connection.execute("""
            INSERT INTO thalion.passage (
                org_id, space_id, version_id, locator_revision, heading_path, paragraph, kind, byte_start, byte_end
            )
            SELECT org_id, space_id, version_id, 1, ARRAY['Wrong format'], 1, 'paragraph', 1, 2
            FROM thalion.document_version
        """)


def test_csv_reprocessing_preserves_cell_identity_without_reusing_approval(evidence_db):
    connection, tenant, _, _, store = evidence_db
    version = register_csv(evidence_db)
    first = processing.process_evidence_job(connection, claim(evidence_db), store)
    review(evidence_db, first)
    before = csv_cells(evidence_db, version)
    configuration, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT configuration_revision + 1, parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE configuration_revision = (
            SELECT configuration_revision FROM thalion.processing_run WHERE run_ref = %s
        ) RETURNING configuration_revision
    """, (first.run_ref,)).fetchone()
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, configuration))
    second = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert csv_cells(evidence_db, version) == ()
    review(evidence_db, second)
    after = csv_cells(evidence_db, version)
    assert [cell.passage_ref for cell in before] == [cell.passage_ref for cell in after]
    assert {cell.revision for cell in after} == {2}
    assert connection.execute("SELECT count(*) FROM thalion.passage_excerpt").fetchone() == (12,)
    review(evidence_db, second, decision="quarantined")
    assert csv_cells(evidence_db, version) == ()


def test_csv_rejects_bad_rows_and_does_not_partially_persist_on_event_failure(evidence_db):
    connection, _, _, _, store = evidence_db
    bad = register_csv(evidence_db, b"ID,Amount\r\n0017,600\r\n0018\r\n")
    invalid = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert (invalid.outcome, invalid.reason, invalid.passage_count) == ("quarantined", "unsupported_structure", 0)
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, invalid)
    good = register_csv(evidence_db, key="good-csv", source_version_key="rev-b")
    lease = claim(evidence_db)
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_csv_event
        CHECK (event_type <> 'evidence.candidate.recorded') NOT VALID
    """)
    with pytest.raises(errors.CheckViolation):
        processing.process_evidence_job(connection, lease, store)
    assert connection.execute("SELECT count(*) FROM thalion.passage").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (1,)
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_csv_event")
    result = processing.process_evidence_job(connection, lease, store)
    review(evidence_db, result)
    assert len(csv_cells(evidence_db, good)) == 6 and csv_cells(evidence_db, bad) == ()


def test_csv_storage_limit_allows_exact_boundary_without_partial_overflow(evidence_db):
    connection, _, _, _, store = evidence_db
    limit = processing.MAX_CSV_EVIDENCE_CELLS
    payload = b"ID\r\n" + b"0017\r\n" * limit
    oversized = register_csv(evidence_db, payload + b"0018\r\n")
    overflow = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert (overflow.outcome, overflow.reason, overflow.passage_count) == ("quarantined", "size_limit", 0)
    assert connection.execute("SELECT count(*) FROM thalion.passage").fetchone() == (0,)
    assert csv_cells(evidence_db, oversized) == ()

    allowed = register_csv(evidence_db, payload, key="at-csv-cell-limit", source_version_key="at-limit")
    candidate = processing.process_evidence_job(connection, claim(evidence_db), store)
    assert (candidate.outcome, candidate.passage_count) == ("pending_review", limit)
    review(evidence_db, candidate)
    cells = csv_cells(evidence_db, allowed)
    assert len(cells) == limit and (cells[-1].record_number, cells[-1].column_number) == (limit + 1, 1)


def test_approved_csv_cannot_enter_markdown_read_search_or_archive_format(archive_fixture):
    client, db, owner, _, _, _, _ = archive_fixture
    connection, tenant, _, _, store = db
    version = register_csv(
        db, key="csv-archive-original", object_key=str(uuid4()), source_version_key="csv-a",
    )
    result = processing.process_evidence_job(connection, claim(db), store)
    review(db, result)
    approve(connection, tenant, version, BEGIN)
    locator = csv_cells(db, version)[2]
    assert client.get(f"/v1/passages/{locator.passage_ref}", headers=bearer(owner)).status_code == 404
    reply = client.post("/v1/search", headers=bearer(owner), json={"query": "不得补报"})
    assert reply.status_code == 200 and reply.json()["passages"] == []
    assert request(client, owner, version).status_code == 403
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_export_request").fetchone() == (0,)


def test_csv_upgrade_preserves_existing_markdown_receipts_and_configuration(database_url, tmp_path):
    migrate_to_revision(database_url, "0050_gap_feedback_link")
    with open_database(database_url) as connection:
        db = create_evidence_db(connection, register_tenant(connection, "Migration fixture"), database_url, tmp_path)
        store = db[-1]
        version = register_markdown(db)
        run = processing.process_markdown_job(connection, claim(db), store)
        decision = review(db, run)
        locators = approved(db, version)
        connection.execute("""
            INSERT INTO thalion.processing_config_revision
                (configuration_revision, parser_version, profile, locator_revision)
            SELECT 3, parser_version, profile, locator_revision FROM thalion.processing_config_revision
            WHERE configuration_revision = 1
        """)
        assert upgrade(database_url) == ["0113_source_connector_cursor"]
        assert approved(db, version) == locators
        assert connection.execute("SELECT decision_ref FROM thalion.quality_decision").fetchone() == (decision,)
        register_csv(db, key="different-csv-version", source_version_key="csv-a")
        lease = claim(db)
        assert lease.spec.configuration_revision == 4
        assert processing.process_evidence_job(connection, lease, store).passage_count == 6
