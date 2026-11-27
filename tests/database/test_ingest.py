from dataclasses import replace
from hashlib import sha256
import pytest
from psycopg import errors

from enterprise_kb.modules.sources import ingest, registry
from enterprise_kb.runtime.commands import IdempotencyConflict

from docx_fixture import docx_package
from test_evidence import evidence_db
from test_pdf_processing import pdf_document, text_page
from test_runtime import runtime_db
from test_sources import CONTENT, OTHER_CONTENT, request_for


MARKDOWN = b"# Synthetic travel rules\n\nBook rail tickets in advance.\n"


@pytest.fixture
def source(evidence_db):
    connection, tenant, _, source_ref, store = evidence_db
    return connection, tenant, source_ref, store


def item(payload, **changes):
    return replace(
        ingest.IngestFile(
            "Synthetic travel rules", "A", "policy-23", "first", "rev-a", payload,
        ),
        **changes,
    )


def run(source, *files, key="batch-key", actor_id=None):
    connection, tenant, source_ref, store = source
    context = request_for(connection, tenant, tenant.worker_id, key, "register_version")
    return ingest.ingest_batch(connection, context, tenant.space_id, source_ref, tuple(files), store, actor_id=actor_id)


def other_source(source):
    connection, tenant, _, store = source
    context = request_for(connection, tenant, tenant.actor_id, "other-source", "register_source_contract")
    source_ref = registry.register_synthetic_source(
        connection, context, tenant.space_id,
        registry.SyntheticSource("other-files", "other-archive", tenant.worker_id),
    )
    return connection, tenant, source_ref, store


def test_mixed_batch_registers_each_file_and_reports_its_own_status(source):
    connection, tenant, _, store = source
    pdf = pdf_document(text_page(b"Travel allowance 600 CNY"))
    docx = docx_package()
    outcomes = run(
        source,
        item(MARKDOWN, object_key="policy-23", source_version_key="rev-a"),
        item(pdf, display_name="Travel PDF", object_key="policy-24", source_version_key="rev-pdf"),
        item(docx, display_name="Travel DOCX", object_key="policy-25", source_version_key="rev-docx"),
    )
    assert [out.status for out in outcomes] == ["registered"] * 3
    assert [out.media_type for out in outcomes] == [
        "text/markdown", "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]
    assert [out.digest for out in outcomes] == [sha256(value).digest() for value in (MARKDOWN, pdf, docx)]
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (3,)
    assert connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone() == (3,)
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_batch").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_item").fetchone() == (3,)
    assert sorted(path.read_bytes() for path in store.root.iterdir()) == sorted((MARKDOWN, pdf, docx))


def test_duplicate_upload_points_to_the_existing_version_and_does_not_copy_rights(source):
    connection, _, _, _ = source
    first, = run(source, item(MARKDOWN))
    repeated, = run(source, item(MARKDOWN, display_name="Renamed file"), key="second")
    assert (first.status, repeated.status) == ("registered", "duplicate")
    assert (first.document_ref, first.version_ref) == (repeated.document_ref, repeated.version_ref)
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone() == (0,)


def test_same_label_with_different_content_needs_a_confirmed_new_version(source):
    connection, _, _, _ = source
    first, = run(source, item(CONTENT), key="first")
    blocked, = run(source, item(OTHER_CONTENT, source_version_key="rev-a2"), key="second")
    assert blocked.status == "needs_confirmation"
    assert blocked.reason == "version_label_changed_content"
    assert (blocked.document_ref, blocked.version_ref) == (first.document_ref, first.version_ref)
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)

    unconfirmed, = run(source, item(
        OTHER_CONTENT, version_label="B", source_version_key="rev-b",
    ), key="unconfirmed")
    assert unconfirmed.status == "needs_confirmation"
    assert unconfirmed.version_ref == first.version_ref

    confirmed, = run(source, item(
        OTHER_CONTENT, version_label="B", source_version_key="rev-b", confirm_new_version=True,
    ), key="third")
    assert confirmed.status == "registered" and confirmed.document_ref == first.document_ref
    assert confirmed.version_ref != first.version_ref
    assert connection.execute("""
        SELECT version_label, registration_sequence FROM thalion.document_version ORDER BY registration_sequence
    """).fetchall() == [("A", 1), ("B", 2)]


def test_confirmation_cannot_reuse_the_same_label_or_version_key(source):
    connection, _, _, _ = source
    run(source, item(CONTENT))
    assert run(source, item(OTHER_CONTENT, confirm_new_version=True), key="second")[0].status == "needs_confirmation"
    assert run(source, item(
        OTHER_CONTENT, source_version_key="rev-a2", confirm_new_version=True,
    ), key="alternate")[0].reason == "version_label_changed_content"
    assert run(source, item(
        OTHER_CONTENT, version_label="B", confirm_new_version=True,
    ), key="third")[0].reason == "version_key_changed_content"
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)


def test_one_bad_file_does_not_roll_back_the_rest_of_the_batch(source):
    connection, _, _, _ = source
    outcomes = run(
        source,
        item(b"not a supported document \xff", object_key="bad", source_version_key="bad-rev"),
        item(MARKDOWN),
        item(b"", display_name="Empty file", object_key="empty", source_version_key="empty-rev"),
    )
    assert [out.status for out in outcomes] == ["rejected", "registered", "rejected"]
    assert outcomes[0].reason == "unsupported_media" and outcomes[2].reason == "empty"
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)


def test_batch_replay_is_idempotent_and_does_not_create_duplicate_versions(source):
    connection, _, _, _ = source
    first = run(source, item(CONTENT))
    replay = run(source, item(CONTENT))
    assert [(out.status, out.version_ref) for out in replay] == [
        ("registered", first[0].version_ref),
    ]
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone() == (1,)


def test_same_batch_key_with_changed_file_is_rejected(source):
    connection, _, _, _ = source
    run(source, item(CONTENT))
    with pytest.raises(IdempotencyConflict):
        run(source, item(OTHER_CONTENT))
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)


def test_same_actor_key_is_bound_to_the_requested_source(source):
    connection, tenant, _, _ = source
    second = other_source(source)
    first = run(source, item(CONTENT), actor_id=tenant.actor_id)
    with pytest.raises(IdempotencyConflict):
        run(second, item(CONTENT), actor_id=tenant.actor_id)
    assert run(source, item(CONTENT), actor_id=tenant.actor_id) == first
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_batch").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)


def test_different_actor_batches_do_not_share_collector_command_keys(source):
    connection, tenant, _, _ = source
    second = other_source(source)
    first, = run(source, item(CONTENT), actor_id=tenant.actor_id)
    separate, = run(second, item(CONTENT), actor_id=tenant.other_actor_id)
    assert first.status == separate.status == "registered"
    assert first.version_ref != separate.version_ref
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_batch").fetchone() == (2,)
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (2,)


def test_bad_metadata_is_rejected_per_file(source):
    connection, _, _, _ = source
    outcomes = run(
        source,
        item(MARKDOWN, display_name=" "),
        item(MARKDOWN, object_key="../escape", source_version_key="rev-2"),
        item(MARKDOWN, object_key="policy-2", source_version_key="rev-3"),
    )
    assert [out.status for out in outcomes] == ["rejected", "rejected", "registered"]
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (1,)


def test_batch_limits_are_rejected_before_any_write(source):
    connection, _, _, _ = source
    with pytest.raises(ingest.BatchNotAdmitted):
        run(source, *[item(MARKDOWN, object_key=f"policy-{index}", source_version_key=f"rev-{index}")
                      for index in range(21)])
    with pytest.raises(ingest.BatchNotAdmitted):
        run(source, item(b"x" * (ingest.MAX_BATCH_BYTES + 1)))
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (0,)


def test_recorded_batch_and_item_results_cannot_be_rewritten(source):
    connection, _, _, _ = source
    run(source, item(MARKDOWN))
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.source_ingest_batch SET input_digest = %s", (b"\0" * 32,))
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.source_ingest_item SET status = 'registered'")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.source_ingest_item")


def test_unadmitted_collector_cannot_ingest(source):
    connection, tenant, source_ref, store = source
    outsider = request_for(connection, tenant, tenant.other_worker_id, "bad-ingest", "register_version")
    with pytest.raises(registry.SourceNotAdmitted):
        ingest.ingest_batch(connection, outsider, tenant.space_id, source_ref, (item(CONTENT),), store)
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (0,)
