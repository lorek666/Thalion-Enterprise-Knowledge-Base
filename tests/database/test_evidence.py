from dataclasses import replace
from hashlib import sha256
from uuid import uuid4

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity, originals, registry
from enterprise_kb.runtime.events import pending_events
from enterprise_kb.runtime.jobs import JobSpec, LeaseLost, claim_job, enqueue_job

from test_external_calls import expire
from test_runtime import LEASE_FOR, open_database, runtime_db
from test_sources import register, request_for


CONTENT = b"# Travel\r\n\r\nDo not reimburse without written approval.\r\n"


@pytest.fixture
def evidence_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    return create_evidence_db(connection, tenant, database_url, tmp_path)


def create_evidence_db(connection, tenant, database_url, tmp_path, **contract_roles):
    context = request_for(
        connection, tenant, tenant.actor_id, "create-evidence-source", "register_source_contract",
    )
    source = registry.register_synthetic_source(
        connection, context, tenant.space_id,
        registry.SyntheticSource(
            "travel", "travel-archive", tenant.worker_id,
            approver_id=tenant.other_actor_id, processor_id=tenant.other_worker_id,
            quality_reviewer_id=tenant.actor_id, **contract_roles,
        ),
    )
    return connection, tenant, database_url, source, originals.SyntheticOriginalStore(tmp_path)


def register_markdown(db, *, payload=CONTENT):
    connection, tenant, _, source, store = db
    return register(connection, tenant, source, store, payload=payload, digest=sha256(payload).digest())


def claim(db, *, worker_id=None):
    connection, tenant, *_ = db
    return claim_job(connection, tenant.org_id, "parse", worker_id or tenant.other_worker_id, LEASE_FOR)


def review(db, run, *, principal_id=None, decision="approved", digest=None):
    connection, tenant, *_ = db
    context = request_for(
        connection, tenant, principal_id or tenant.actor_id, str(uuid4()), "decide_evidence_quality",
    )
    return processing.decide_quality(
        connection, context, tenant.space_id, run.run_ref,
        digest or run.manifest_digest, decision, uuid4(),
    )


def approved(db, version):
    connection, tenant, *_ = db
    return processing.list_approved_passages(
        connection, tenant.org_id, tenant.space_id, version.version_ref,
    )


def test_worker_stages_exact_location_and_quality_is_separate(evidence_db):
    connection, tenant, _, _, store = evidence_db
    version = register_markdown(evidence_db)
    lease = claim(evidence_db)
    run = processing.process_markdown_job(connection, lease, store)
    assert (run.outcome, run.passage_count) == ("pending_review", 1)
    assert approved(evidence_db, version) == ()
    assert connection.execute(
        "SELECT state, result_ref FROM thalion.job WHERE job_id = %s", (lease.job_id,),
    ).fetchone() == ("succeeded", run.run_ref)
    with pytest.raises(processing.ProcessingNotAdmitted):
        review(evidence_db, run, principal_id=tenant.other_actor_id)
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, run, digest=bytes(32))
    review(evidence_db, run)
    passage, = approved(evidence_db, version)
    assert (passage.heading_path, passage.paragraph, passage.revision) == (("Travel",), 1, 1)
    assert CONTENT[passage.byte_start:passage.byte_end] == b"Do not reimburse without written approval.\r\n"
    assert passage.digest == sha256(CONTENT[passage.byte_start:passage.byte_end]).digest()
    assert {event.event_type for event in pending_events(connection, tenant.org_id, "test")} == {
        "sources.version.registered", "evidence.candidate.recorded", "evidence.quality.decided",
    }
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.passage_excerpt SET content_digest = %s", (bytes(32),))


def test_reprocessing_preserves_ref_and_old_revision_but_requires_current_review(evidence_db):
    connection, tenant, _, _, store = evidence_db
    version = register_markdown(evidence_db)
    first = processing.process_markdown_job(connection, claim(evidence_db), store)
    review(evidence_db, first)
    initial, = approved(evidence_db, version)
    connection.execute(
        """
        INSERT INTO thalion.processing_config_revision
            (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
        """
    )
    enqueue_job(connection, JobSpec(
        tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, 2,
    ))
    replacement = processing.process_markdown_job(connection, claim(evidence_db), store)
    assert approved(evidence_db, version) == ()
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, first)
    review(evidence_db, replacement)
    current, = approved(evidence_db, version)
    assert (current.passage_ref, current.digest, current.revision) == (
        initial.passage_ref, initial.digest, 2,
    )
    assert connection.execute(
        "SELECT excerpt_revision FROM thalion.passage_excerpt ORDER BY excerpt_revision"
    ).fetchall() == [(1,), (2,)]


def test_quarantine_retracts_approved_locators_and_cannot_be_reopened(evidence_db):
    connection, _, _, _, store = evidence_db
    version = register_markdown(evidence_db)
    run = processing.process_markdown_job(connection, claim(evidence_db), store)
    review(evidence_db, run)
    assert len(approved(evidence_db, version)) == 1
    review(evidence_db, run, decision="quarantined")
    assert approved(evidence_db, version) == ()
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, run)
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision").fetchone() == (2,)


def test_run_cannot_reference_another_versions_task(evidence_db):
    connection, tenant, _, _, _ = evidence_db
    first = register_markdown(evidence_db)
    lease = claim(evidence_db)
    _, _, _, source, store = evidence_db
    other = register(
        connection, tenant, source, store, key="second-version", source_version_key="second",
        payload=CONTENT, digest=first.digest,
    )
    with pytest.raises(errors.CheckViolation):
        connection.execute(
            """
            INSERT INTO thalion.processing_run (
                org_id, space_id, version_id, contract_revision, job_id, generation,
                configuration_revision, input_digest, manifest_digest, outcome, reason, passage_count
            )
            SELECT org_id, space_id, object_id, 1, %s, %s, 1, %s, %s, 'quarantined', 'empty', 0
            FROM thalion.object_identity WHERE public_id = %s
            """,
            (lease.job_id, lease.generation, first.digest, first.digest, other.version_ref),
        )


def test_approved_run_cannot_gain_unreviewed_excerpts(evidence_db):
    connection, _, _, _, store = evidence_db
    version = register_markdown(evidence_db, payload=CONTENT + b"\r\nSecond paragraph.\r\n")
    run = processing.process_markdown_job(connection, claim(evidence_db), store)
    review(evidence_db, run)
    connection.execute(
        """
        DO $$
        DECLARE original thalion.passage%ROWTYPE;
        DECLARE new_passage bigint;
        BEGIN
            SELECT * INTO original FROM thalion.passage ORDER BY passage_id LIMIT 1;
            INSERT INTO thalion.passage (
                org_id, space_id, version_id, locator_revision, byte_start, byte_end,
                heading_path, paragraph, kind
            ) VALUES (original.org_id, original.space_id, original.version_id, 2,
                original.byte_start, original.byte_end, original.heading_path, original.paragraph, original.kind
            ) RETURNING passage_id INTO new_passage;
            INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id)
            VALUES (original.org_id, original.space_id, 'passage', new_passage);
        END;
        $$
        """
    )
    with pytest.raises(errors.CheckViolation):
        connection.execute(
            """
            INSERT INTO thalion.passage_excerpt (
                org_id, space_id, version_id, passage_id, excerpt_revision, run_ref, content_digest
            )
            SELECT passage.org_id, passage.space_id, passage.version_id, passage.passage_id, 1, %s, %s
            FROM thalion.passage AS passage WHERE passage.locator_revision = 2
            """,
            (run.run_ref, bytes(32)),
        )
    assert len(approved(evidence_db, version)) == 2


def test_mismatched_manifest_count_rolls_back_the_processing_run(evidence_db, monkeypatch):
    connection, _, _, _, store = evidence_db
    register_markdown(evidence_db)
    lease = claim(evidence_db)
    monkeypatch.setattr(processing, "_write_passage", lambda *args: None)
    with pytest.raises(errors.CheckViolation):
        processing.process_markdown_job(connection, lease, store)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert connection.execute(
        "SELECT state, result_ref FROM thalion.job WHERE job_id = %s", (lease.job_id,),
    ).fetchone() == ("running", None)


def test_quarantined_markdown_cannot_be_approved_or_publish_a_partial_passage(evidence_db):
    connection, _, _, _, store = evidence_db
    version = register_markdown(evidence_db, payload=b"# Travel\n\nValid paragraph.\n\n<!-- hidden -->\n")
    run = processing.process_markdown_job(connection, claim(evidence_db), store)
    assert (run.outcome, run.reason, run.passage_count) == ("quarantined", "unsupported_structure", 0)
    with pytest.raises(processing.QualityConflict):
        review(evidence_db, run)
    assert approved(evidence_db, version) == ()
    assert connection.execute("SELECT count(*) FROM thalion.passage").fetchone() == (0,)


def test_wrong_worker_never_opens_original(evidence_db, monkeypatch):
    connection, tenant, _, _, store = evidence_db
    register_markdown(evidence_db)
    lease = claim(evidence_db, worker_id=tenant.worker_id)
    monkeypatch.setattr(store, "read", lambda _: pytest.fail("invalid worker reached original bytes"))
    with pytest.raises(processing.ProcessingNotAdmitted):
        processing.process_markdown_job(connection, lease, store)


def test_expired_lease_cannot_commit_a_result_after_parsing(evidence_db, monkeypatch):
    connection, _, database_url, _, store = evidence_db
    register_markdown(evidence_db)
    lease = claim(evidence_db)
    parse = processing.parse_markdown

    def parse_then_expire(payload):
        assert connection.info.transaction_status.name == "IDLE"
        with open_database(database_url) as other:
            expire(other, lease)
        return parse(payload)

    monkeypatch.setattr(processing, "parse_markdown", parse_then_expire)
    with pytest.raises(LeaseLost):
        processing.process_markdown_job(connection, lease, store)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.passage").fetchone() == (0,)


def test_source_stop_while_parsing_blocks_the_commit(evidence_db, monkeypatch):
    connection, tenant, database_url, _, store = evidence_db
    version = register_markdown(evidence_db)
    lease = claim(evidence_db)
    parse = processing.parse_markdown
    context = request_for(
        connection, tenant, tenant.other_actor_id, "withdraw-during-parse", "stop_rule_use",
    )

    def parse_then_withdraw(payload):
        with open_database(database_url) as other:
            effectivity.stop_synthetic_rule(
                other, context, tenant.space_id, version.version_ref, "withdrawn", uuid4(),
            )
        return parse(payload)

    monkeypatch.setattr(processing, "parse_markdown", parse_then_withdraw)
    with pytest.raises(processing.ProcessingNotAdmitted):
        processing.process_markdown_job(connection, lease, store)
    assert approved(evidence_db, version) == ()
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)


def test_unavailable_original_is_not_treated_as_a_successful_parse(evidence_db):
    connection, _, _, _, store = evidence_db
    register_markdown(evidence_db)
    original, = store.root.iterdir()
    original.unlink()
    lease = claim(evidence_db)
    with pytest.raises(originals.OriginalIntegrityError):
        processing.process_markdown_job(connection, lease, store)
    assert connection.execute(
        "SELECT state, result_ref FROM thalion.job WHERE job_id = %s", (lease.job_id,),
    ).fetchone() == ("running", None)
