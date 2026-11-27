from dataclasses import replace

import pytest
from psycopg import errors

from enterprise_kb.modules.evidence import csv_evidence, processing
from enterprise_kb.modules.sources import originals, registry
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from test_csv_processing import csv_cells, register_csv
from test_evidence import claim, review
from test_runtime import runtime_db
from test_sources import request_for


PAYLOAD = (
    "编码,限额,单位,适用情形,例外,备注\r\n"
    "0017,600,元/人·晚,普通员工,会议统一安排除外,不属于证据组\r\n"
    "0018,750,,普通员工,会议统一安排除外,不得补单位\r\n"
    "0019,待定,元/人·晚,普通员工,无,不是金额\r\n"
    "0020,0,元/人·晚,实习员工,无,保留零值\r\n"
).encode()


def enroll(connection, tenant, layout, *, key="csv-layout", source_key="travel-table"):
    context = request_for(connection, tenant, tenant.actor_id, key, "register_source_contract")
    return registry.register_synthetic_source(
        connection, context, tenant.space_id,
        registry.SyntheticSource(
            source_key, "travel-csv", tenant.worker_id, processor_id=tenant.other_worker_id,
            quality_reviewer_id=tenant.actor_id, approver_id=tenant.other_actor_id, csv_amount_layout=layout,
        ),
    )


@pytest.fixture
def amount_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    layout = csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外")
    source = enroll(connection, tenant, layout)
    return connection, tenant, database_url, source, originals.SyntheticOriginalStore(tmp_path)


def units(db, version):
    connection, tenant, *_ = db
    return processing.list_approved_csv_units(connection, tenant.org_id, tenant.space_id, version.version_ref)


def process(db, payload=PAYLOAD, **changes):
    connection, _, _, _, store = db
    version = register_csv(db, payload, **changes)
    return version, processing.process_evidence_job(connection, claim(db), store)


def test_only_independently_approved_complete_rows_become_evidence_units(amount_db):
    connection, tenant, *_ = amount_db
    version, candidate = process(amount_db)
    assert units(amount_db, version) == ()
    with pytest.raises(processing.ProcessingNotAdmitted):
        review(amount_db, candidate, principal_id=tenant.other_actor_id)
    review(amount_db, candidate)
    assert connection.execute("""
        SELECT record_number, reason FROM thalion.evidence_unit ORDER BY record_number
    """).fetchall() == [(2, None), (3, "missing_value"), (4, "invalid_amount"), (5, None)]
    populated = units(amount_db, version)
    assert [unit.record_number for unit in populated] == [2, 5]
    cells = {(cell.record_number, cell.column_number): cell for cell in csv_cells(amount_db, version)}
    for unit in populated:
        assert {member.role: member.cell for member in unit.members} == {
            role: cells[(unit.record_number, column)]
            for column, role in enumerate(("amount", "unit", "condition", "exception"), start=2)
        }
    assert processing.list_approved_csv_units(
        connection, tenant.org_id, tenant.space_id + 1000, version.version_ref,
    ) == ()
    with pytest.raises(errors.CheckViolation, match="manifest is not open"):
        connection.execute("""
            INSERT INTO thalion.evidence_unit (run_ref, record_number, reason)
            VALUES (%s, 999, 'missing_value')
        """, (candidate.run_ref,))
    review(amount_db, candidate, decision="quarantined")
    assert units(amount_db, version) == ()


def test_required_column_is_not_inferred_and_source_layout_cannot_change_on_replay(amount_db):
    connection, tenant, *_ = amount_db
    layout = csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外")
    assert enroll(connection, tenant, layout) == amount_db[3]
    with pytest.raises(registry.VersionConflict):
        enroll(connection, tenant, replace(layout, unit="备注"), key="changed-layout")
    without_unit_header = PAYLOAD.decode().replace(",单位,", ",未声明单位,").encode()
    version, candidate = process(amount_db, without_unit_header)
    review(amount_db, candidate)
    assert units(amount_db, version) == ()
    assert connection.execute("""
        SELECT DISTINCT reason FROM thalion.evidence_unit
    """).fetchall() == [("missing_column",)]
    assert len(csv_cells(amount_db, version)) == 24


def test_reprocessing_replaces_the_whole_unit_without_reusing_members_or_approval(amount_db):
    connection, tenant, _, _, store = amount_db
    version, candidate = process(amount_db)
    review(amount_db, candidate)
    original = units(amount_db, version)
    configuration, = connection.execute("""
        INSERT INTO thalion.processing_config_revision (configuration_revision, parser_version, profile, locator_revision)
        SELECT configuration_revision + 1, parser_version, profile, locator_revision
        FROM thalion.processing_config_revision WHERE configuration_revision = (
            SELECT configuration_revision FROM thalion.processing_run WHERE run_ref = %s
        ) RETURNING configuration_revision
    """, (candidate.run_ref,)).fetchone()
    enqueue_job(connection, JobSpec(
        tenant.org_id, tenant.space_id, version.version_ref, "parse", version.digest, configuration,
    ))
    replacement = processing.process_evidence_job(connection, claim(amount_db), store)
    assert units(amount_db, version) == ()
    with pytest.raises(processing.QualityConflict):
        review(amount_db, replacement, digest=candidate.manifest_digest)
    review(amount_db, replacement)
    current = units(amount_db, version)
    assert {unit.unit_ref for unit in original}.isdisjoint(unit.unit_ref for unit in current)
    assert {member.cell.revision for unit in current for member in unit.members} == {2}
    assert connection.execute("SELECT count(*) FROM thalion.evidence_unit_member").fetchone() == (16,)
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.evidence_unit_member SET role = 'unit' WHERE role = 'amount'")


def test_csv_without_declared_layout_preserves_cells_but_never_proposes_a_group(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    source = enroll(connection, tenant, None)
    db = (connection, tenant, database_url, source, originals.SyntheticOriginalStore(tmp_path))
    version, candidate = process(db)
    review(db, candidate)
    assert len(csv_cells(db, version)) == 24
    assert units(db, version) == ()
    assert connection.execute("SELECT count(*) FROM thalion.evidence_unit").fetchone() == (0,)


def test_csv_unit_must_seal_all_required_members_or_rollback_the_entire_run(amount_db, monkeypatch):
    connection, _, _, _, store = amount_db
    version = register_csv(amount_db, PAYLOAD)
    lease = claim(amount_db)
    write_unit = processing._write_csv_unit

    def drop_exception(transaction, run_ref, unit):
        if unit.reason is None:
            unit = replace(unit, columns=unit.columns[:-1])
        return write_unit(transaction, run_ref, unit)

    with monkeypatch.context() as patch:
        patch.setattr(processing, "_write_csv_unit", drop_exception)
        with pytest.raises(errors.CheckViolation, match="all four required members together"):
            processing.process_evidence_job(connection, lease, store)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.passage").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM thalion.evidence_unit").fetchone() == (0,)
    candidate = processing.process_evidence_job(connection, lease, store)
    review(amount_db, candidate)
    assert len(units(amount_db, version)) == 2
