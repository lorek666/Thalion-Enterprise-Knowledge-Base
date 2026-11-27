from dataclasses import replace
import json
from uuid import UUID

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import originals, registry
from enterprise_kb.modules.wiki import drafts

from test_csv_delivery import permit
from test_csv_linked_exceptions import TABLE, linked_layout, prepare
from test_csv_processing import csv_cells, register_csv
from test_csv_units import enroll, process, units
from test_csv_wiki import exact, role_rules, withhold
from test_effectivity import BEGIN, approve
from test_evidence import claim, review
from test_identity import migrate_to_revision
from test_persisted_access import authority_for, set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_travel_search import search
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble
from test_wiki_publication import authorize


ALTERNATES = (None, "计价单位", None, "例外副本")
TABLE_WITH_ALTERNATES = (
    "金额,单位,条件,例外,脚注引用,脚注键,计价单位,例外副本,未声明列\n"
    "600,元/晚,普通员工,,meeting,,元/晚,,元/晚\n"
    "750,元/晚,驻点员工,,meeting,,美元/晚,,元/晚\n"
    ",,,会议统一安排除外,,meeting,,会议统一安排除外,\n"
    "300,元/晚,实习员工,无,,,元/晚 ,无,元/晚\n"
    "301,元/晚,其他员工,无,,,,,元/晚\n"
    "302,,欠缺单位,无,,,元/晚,,元/晚\n"
).encode()


@pytest.fixture
def alternate_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    source = enroll(connection, tenant, replace(linked_layout(), alternate_columns=ALTERNATES))
    return connection, tenant, database_url, source, originals.SyntheticOriginalStore(tmp_path)


def publish_table(db):
    connection, tenant, *_ = db
    version, batch = process(db, TABLE_WITH_ALTERNATES)
    assert units(db, version) == ()
    review(db, batch)
    approve(connection, tenant, version, BEGIN)
    return version, {(cell.record_number, cell.column_number): cell for cell in csv_cells(db, version)}


def first_rule(cells, *, unit_column=2, note_column=4):
    return tuple(cells[position] for position in ((2, 1), (2, unit_column), (2, 3), (2, 5), (4, note_column), (4, 6)))


def test_only_declared_literal_equal_values_become_alternates(alternate_db):
    version, _ = publish_table(alternate_db)
    assert {
        (group.record_number, member.role, member.cell.record_number, member.cell.column_number)
        for group in units(alternate_db, version) for member in group.members if member.is_alternative
    } == {(2, "unit", 2, 7), (2, "exception", 4, 8), (3, "exception", 4, 8), (5, "exception", 5, 8)}
    assert [group.record_number for group in units(alternate_db, version)] == [2, 3, 5, 6]
    connection, tenant, *_ = alternate_db
    with pytest.raises(registry.VersionConflict):
        enroll(connection, tenant, linked_layout(), key="drop-alternate-contract")


def test_search_uses_only_current_exact_positions_and_never_splits_groups(alternate_db):
    connection, tenant, *_ = alternate_db
    _, cells = publish_table(alternate_db)
    primary = first_rule(cells)
    alternate = first_rule(cells, unit_column=7, note_column=8)
    second = tuple(cells[position] for position in ((3, 1), (3, 2), (3, 3), (3, 5), (4, 8), (4, 6)))
    grants = tuple(dict.fromkeys(primary + alternate + second + (cells[3, 7], cells[3, 9])))
    set_rules(alternate_db, *(permit(tenant.actor_id, cell) for cell in grants))
    delivered = json.loads(search(alternate_db, "600", top_k=6).payload)
    assert {UUID(part["passage_id"]) for part in delivered["passages"]} == {cell.passage_ref for cell in primary}

    allowed = tuple(cell for cell in grants if cell not in (cells[2, 2], cells[4, 4]))
    set_rules(alternate_db, *(permit(tenant.actor_id, cell) for cell in allowed), expected=2)
    assert search(alternate_db, "600", top_k=5).status == "no_evidence"
    payload = json.loads(search(alternate_db, "meeting", top_k=10).payload)
    expected = {cell.passage_ref for cell in alternate + second}
    assert len(payload["passages"]) == 10 and {UUID(part["passage_id"]) for part in payload["passages"]} == expected
    assert set(connection.execute("""
        SELECT dependency.passage_ref FROM thalion.delivery_record AS receipt
        JOIN thalion.delivery_dependency AS dependency USING (check_id)
        WHERE receipt.request_id = %s
    """, (UUID(payload["request_id"]),)).fetchall()) == {(ref,) for ref in expected}
    assert search(alternate_db, "600", top_k=6, authority=withhold(tenant.actor_id, cells[2, 7])).status == "no_evidence"
    assert search(alternate_db, "750", top_k=6, authority=withhold(tenant.actor_id, cells[3, 2])).status == "no_evidence"


def test_alternate_revoked_at_final_check_does_not_seal_receipt(alternate_db):
    connection, tenant, *_ = alternate_db
    _, cells = publish_table(alternate_db)
    alternate = first_rule(cells, unit_column=7)
    set_rules(alternate_db, *(permit(tenant.actor_id, cell) for cell in alternate))
    allow = authority_for({tenant.actor_id})
    deny = withhold(tenant.actor_id, cells[2, 7])
    checks = []

    def revoke_on_delivery(probe):
        checks.append({scope.object_id for scope in probe.scopes})
        return (allow if len(checks) == 1 else deny)(probe)

    result = search(alternate_db, "600", top_k=6, authority=revoke_on_delivery)
    assert len(checks) == 2 and checks[1] == {cell.passage_ref for cell in alternate}
    assert (result.status, result.payload) == ("rejected", None)
    assert connection.execute("SELECT count(*) FROM thalion.delivery_record").fetchone() == (0,)


def test_wiki_can_seal_alternates_without_replacing_previously_used_inputs(alternate_db):
    _, tenant, *_ = alternate_db
    _, cells = publish_table(alternate_db)
    primary, alternate = first_rule(cells), first_rule(cells, unit_column=7, note_column=8)
    set_rules(alternate_db, *role_rules(alternate_db, tuple(dict.fromkeys(primary + alternate))))

    old_seal = assemble(alternate_db, primary)
    assert old_seal.status == "succeeded"
    old_statement = drafts.WikiStatement("普通员工限额为 600 元/晚。", (exact(primary),))
    old_draft = candidate((alternate_db, old_seal, *primary[:2]), cited=exact(primary), statements=(old_statement,))
    approved = submit(alternate_db, old_draft.ref, preview(alternate_db, old_draft.ref))
    assert authorize(alternate_db, old_draft.ref, approved.ref).status == "succeeded"
    assert json.loads(search(alternate_db, "600", include_wiki=True, top_k=6).payload)["wiki"]

    revoked = withhold(tenant.actor_id, cells[2, 2])
    result = json.loads(search(alternate_db, "600", top_k=6, include_wiki=True, authority=revoked).payload)
    assert result["wiki"] == [] and str(cells[2, 7].passage_ref) in {part["passage_id"] for part in result["passages"]}
    assert assemble(alternate_db, inherited=(old_seal.manifest_ref,), authority=revoked).status == "rejected"
    assert assemble(alternate_db, alternate[:-1], authority=revoked).status == "rejected"
    new_seal = assemble(alternate_db, alternate, authority=revoked)
    assert new_seal.status == "succeeded"
    workspace = (alternate_db, new_seal, *alternate[:2])
    split = drafts.WikiStatement("普通员工限额为 600。", (exact(alternate[:-1]), exact(alternate[-1:])))
    assert candidate(workspace, cited=exact(alternate), statements=(split,), authority=revoked).status == "rejected"
    new_statement = drafts.WikiStatement("普通员工限额为 600 元/晚。", (exact(alternate),))
    assert candidate(workspace, cited=exact(alternate), statements=(new_statement,), authority=revoked).status == "succeeded"


@pytest.mark.parametrize(("row", "column"), [(3, 7), (2, 9)])
def test_seal_rejects_different_values_and_undeclared_equal_columns(alternate_db, monkeypatch, row, column):
    connection, _, _, _, store = alternate_db
    register_csv(alternate_db, TABLE_WITH_ALTERNATES)
    write_unit = processing._write_csv_unit

    def insert_unproven_alternate(transaction, run_ref, unit):
        if unit.record_number == row:
            members = tuple(member for member in unit.alternatives if member[0] != "unit")
            unit = replace(unit, alternatives=members + (("unit", column),))
        return write_unit(transaction, run_ref, unit)

    monkeypatch.setattr(processing, "_write_csv_unit", insert_unproven_alternate)
    with pytest.raises(errors.CheckViolation, match="declared, exact equivalent"):
        processing.process_evidence_job(connection, claim(alternate_db), store)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)


def test_upgrade_keeps_linked_units_and_existing_wiki_manifest(database_url, tmp_path):
    migrate_to_revision(database_url, "0054_csv_exception_links")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "legacy-linked-csv")
        source = enroll(connection, tenant, linked_layout())
        db = (connection, tenant, database_url, source, originals.SyntheticOriginalStore(tmp_path))
        version, (first, _, inline) = prepare(db, TABLE)
        set_rules(db, *role_rules(db, first + inline))
        before = units(db, version)
        seal = assemble(db, first + inline)
        assert seal.status == "succeeded"

        assert upgrade(database_url) == ["0112_flexible_vector_dimensions"]
        assert units(db, version) == before
        inherited = assemble(db, inherited=(seal.manifest_ref,))
        assert inherited.status == "succeeded" and inherited.payload == seal.payload
