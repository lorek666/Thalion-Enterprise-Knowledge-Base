from dataclasses import replace
import json
from uuid import UUID

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.evidence import csv_evidence, processing
from enterprise_kb.modules.sources import originals, registry
from enterprise_kb.modules.wiki import drafts

from test_csv_delivery import permit
from test_csv_processing import register_csv
from test_csv_units import PAYLOAD, enroll, process, units
from test_csv_wiki import exact, role_rules, withhold
from test_effectivity import BEFORE, BEGIN, approve
from test_employee_portal import browser, load_credential, portal, screenshot
from test_evidence import claim, evidence_db, review
from test_evidence_transport import evidence_transport
from test_identity import migrate_to_revision
from test_persisted_access import set_rules
from test_runtime import open_database, register_tenant, runtime_db
from test_travel_search import corpus, search
from test_wiki_drafts import candidate, preview, submit
from test_wiki_inputs import assemble
from test_wiki_publication import authorize


HEADER = "金额,单位,条件,例外,脚注引用,脚注键\n"
TABLE = (
    HEADER
    + "600,元/晚,普通员工,,meeting,\n"
    + "750,元/晚,驻点员工,,meeting,\n"
    + ",,,会议统一安排除外,,meeting\n"
    + "300,元/晚,实习员工,无,,\n"
).encode()


@pytest.fixture
def linked_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    source = enroll(connection, tenant, linked_layout())
    return connection, tenant, database_url, source, originals.SyntheticOriginalStore(tmp_path)


def linked_layout():
    return csv_evidence.AmountLayout("金额", "单位", "条件", "例外", exception_link=("脚注引用", "脚注键"))


def prepare(db, payload=TABLE):
    connection, tenant, *_ = db
    version, batch = process(db, payload)
    assert units(db, version) == ()
    review(db, batch)
    approve(connection, tenant, version, BEGIN)
    return version, tuple(tuple(member.cell for member in unit.members) for unit in units(db, version))


def test_linked_exception_binds_exact_same_file_cells_and_is_not_guessed(linked_db):
    connection, tenant, *_ = linked_db
    payload = (
        TABLE.decode()
        + "411,元/晚,一组,另有例外,meeting,\n"
        + "412,元/晚,二组,,missing,\n"
        + "413,元/晚,三组,,Meeting,\n"
        + "414,元/晚,四组,,duplicate,\n"
        + ",,,不同的第一条说明,,duplicate\n"
        + ",,,不同的第二条说明,,duplicate\n"
        + "415,元/晚,五组,,indirect,\n"
        + ",,,,meeting,indirect\n"
    ).encode()
    version, (first, second, inline) = prepare(linked_db, payload)
    assert [(cell.record_number, cell.column_number) for cell in first] == [
        (2, 1), (2, 2), (2, 3), (2, 5), (4, 4), (4, 6),
    ]
    assert first[-2:] == second[-2:]
    assert [len(group) for group in (first, second, inline)] == [6, 6, 4]
    assert connection.execute("""
        SELECT record_number, reason FROM thalion.evidence_unit
        WHERE reason IS NOT NULL ORDER BY record_number
    """).fetchall() == [(row, "invalid_exception_link") for row in (6, 7, 8, 9, 12)]
    assert len(units(linked_db, version)) == 3
    with pytest.raises(registry.VersionConflict):
        enroll(connection, tenant, csv_evidence.AmountLayout("金额", "单位", "条件", "例外"), key="no-link")


def test_linked_search_does_not_split_groups_or_block_other_users_of_shared_note(linked_db):
    connection, tenant, *_ = linked_db
    _, (first, second, inline) = prepare(linked_db)
    cells = tuple(dict.fromkeys(first + second + inline))
    set_rules(linked_db, *(permit(tenant.actor_id, cell) for cell in cells))

    assert search(linked_db, "会议", top_k=5).status == "no_evidence"
    both = json.loads(search(linked_db, "会议", top_k=10).payload)
    assert {UUID(part["passage_id"]) for part in both["passages"]} == {cell.passage_ref for cell in first + second}
    assert len(both["passages"]) == 10
    assert connection.execute("""
        SELECT dependency_count FROM thalion.delivery_record WHERE request_id = %s
    """, (UUID(both["request_id"]),)).fetchone() == (10,)
    one = json.loads(search(linked_db, "会议", top_k=9).payload)
    assert len(one["passages"]) == 6
    assert any(part["location"]["row_id"] == 4 and part["excerpt"] == "会议统一安排除外" for part in one["passages"])

    deny_first = withhold(tenant.actor_id, first[0])
    surviving = json.loads(search(linked_db, "会议", top_k=10, authority=deny_first).payload)
    assert [UUID(part["passage_id"]) for part in surviving["passages"]] == [cell.passage_ref for cell in second]
    deny_shared = withhold(tenant.actor_id, first[-1], "location")
    surviving = json.loads(search(linked_db, "会议 实习员工", top_k=16, authority=deny_shared).payload)
    assert [UUID(part["passage_id"]) for part in surviving["passages"]] == [cell.passage_ref for cell in inline]


def test_linked_wiki_can_cite_one_complete_group_and_keeps_note_permission(linked_db):
    _, tenant, *_ = linked_db
    _, (first, second, _) = prepare(linked_db)
    set_rules(linked_db, *role_rules(linked_db, tuple(dict.fromkeys(first + second))))
    assert assemble(linked_db, first[:-1]).status == "rejected"
    seal = assemble(linked_db, first)
    assert seal.status == "succeeded"
    workspace = (linked_db, seal, first[0], first[1])
    assert candidate(workspace, cited=exact(first[:-1])).status == "rejected"
    statement = drafts.WikiStatement("普通员工限额为 600 元/晚，会议统一安排除外。", (exact(first),))
    draft = candidate(workspace, cited=exact(first), statements=(statement,))
    assert draft.status == "succeeded"
    approved = submit(linked_db, draft.ref, preview(linked_db, draft.ref))
    assert approved.status == "succeeded"
    publication = authorize(linked_db, draft.ref, approved.ref)
    assert publication.status == "succeeded"
    found = json.loads(search(linked_db, "600", include_wiki=True, top_k=6).payload)
    assert found["wiki"][0]["claims"][0]["passage_ids"] == [str(cell.passage_ref) for cell in first]
    assert search(linked_db, "600", top_k=6, include_wiki=True,
                  authority=withhold(tenant.actor_id, first[-2])).status == "no_evidence"


def test_incomplete_cross_row_bundle_rolls_back_the_candidate(linked_db, monkeypatch):
    connection, _, _, _, store = linked_db
    register_csv(linked_db, TABLE)
    lease = claim(linked_db)
    write_unit = processing._write_csv_unit

    def omit_key(transaction, run_ref, unit):
        if unit.record_number == 2:
            unit = replace(unit, columns=unit.columns[:-1])
        return write_unit(transaction, run_ref, unit)

    monkeypatch.setattr(processing, "_write_csv_unit", omit_key)
    with pytest.raises(errors.CheckViolation, match="six linked members"):
        processing.process_evidence_job(connection, lease, store)
    assert connection.execute("SELECT count(*) FROM thalion.processing_run").fetchone() == (0,)


def test_upgrade_keeps_existing_approved_four_cell_groups(database_url, tmp_path):
    migrate_to_revision(database_url, "0053_csv_wiki_inputs")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "legacy-csv")
        layout = csv_evidence.AmountLayout("限额", "单位", "适用情形", "例外")
        source = enroll(connection, tenant, layout)
        db = (connection, tenant, database_url, source, originals.SyntheticOriginalStore(tmp_path))
        version, (first, _) = prepare(db, PAYLOAD)
        set_rules(db, *role_rules(db, first))
        original_groups = units(db, version)
        prior_seal = assemble(db, first)
        assert prior_seal.status == "succeeded"

        assert upgrade(database_url) == ["0113_source_connector_cursor"]
        assert units(db, version) == original_groups
        inherited = assemble(db, inherited=(prior_seal.manifest_ref,))
        assert inherited.status == "succeeded" and inherited.payload == prior_seal.payload
        assert candidate((db, inherited, first[0], first[1]), cited=exact(first)).status == "succeeded"


def test_employee_search_opens_cross_row_note_and_clears_it_after_revocation(portal):
    from playwright.sync_api import expect

    page, _, db, (employee, _), *_ = portal
    connection, tenant, _, _, store = db
    source = enroll(connection, tenant, linked_layout())
    linked = (*db[:3], source, store)
    _, (first, _, _) = prepare(linked)
    set_rules(linked, *(permit(tenant.actor_id, cell) for cell in first))
    page.set_viewport_size({"width": 390, "height": 844})
    load_credential(page, employee)
    page.get_by_label("关键词或问题").fill("600")
    page.get_by_label("业务日期").fill(BEFORE.isoformat())
    button = page.get_by_role("button", name="查找依据")
    result = page.get_by_role("region", name="检索结果")
    with page.expect_request("**/v1/search") as prior:
        button.click()
    assert prior.value.post_data_json["top_k"] == 5
    expect(result.get_by_text("有匹配资料，当前条数上限不足以显示完整证据", exact=True)).to_be_visible()
    facets = result.get_by_role("region", name="匹配资料按来源")
    expect(facets.get_by_text("1 份", exact=True)).to_be_visible()
    passages = result.locator("#results").get_by_role("listitem")
    expect(passages).to_have_count(0)
    count = page.get_by_role("spinbutton", name="原文条数")
    expect(count).to_have_value("5")
    count.fill("6")
    button.click()
    expect(passages).to_have_count(6)
    note = passages.filter(has_text="会议统一安排除外")
    note.get_by_role("button", name="核对原文：Synthetic travel rules").click()
    original = page.get_by_role("region", name="原文核对")
    expect(original.get_by_text("第 4 行 / 第 4 列（例外）", exact=True)).to_be_visible()
    expect(original.get_by_text("会议统一安排除外", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    screenshot(page, "employee-csv-cross-row-exception.png")
    set_rules(linked, *(permit(tenant.actor_id, cell) for cell in first[:-1]), expected=2)
    button.click()
    expect(result.get_by_text("没有找到可用依据。可换个关键词或检查业务日期。", exact=True)).to_be_visible()
    expect(facets).to_have_count(0)
    expect(original.get_by_text("会议统一安排除外", exact=True)).to_be_hidden()
    page.get_by_role("button", name="更换凭据").click()
    load_credential(page, employee)
    expect(count).to_have_value("5")
