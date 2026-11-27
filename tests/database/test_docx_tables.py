from dataclasses import replace
from hashlib import sha256
from uuid import uuid4
from xml.sax.saxutils import escape

import pytest
from psycopg import errors

from enterprise_kb.database import upgrade
from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.evidence.docx_evidence import parse_docx
from enterprise_kb.modules.sources import registry
from enterprise_kb.runtime.commands import IdempotencyConflict

from docx_fixture import DOCUMENT, STYLES, docx_package
from test_docx_processing import docx_locators, register_docx
from test_evidence import claim, create_evidence_db, review
from test_identity import migrate_to_revision
from test_runtime import open_database, register_tenant, runtime_db
from test_sources import request_for


AMOUNT_COLUMNS = ("上限", "单位", "适用人群", "例外")
HEADERS = ("适用人群", "上限", "单位", "例外")
COMPLETE = ("上海正式员工", "0600.50", "元/人·晚", "会议统一安排除外。\n须另行审批。")
DEFAULT_TABLE_STYLE = """<w:style w:type="table" w:default="1" w:styleId="NormalTable">
  <w:name w:val="Normal Table"/><w:semiHidden/>
  <w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:left w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr>
</w:style>"""


def grid(rows, *, after=""):
    def cell(text):
        paragraphs = "".join(f"<w:p><w:r><w:t>{escape(part)}</w:t></w:r></w:p>" for part in text.split("\n"))
        return f"<w:tc>{paragraphs}</w:tc>"

    columns = "<w:gridCol w:w=\"1800\"/>" * len(rows[0])
    body = "".join(f"<w:tr>{''.join(map(cell, row))}</w:tr>" for row in rows)
    return f'<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr><w:tblGrid>{columns}</w:tblGrid>{body}</w:tbl>{after}'


def table_package(*tables, styles=STYLES):
    marker = "  <w:sectPr/>"
    return docx_package(DOCUMENT.replace(marker, "\n".join(tables) + marker), styles=styles)


def test_docx_table_preserves_each_literal_value_and_binds_roles_by_exact_header():
    following = "<w:p><w:r><w:t>独立段落。</w:t></w:r></w:p>"
    payload = table_package(grid((HEADERS, COMPLETE), after=following), grid((HEADERS, COMPLETE)))

    candidate = parse_docx(payload, amount_columns=AMOUNT_COLUMNS)

    assert candidate.outcome == "pending_review"
    assert [part.document_paragraph for part in candidate.passages] == [3, 5, 6]
    assert [table.ordinal for table in candidate.tables] == [1, 2]
    for table in candidate.tables:
        assert table.heading_path == ("差旅", "住宿")
        assert table.headers == HEADERS
        assert [(row.record_number, row.values) for row in table.rows] == [(2, COMPLETE)]
        assert [(unit.record_number, unit.columns, unit.reason) for unit in table.units] == [(2, (2, 3, 1, 4), None)]


@pytest.mark.parametrize(("headers", "row", "reason"), [
    (("适用人群", "上限", "计量单位", "例外"), COMPLETE, "missing_column"),
    (HEADERS, ("正式员工", "600", "", "无例外"), "missing_value"),
    (HEADERS, ("正式员工", "600", "元", "?"), "missing_value"),
    (HEADERS, ("正式员工", "约600", "元", "无例外"), "invalid_amount"),
])
def test_docx_table_never_emits_a_partial_amount_unit(headers, row, reason):
    candidate = parse_docx(table_package(grid((headers, row))), amount_columns=AMOUNT_COLUMNS)
    table, = candidate.tables
    unit, = table.units
    assert (unit.record_number, unit.columns, unit.reason) == (2, (), reason)


@pytest.mark.parametrize("variant", ["duplicate_header", "ragged", "merged", "hidden", "nested", "row_omitted_cells"])
def test_ambiguous_docx_table_quarantines_the_complete_document(variant):
    source = grid((HEADERS, COMPLETE))
    if variant == "duplicate_header":
        source = source.replace("单位", "上限")
    elif variant == "ragged":
        source = source.replace('<w:tc><w:p><w:r><w:t>0600.50</w:t></w:r></w:p></w:tc>', "")
    elif variant == "merged":
        source = source.replace("<w:tc>", '<w:tc><w:tcPr><w:gridSpan w:val="2"/></w:tcPr>', 1)
    elif variant == "hidden":
        source = source.replace("<w:r><w:t>0600.50", "<w:r><w:rPr><w:vanish/></w:rPr><w:t>0600.50")
    elif variant == "nested":
        source = source.replace("</w:tc>", grid((HEADERS, COMPLETE)) + "</w:tc>", 1)
    else:
        source = source.replace("<w:tr>", '<w:tr><w:trPr><w:gridBefore w:val="1"/></w:trPr>', 1)
    candidate = parse_docx(table_package(source), amount_columns=AMOUNT_COLUMNS)
    assert (candidate.outcome, candidate.reason, candidate.passages, candidate.tables) == (
        "quarantined", "unsupported_structure", (), (),
    )


def test_docx_table_without_an_explicit_layout_cannot_drop_table_and_release_neighboring_paragraphs():
    payload = table_package(grid((HEADERS, COMPLETE)))
    candidate = parse_docx(payload)
    assert (candidate.outcome, candidate.reason, candidate.passages) == ("quarantined", "unsupported_structure", ())


def test_docx_default_table_style_may_format_margins_but_cannot_hide_text():
    table = grid((HEADERS, COMPLETE))
    visible = STYLES.replace("</w:styles>", DEFAULT_TABLE_STYLE + "</w:styles>")
    candidate = parse_docx(table_package(table, styles=visible), amount_columns=AMOUNT_COLUMNS)
    assert candidate.outcome == "pending_review" and candidate.tables[0].rows[0].values == COMPLETE

    hidden = visible.replace("<w:semiHidden/>", "<w:rPr><w:vanish/></w:rPr>")
    refused = parse_docx(table_package(table, styles=hidden), amount_columns=AMOUNT_COLUMNS)
    assert (refused.outcome, refused.reason, refused.tables) == ("quarantined", "unsupported_structure", ())


@pytest.mark.parametrize("limit", ["table_count", "table_rows", "table_columns", "total_cells", "cell_paragraphs"])
def test_docx_table_bounds_quarantine_without_retaining_an_earlier_table(limit):
    admitted = grid((HEADERS, COMPLETE))
    wide = tuple(f"列{column}" for column in range(16))
    exceeded = {
        "table_count": (admitted,) * 16,
        "table_rows": (grid((HEADERS,) + (COMPLETE,) * 128),),
        "table_columns": (grid(((*wide, "超限"),) * 2),),
        "total_cells": (grid((wide,) * 64),),
        "cell_paragraphs": (grid((HEADERS, (*COMPLETE[:3], "例外\n" * 16 + "结束"))),),
    }[limit]
    candidate = parse_docx(table_package(admitted, *exceeded), amount_columns=AMOUNT_COLUMNS)
    assert (candidate.outcome, candidate.reason, candidate.passages, candidate.tables) == ("quarantined", "size_limit", (), ())


def test_docx_worker_seals_exact_complete_rows_in_the_shared_evidence_model(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    db = create_evidence_db(connection, tenant, database_url, tmp_path, docx_amount_columns=AMOUNT_COLUMNS)
    second = ("其他正式员工", "750", "元/人·晚", "无例外")
    incomplete = ("非正式员工", "800", "", "另行审批")
    payload = table_package(grid((HEADERS, COMPLETE, incomplete)), grid((HEADERS, second)))
    version = register_docx(db, payload)

    run = processing.process_evidence_job(connection, claim(db), db[-1])

    assert (run.outcome, run.passage_count) == ("pending_review", 14)
    assert docx_locators(db, version) == ()
    assert connection.execute("""
        SELECT docx_table, record_number, reason FROM thalion.evidence_unit
        WHERE run_ref = %s ORDER BY docx_table, record_number
        """, (run.run_ref,)).fetchall() == [(1, 2, None), (1, 3, "missing_value"), (2, 2, None)]
    assert connection.execute("""
        SELECT passage.heading_path, excerpt.docx_header_digest
        FROM thalion.passage AS passage JOIN thalion.passage_excerpt AS excerpt USING (passage_id)
        WHERE excerpt.run_ref = %s AND (passage.docx_table, passage.docx_row, passage.docx_column) = (1, 2, 2)
    """, (run.run_ref,)).fetchone() == (["差旅", "住宿"], sha256("上限".encode()).digest())
    assert connection.execute("""
        SELECT unit.docx_table, unit.record_number, member.role, passage.docx_table, passage.docx_row,
               passage.docx_column, member.excerpt_revision
        FROM thalion.evidence_unit AS unit
        JOIN thalion.evidence_unit_member AS member USING (unit_ref, run_ref)
        JOIN thalion.passage AS passage USING (passage_id)
        WHERE unit.run_ref = %s ORDER BY unit.docx_table, passage.docx_column
        """, (run.run_ref,)).fetchall() == [
        (table, 2, role, table, 2, column, 1)
        for table in (1, 2)
        for column, role in enumerate(("condition", "amount", "unit", "exception"), 1)
    ]
    with pytest.raises(processing.QualityConflict, match="preview"):
        review(db, run)
    approval = request_for(connection, tenant, tenant.actor_id, "direct-approval", "decide_evidence_quality")
    with pytest.raises(errors.CheckViolation, match="preview"):
        connection.execute("""
            INSERT INTO thalion.quality_decision (org_id, space_id, version_id, run_ref, reviewer_id, request_id, basis_ref, outcome)
            SELECT org_id, space_id, version_id, run_ref, %s, %s, %s, 'approved'
            FROM thalion.processing_run WHERE run_ref = %s
        """, (tenant.actor_id, approval.request_id, uuid4(), run.run_ref))
    assert connection.execute("SELECT count(*) FROM thalion.quality_decision WHERE run_ref = %s", (run.run_ref,)).fetchone() == (0,)


def test_docx_layout_is_part_of_the_immutable_source_contract(runtime_db):
    connection, tenant, _ = runtime_db
    spec = registry.SyntheticSource(
        "travel-docx", "travel-archive", tenant.worker_id, processor_id=tenant.other_worker_id,
        quality_reviewer_id=tenant.actor_id, docx_amount_columns=AMOUNT_COLUMNS,
    )

    def enroll(key, contract):
        return registry.register_synthetic_source(connection, request_for(
            connection, tenant, tenant.actor_id, key, "register_source_contract",
        ), tenant.space_id, contract)

    source = enroll("layout", spec)
    assert enroll("layout", spec) == source
    assert enroll("layout-again", spec) == source
    changed = replace(spec, docx_amount_columns=("定额", *AMOUNT_COLUMNS[1:]))
    with pytest.raises(IdempotencyConflict):
        enroll("layout", changed)
    with pytest.raises(registry.VersionConflict):
        enroll("layout-change", changed)
    with pytest.raises(ValueError):
        enroll("no-reviewer", replace(spec, quality_reviewer_id=None))


def test_docx_table_rows_cannot_use_another_tables_cells_or_commit_partial_groups(runtime_db, tmp_path, monkeypatch):
    connection, tenant, database_url = runtime_db
    db = create_evidence_db(connection, tenant, database_url, tmp_path, docx_amount_columns=AMOUNT_COLUMNS)
    register_docx(db, table_package(grid((HEADERS, COMPLETE)), grid((HEADERS, COMPLETE))))
    lease = claim(db)
    write_unit = processing._write_docx_unit

    for corruption, message in (("other_table", "exact declared row"), ("wrong_role", "exact declared row"),
                                ("partial", "all four required members together"), ("unrecorded", "each DOCX row")):
        def corrupt_unit(transaction, run_ref, table, unit):
            if table == 2 and corruption == "unrecorded":
                return
            if table == 2 and corruption == "other_table":
                unit_ref, = transaction.execute("""
                    INSERT INTO thalion.evidence_unit (run_ref, docx_table, record_number)
                    VALUES (%s, %s, %s) RETURNING unit_ref
                """, (run_ref, table, unit.record_number)).fetchone()
                transaction.execute("""
                    INSERT INTO thalion.evidence_unit_member (unit_ref, run_ref, role, passage_id, excerpt_revision)
                    SELECT %s, member.run_ref, member.role, member.passage_id, member.excerpt_revision
                    FROM thalion.evidence_unit AS previous
                    JOIN thalion.evidence_unit_member AS member USING (unit_ref, run_ref)
                    WHERE previous.run_ref = %s AND previous.docx_table = 1 AND member.role = 'amount'
                """, (unit_ref, run_ref))
                return
            if corruption == "wrong_role":
                unit = replace(unit, columns=(unit.columns[1], unit.columns[0], *unit.columns[2:]))
            if corruption == "partial":
                unit = replace(unit, columns=unit.columns[:-1])
            return write_unit(transaction, run_ref, table, unit)

        with monkeypatch.context() as patch:
            patch.setattr(processing, "_write_docx_unit", corrupt_unit)
            with pytest.raises(errors.CheckViolation, match=message):
                processing.process_evidence_job(connection, lease, db[-1])
        assert connection.execute("""
            SELECT (SELECT count(*) FROM thalion.processing_run), (SELECT count(*) FROM thalion.passage),
                   (SELECT count(*) FROM thalion.evidence_unit),
                   (SELECT count(*) FROM thalion.outbox_event WHERE event_type = 'evidence.candidate.recorded'),
                   (SELECT state FROM thalion.job WHERE job_id = %s)
        """, (lease.job_id,)).fetchone() == (0, 0, 0, 0, "running")

    assert processing.process_evidence_job(connection, lease, db[-1]).outcome == "pending_review"


def test_docx_table_migration_preserves_approved_paragraphs_from_the_previous_schema(database_url, tmp_path):
    migrate_to_revision(database_url, "0078_mixed_wiki_rebuild")
    with open_database(database_url) as connection:
        tenant = register_tenant(connection, "Existing paragraphs")
        db = create_evidence_db(connection, tenant, database_url, tmp_path)
        version = register_docx(db, docx_package())
        run = processing.process_evidence_job(connection, claim(db), db[-1])
        review(db, run)
        before = docx_locators(db, version)
        assert len(before) == 2

        upgrade(database_url)

        assert docx_locators(db, version) == before
