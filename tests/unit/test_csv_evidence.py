import pytest

from enterprise_kb.modules.evidence import csv_evidence


def test_csv_preserves_cell_values_and_uses_logical_row_numbers():
    original = (
        "\ufeff编号,费率,限额（元/人·晚）,例外,备注\r\n"
        '0017,0.5%,0,"会议安排,不得补报\r\n书面批准除外",\r\n'
        '17,5%,未知,不适用,"原样保留 ""双引号"" "\r\n'
    ).encode("utf-8")

    result = csv_evidence.parse_csv(original)

    assert result.outcome == "pending_review"
    assert result.headers == ("编号", "费率", "限额（元/人·晚）", "例外", "备注")
    assert [(row.record_number, row.values) for row in result.rows] == [
        (2, ("0017", "0.5%", "0", "会议安排,不得补报\r\n书面批准除外", "")),
        (3, ("17", "5%", "未知", "不适用", '原样保留 "双引号" ')),
    ]


@pytest.mark.parametrize(
    ("original", "reason"),
    [
        (b"", "empty"),
        (b"ID,Amount\r\n", "empty"),
        (b"ID,Amount\r\n0017,\xff\r\n", "invalid_encoding"),
        (b"ID, id \r\n0017,600\r\n", "unsupported_structure"),
        (b'ID,"Amount\r\nCNY"\r\n0017,600\r\n', "unsupported_structure"),
        (b"ID,\r\n0017,600\r\n", "unsupported_structure"),
        (b"ID,Amount\r\n0017,600\r\n0018\r\n", "unsupported_structure"),
        (b"ID,Amount\r\n0017,600\r\n\r\n0018,500\r\n", "unsupported_structure"),
        (b'ID,Amount\r\n0017,"600\r\n', "unsupported_structure"),
        (b"ID,Amount\r\n0017,6\x0000\r\n", "unsupported_structure"),
    ],
)
def test_csv_quarantine_clears_entire_candidate(original, reason):
    result = csv_evidence.parse_csv(original)

    assert (result.outcome, result.reason, result.headers, result.rows) == ("quarantined", reason, (), ())


@pytest.mark.parametrize(
    ("limit", "value", "original"),
    [
        ("MAX_CSV_BYTES", 10, b"ID,Amount\r\n0017,600\r\n"),
        ("MAX_CSV_RECORDS", 1, b"ID,Amount\r\n0017,600\r\n0018,601\r\n"),
        ("MAX_CSV_COLUMNS", 1, b"ID,Amount\r\n0017,600\r\n"),
        ("MAX_CSV_CELL_LENGTH", 6, b"ID,Amount\r\n0017,1234567\r\n"),
    ],
)
def test_csv_processing_limits_reject_without_partial_rows(monkeypatch, limit, value, original):
    monkeypatch.setattr(csv_evidence, limit, value)

    result = csv_evidence.parse_csv(original)

    assert (result.outcome, result.reason, result.headers, result.rows) == ("quarantined", "size_limit", (), ())
