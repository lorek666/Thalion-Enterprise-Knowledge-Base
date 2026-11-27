from hashlib import sha256

import pytest

from enterprise_kb.modules.evidence.markdown import parse_markdown


def test_markdown_locations_preserve_original_bytes_and_heading_context():
    original = (
        "# 差旅\r\n\r\n## 住宿\r\n\r\n未经书面批准不得报销。\r\n"
        "会议统一安排住宿的除外。\r\n\r\n"
        "| 城市 | 限额（元/人·晚） |\r\n| --- | --- |\r\n| 上海 | 600 |\r\n\r\n"
        "## 审批\r\n\r\n编号 0017；税率 0.5%。"
    ).encode()
    result = parse_markdown(original)
    assert result.outcome == "pending_review"
    assert [(part.heading_path, part.paragraph, part.kind) for part in result.passages] == [
        (("差旅", "住宿"), 1, "paragraph"),
        (("差旅", "住宿"), 2, "table"),
        (("差旅", "审批"), 1, "paragraph"),
    ]
    slices = tuple(original[part.byte_start:part.byte_end] for part in result.passages)
    assert b"\r\n" in slices[0]
    assert "不得报销".encode() in slices[0]
    assert "除外".encode() in slices[0]
    assert all(value.encode() in slices[1] for value in ("元/人·晚", "上海", "600"))
    assert b"0017" in slices[2] and b"0.5%" in slices[2]
    assert all(part.digest == sha256(raw).digest() for part, raw in zip(result.passages, slices))


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"# No content\n\n", "empty"),
        (b"# Travel\n\nBroken \xff", "invalid_encoding"),
        (b"# Travel\n\nVisible.\n\n<!-- withheld -->\n", "unsupported_structure"),
        (b"# Travel\n\nRule <span hidden>withheld</span>.\n", "unsupported_structure"),
        (b"# Travel\n\n600 CNY[^rooms]\n", "unsupported_structure"),
        (b"# Travel\n\n[Policy][doc]\n\n[doc]: https://synthetic.invalid/private\n",
         "unsupported_structure"),
    ],
)
def test_unsupported_content_is_not_promoted_as_partial_evidence(data, reason):
    result = parse_markdown(data)
    assert (result.outcome, result.reason, result.passages) == ("quarantined", reason, ())
