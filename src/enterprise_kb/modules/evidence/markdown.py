from dataclasses import dataclass, field
from hashlib import sha256
from importlib.metadata import version
from itertools import accumulate
from typing import Literal

from markdown_it import MarkdownIt


PARSER_VERSION = version("markdown-it-py")
PROFILE = "commonmark_table_v1"
LOCATOR_REVISION = 1
MAX_BYTES = 4 * 1024 * 1024
MAX_LINES = 20_000
BLOCKS = {
    "paragraph_open": "paragraph",
    "table_open": "table",
    "blockquote_open": "blockquote",
    "bullet_list_open": "list",
    "ordered_list_open": "list",
    "code_block": "code",
    "fence": "code",
}
QuarantineReason = Literal["empty", "invalid_encoding", "unsupported_structure", "size_limit"]


@dataclass(frozen=True)
class MarkdownPassage:
    heading_path: tuple[str, ...] = field(repr=False)
    paragraph: int
    kind: str
    byte_start: int
    byte_end: int
    digest: bytes


@dataclass(frozen=True)
class MarkdownCandidate:
    outcome: Literal["pending_review", "quarantined"]
    reason: QuarantineReason | None = None
    passages: tuple[MarkdownPassage, ...] = ()


def parse_markdown(payload: bytes) -> MarkdownCandidate:
    """Map admitted blocks to exact original bytes without rendering or fetching links."""
    if len(payload) > MAX_BYTES:
        return MarkdownCandidate("quarantined", "size_limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return MarkdownCandidate("quarantined", "invalid_encoding")
    if "\0" in text or "[^" in text:
        return MarkdownCandidate("quarantined", "unsupported_structure")
    lines = payload.splitlines(keepends=True)
    if len(lines) > MAX_LINES:
        return MarkdownCandidate("quarantined", "size_limit")
    offsets = tuple(accumulate(map(len, lines), initial=0))
    parser = MarkdownIt("commonmark").enable("table")
    tokens = parser.parse(text)
    if any(
        token.type == "html_block"
        or any(child.type in ("html_inline", "image") for child in token.children or ())
        for token in tokens
    ):
        return MarkdownCandidate("quarantined", "unsupported_structure")

    headings: list[tuple[int, str]] = []
    paragraph = 0
    covered = 0
    passages = []
    for index, token in enumerate(tokens):
        if token.level != 0 or token.map is None:
            continue
        start, end = token.map
        if not (covered <= start < end <= len(lines)) or any(
            line.strip() for line in lines[covered:start]
        ):
            return MarkdownCandidate("quarantined", "unsupported_structure")
        covered = end
        if token.type == "heading_open":
            depth = int(token.tag[1:])
            title = tokens[index + 1].content
            if not title or len(title) > 512:
                return MarkdownCandidate("quarantined", "unsupported_structure")
            while headings and headings[-1][0] >= depth:
                headings.pop()
            headings.append((depth, title))
            paragraph = 0
        elif token.type in BLOCKS:
            paragraph += 1
            first, last = offsets[start], offsets[end]
            passages.append(MarkdownPassage(
                tuple(title for _, title in headings), paragraph, BLOCKS[token.type],
                first, last, sha256(payload[first:last]).digest(),
            ))
        elif token.type != "hr":
            return MarkdownCandidate("quarantined", "unsupported_structure")
    if any(line.strip() for line in lines[covered:]):
        return MarkdownCandidate("quarantined", "unsupported_structure")
    if not passages:
        return MarkdownCandidate("quarantined", "empty")
    return MarkdownCandidate("pending_review", passages=tuple(passages))
