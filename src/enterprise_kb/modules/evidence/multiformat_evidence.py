from dataclasses import dataclass
from hashlib import sha256
from html.parser import HTMLParser
from io import BytesIO
import posixpath
import re
from typing import Literal
import xml.etree.ElementTree as ET
from zipfile import BadZipFile, ZipFile

from . import pdf_evidence


XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
PPTX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
HTML_MEDIA_TYPE = "text/html"
PNG_MEDIA_TYPE = "image/png"
JPEG_MEDIA_TYPE = "image/jpeg"

IMAGE_MEDIA_TYPES = frozenset({PNG_MEDIA_TYPE, JPEG_MEDIA_TYPE})
STRUCTURED_MEDIA_TYPES = frozenset({
    XLSX_MEDIA_TYPE,
    PPTX_MEDIA_TYPE,
    HTML_MEDIA_TYPE,
    PNG_MEDIA_TYPE,
    JPEG_MEDIA_TYPE,
})

PARSER_VERSION = "1"
LOCATOR_REVISION = 1

PROFILES: dict[str, str] = {
    XLSX_MEDIA_TYPE: "xlsx_sheet_rows_v1",
    PPTX_MEDIA_TYPE: "pptx_slides_v1",
    HTML_MEDIA_TYPE: "html_blocks_v1",
    PNG_MEDIA_TYPE: "image_ocr_v1",
    JPEG_MEDIA_TYPE: "image_ocr_v1",
}

MEDIA_SOURCE_TYPE: dict[str, str] = {
    XLSX_MEDIA_TYPE: "xlsx",
    PPTX_MEDIA_TYPE: "pptx",
    HTML_MEDIA_TYPE: "html",
    PNG_MEDIA_TYPE: "image",
    JPEG_MEDIA_TYPE: "image",
}

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_PASSAGES = 512
MAX_PASSAGE_BYTES = 65536
MAX_HTML_BYTES = 4 * 1024 * 1024
MAX_IMAGE_BYTES = 16 * 1024 * 1024

XLSX_PARTS = frozenset({"[Content_Types].xml", "xl/workbook.xml"})
PPTX_PARTS = frozenset({"[Content_Types].xml", "ppt/presentation.xml"})

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"

StructuredKind = Literal["xlsx_row", "pptx_slide", "html_block", "image_ocr"]
QuarantineReason = Literal["empty", "invalid_encoding", "unsupported_structure", "size_limit"]


class ImageOcrUnavailable(Exception):
    pass


@dataclass(frozen=True)
class StructuredPassage:
    kind: StructuredKind
    structured_locator: str
    heading_path: tuple[str, ...]
    paragraph: int
    text: str
    digest: bytes


@dataclass(frozen=True)
class StructuredCandidate:
    media_type: str
    passages: tuple[StructuredPassage, ...]
    reason: QuarantineReason | None = None
    detail: str | None = None


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"[ \t\r\f\v]+", " ", value).strip()


def _safe_read_zip_members(payload: bytes) -> dict[str, bytes] | None:
    if not payload or len(payload) > MAX_ARCHIVE_BYTES:
        return None
    try:
        with ZipFile(BytesIO(payload)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
                return None
            seen: set[str] = set()
            total_uncompressed = 0
            members: dict[str, bytes] = {}
            for info in infos:
                name = info.filename
                if (
                    not name
                    or name.startswith("/")
                    or "\\" in name
                    or ".." in name.split("/")
                    or (info.flag_bits & 0x1) != 0
                    or name in seen
                ):
                    return None
                seen.add(name)
                if info.is_dir():
                    continue
                if info.file_size < 0 or total_uncompressed + info.file_size > MAX_UNCOMPRESSED_BYTES:
                    return None
                raw = archive.read(info)
                total_uncompressed += len(raw)
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    return None
                members[name] = raw
            return members
    except (BadZipFile, OSError, ValueError, RuntimeError):
        return None


def _resolve_rel_target(base_dir: str, target: str) -> str:
    cleaned = target.lstrip("/")
    if target.startswith("/"):
        return posixpath.normpath(cleaned)
    return posixpath.normpath(posixpath.join(base_dir, target))


def _parse_xml_strict(raw: bytes) -> ET.Element | None:
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        return None
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_xlsx(payload: bytes) -> StructuredCandidate:
    members = _safe_read_zip_members(payload)
    if members is None or not XLSX_PARTS <= members.keys():
        return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "invalid_xlsx_archive")

    workbook_xml = _parse_xml_strict(members["xl/workbook.xml"])
    if workbook_xml is None:
        return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "invalid_xlsx_xml")

    rel_map: dict[str, str] = {}
    rels_bytes = members.get("xl/_rels/workbook.xml.rels")
    if rels_bytes is not None:
        rels_root = _parse_xml_strict(rels_bytes)
        if rels_root is None:
            return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "invalid_xlsx_xml")
        for rel in rels_root:
            if _local_tag(rel.tag) == "Relationship":
                rid = rel.attrib.get("Id")
                target = rel.attrib.get("Target")
                if rid and target:
                    rel_map[rid] = _resolve_rel_target("xl", target)

    shared_strings: list[str] = []
    ss_bytes = members.get("xl/sharedStrings.xml")
    if ss_bytes is not None:
        ss_root = _parse_xml_strict(ss_bytes)
        if ss_root is None:
            return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "invalid_xlsx_xml")
        for si in ss_root:
            if _local_tag(si.tag) == "si":
                parts = [elem.text or "" for elem in si.iter() if _local_tag(elem.tag) == "t"]
                shared_strings.append("".join(parts))

    sheets: list[tuple[str, str]] = []
    for elem in workbook_xml.iter():
        if _local_tag(elem.tag) == "sheet":
            name = (elem.attrib.get("name") or "").strip() or f"Sheet{len(sheets) + 1}"
            rid = None
            for attr_k, attr_v in elem.attrib.items():
                if attr_k.endswith("}id") or attr_k == "id":
                    rid = attr_v
                    break
            if rid and rid in rel_map:
                sheets.append((name, rel_map[rid]))
            else:
                fallback = f"xl/worksheets/sheet{len(sheets) + 1}.xml"
                if fallback in members:
                    sheets.append((name, fallback))

    if not sheets:
        return StructuredCandidate(XLSX_MEDIA_TYPE, (), "empty", "empty_xlsx_workbook")

    passages: list[StructuredPassage] = []
    ordinal = 0
    for sheet_idx, (sheet_name, sheet_path) in enumerate(sheets, start=1):
        sheet_bytes = members.get(sheet_path)
        if sheet_bytes is None:
            return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "missing_xlsx_sheet")
        sheet_root = _parse_xml_strict(sheet_bytes)
        if sheet_root is None:
            return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "invalid_xlsx_xml")
        for row_elem in sheet_root.iter():
            if _local_tag(row_elem.tag) != "row":
                continue
            row_attr = row_elem.attrib.get("r", "")
            row_num = int(row_attr) if row_attr.isdigit() else (ordinal + 1)
            cell_texts: list[str] = []
            for cell_idx, cell in enumerate(row_elem, start=1):
                if _local_tag(cell.tag) != "c":
                    continue
                cell_ref = cell.attrib.get("r") or f"C{cell_idx}"
                cell_type = cell.attrib.get("t", "")
                has_formula = False
                value_elem = None
                inline_elem = None
                for child in cell:
                    tag = _local_tag(child.tag)
                    if tag == "f":
                        has_formula = True
                    elif tag == "v":
                        value_elem = child
                    elif tag == "is":
                        inline_elem = child
                if has_formula and (value_elem is None or value_elem.text is None):
                    return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "uncomputed_xlsx_formula")
                raw_val = ""
                if cell_type == "s" and value_elem is not None and value_elem.text is not None:
                    idx = int(value_elem.text)
                    if not 0 <= idx < len(shared_strings):
                        return StructuredCandidate(XLSX_MEDIA_TYPE, (), "unsupported_structure", "invalid_xlsx_shared_string")
                    raw_val = shared_strings[idx]
                elif cell_type == "inlineStr" and inline_elem is not None:
                    raw_val = "".join(t.text or "" for t in inline_elem.iter() if _local_tag(t.tag) == "t")
                elif cell_type == "b" and value_elem is not None and value_elem.text is not None:
                    raw_val = "TRUE" if value_elem.text.strip() == "1" else "FALSE"
                elif value_elem is not None and value_elem.text is not None:
                    raw_val = value_elem.text
                cleaned = _normalize_whitespace(raw_val)
                if cleaned:
                    cell_texts.append(f"{cell_ref}={cleaned}")
            if not cell_texts:
                continue
            ordinal += 1
            if ordinal > MAX_PASSAGES:
                return StructuredCandidate(XLSX_MEDIA_TYPE, (), "size_limit", "passage_limit_exceeded")
            text = f"[{sheet_name} R{row_num}] " + " | ".join(cell_texts)
            encoded = text.encode("utf-8")
            if len(encoded) > MAX_PASSAGE_BYTES:
                return StructuredCandidate(XLSX_MEDIA_TYPE, (), "size_limit", "passage_size_exceeded")
            passages.append(
                StructuredPassage(
                    kind="xlsx_row",
                    structured_locator=f"sheet:{sheet_idx}!row:{row_num}",
                    heading_path=(sheet_name[:120],),
                    paragraph=ordinal,
                    text=text,
                    digest=sha256(encoded).digest(),
                )
            )

    if not passages:
        return StructuredCandidate(XLSX_MEDIA_TYPE, (), "empty", "empty_xlsx_content")
    return StructuredCandidate(XLSX_MEDIA_TYPE, tuple(passages))


def _extract_pptx_text_blocks(root: ET.Element) -> tuple[str | None, list[str]]:
    title_text: str | None = None
    lines: list[str] = []
    for sp in root.iter():
        tag = _local_tag(sp.tag)
        if tag == "sp":
            is_title = False
            for ph in sp.iter():
                if _local_tag(ph.tag) == "ph" and ph.attrib.get("type") in ("title", "ctrTitle"):
                    is_title = True
                    break
            shape_paras: list[str] = []
            for p_elem in sp.iter():
                if _local_tag(p_elem.tag) == "p":
                    runs = [t.text or "" for t in p_elem.iter() if _local_tag(t.tag) == "t"]
                    joined = _normalize_whitespace("".join(runs))
                    if joined:
                        shape_paras.append(joined)
            if shape_paras:
                if is_title and title_text is None:
                    title_text = shape_paras[0][:120]
                lines.extend(shape_paras)
        elif tag == "tbl":
            for tr in sp:
                if _local_tag(tr.tag) != "tr":
                    continue
                row_cells: list[str] = []
                for tc in tr:
                    if _local_tag(tc.tag) != "tc":
                        continue
                    cell_text = _normalize_whitespace(
                        " ".join(t.text or "" for t in tc.iter() if _local_tag(t.tag) == "t")
                    )
                    if cell_text:
                        row_cells.append(cell_text)
                if row_cells:
                    lines.append(" | ".join(row_cells))
    return title_text, lines


def parse_pptx(payload: bytes) -> StructuredCandidate:
    members = _safe_read_zip_members(payload)
    if members is None or not PPTX_PARTS <= members.keys():
        return StructuredCandidate(PPTX_MEDIA_TYPE, (), "unsupported_structure", "invalid_pptx_archive")

    pres_root = _parse_xml_strict(members["ppt/presentation.xml"])
    if pres_root is None:
        return StructuredCandidate(PPTX_MEDIA_TYPE, (), "unsupported_structure", "invalid_pptx_xml")

    rel_map: dict[str, str] = {}
    rels_bytes = members.get("ppt/_rels/presentation.xml.rels")
    if rels_bytes is not None:
        rels_root = _parse_xml_strict(rels_bytes)
        if rels_root is None:
            return StructuredCandidate(PPTX_MEDIA_TYPE, (), "unsupported_structure", "invalid_pptx_xml")
        for rel in rels_root:
            if _local_tag(rel.tag) == "Relationship":
                rid = rel.attrib.get("Id")
                target = rel.attrib.get("Target")
                if rid and target:
                    rel_map[rid] = _resolve_rel_target("ppt", target)

    slide_paths: list[str] = []
    for elem in pres_root.iter():
        if _local_tag(elem.tag) == "sldId":
            rid = None
            for k, v in elem.attrib.items():
                if k.endswith("}id") or k == "id":
                    rid = v
                    break
            if rid and rid in rel_map:
                slide_paths.append(rel_map[rid])

    if not slide_paths:
        slide_paths = sorted(
            name for name in members if re.fullmatch(r"ppt/slides/slide\d+\.xml", name)
        )
    if not slide_paths:
        return StructuredCandidate(PPTX_MEDIA_TYPE, (), "empty", "empty_pptx_presentation")

    passages: list[StructuredPassage] = []
    ordinal = 0
    for slide_idx, slide_path in enumerate(slide_paths, start=1):
        slide_bytes = members.get(slide_path)
        if slide_bytes is None:
            return StructuredCandidate(PPTX_MEDIA_TYPE, (), "unsupported_structure", "missing_pptx_slide")
        slide_root = _parse_xml_strict(slide_bytes)
        if slide_root is None:
            return StructuredCandidate(PPTX_MEDIA_TYPE, (), "unsupported_structure", "invalid_pptx_xml")
        title_text, body_lines = _extract_pptx_text_blocks(slide_root)
        slide_heading = title_text or f"Slide {slide_idx}"
        if body_lines:
            ordinal += 1
            if ordinal > MAX_PASSAGES:
                return StructuredCandidate(PPTX_MEDIA_TYPE, (), "size_limit", "passage_limit_exceeded")
            text = "\n".join(body_lines)
            encoded = text.encode("utf-8")
            if len(encoded) > MAX_PASSAGE_BYTES:
                return StructuredCandidate(PPTX_MEDIA_TYPE, (), "size_limit", "passage_size_exceeded")
            passages.append(
                StructuredPassage(
                    kind="pptx_slide",
                    structured_locator=f"slide:{slide_idx}",
                    heading_path=(slide_heading,),
                    paragraph=ordinal,
                    text=text,
                    digest=sha256(encoded).digest(),
                )
            )

        # Optional speaker notes slide via slide rels
        slide_dir, slide_base = posixpath.split(slide_path)
        slide_rels_path = posixpath.join(slide_dir, "_rels", f"{slide_base}.rels")
        slide_rels_bytes = members.get(slide_rels_path)
        if slide_rels_bytes is not None:
            slide_rels_root = _parse_xml_strict(slide_rels_bytes)
            if slide_rels_root is not None:
                for rel in slide_rels_root:
                    if _local_tag(rel.tag) == "Relationship" and "notesSlide" in (rel.attrib.get("Type") or ""):
                        target = rel.attrib.get("Target")
                        if target:
                            notes_path = _resolve_rel_target(slide_dir, target)
                            notes_bytes = members.get(notes_path)
                            if notes_bytes is not None:
                                notes_root = _parse_xml_strict(notes_bytes)
                                if notes_root is not None:
                                    _, note_lines = _extract_pptx_text_blocks(notes_root)
                                    if note_lines:
                                        ordinal += 1
                                        if ordinal > MAX_PASSAGES:
                                            return StructuredCandidate(PPTX_MEDIA_TYPE, (), "size_limit", "passage_limit_exceeded")
                                        note_text = "\n".join(note_lines)
                                        note_encoded = note_text.encode("utf-8")
                                        if len(note_encoded) > MAX_PASSAGE_BYTES:
                                            return StructuredCandidate(PPTX_MEDIA_TYPE, (), "size_limit", "passage_size_exceeded")
                                        passages.append(
                                            StructuredPassage(
                                                kind="pptx_slide",
                                                structured_locator=f"slide:{slide_idx}!notes",
                                                heading_path=(slide_heading, "notes"),
                                                paragraph=ordinal,
                                                text=note_text,
                                                digest=sha256(note_encoded).digest(),
                                            )
                                        )

    if not passages:
        return StructuredCandidate(PPTX_MEDIA_TYPE, (), "empty", "empty_pptx_content")
    return StructuredCandidate(PPTX_MEDIA_TYPE, tuple(passages))


class _HtmlEvidenceExtractor(HTMLParser):
    IGNORED_TAGS = frozenset({"script", "style", "noscript", "template", "svg", "head"})
    HEADING_LEVELS = {"h1": 1, "h2": 2, "h3": 3, "h4": 4, "h5": 5, "h6": 6}
    BLOCK_TAGS = frozenset({"p", "li", "blockquote", "pre", "tr", "dt", "dd", "figcaption"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._ignore_depth = 0
        self._heading_stack: list[tuple[int, str]] = []
        self._current_heading_level: int | None = None
        self._heading_buf: list[str] = []
        self._block_depth = 0
        self._in_tr = False
        self._tr_cells: list[str] = []
        self._cell_buf: list[str] = []
        self._in_cell = False
        self._block_buf: list[str] = []
        self._title_buf: list[str] = []
        self._in_title = False
        self.doc_title: str = ""
        self.blocks: list[tuple[tuple[str, ...], str]] = []

    def _current_path(self) -> tuple[str, ...]:
        if self._heading_stack:
            return tuple(text for _, text in self._heading_stack[:6])
        if self.doc_title:
            return (self.doc_title[:120],)
        return ("html",)

    def _flush_block(self):
        text = _normalize_whitespace("".join(self._block_buf))
        self._block_buf.clear()
        if text:
            self.blocks.append((self._current_path(), text))

    def handle_starttag(self, tag: str, attrs):
        name = tag.lower()
        if name == "title":
            self._in_title = True
            return
        if name in self.IGNORED_TAGS:
            self._ignore_depth += 1
            return
        if self._ignore_depth > 0:
            return
        if name in self.HEADING_LEVELS:
            self._flush_block()
            self._current_heading_level = self.HEADING_LEVELS[name]
            self._heading_buf.clear()
            return
        if name == "tr":
            self._flush_block()
            self._in_tr = True
            self._tr_cells = []
            return
        if name in ("td", "th") and self._in_tr:
            self._in_cell = True
            self._cell_buf = []
            return
        if name in self.BLOCK_TAGS:
            self._flush_block()
            self._block_depth += 1
        elif name == "br":
            if self._in_cell:
                self._cell_buf.append(" ")
            elif self._current_heading_level is not None:
                self._heading_buf.append(" ")
            else:
                self._block_buf.append(" ")

    def handle_endtag(self, tag: str):
        name = tag.lower()
        if name == "title":
            self._in_title = False
            self.doc_title = _normalize_whitespace("".join(self._title_buf))
            self._title_buf.clear()
            return
        if name in self.IGNORED_TAGS:
            if self._ignore_depth > 0:
                self._ignore_depth -= 1
            return
        if self._ignore_depth > 0:
            return
        if name in self.HEADING_LEVELS and self._current_heading_level is not None:
            heading_text = _normalize_whitespace("".join(self._heading_buf))[:120]
            self._heading_buf.clear()
            level = self._current_heading_level
            self._current_heading_level = None
            if heading_text:
                while self._heading_stack and self._heading_stack[-1][0] >= level:
                    self._heading_stack.pop()
                self._heading_stack.append((level, heading_text))
            return
        if name in ("td", "th") and self._in_cell:
            cell_text = _normalize_whitespace("".join(self._cell_buf))
            self._cell_buf.clear()
            self._in_cell = False
            if cell_text:
                self._tr_cells.append(cell_text)
            return
        if name == "tr" and self._in_tr:
            self._in_tr = False
            if self._tr_cells:
                self.blocks.append((self._current_path(), " | ".join(self._tr_cells)))
            self._tr_cells = []
            return
        if name in self.BLOCK_TAGS:
            self._flush_block()
            if self._block_depth > 0:
                self._block_depth -= 1

    def handle_data(self, data: str):
        if self._in_title:
            self._title_buf.append(data)
            return
        if self._ignore_depth > 0:
            return
        if self._current_heading_level is not None:
            self._heading_buf.append(data)
        elif self._in_cell:
            self._cell_buf.append(data)
        else:
            self._block_buf.append(data)

    def close(self):
        super().close()
        self._flush_block()


def parse_html(payload: bytes) -> StructuredCandidate:
    if not payload:
        return StructuredCandidate(HTML_MEDIA_TYPE, (), "empty", "empty_html_payload")
    if len(payload) > MAX_HTML_BYTES:
        return StructuredCandidate(HTML_MEDIA_TYPE, (), "size_limit", "html_size_limit")
    if b"\x00" in payload:
        return StructuredCandidate(HTML_MEDIA_TYPE, (), "invalid_encoding", "invalid_html_payload")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        return StructuredCandidate(HTML_MEDIA_TYPE, (), "invalid_encoding", "invalid_utf8_html")

    extractor = _HtmlEvidenceExtractor()
    extractor.feed(decoded)
    extractor.close()

    passages: list[StructuredPassage] = []
    for ordinal, (path, text) in enumerate(extractor.blocks, start=1):
        if ordinal > MAX_PASSAGES:
            return StructuredCandidate(HTML_MEDIA_TYPE, (), "size_limit", "passage_limit_exceeded")
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_PASSAGE_BYTES:
            return StructuredCandidate(HTML_MEDIA_TYPE, (), "size_limit", "passage_size_exceeded")
        passages.append(
            StructuredPassage(
                kind="html_block",
                structured_locator=f"block:{ordinal}",
                heading_path=path,
                paragraph=ordinal,
                text=text,
                digest=sha256(encoded).digest(),
            )
        )
    if not passages:
        return StructuredCandidate(HTML_MEDIA_TYPE, (), "empty", "empty_html_content")
    return StructuredCandidate(HTML_MEDIA_TYPE, tuple(passages))


def validate_image_magic(payload: bytes, media_type: str) -> bool:
    if not payload or len(payload) > MAX_IMAGE_BYTES:
        return False
    if media_type == PNG_MEDIA_TYPE:
        return payload.startswith(PNG_MAGIC)
    if media_type == JPEG_MEDIA_TYPE:
        return payload.startswith(JPEG_MAGIC)
    return False


def parse_image_ocr(
    payload: bytes,
    media_type: str,
    *,
    ocr: pdf_evidence.Tesseract | None,
) -> StructuredCandidate:
    if not payload:
        return StructuredCandidate(media_type, (), "empty", "empty_image_payload")
    if len(payload) > MAX_IMAGE_BYTES:
        return StructuredCandidate(media_type, (), "size_limit", "image_size_limit")
    if media_type not in IMAGE_MEDIA_TYPES or not validate_image_magic(payload, media_type):
        return StructuredCandidate(media_type, (), "unsupported_structure", "invalid_image_payload")
    if ocr is None:
        raise ImageOcrUnavailable("Standalone image OCR requires an admitted local Tesseract engine.")
    try:
        ocr.fingerprint()
        text, reason = ocr.read(payload, remaining=10.0)
    except pdf_evidence.PdfDependencyUnavailable as exc:
        raise ImageOcrUnavailable(str(exc)) from None
    if reason is not None:
        mapped: QuarantineReason = reason if reason in ("empty", "invalid_encoding", "unsupported_structure", "size_limit") else "unsupported_structure"
        return StructuredCandidate(media_type, (), mapped, f"image_ocr_{reason}")
    decoded_text = text.decode("utf-8", errors="strict") if isinstance(text, (bytes, bytearray)) else (text or "")
    cleaned = decoded_text.strip()
    if not cleaned:
        return StructuredCandidate(media_type, (), "empty", "empty_image_ocr")
    encoded = cleaned.encode("utf-8")
    if len(encoded) > MAX_PASSAGE_BYTES:
        return StructuredCandidate(media_type, (), "size_limit", "passage_size_exceeded")
    return StructuredCandidate(
        media_type,
        (
            StructuredPassage(
                kind="image_ocr",
                structured_locator="image:1",
                heading_path=(f"image:{media_type.split('/', 1)[1]}",),
                paragraph=1,
                text=cleaned,
                digest=sha256(encoded).digest(),
            ),
        ),
    )


def parse_structured(
    payload: bytes,
    media_type: str,
    *,
    ocr: pdf_evidence.Tesseract | None = None,
) -> StructuredCandidate:
    if media_type == XLSX_MEDIA_TYPE:
        return parse_xlsx(payload)
    if media_type == PPTX_MEDIA_TYPE:
        return parse_pptx(payload)
    if media_type == HTML_MEDIA_TYPE:
        return parse_html(payload)
    if media_type in IMAGE_MEDIA_TYPES:
        return parse_image_ocr(payload, media_type, ocr=ocr)
    raise ValueError(f"Unsupported structured media type: {media_type}")
