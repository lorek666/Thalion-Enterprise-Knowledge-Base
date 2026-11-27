from dataclasses import dataclass, field
from hashlib import sha256
from io import BytesIO
from typing import Literal
from xml.etree import ElementTree as ET
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile
from zlib import error as CompressionError

from .csv_evidence import AmountLayout, AmountUnitCandidate, CsvRow, amount_units_for_rows


MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PARSER_VERSION = "1"
PROFILE = "docx_literal_paragraphs_v1"
LOCATOR_REVISION = 1
MAX_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_PARTS = 128
MAX_PARAGRAPHS = 2048
MAX_TEXT_BYTES = 32768
MAX_TABLES = 16
MAX_TABLE_ROWS = 128
MAX_TABLE_COLUMNS = 16
MAX_TABLE_CELLS = 1024
MAX_CELL_PARAGRAPHS = 16
WORD = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships/"
RELATIONSHIP = "{" + PACKAGE_REL.removesuffix("/") + "}Relationship"
OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
OFFICE_XML = OFFICE_REL.removesuffix("relationships/")
CONTENT_TYPES = "{http://schemas.openxmlformats.org/package/2006/content-types}"
WORD_MEDIA = "application/vnd.openxmlformats-officedocument.wordprocessingml."
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
PARAGRAPH_FORMATTING = frozenset({
    "keepNext", "keepLines", "pageBreakBefore", "widowControl", "spacing", "ind", "jc",
    "contextualSpacing", "snapToGrid", "bidi", "suppressLineNumbers",
})
RUN_FORMATTING = frozenset({
    "rFonts", "b", "bCs", "i", "iCs", "color", "sz", "szCs", "lang", "u", "highlight", "rtl", "cs", "noProof",
})
STYLE_METADATA = frozenset({"name", "aliases", "next", "link", "uiPriority", "qFormat", "semiHidden", "unhideWhenUsed", "locked", "rsid"})
SECTION_FORMATTING = frozenset({"pgSz", "pgMar", "cols", "docGrid", "type", "vAlign"})
TABLE_FORMATTING = frozenset({"tblW", "tblInd", "tblLook", "tblLayout", "tblCellMar"})
TABLE_MARGIN_EDGES = frozenset({"top", "left", "bottom", "right", "start", "end"})
ROOT_RELATIONS = {
    OFFICE_REL + "officeDocument": ("word/document.xml", WORD + "document"),
    PACKAGE_REL + "metadata/core-properties": (
        "docProps/core.xml", "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}coreProperties",
    ),
    OFFICE_REL + "extended-properties": ("docProps/app.xml", "{" + OFFICE_XML + "extended-properties}Properties"),
    PACKAGE_REL + "metadata/thumbnail": ("docProps/thumbnail.jpeg", None),
}
EFFECTS_REL = "http://schemas.microsoft.com/office/2007/relationships/stylesWithEffects"
CUSTOM_REL = OFFICE_REL + "customXml"
DOCUMENT_RELATIONS = {
    OFFICE_REL + role: (role + ".xml", WORD + role) for role in ("styles", "settings", "webSettings", "numbering")
} | {
    OFFICE_REL + "fontTable": ("fontTable.xml", WORD + "fonts"),
    OFFICE_REL + "theme": ("theme/theme1.xml", "{http://schemas.openxmlformats.org/drawingml/2006/main}theme"),
    EFFECTS_REL: ("stylesWithEffects.xml", WORD + "styles"),
    CUSTOM_REL: ("../customXml/item1.xml", "{" + OFFICE_XML + "bibliography}Sources"),
}


@dataclass(frozen=True)
class DocxParagraph:
    heading_path: tuple[str, ...] = field(repr=False)
    paragraph: int
    document_paragraph: int
    text: bytes = field(repr=False)

    @property
    def digest(self) -> bytes:
        return sha256(self.text).digest()


@dataclass(frozen=True)
class DocxTable:
    ordinal: int
    heading_path: tuple[str, ...] = field(repr=False)
    headers: tuple[str, ...] = field(repr=False)
    rows: tuple[CsvRow, ...]
    units: tuple[AmountUnitCandidate, ...]


@dataclass(frozen=True)
class DocxCandidate:
    outcome: Literal["pending_review", "quarantined"]
    reason: Literal["empty", "unsupported_structure", "size_limit"] | None = None
    passages: tuple[DocxParagraph, ...] = ()
    tables: tuple[DocxTable, ...] = ()


class _Unsupported(Exception):
    pass


class _SizeLimit(Exception):
    pass


def _xml(archive: ZipFile, name: str) -> ET.Element:
    entry = archive.getinfo(name)
    if entry.file_size > MAX_BYTES:
        raise _SizeLimit
    with archive.open(entry) as stream:
        literal = stream.read(MAX_BYTES + 1).decode("utf-8-sig")
    if "<!" in literal or "\0" in literal:
        raise _Unsupported
    return ET.fromstring(literal)


def _relationships(root: ET.Element) -> tuple[tuple[str, str], ...]:
    if root.tag != RELATIONSHIP.removesuffix("Relationship") + "Relationships":
        raise _Unsupported
    seen = set()
    relations = []
    for node in root:
        ref, role, target = (node.get(name) for name in ("Id", "Type", "Target"))
        if (node.tag != RELATIONSHIP or len(node) or not ref or not role or not target
                or ref in seen or node.get("TargetMode", "Internal") != "Internal"):
            raise _Unsupported
        seen.add(ref)
        relations.append((role, target))
    return tuple(relations)


def _related_parts(archive, relation_path, supported, parent=""):
    parts = {}
    for role, target in _relationships(_xml(archive, relation_path)):
        relative, tag = supported[role]
        name = relative.removeprefix("../") if relative.startswith("../") else parent + relative
        if role in parts or target not in (relative, "/" + name):
            raise _Unsupported
        archive.getinfo(name)
        node = _xml(archive, name) if tag is not None else None
        if node is not None and node.tag != tag:
            raise _Unsupported
        parts[role] = node
    return parts


def _parts(archive: ZipFile) -> tuple[ET.Element, tuple[ET.Element | None, ...]]:
    entries = archive.infolist()
    if len(entries) > MAX_PARTS or sum(entry.file_size for entry in entries) > MAX_EXPANDED_BYTES:
        raise _SizeLimit
    names = {entry.filename for entry in entries}
    if len({name.casefold() for name in names}) != len(entries) or any(
        entry.orig_filename != entry.filename or entry.flag_bits & 1
        or entry.compress_type not in (ZIP_STORED, ZIP_DEFLATED)
        or "\\" in entry.filename or any(part in ("", ".", "..") for part in entry.filename.split("/"))
        for entry in entries
    ):
        raise _Unsupported
    types = _xml(archive, "[Content_Types].xml")
    if types.tag != CONTENT_TYPES + "Types":
        raise _Unsupported
    declarations = {}
    for node in types:
        if node.tag == CONTENT_TYPES + "Override":
            name = node.attrib["PartName"]
            if name in declarations:
                raise _Unsupported
            declarations[name] = node.attrib["ContentType"]
        elif node.tag != CONTENT_TYPES + "Default":
            raise _Unsupported
    if declarations.get("/word/document.xml") != WORD_MEDIA + "document.main+xml":
        raise _Unsupported
    document = _related_parts(archive, "_rels/.rels", ROOT_RELATIONS)[OFFICE_REL + "officeDocument"]
    relation_path = "word/_rels/document.xml.rels"
    related = _related_parts(archive, relation_path, DOCUMENT_RELATIONS, "word/") if relation_path in names else {}
    allowed_relation_paths = {"_rels/.rels", relation_path}
    if CUSTOM_REL in related:
        _leaf(related[CUSTOM_REL])
        custom_path = "customXml/_rels/item1.xml.rels"
        if not _related_parts(archive, custom_path, {
            OFFICE_REL + "customXmlProps": ("itemProps1.xml", "{" + OFFICE_XML + "customXml}datastoreItem"),
        }, "customXml/"):
            raise _Unsupported
        allowed_relation_paths.add(custom_path)
    if any(name.endswith(".rels") and name not in allowed_relation_paths for name in names):
        raise _Unsupported
    styles = related.get(OFFICE_REL + "styles")
    if styles is not None and declarations.get("/word/styles.xml") != WORD_MEDIA + "styles+xml":
        raise _Unsupported
    if styles is None and ("word/styles.xml" in names or EFFECTS_REL in related):
        raise _Unsupported
    effects = related.get(EFFECTS_REL)
    if effects is None and "word/stylesWithEffects.xml" in names:
        raise _Unsupported
    return document, (styles,) if effects is None else (styles, effects)


def _elements(node: ET.Element, allowed: frozenset[str]) -> dict[str, ET.Element]:
    children = {}
    if node.text and node.text.strip():
        raise _Unsupported
    for child in node:
        name = child.tag.removeprefix(WORD)
        if (child.tag != WORD + name or name not in allowed or name in children
                or (child.tail and child.tail.strip())):
            raise _Unsupported
        children[name] = child
    return children


def _leaf(node: ET.Element):
    if len(node) or (node.text and node.text.strip()):
        raise _Unsupported


def _properties(node: ET.Element, allowed: frozenset[str]) -> dict[str, ET.Element]:
    children = _elements(node, allowed)
    for child in children.values():
        _leaf(child)
    return children


def _outline(properties: dict[str, ET.Element]) -> int | None:
    if "outlineLvl" not in properties:
        return None
    value = properties["outlineLvl"].get(WORD + "val")
    if value not in tuple("0123459"):
        raise _Unsupported
    return int(value)


def _style_catalogue(root: ET.Element | None) -> tuple[dict[str, ET.Element], str | None, int | None]:
    if root is None:
        return {}, None, None
    if root.tag != WORD + "styles":
        raise _Unsupported
    styles = {}
    default = None
    defaults = None
    for node in root:
        if node.tag == WORD + "docDefaults" and defaults is None:
            defaults = _elements(node, frozenset({"pPrDefault", "rPrDefault"}))
        elif node.tag == WORD + "style":
            style_id = node.attrib[WORD + "styleId"]
            if not style_id or style_id in styles:
                raise _Unsupported
            styles[style_id] = node
            if node.get(WORD + "type") == "paragraph" and node.get(WORD + "default") in ("1", "true", "on"):
                if default is not None:
                    raise _Unsupported
                default = style_id
        elif node.tag != WORD + "latentStyles":
            raise _Unsupported
    outline = None
    for name, node in (defaults or {}).items():
        property_name = name.removesuffix("Default")
        settings = _elements(node, frozenset({property_name})).get(property_name)
        if settings is not None:
            if property_name == "rPr":
                _properties(settings, RUN_FORMATTING)
            else:
                outline = _outline(_properties(settings, PARAGRAPH_FORMATTING | {"outlineLvl"}))
    return styles, default, outline


def _style_outline(styles: dict[str, ET.Element], style_id: str | None) -> int | None:
    visited = set()
    outline = None
    while style_id is not None:
        if style_id in visited or len(visited) >= 32:
            raise _Unsupported
        visited.add(style_id)
        node = styles[style_id]
        if node.get(WORD + "type") != "paragraph":
            raise _Unsupported
        children = _elements(node, STYLE_METADATA | {"basedOn", "pPr", "rPr"})
        if "pPr" in children:
            depth = _outline(_properties(children["pPr"], PARAGRAPH_FORMATTING | {"outlineLvl"}))
            if outline is None:
                outline = depth
        if "rPr" in children:
            _properties(children["rPr"], RUN_FORMATTING)
        for name in children.keys() - {"pPr", "rPr"}:
            _leaf(children[name])
        style_id = children["basedOn"].attrib[WORD + "val"] if "basedOn" in children else None
    return outline


def _effective_style_outline(catalogue, style_id):
    styles, default_style, default_outline = catalogue
    outline = _style_outline(styles, default_style if style_id is None else style_id)
    return default_outline if outline is None else outline


def _paragraph(node: ET.Element) -> tuple[bytes, int | None, str | None]:
    parts = []
    outline = style_id = None
    if node.text and node.text.strip():
        raise _Unsupported
    for index, child in enumerate(node):
        if child.tail and child.tail.strip():
            raise _Unsupported
        if child.tag == WORD + "pPr" and index == 0:
            properties = _properties(child, PARAGRAPH_FORMATTING | {"pStyle", "outlineLvl"})
            outline = _outline(properties)
            if "pStyle" in properties:
                style_id = properties["pStyle"].attrib[WORD + "val"]
        elif child.tag == WORD + "r" and not (child.text and child.text.strip()):
            for run_index, item in enumerate(child):
                if item.tail and item.tail.strip():
                    raise _Unsupported
                if item.tag == WORD + "rPr" and run_index == 0:
                    _properties(item, RUN_FORMATTING)
                elif item.tag == WORD + "t" and not len(item) and item.attrib.keys() <= {XML_SPACE}:
                    if any(character in (item.text or "") for character in "\n\r\t"):
                        raise _Unsupported
                    parts.append(item.text or "")
                elif item.tag in (WORD + "tab", WORD + "cr", WORD + "br"):
                    _leaf(item)
                    attrs = item.attrib
                    if attrs and not (item.tag == WORD + "br" and attrs == {WORD + "type": "textWrapping"}):
                        raise _Unsupported
                    parts.append("\t" if item.tag == WORD + "tab" else "\n")
                else:
                    raise _Unsupported
        else:
            raise _Unsupported
    text = "".join(parts).encode("utf-8")
    if len(text) > MAX_TEXT_BYTES:
        raise _SizeLimit
    return text, outline, style_id


def _resolved_paragraph(node, catalogues, outlines):
    text, outline, style_id = _paragraph(node)
    if style_id not in outlines:
        outlines[style_id] = {_effective_style_outline(catalogue, style_id) for catalogue in catalogues}
    if outline is None:
        if len(outlines[style_id]) != 1:
            raise _Unsupported
        outline, = outlines[style_id]
    return text, outline


def _table_children(node, member, *properties):
    children = []
    metadata = {}
    allowed = {WORD + name: index for index, name in enumerate(properties)}
    previous = -1
    if node.text and node.text.strip():
        raise _Unsupported
    for child in node:
        if child.tail and child.tail.strip():
            raise _Unsupported
        if child.tag == WORD + member:
            children.append(child)
        elif not children and child.tag in allowed and allowed[child.tag] > previous:
            previous = allowed[child.tag]
            metadata[properties[previous]] = child
        else:
            raise _Unsupported
    return children, metadata


def _table_format(node):
    for name, child in _elements(node, TABLE_FORMATTING).items():
        if name == "tblCellMar":
            _properties(child, TABLE_MARGIN_EDGES)
        else:
            _leaf(child)


def _validate_default_table_styles(catalogues):
    for catalogue, _, _ in catalogues:
        defaults = [style for style in catalogue.values()
                    if style.get(WORD + "type") == "table" and style.get(WORD + "default") in ("1", "true", "on")]
        if len(defaults) > 1:
            raise _Unsupported
        for style in defaults:
            for name, node in _elements(style, STYLE_METADATA | {"tblPr"}).items():
                if name == "tblPr":
                    _table_format(node)
                else:
                    _leaf(node)


def _docx_table(node, ordinal, headings, catalogues, outlines, layout, cell_budget):
    rows, metadata = _table_children(node, "tr", "tblPr", "tblGrid")
    if len(rows) > MAX_TABLE_ROWS:
        raise _SizeLimit
    if len(rows) < 2 or "tblGrid" not in metadata:
        raise _Unsupported
    columns, _ = _table_children(metadata["tblGrid"], "gridCol")
    if len(columns) > MAX_TABLE_COLUMNS:
        raise _SizeLimit
    if not columns:
        raise _Unsupported
    if len(rows) * len(columns) > cell_budget:
        raise _SizeLimit
    for column in columns:
        _leaf(column)
        if column.attrib.keys() - {WORD + "w"}:
            raise _Unsupported
    if "tblPr" in metadata:
        _table_format(metadata["tblPr"])

    records = []
    for number, row in enumerate(rows, 1):
        cells, properties = _table_children(row, "tc", "trPr")
        if len(cells) != len(columns):
            raise _Unsupported
        if "trPr" in properties:
            allowed = frozenset({"tblHeader", "cantSplit"} if number == 1 else {"cantSplit"})
            _properties(properties["trPr"], allowed)
        values = []
        for cell in cells:
            paragraphs, properties = _table_children(cell, "p", "tcPr")
            if not paragraphs:
                raise _Unsupported
            if len(paragraphs) > MAX_CELL_PARAGRAPHS:
                raise _SizeLimit
            if "tcPr" in properties:
                _properties(properties["tcPr"], frozenset({"tcW"}))
            parts = []
            for paragraph in paragraphs:
                text, outline = _resolved_paragraph(paragraph, catalogues, outlines)
                if outline not in (None, 9):
                    raise _Unsupported
                parts.append(text)
            literal = b"\n".join(parts)
            if len(literal) > MAX_TEXT_BYTES:
                raise _SizeLimit
            values.append(literal.decode("utf-8"))
        records.append(CsvRow(number, tuple(values)))
    headers = records[0].values
    keys = {header.strip().casefold() for header in headers}
    if "" in keys or len(keys) != len(headers) or any(
        len(header) > 128 or any(ord(character) < 32 or ord(character) == 127 for character in header) for header in headers
    ):
        raise _Unsupported
    data_rows = tuple(records[1:])
    units = amount_units_for_rows(headers, data_rows, layout)
    return DocxTable(ordinal, headings, headers, data_rows, units)


def parse_docx(payload: bytes, *, amount_columns: tuple[str, str, str, str] | None = None) -> DocxCandidate:
    if len(payload) > MAX_BYTES:
        return DocxCandidate("quarantined", "size_limit")
    layout = AmountLayout(*amount_columns) if amount_columns is not None else None
    try:
        with ZipFile(BytesIO(payload)) as archive:
            document, style_roots = _parts(archive)
        body = _elements(document, frozenset({"body"}))["body"]
        if body.text and body.text.strip():
            raise _Unsupported
        catalogues = tuple(_style_catalogue(root) for root in style_roots)
        outlines = {}
        headings = []
        passages = []
        tables = []
        table_cells = 0
        paragraph = 0
        document_paragraph = 0
        for index, node in enumerate(body, start=1):
            if node.tail and node.tail.strip():
                raise _Unsupported
            if node.tag == WORD + "sectPr" and index == len(body):
                _properties(node, SECTION_FORMATTING)
                continue
            if node.tag == WORD + "tbl" and layout is not None:
                if len(tables) == MAX_TABLES:
                    raise _SizeLimit
                if not tables:
                    _validate_default_table_styles(catalogues)
                table = _docx_table(
                    node, len(tables) + 1, tuple(title for _, title in headings), catalogues, outlines, layout,
                    MAX_TABLE_CELLS - table_cells,
                )
                table_cells += len(table.headers) * (1 + len(table.rows))
                tables.append(table)
                continue
            if node.tag != WORD + "p":
                raise _Unsupported
            document_paragraph += 1
            if document_paragraph > MAX_PARAGRAPHS:
                raise _SizeLimit
            text, outline = _resolved_paragraph(node, catalogues, outlines)
            if outline is not None and outline < 9:
                title = text.decode("utf-8")
                if not title.strip() or len(title) > 512 or "\n" in title or "\t" in title:
                    raise _Unsupported
                while headings and headings[-1][0] >= outline:
                    headings.pop()
                headings.append((outline, title))
                paragraph = 0
                continue
            paragraph += 1
            if text.strip():
                passages.append(DocxParagraph(tuple(title for _, title in headings), paragraph, document_paragraph, text))
    except _SizeLimit:
        return DocxCandidate("quarantined", "size_limit")
    except (_Unsupported, BadZipFile, ET.ParseError, UnicodeError, KeyError, RuntimeError, EOFError, CompressionError):
        return DocxCandidate("quarantined", "unsupported_structure")
    if not passages and not tables:
        return DocxCandidate("quarantined", "empty")
    return DocxCandidate("pending_review", passages=tuple(passages), tables=tuple(tables))
