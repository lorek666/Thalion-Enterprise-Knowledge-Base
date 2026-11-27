from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import struct
from uuid import uuid4
from zipfile import ZipFile
import zlib

from fastapi.testclient import TestClient
import pytest

from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import multiformat_evidence, pdf_evidence, processing
from enterprise_kb.modules.retrieval import lexical, vector
from enterprise_kb.modules.sources import effectivity, ingest, registry
from enterprise_kb.runtime.jobs import claim_job
from enterprise_kb.transport import api, evidence

from test_evidence import create_evidence_db
from test_evidence_transport import bearer
from test_persisted_access import authority_for, binding, set_rules
from test_runtime import LEASE_FOR, open_database, runtime_db
from test_sources import request_for


BEFORE = date(2026, 11, 20)
SEARCH_FIELDS = frozenset({"excerpt", "citation", "title", "location", "version"})


def _build_xlsx(*, include_uncomputed_formula: bool = False) -> bytes:
    buf = BytesIO()
    with ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="住宿标准" sheetId="1" r:id="rId1"/></sheets></workbook>',
        )
        zf.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '</Relationships>',
        )
        zf.writestr(
            "xl/sharedStrings.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<si><t>城市</t></si>'
            '<si><t>限额</t></si>'
            '<si><t>上海</t></si>'
            '<si><t>680元每晚不可超标</t></si>'
            '</sst>',
        )
        extra_formula = '<row r="3"><c r="A3"><f>SUM(B2:B2)</f></c></row>' if include_uncomputed_formula else ""
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData>'
            '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
            '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2" t="s"><v>3</v></c></row>'
            f'{extra_formula}'
            '</sheetData></worksheet>',
        )
    return buf.getvalue()


def _build_pptx() -> bytes:
    buf = BytesIO()
    with ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr(
            "ppt/presentation.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>',
        )
        zf.writestr(
            "ppt/_rels/presentation.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>'
            '</Relationships>',
        )
        zf.writestr(
            "ppt/slides/slide1.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            '<p:cSld><p:spTree>'
            '<p:sp><p:nvSpPr><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr>'
            '<p:txBody><a:p><a:r><a:t>差旅交通规范幻灯片</a:t></a:r></a:p></p:txBody></p:sp>'
            '<p:sp><p:nvSpPr><p:nvPr/></p:nvSpPr>'
            '<p:txBody><a:p><a:r><a:t>高铁二等座按实报销，禁止无审批升舱。</a:t></a:r></a:p></p:txBody></p:sp>'
            '</p:spTree></p:cSld></p:sld>',
        )
        zf.writestr(
            "ppt/slides/_rels/slide1.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../notesSlides/notesSlide1.xml"/>'
            '</Relationships>',
        )
        zf.writestr(
            "ppt/notesSlides/notesSlide1.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            '<p:cSld><p:spTree><p:sp><p:nvSpPr><p:nvPr/></p:nvSpPr>'
            '<p:txBody><a:p><a:r><a:t>演讲者备注：特殊紧急行程须总监签批。</a:t></a:r></a:p></p:txBody></p:sp>'
            '</p:spTree></p:cSld></p:notes>',
        )
    return buf.getvalue()


def _build_html() -> bytes:
    return (
        "<!doctype html><html><head><title>报销细则HTML</title>"
        "<style>.hidden{display:none;} SECRET_CSS_TOKEN</style>"
        "<script>var SECRET_JS_TOKEN = 999999;</script></head>"
        "<body><h1>海外差旅</h1><h2>餐饮补贴</h2>"
        "<p>新加坡出差餐饮补贴每日不超过 120 美元。</p>"
        "<table><tr><th>城市</th><th>补贴</th></tr><tr><td>新加坡</td><td>120 USD</td></tr></table>"
        "</body></html>"
    ).encode("utf-8")


# Crisp 5x7 pixel font for high-confidence OCR PNG synthesis (zero external libs)
_GLYPHS = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "C": ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["11111", "00100", "00100", "00100", "00100", "00100", "11111"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10001", "10001", "10001", "10001"],
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "0": ["01110", "10011", "10101", "10101", "11001", "10001", "01110"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["01110", "10000", "11110", "10001", "10001", "10001", "01110"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
}


def _render_crisp_text_png(text: str) -> bytes:
    try:
        from contextlib import closing
        import pypdfium2 as pdfium
        from test_pdf_processing import pdf_document, text_page

        with pdfium.PdfDocument(pdf_document(text_page(text.encode("ascii")))) as native:
            with closing(native[0]) as page, closing(page.render(scale=3, grayscale=True)) as bitmap:
                width, height = bitmap.width, bitmap.height
                rows = [
                    bytes(bitmap.buffer[offset:offset + width])
                    for offset in range(0, height * bitmap.stride, bitmap.stride)
                ]
        raw = b"".join(b"\x00" + r for r in rows)

        def _chunk(ctype: bytes, data: bytes) -> bytes:
            return struct.pack("!I", len(data)) + ctype + data + struct.pack("!I", zlib.crc32(ctype + data) & 0xFFFFFFFF)

        ihdr = struct.pack("!IIBBBBB", width, height, 8, 0, 0, 0, 0)
        return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")
    except Exception:
        return _synthesize_text_png(text.upper())


def _synthesize_text_png(text: str, scale: int = 8) -> bytes:
    margin = 40
    char_w = 5 * scale
    gap = 2 * scale
    width = margin * 2 + len(text) * (char_w + gap)
    height = margin * 2 + 7 * scale
    rows = [bytearray([255] * width) for _ in range(height)]
    x_cursor = margin
    for ch in text:
        pattern = _GLYPHS.get(ch, _GLYPHS[" "])
        for r_idx, row_str in enumerate(pattern):
            for c_idx, bit in enumerate(row_str):
                if bit == "1":
                    for sy in range(scale):
                        for sx in range(scale):
                            rows[margin + r_idx * scale + sy][x_cursor + c_idx * scale + sx] = 0
        x_cursor += char_w + gap

    raw = b"".join(b"\x00" + bytes(r) for r in rows)

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + ctype + data + struct.pack("!I", zlib.crc32(ctype + data) & 0xFFFFFFFF)

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(raw))
        + _chunk(b"IEND", b"")
    )


def _register_approve_publish(db, *, object_key: str, display_name: str, media_type: str, payload: bytes, ocr=None):
    connection, tenant, _, source_ref, store = db
    reg_ctx = request_for(connection, tenant, tenant.worker_id, str(uuid4()), "register_version")
    version = registry.register_synthetic_version(
        connection,
        reg_ctx,
        registry.SourceVersion(
            tenant.space_id,
            source_ref,
            1,
            object_key,
            "v1",
            "rev-1",
            display_name,
            "1.0",
            sha256(payload).digest(),
            media_type=media_type,
        ),
        payload,
        store,
    )
    lease = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert lease is not None
    run = processing.process_evidence_job(connection, lease, store, pdf_ocr=ocr)
    if run.outcome == "quarantined":
        return version, run
    q_ctx = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "decide_evidence_quality")
    processing.decide_quality(connection, q_ctx, tenant.space_id, run.run_ref, run.manifest_digest, "approved", uuid4())
    eff_ctx = request_for(connection, tenant, tenant.other_actor_id, str(uuid4()), effectivity.APPROVE)
    effectivity.approve_synthetic_rule(
        connection,
        eff_ctx,
        tenant.space_id,
        version.version_ref,
        effectivity.Approval(
            BEFORE - timedelta(days=5),
            None,
            "shanghai",
            "employee",
            uuid4(),
        ),
    )
    return version, run


@pytest.fixture
def mf_db(runtime_db, tmp_path):
    connection, tenant, database_url = runtime_db
    return create_evidence_db(connection, tenant, database_url, tmp_path)


def test_xlsx_pptx_html_and_image_ocr_end_to_end_pipeline(mf_db):
    connection, tenant, database_url, source_ref, store = mf_db

    # 0. Verify ingest format detection recognizes all 5 new media types + rejects mismatched extension
    xlsx_bytes = _build_xlsx()
    pptx_bytes = _build_pptx()
    html_bytes = _build_html()
    png_bytes = _render_crisp_text_png("Travel hotel cap 680 CNY")
    assert ingest._detect(xlsx_bytes, "rates.xlsx") == multiformat_evidence.XLSX_MEDIA_TYPE
    assert ingest._detect(pptx_bytes, "deck.pptx") == multiformat_evidence.PPTX_MEDIA_TYPE
    assert ingest._detect(html_bytes, "policy.html") == multiformat_evidence.HTML_MEDIA_TYPE
    assert ingest._detect(png_bytes, "receipt.png") == multiformat_evidence.PNG_MEDIA_TYPE
    with pytest.raises(ValueError, match="unsupported_media"):
        ingest._detect(xlsx_bytes, "fake.docx")

    # 1. Uncomputed XLSX formula is quarantined fail-closed (never guesses values!)
    bad_xlsx = _build_xlsx(include_uncomputed_formula=True)
    _, bad_run = _register_approve_publish(
        mf_db,
        object_key="bad-xlsx",
        display_name="未求值公式表",
        media_type=multiformat_evidence.XLSX_MEDIA_TYPE,
        payload=bad_xlsx,
    )
    assert bad_run.outcome == "quarantined"
    assert bad_run.reason == "unsupported_structure"
    assert multiformat_evidence.parse_xlsx(bad_xlsx).detail == "uncomputed_xlsx_formula"

    # 2. Valid XLSX, PPTX, HTML end-to-end registration, parse, quality, lexical & vector index
    xlsx_ver, xlsx_run = _register_approve_publish(
        mf_db,
        object_key="rates-xlsx",
        display_name="上海住宿限额表",
        media_type=multiformat_evidence.XLSX_MEDIA_TYPE,
        payload=xlsx_bytes,
    )
    assert xlsx_run.outcome == "pending_review" and xlsx_run.passage_count == 2

    pptx_ver, pptx_run = _register_approve_publish(
        mf_db,
        object_key="rail-pptx",
        display_name="差旅交通幻灯片",
        media_type=multiformat_evidence.PPTX_MEDIA_TYPE,
        payload=pptx_bytes,
    )
    assert pptx_run.outcome == "pending_review" and pptx_run.passage_count == 2  # slide + notes

    html_ver, html_run = _register_approve_publish(
        mf_db,
        object_key="overseas-html",
        display_name="海外餐饮HTML政策",
        media_type=multiformat_evidence.HTML_MEDIA_TYPE,
        payload=html_bytes,
    )
    assert html_run.outcome == "pending_review" and html_run.passage_count >= 2

    # 3. Standalone PNG image OCR: missing OCR fails closed; real Tesseract extracts text cleanly
    reg_ctx = request_for(connection, tenant, tenant.worker_id, str(uuid4()), "register_version")
    png_ver = registry.register_synthetic_version(
        connection,
        reg_ctx,
        registry.SourceVersion(
            tenant.space_id,
            source_ref,
            1,
            "scan-png",
            "v1",
            "rev-1",
            "扫描公告图片",
            "1.0",
            sha256(png_bytes).digest(),
            media_type=multiformat_evidence.PNG_MEDIA_TYPE,
        ),
        png_bytes,
        store,
    )
    png_lease = claim_job(connection, tenant.org_id, "parse", tenant.other_worker_id, LEASE_FOR)
    assert png_lease is not None
    with pytest.raises(processing.ProcessingDependencyUnavailable):
        processing.process_evidence_job(connection, png_lease, store, pdf_ocr=None)

    tesseract_bin = shutil.which("tesseract")
    tessdata_dir = os.environ.get("THALION_TESSDATA_DIR", "/opt/homebrew/share/tessdata")
    png_indexed = False
    if tesseract_bin and Path(tessdata_dir).is_dir():
        ocr = pdf_evidence.Tesseract(Path(tesseract_bin).resolve(), Path(tessdata_dir).resolve())
        png_run = processing.process_evidence_job(connection, png_lease, store, pdf_ocr=ocr)
        assert png_run.outcome == "pending_review" and png_run.passage_count == 1
        q_ctx = request_for(connection, tenant, tenant.actor_id, str(uuid4()), "decide_evidence_quality")
        processing.decide_quality(connection, q_ctx, tenant.space_id, png_run.run_ref, png_run.manifest_digest, "approved", uuid4())
        eff_ctx = request_for(connection, tenant, tenant.other_actor_id, str(uuid4()), effectivity.APPROVE)
        effectivity.approve_synthetic_rule(
            connection,
            eff_ctx,
            tenant.space_id,
            png_ver.version_ref,
            effectivity.Approval(
                BEFORE - timedelta(days=5), None, "shanghai", "employee", uuid4(),
            ),
        )
        lexical.build_index(connection, store, tenant.space_ref, png_ver.version_ref, png_run.run_ref)
        vector.build_vector_index(
            connection, store, tenant.space_ref, png_ver.version_ref, png_run.run_ref,
            vector.resolve_synthetic_embedding_provider(vector.DEFAULT_MODEL_ID),
        )
        png_indexed = True

    # Build lexical + vector indices for XLSX, PPTX, HTML
    emb = vector.resolve_synthetic_embedding_provider(vector.DEFAULT_MODEL_ID)
    for ver, run in ((xlsx_ver, xlsx_run), (pptx_ver, pptx_run), (html_ver, html_run)):
        lexical.build_index(connection, store, tenant.space_ref, ver.version_ref, run.run_ref)
        vector.build_vector_index(connection, store, tenant.space_ref, ver.version_ref, run.run_ref, emb)

    # 4. Grant employee read + original download policies & verify HTTP search, passage read, and original download!
    now = datetime.now(UTC)
    dl_rules = tuple(
        policy.LocalRule(
            tenant.actor_id,
            policy.ORIGINAL_DOWNLOAD_ACCESS[0],
            "allow",
            policy.ORIGINAL_DOWNLOAD_ACCESS[1],
            policy.ORIGINAL_DOWNLOAD_ACCESS[2],
            policy.ORIGINAL_FIELDS,
            now - timedelta(hours=1),
            version_ref=ver.version_ref,
        )
        for ver in (xlsx_ver, pptx_ver, html_ver, *([png_ver] if png_indexed else []))
    )
    set_rules(mf_db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS), *dl_rules)

    employee_ref = connection.execute(
        "SELECT public_id FROM thalion.object_identity WHERE object_type = %s AND object_id = %s",
        ("principal", tenant.actor_id),
    ).fetchone()[0]
    from secrets import token_urlsafe
    token = token_urlsafe(32)
    credentials = {
        token: evidence.SyntheticCredential(
            employee_ref,
            tenant.space_ref,
            "synthetic-ui",
            "shanghai",
            "employee",
            frozenset({"search", "read_passage", "download_original"}),
            now + timedelta(minutes=10),
        )
    }
    service = evidence.EvidenceService(
        lambda: open_database(database_url),
        credentials.get,
        lambda _cred, probe: authority_for({tenant.actor_id})(probe),
        store,
    )

    with TestClient(api.create_app(service), base_url="http://127.0.0.1") as client:
        # Search XLSX
        r_xlsx = client.post(
            "/v1/search", headers=bearer(token), json={"query": "680元每晚不可超标", "business_date": BEFORE.isoformat()}
        )
        assert r_xlsx.status_code == 200
        hits_xlsx = r_xlsx.json()["passages"]
        xlsx_hit = next((h for h in hits_xlsx if h["source_type"] == "xlsx" and h["location"]["locator"] == "sheet:1!row:2"), None)
        assert xlsx_hit is not None
        r_read = client.get(f"/v1/passages/{xlsx_hit['passage_id']}", headers=bearer(token))
        assert r_read.status_code == 200 and r_read.json()["passage"]["source_type"] == "xlsx"

        # Search PPTX (both slide body and speaker notes!)
        r_pptx = client.post(
            "/v1/search", headers=bearer(token), json={"query": "总监签批", "business_date": BEFORE.isoformat()}
        )
        assert r_pptx.status_code == 200
        hits_pptx = r_pptx.json()["passages"]
        assert any(h["source_type"] == "pptx" and h["location"]["locator"] == "slide:1!notes" for h in hits_pptx)

        # Search HTML & verify <script>/<style> never leaked
        r_html = client.post(
            "/v1/search", headers=bearer(token), json={"query": "新加坡", "business_date": BEFORE.isoformat()}
        )
        assert r_html.status_code == 200
        hits_html = r_html.json()["passages"]
        assert any(h["source_type"] == "html" and "120" in h["excerpt"] for h in hits_html)
        r_script = client.post(
            "/v1/search", headers=bearer(token), json={"query": "SECRET_JS_TOKEN", "business_date": BEFORE.isoformat()}
        )
        assert r_script.status_code == 200 and r_script.json()["passages"] == []

        # Original downloads match exact uploaded bytes!
        for ver, expected_bytes, ext in (
            (xlsx_ver, xlsx_bytes, "original.xlsx"),
            (pptx_ver, pptx_bytes, "original.pptx"),
            (html_ver, html_bytes, "original.html"),
        ):
            dl = client.get(
                f"/employee/originals/{ver.version_ref}",
                headers=bearer(token),
            )
            assert dl.status_code == 200
            assert dl.content == expected_bytes
            assert ext in dl.headers.get("Content-Disposition", "")

        # Search & download standalone OCR PNG image!
        if png_indexed:
            r_png = client.post(
                "/v1/search", headers=bearer(token), json={"query": "680", "business_date": BEFORE.isoformat()}
            )
            assert r_png.status_code == 200
            hits_png = r_png.json()["passages"]
            assert any(h["source_type"] == "image" and h["location"]["locator"] == "image:1" for h in hits_png)
            dl_png = client.get(
                f"/employee/originals/{png_ver.version_ref}",
                headers=bearer(token),
            )
            assert dl_png.status_code == 200 and dl_png.content == png_bytes
            assert "original.png" in dl_png.headers.get("Content-Disposition", "")
