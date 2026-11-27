from contextlib import closing
from dataclasses import dataclass, field
from hashlib import file_digest, sha256
from importlib.metadata import PackageNotFoundError, version
from math import ceil, isfinite
from pathlib import Path
from struct import pack
import subprocess
from tempfile import TemporaryFile
from threading import Lock
from time import monotonic
from uuid import UUID
from zlib import compress, crc32


MEDIA_TYPE = "application/pdf"
PARSER_VERSION = "pdfium2:5.15.2;tesseract:5.5.3"
PROFILE = "pdf_pages_v1"
LOCATOR_REVISION = 1
MAX_PAGES = 16
MAX_PAGE_BYTES = 32768
MAX_BITMAP_PIXELS = 12_000_000
MAX_TSV_BYTES = 1_048_576
OCR_LANGUAGES = ("eng", "chi_sim")
OCR_SCALE = 300 / 72
OCR_MIN_CONFIDENCE = 80
PREVIEW_SCALE = 2
PREVIEW_MAX_PIXELS = 4_000_000
_PDFIUM_LOCK = Lock()
_OCR_ENV = {"LANG": "C", "OMP_THREAD_LIMIT": "1"}
_TSV_HEADER = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext"


class PdfDependencyUnavailable(Exception):
    pass


@dataclass(frozen=True)
class PageObservation:
    number: int
    method: str
    transcript: bytes | None = field(default=None, repr=False)
    reason: str | None = None
    ocr_profile_digest: bytes | None = None
    repair_decision_ref: UUID | None = None


@dataclass(frozen=True)
class PdfCandidate:
    pages: tuple[PageObservation, ...] = field(default=(), repr=False)
    reason: str | None = None


@dataclass(frozen=True)
class Tesseract:
    executable: Path = field(repr=False)
    tessdata: Path = field(repr=False)

    def _run(self, arguments, **kwargs):
        try:
            if not self.executable.is_absolute() or not self.tessdata.is_absolute():
                raise ValueError
            result = subprocess.run(
                (str(self.executable), *arguments), stderr=subprocess.DEVNULL, env=_OCR_ENV, check=True, **kwargs,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            raise PdfDependencyUnavailable("The admitted local OCR engine is unavailable.") from None
        return result

    def fingerprint(self):
        result = self._run(("--version",), stdout=subprocess.PIPE, timeout=3)
        if not result.stdout.startswith(b"tesseract 5.5.3\n"):
            raise PdfDependencyUnavailable("The local OCR version is not admitted.")
        digest = sha256(f"{PARSER_VERSION};eng+chi_sim;300dpi;psm6;{OCR_MIN_CONFIDENCE}".encode())
        try:
            for language in OCR_LANGUAGES:
                path = self.tessdata / f"{language}.traineddata"
                if not path.is_file() or not 0 < path.stat().st_size <= 32 * 1024 * 1024:
                    raise ValueError
                with path.open("rb") as stream:
                    digest.update(file_digest(stream, "sha256").digest())
        except (OSError, ValueError):
            raise PdfDependencyUnavailable("The admitted local OCR language data is unavailable.") from None
        return digest.digest()

    def read(self, bitmap, remaining):
        if remaining <= 0:
            raise PdfDependencyUnavailable("The local OCR processing budget was exceeded.")
        with TemporaryFile() as output:
            self._run(
                ("stdin", "stdout", "--tessdata-dir", str(self.tessdata), "-l", "+".join(OCR_LANGUAGES),
                 "--dpi", "300", "--psm", "6", "tsv"),
                input=bitmap, stdout=output, timeout=min(8, remaining),
            )
            if output.tell() > MAX_TSV_BYTES:
                return None, "size_limit"
            output.seek(0)
            return _ocr_text(output.read(MAX_TSV_BYTES))


def _bounded_text(value):
    text = value.replace("\r\n", "\n").strip()
    if not text:
        return None, "empty"
    if "\ufffd" in text or any(not character.isprintable() and character not in "\n\t" for character in text):
        return None, "unsupported_structure"
    content = text.encode("utf-8")
    return (content, None) if len(content) <= MAX_PAGE_BYTES else (None, "size_limit")


def _ocr_text(raw):
    try:
        header, *rows = raw.decode("utf-8").splitlines()
        if header.rstrip("\t") != _TSV_HEADER:
            raise ValueError
        lines = {}
        for row in rows:
            columns = row.split("\t", 11)
            if len(columns) != 12:
                raise ValueError
            if columns[0] != "5" or not columns[-1].strip():
                continue
            confidence = float(columns[-2])
            if not 0 <= confidence <= 100:
                raise ValueError
            if confidence < OCR_MIN_CONFIDENCE:
                return None, "low_confidence"
            lines.setdefault(tuple(columns[1:5]), []).append(columns[-1])
    except (UnicodeError, ValueError):
        raise PdfDependencyUnavailable("The local OCR engine returned an invalid page result.") from None
    return _bounded_text("\n".join(" ".join(words) for words in lines.values()))


def _bitmap_pgm(page):
    dimensions = tuple(page.get_size())
    if any(not isfinite(size) or not 0 < size <= 1440 for size in dimensions):
        return None
    width, height = (ceil(size * OCR_SCALE) for size in dimensions)
    if width * height > MAX_BITMAP_PIXELS:
        return None
    with closing(page.render(scale=OCR_SCALE, grayscale=True)) as bitmap:
        if (bitmap.width, bitmap.height) != (width, height) or bitmap.n_channels != 1:
            return None
        pixels = b"".join(
            bytes(bitmap.buffer[offset:offset + width]) for offset in range(0, height * bitmap.stride, bitmap.stride)
        )
    return f"P5\n{width} {height}\n255\n".encode() + pixels


def _load_pdfium():
    try:
        import pypdfium2 as pdfium
        if version("pypdfium2") != "5.15.2":
            raise PdfDependencyUnavailable("The local PDF parser version is not admitted.")
    except (ImportError, OSError, PackageNotFoundError):
        raise PdfDependencyUnavailable("The admitted local PDF parser is unavailable.") from None
    return pdfium


def _png_chunk(kind, content):
    return pack(">I", len(content)) + kind + content + pack(">I", crc32(kind + content))


def render_review_page(payload, number, expected_pages):
    pdfium = _load_pdfium()
    try:
        with _PDFIUM_LOCK, pdfium.PdfDocument(payload) as document:
            if not 1 <= number <= len(document) == expected_pages <= MAX_PAGES:
                raise PdfDependencyUnavailable("The PDF geometry changed after processing.")
            with closing(document[number - 1]) as page:
                dimensions = tuple(page.get_size())
                if any(not isfinite(size) or not 0 < size <= 1440 for size in dimensions):
                    raise PdfDependencyUnavailable("The PDF page cannot be rendered within the review limit.")
                width, height = (ceil(size * PREVIEW_SCALE) for size in dimensions)
                if width * height > PREVIEW_MAX_PIXELS:
                    raise PdfDependencyUnavailable("The PDF page cannot be rendered within the review limit.")
                with closing(page.render(
                    scale=PREVIEW_SCALE, rev_byteorder=True, force_bitmap_format=pdfium.raw.FPDFBitmap_BGR,
                )) as bitmap:
                    if (bitmap.width, bitmap.height, bitmap.mode) != (width, height, "RGB"):
                        raise PdfDependencyUnavailable("The PDF renderer returned an unsupported bitmap.")
                    scanlines = b"".join(
                        b"\0" + bytes(bitmap.buffer[offset:offset + width * 3])
                        for offset in range(0, height * bitmap.stride, bitmap.stride)
                    )
    except pdfium.PdfiumError:
        raise PdfDependencyUnavailable("The registered PDF page could not be rendered.") from None
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + (
        _png_chunk(b"IDAT", compress(scanlines)) + _png_chunk(b"IEND", b"")
    )


def parse_pdf(payload, *, ocr=None):
    if not payload.startswith(b"%PDF-"):
        return PdfCandidate(reason="unsupported_structure")
    pdfium = _load_pdfium()
    pages, fingerprint = [], None
    deadline = monotonic() + 30
    try:
        with _PDFIUM_LOCK, pdfium.PdfDocument(payload) as document:
            if not 1 <= len(document) <= MAX_PAGES:
                return PdfCandidate(reason="empty" if not len(document) else "size_limit")
            for number in range(1, len(document) + 1):
                with closing(document[number - 1]) as page, closing(page.get_textpage()) as layer:
                    if layer.count_chars() > MAX_PAGE_BYTES:
                        pages.append(PageObservation(number, "text_layer", reason="size_limit"))
                        continue
                    value, reason = _bounded_text(layer.get_text_bounded(errors="replace"))
                    if reason not in {"empty", "unsupported_structure"}:
                        pages.append(PageObservation(number, "text_layer", value, reason))
                        continue
                    bitmap = _bitmap_pgm(page)
                    if bitmap is None:
                        pages.append(PageObservation(number, "ocr", reason="size_limit"))
                        continue
                if ocr is None:
                    raise PdfDependencyUnavailable("Raster pages require the admitted local OCR engine.")
                if fingerprint is None:
                    fingerprint = ocr.fingerprint()
                value, reason = ocr.read(bitmap, deadline - monotonic())
                pages.append(PageObservation(number, "ocr", value, reason, fingerprint))
    except (pdfium.PdfiumError, UnicodeError):
        return PdfCandidate(reason="unsupported_structure")
    if fingerprint is not None and ocr.fingerprint() != fingerprint:
        raise PdfDependencyUnavailable("OCR inputs changed while the document was being processed.")
    return PdfCandidate(tuple(pages), None if any(page.transcript for page in pages) else "unsupported_structure")
