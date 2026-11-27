import pytest

from enterprise_kb.modules.evidence import pdf_evidence


def tsv(*words):
    return (pdf_evidence._TSV_HEADER + "\n" + "\n".join(
        f"5\t1\t1\t1\t{line}\t{index}\t0\t0\t1\t1\t{confidence}\t{text}"
        for index, (line, confidence, text) in enumerate(words, 1)
    )).encode()


def test_ocr_preserves_lines_and_does_not_guess_low_confidence_units():
    assert pdf_evidence._ocr_text(tsv((1, 96, "600"), (1, 95, "CNY"), (2, 90, "exception"))) == (
        b"600 CNY\nexception", None,
    )
    assert pdf_evidence._ocr_text(tsv((1, 96, "600"), (1, 79, "CNY"))) == (None, "low_confidence")


def test_ocr_invalid_engine_output_is_not_a_blank_observation():
    with pytest.raises(pdf_evidence.PdfDependencyUnavailable):
        pdf_evidence._ocr_text(tsv((1, "NaN", "600")))
