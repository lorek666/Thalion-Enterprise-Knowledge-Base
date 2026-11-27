from pathlib import Path

from alembic import op


revision = "0063_pdf_ocr_review"
down_revision = "0062_pdf_ocr_correction"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed OCR review decisions require a reviewed forward migration.")
