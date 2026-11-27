from pathlib import Path

from alembic import op


revision = "0072_docx_paragraphs"
down_revision = "0071_pdf_processing_quarantine"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Registered DOCX originals require a reviewed forward migration.")
