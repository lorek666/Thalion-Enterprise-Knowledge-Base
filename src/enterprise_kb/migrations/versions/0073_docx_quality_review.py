from pathlib import Path

from alembic import op


revision = "0073_docx_quality_review"
down_revision = "0072_docx_paragraphs"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Recorded DOCX review receipts require a reviewed forward migration.")
