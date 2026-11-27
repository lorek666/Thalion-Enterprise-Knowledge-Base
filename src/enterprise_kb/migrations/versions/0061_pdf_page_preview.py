from pathlib import Path

from alembic import op


revision = "0061_pdf_page_preview"
down_revision = "0060_pdf_page_evidence"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed PDF page previews require a reviewed forward migration.")
