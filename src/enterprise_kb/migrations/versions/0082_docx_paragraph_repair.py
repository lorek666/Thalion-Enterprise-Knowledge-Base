from pathlib import Path

from alembic import op


revision = "0082_docx_paragraph_repair"
down_revision = "0081_docx_original_archive"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed DOCX paragraph repairs require a reviewed forward migration.")
