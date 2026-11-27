from pathlib import Path

from alembic import op


revision = "0069_pdf_archive_rebuild"
down_revision = "0068_pdf_repair_archive"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("PDF reconstruction requires a reviewed forward migration.")
