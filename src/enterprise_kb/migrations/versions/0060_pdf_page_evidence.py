from pathlib import Path

from alembic import op


revision = "0060_pdf_page_evidence"
down_revision = "0059_repair_archive_rebuild"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed PDF observations require a reviewed forward migration.")
