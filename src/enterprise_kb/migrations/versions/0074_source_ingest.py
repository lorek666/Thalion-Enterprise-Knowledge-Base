from pathlib import Path

from alembic import op


revision = "0074_source_ingest"
down_revision = "0073_docx_quality_review"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Recorded ingest batches require a reviewed forward migration.")
