from pathlib import Path

from alembic import op


revision = "0075_document_responsibility"
down_revision = "0074_source_ingest"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Recorded responsibility decisions require a reviewed forward migration.")
