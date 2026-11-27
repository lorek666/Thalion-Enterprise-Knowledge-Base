from pathlib import Path

from alembic import op


revision = "0029_export_transcripts"
down_revision = "0028_synthetic_original_exports"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed transcript exports require a reviewed forward migration.")
