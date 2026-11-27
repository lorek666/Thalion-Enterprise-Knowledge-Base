from pathlib import Path

from alembic import op


revision = "0059_repair_archive_rebuild"
down_revision = "0058_repair_transcript_archive"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Archived repair reconstructions require a reviewed forward migration.")
