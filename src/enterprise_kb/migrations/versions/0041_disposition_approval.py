from pathlib import Path

from alembic import op


revision = "0041_disposition_approval"
down_revision = "0040_archive_source_checkpoint"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Disposition decisions require a reviewed forward migration.")
