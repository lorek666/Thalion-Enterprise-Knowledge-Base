from pathlib import Path

from alembic import op


revision = "0040_archive_source_checkpoint"
down_revision = "0039_source_revocations"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Archive source checkpoints require a reviewed forward migration.")
