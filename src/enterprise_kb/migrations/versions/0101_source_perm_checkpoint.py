from pathlib import Path

from alembic import op


revision = "0101_source_perm_checkpoint"
down_revision = "0100_source_restriction_receipts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Source permission checkpoints require a reviewed forward migration.")
