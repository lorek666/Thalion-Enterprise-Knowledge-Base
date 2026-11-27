from pathlib import Path

from alembic import op


revision = "0102_source_delete_isolation"
down_revision = "0101_source_perm_checkpoint"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Source deletion isolation requires a reviewed forward migration.")
