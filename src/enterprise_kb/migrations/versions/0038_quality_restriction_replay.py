from pathlib import Path

from alembic import op


revision = "0038_quality_restriction_replay"
down_revision = "0037_quality_restriction_log"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Quality restriction replay records require a reviewed forward migration.")
