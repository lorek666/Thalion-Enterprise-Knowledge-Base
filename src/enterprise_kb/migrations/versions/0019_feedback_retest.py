from pathlib import Path

from alembic import op


revision = "0019_feedback_retest"
down_revision = "0018_feedback_work"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Search retest receipts require a reviewed forward migration.")
