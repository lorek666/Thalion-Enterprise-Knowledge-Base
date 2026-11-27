from pathlib import Path

from alembic import op


revision = "0020_feedback_notices"
down_revision = "0019_feedback_retest"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Feedback conclusions require a reviewed forward migration.")
