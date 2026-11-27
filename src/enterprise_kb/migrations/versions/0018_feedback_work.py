from pathlib import Path

from alembic import op


revision = "0018_feedback_work"
down_revision = "0017_feedback"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Feedback handling receipts require a reviewed forward migration.")
