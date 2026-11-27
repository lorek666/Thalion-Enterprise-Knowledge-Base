from pathlib import Path

from alembic import op


revision = "0047_feedback_correction"
down_revision = "0046_feedback_handoffs"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Feedback correction evidence requires a reviewed forward migration.")
