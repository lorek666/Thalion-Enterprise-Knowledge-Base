from pathlib import Path

from alembic import op


revision = "0046_feedback_handoffs"
down_revision = "0045_disposition_copy_receipts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Feedback handoffs require a reviewed forward migration.")
