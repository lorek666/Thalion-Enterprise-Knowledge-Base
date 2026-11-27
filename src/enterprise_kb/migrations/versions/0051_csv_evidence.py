from pathlib import Path

from alembic import op


revision = "0051_csv_evidence"
down_revision = "0050_gap_feedback_link"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("A recorded CSV evidence revision requires a reviewed forward migration.")
