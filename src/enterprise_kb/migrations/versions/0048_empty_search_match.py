from pathlib import Path

from alembic import op


revision = "0048_empty_search_match"
down_revision = "0047_feedback_correction"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Empty search matching evidence requires a reviewed forward migration.")
