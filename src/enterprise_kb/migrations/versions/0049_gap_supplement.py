from pathlib import Path

from alembic import op


revision = "0049_gap_supplement"
down_revision = "0048_empty_search_match"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Gap supplementation evidence requires a reviewed forward migration.")
