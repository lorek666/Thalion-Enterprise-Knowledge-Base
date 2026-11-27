from pathlib import Path

from alembic import op


revision = "0017_feedback"
down_revision = "0016_wiki_availability"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Feedback records require a reviewed forward migration.")
