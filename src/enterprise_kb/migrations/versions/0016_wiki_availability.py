from pathlib import Path

from alembic import op


revision = "0016_wiki_availability"
down_revision = "0015_wiki_search"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Wiki unavailability records require a reviewed forward migration.")
