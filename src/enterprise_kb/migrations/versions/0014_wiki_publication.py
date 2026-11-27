from pathlib import Path

from alembic import op


revision = "0014_wiki_publication"
down_revision = "0013_wiki_drafts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Wiki publications require a reviewed forward migration.")
