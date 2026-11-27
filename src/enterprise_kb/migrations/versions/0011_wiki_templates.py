from pathlib import Path

from alembic import op


revision = "0011_wiki_templates"
down_revision = "0010_search_delivery"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Template decisions require a reviewed forward migration.")
