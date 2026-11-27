from pathlib import Path

from alembic import op


revision = "0054_csv_exception_links"
down_revision = "0053_csv_wiki_inputs"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed cross-row evidence requires a reviewed forward migration.")
