from pathlib import Path

from alembic import op


revision = "0092_ingest_ledger"
down_revision = "0091_search_source_facets"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Ingest ledger indexes require a reviewed forward migration.")
