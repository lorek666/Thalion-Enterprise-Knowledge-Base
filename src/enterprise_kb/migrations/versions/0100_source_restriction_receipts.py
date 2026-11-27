from pathlib import Path

from alembic import op


revision = "0100_source_restriction_receipts"
down_revision = "0099_source_reconciliation"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Source restriction receipts require a reviewed forward migration.")
