from pathlib import Path

from alembic import op


revision = "0098_source_content_sync"
down_revision = "0097_runtime_backlog_alerts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Source sync receipts require a reviewed forward migration.")
