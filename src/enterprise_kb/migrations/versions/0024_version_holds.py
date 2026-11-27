from pathlib import Path

from alembic import op


revision = "0024_version_holds"
down_revision = "0023_disposition_preview"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Version hold decisions require a reviewed forward migration.")
