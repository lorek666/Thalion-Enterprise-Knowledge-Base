from pathlib import Path

from alembic import op


revision = "0028_synthetic_original_exports"
down_revision = "0027_synthetic_backup_inventory"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed original exports require a reviewed forward migration.")
