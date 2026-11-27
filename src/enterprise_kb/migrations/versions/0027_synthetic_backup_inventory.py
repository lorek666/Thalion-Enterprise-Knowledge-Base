from pathlib import Path

from alembic import op


revision = "0027_synthetic_backup_inventory"
down_revision = "0026_original_verification"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Backup inventory requires a reviewed forward migration.")
