from pathlib import Path

from alembic import op


revision = "0043_backup_catalogue"
down_revision = "0042_deletion_tombstone"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Backup manifests require a reviewed forward migration.")
