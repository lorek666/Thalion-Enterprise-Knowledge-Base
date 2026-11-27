from pathlib import Path

from alembic import op


revision = "0114_admin_operations"
down_revision = "0113_source_connector_cursor"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Admin operations are removed by a reviewed forward migration.")
