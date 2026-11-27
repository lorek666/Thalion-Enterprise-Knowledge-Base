from pathlib import Path

from alembic import op


revision = "0113_source_connector_cursor"
down_revision = "0112_flexible_vector_dimensions"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Dropping vendor cursors requires a reviewed forward migration.")
