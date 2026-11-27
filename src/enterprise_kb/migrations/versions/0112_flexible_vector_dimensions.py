from pathlib import Path

from alembic import op


revision = "0112_flexible_vector_dimensions"
down_revision = "0111_production_mode_admission"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Flexible vector dimension migration requires a reviewed forward migration.")
