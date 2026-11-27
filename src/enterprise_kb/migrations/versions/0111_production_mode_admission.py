from pathlib import Path

from alembic import op


revision = "0111_production_mode_admission"
down_revision = "0110_glossary_and_departments"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Production mode admission and isolation guards require a reviewed forward migration.")
