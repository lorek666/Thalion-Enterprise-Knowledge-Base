from pathlib import Path

from alembic import op


revision = "0003_external_calls"
down_revision = "0002_execution"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("External call records require a reviewed forward migration.")
