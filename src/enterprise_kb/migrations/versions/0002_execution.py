from pathlib import Path

from alembic import op


revision = "0002_execution"
down_revision = "0001_identity"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Execution records require a reviewed forward migration.")
