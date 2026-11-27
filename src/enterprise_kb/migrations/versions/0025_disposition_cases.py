from pathlib import Path

from alembic import op


revision = "0025_disposition_cases"
down_revision = "0024_version_holds"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed disposition cases require a reviewed forward migration.")
