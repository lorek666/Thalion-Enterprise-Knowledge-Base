from pathlib import Path

from alembic import op


revision = "0052_csv_evidence_units"
down_revision = "0051_csv_evidence"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("A sealed evidence unit requires a reviewed forward migration.")
