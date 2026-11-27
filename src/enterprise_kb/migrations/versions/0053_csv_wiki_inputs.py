from pathlib import Path

from alembic import op


revision = "0053_csv_wiki_inputs"
down_revision = "0052_csv_evidence_units"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed Wiki evidence groups require a reviewed forward migration.")
