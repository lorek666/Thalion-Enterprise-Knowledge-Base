from pathlib import Path

from alembic import op


revision = "0110_glossary_and_departments"
down_revision = "0109_multiformat_evidence"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Glossary and department definitions require a reviewed forward migration.")
