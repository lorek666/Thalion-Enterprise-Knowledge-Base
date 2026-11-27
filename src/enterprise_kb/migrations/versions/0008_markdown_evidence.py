from pathlib import Path

from alembic import op


revision = "0008_markdown_evidence"
down_revision = "0007_rule_effectivity"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Evidence records require a reviewed forward migration.")
