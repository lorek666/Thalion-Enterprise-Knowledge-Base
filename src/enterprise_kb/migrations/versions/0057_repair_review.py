from pathlib import Path

from alembic import op


revision = "0057_repair_review"
down_revision = "0056_markdown_repair"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed repair reviews require a reviewed forward migration.")
