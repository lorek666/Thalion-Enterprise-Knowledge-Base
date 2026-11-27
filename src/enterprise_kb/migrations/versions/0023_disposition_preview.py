from pathlib import Path

from alembic import op


revision = "0023_disposition_preview"
down_revision = "0022_lint_findings"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Retention policy history requires a reviewed forward migration.")
