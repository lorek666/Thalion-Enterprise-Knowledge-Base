from pathlib import Path

from alembic import op


revision = "0033_archive_rebuild"
down_revision = "0032_rule_restriction_log"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("The archive scope requires a reviewed forward migration.")
