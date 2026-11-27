from pathlib import Path

from alembic import op


revision = "0032_rule_restriction_log"
down_revision = "0031_backup_expiry"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Rule restrictions require a reviewed forward migration.")
