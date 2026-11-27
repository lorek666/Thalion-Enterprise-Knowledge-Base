from pathlib import Path

from alembic import op


revision = "0104_governance_sharing_deleg"
down_revision = "0103_rule_rollback_impact"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Governance sharing and delegation audit records require a reviewed forward migration.")
