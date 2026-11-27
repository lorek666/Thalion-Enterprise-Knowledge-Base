from pathlib import Path

from alembic import op


revision = "0105_space_release_eval"
down_revision = "0104_governance_sharing_deleg"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Space release rollout and Wiki rollback audit records require a reviewed forward migration.")
