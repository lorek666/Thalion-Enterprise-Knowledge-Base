from pathlib import Path

from alembic import op


revision = "0076_model_egress_policy"
down_revision = "0075_document_responsibility"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Recorded model egress rules require a reviewed forward migration.")
