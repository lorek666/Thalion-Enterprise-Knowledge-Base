from pathlib import Path

from alembic import op


revision = "0109_multiformat_evidence"
down_revision = "0108_effectivity_conflicts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Multiformat evidence definitions require a reviewed forward migration.")
