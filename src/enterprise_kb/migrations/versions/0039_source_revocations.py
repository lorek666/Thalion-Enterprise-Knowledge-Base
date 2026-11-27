from pathlib import Path

from alembic import op


revision = "0039_source_revocations"
down_revision = "0038_quality_restriction_replay"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Source revocations require a reviewed forward migration.")
