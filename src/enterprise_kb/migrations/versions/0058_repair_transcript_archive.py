from pathlib import Path

from alembic import op


revision = "0058_repair_transcript_archive"
down_revision = "0057_repair_review"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed repair archives require a reviewed forward migration.")
