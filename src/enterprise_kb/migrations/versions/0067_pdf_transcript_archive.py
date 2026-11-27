from pathlib import Path

from alembic import op


revision = "0067_pdf_transcript_archive"
down_revision = "0066_pdf_original_archive"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed PDF transcript archives require a reviewed forward migration.")
