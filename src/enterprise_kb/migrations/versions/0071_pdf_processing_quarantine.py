from pathlib import Path

from alembic import op


revision = "0071_pdf_processing_quarantine"
down_revision = "0070_pdf_repair_rebuild"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Attested PDF processing quarantines require a reviewed forward migration.")
