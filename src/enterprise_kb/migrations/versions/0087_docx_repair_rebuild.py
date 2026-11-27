from pathlib import Path

from alembic import op


revision = "0087_docx_repair_rebuild"
down_revision = "0086_docx_archive_rebuild"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("DOCX repair rehearsal records require a reviewed forward migration.")
