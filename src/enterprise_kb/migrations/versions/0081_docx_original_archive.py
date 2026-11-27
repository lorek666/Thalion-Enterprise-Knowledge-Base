from pathlib import Path

from alembic import op


revision = "0081_docx_original_archive"
down_revision = "0080_docx_wiki_inputs"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed DOCX original archives require a reviewed forward migration.")
