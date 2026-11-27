from pathlib import Path

from alembic import op


revision = "0080_docx_wiki_inputs"
down_revision = "0079_docx_table_evidence"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed DOCX Wiki inputs require a reviewed forward migration.")
