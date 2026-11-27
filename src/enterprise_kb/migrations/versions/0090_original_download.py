from pathlib import Path

from alembic import op


revision = "0090_original_download"
down_revision = "0089_docx_wiki_rebuild"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Original download grants and receipts require a reviewed forward migration.")
