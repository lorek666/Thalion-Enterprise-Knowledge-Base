from pathlib import Path

from alembic import op


revision = "0036_wiki_rebuild_rehearsal"
down_revision = "0035_wiki_rebuild_archive"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Wiki archive rehearsal records require a reviewed forward migration.")
