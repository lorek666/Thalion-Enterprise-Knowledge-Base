from pathlib import Path

from alembic import op


revision = "0037_quality_restriction_log"
down_revision = "0036_wiki_rebuild_rehearsal"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Independent quality restrictions require a reviewed forward migration.")
