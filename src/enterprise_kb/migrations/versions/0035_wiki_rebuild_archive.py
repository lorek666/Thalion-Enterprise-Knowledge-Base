from pathlib import Path

from alembic import op


revision = "0035_wiki_rebuild_archive"
down_revision = "0034_archive_rule_checkpoint"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Wiki rebuild archives require a reviewed forward migration.")
