from pathlib import Path

from alembic import op


revision = "0106_multisource_archive"
down_revision = "0105_space_release_eval"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Multi-source space archive exports and rebuild records require a reviewed forward migration.")
