from pathlib import Path

from alembic import op


revision = "0030_export_wiki"
down_revision = "0029_export_transcripts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed Wiki archives require a reviewed forward migration.")
