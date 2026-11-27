from pathlib import Path

from alembic import op


revision = "0077_pdf_wiki_archive"
down_revision = "0076_model_egress_policy"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Recorded PDF Wiki archives require a reviewed forward migration.")
