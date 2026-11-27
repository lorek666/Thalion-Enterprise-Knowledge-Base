from pathlib import Path

from alembic import op


revision = "0107_vector_index_generation"
down_revision = "0106_multisource_archive"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Vector index generations and hybrid retrieval release configurations require a reviewed forward migration.")
