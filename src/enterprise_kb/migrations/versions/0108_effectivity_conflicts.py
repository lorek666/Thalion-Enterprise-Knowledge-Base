from pathlib import Path

from alembic import op


revision = "0108_effectivity_conflicts"
down_revision = "0107_vector_index_generation"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Effectivity conflict records and withdrawal reasons require a reviewed forward migration.")
