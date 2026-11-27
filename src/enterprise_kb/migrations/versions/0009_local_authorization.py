from pathlib import Path

from alembic import op


revision = "0009_local_authorization"
down_revision = "0008_markdown_evidence"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Authorization records require a reviewed forward migration.")
