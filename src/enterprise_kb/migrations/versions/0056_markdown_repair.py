from pathlib import Path

from alembic import op


revision = "0056_markdown_repair"
down_revision = "0055_csv_alternative_members"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed evidence repairs require a reviewed forward migration.")
