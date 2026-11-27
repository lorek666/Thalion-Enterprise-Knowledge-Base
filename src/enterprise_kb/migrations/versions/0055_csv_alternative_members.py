from pathlib import Path

from alembic import op


revision = "0055_csv_alternative_members"
down_revision = "0054_csv_exception_links"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Sealed CSV alternatives require a reviewed forward migration.")
