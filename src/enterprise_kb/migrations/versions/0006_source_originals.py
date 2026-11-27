from pathlib import Path

from alembic import op


revision = "0006_source_originals"
down_revision = "0005_request_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Original registrations require a reviewed forward migration.")
