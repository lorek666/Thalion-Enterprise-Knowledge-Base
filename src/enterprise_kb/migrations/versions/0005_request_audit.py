from pathlib import Path

from alembic import op


revision = "0005_request_audit"
down_revision = "0004_external_recovery"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Request audit records require a reviewed forward migration.")
