from pathlib import Path

from alembic import op


revision = "0096_job_backlog_indexes"
down_revision = "0095_job_enqueue_time"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Runtime backlog indexes require a reviewed forward migration.")
