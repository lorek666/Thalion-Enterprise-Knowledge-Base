from pathlib import Path

from alembic import op


revision = "0095_job_enqueue_time"
down_revision = "0094_request_ingress"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_suffix(".sql").read_text(encoding="utf-8"))


def downgrade():
    raise RuntimeError("Job enqueue timestamps require a reviewed forward migration.")
