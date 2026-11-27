from alembic import op

revision = "0116_admin_hardening"
down_revision = "0115_admin_complete"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE thalion.directory_sync_run ADD COLUMN IF NOT EXISTS idempotency_key text;
        CREATE UNIQUE INDEX IF NOT EXISTS directory_sync_run_idempotency
            ON thalion.directory_sync_run (org_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL;
        ALTER TABLE thalion.notification_delivery
            ADD COLUMN IF NOT EXISTS template_key text NOT NULL DEFAULT 'admin.default',
            ADD COLUMN IF NOT EXISTS message_digest bytea,
            ADD COLUMN IF NOT EXISTS locked_at timestamptz,
            ADD COLUMN IF NOT EXISTS read_at timestamptz;
        CREATE UNIQUE INDEX IF NOT EXISTS space_name_per_org
            ON thalion.space (org_id, lower(btrim(name)));
    """)


def downgrade():
    raise RuntimeError("Admin operations are removed by a reviewed forward migration.")
