from alembic import context


connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("请使用 thalion-db upgrade 显式执行迁移。")

context.configure(
    connection=connection,
    target_metadata=None,
    version_table_schema="thalion",
)
with context.begin_transaction():
    context.run_migrations()
