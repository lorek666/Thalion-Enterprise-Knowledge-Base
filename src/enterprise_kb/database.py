import argparse
from importlib.resources import files
import os
import sys

import psycopg
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool


MIGRATION_LOCK = 0x5448414C494F4E


def _alembic_config() -> Config:
    configuration = Config()
    configuration.set_main_option(
        "script_location", str(files("enterprise_kb").joinpath("migrations"))
    )
    return configuration


def expected_head_revisions() -> tuple[str, ...]:
    script = ScriptDirectory.from_config(_alembic_config())
    return tuple(sorted(script.get_heads()))


def current_revisions(connection: psycopg.Connection) -> tuple[str, ...]:
    if connection.execute("SELECT to_regclass('thalion.alembic_version')").fetchone() == (None,):
        return ()
    rows = connection.execute("SELECT version_num FROM thalion.alembic_version ORDER BY version_num").fetchall()
    return tuple(row[0] for row in rows)


def require_current_schema(connection: psycopg.Connection) -> tuple[str, ...]:
    expected = expected_head_revisions()
    actual = current_revisions(connection)
    if actual != expected:
        raise ValueError("The shared database migrations have not reached head.")
    return actual


def rehearsal_marker(connection: psycopg.Connection) -> str | None:
    row = connection.execute(
        """
        SELECT substring(entry.value FROM position('=' IN entry.value) + 1)
        FROM pg_catalog.pg_db_role_setting AS setting
        JOIN pg_catalog.pg_database AS database ON database.oid = setting.setdatabase
        CROSS JOIN LATERAL unnest(setting.setconfig) AS entry(value)
        WHERE database.datname = current_database() AND setting.setrole = 0
          AND split_part(entry.value, '=', 1) = 'thalion.restore_rehearsal'
        """,
    ).fetchone()
    return row[0] if row is not None else None


def local_connection_factory(database_url: str):
    url = make_url(database_url)
    if (
        url.drivername not in {"postgresql", "postgresql+psycopg"} or not url.database or not url.username
        or url.host not in {"127.0.0.1", "localhost", "::1"} or url.query
    ):
        raise ValueError("Synthetic operations require an explicit local PostgreSQL database.")

    host = "localhost,localhost" if url.host == "localhost" else url.host
    hostaddr = "127.0.0.1,::1" if url.host == "localhost" else url.host

    def connect():
        connection = psycopg.connect(
            host=host, hostaddr=hostaddr, port=url.port or 5432,
            dbname=url.database, user=url.username, password=url.password or "",
            autocommit=True, connect_timeout=3, application_name="thalion-synthetic",
            options="-c statement_timeout=5000 -c lock_timeout=3000",
        )
        try:
            if rehearsal_marker(connection) is not None:
                raise psycopg.OperationalError("A restore rehearsal database cannot serve local requests.")
        except Exception:
            connection.close()
            raise
        return connection

    return connect


def production_connection_factory(database_url: str):
    url = make_url(database_url)
    if url.drivername not in {"postgresql", "postgresql+psycopg"} or not url.host or not url.database or not url.username:
        raise ValueError("Production operations require an explicit PostgreSQL connection URL.")
    conninfo = url.set(drivername="postgresql").render_as_string(hide_password=False)

    def connect():
        connection = psycopg.connect(
            conninfo,
            autocommit=True,
            connect_timeout=5,
            application_name="thalion-production",
            options="-c statement_timeout=5000 -c lock_timeout=3000",
        )
        try:
            if rehearsal_marker(connection) is not None:
                raise psycopg.OperationalError("A restore rehearsal database cannot serve production requests.")
        except Exception:
            connection.close()
            raise
        return connection

    return connect


def upgrade(database_url):
    url = make_url(database_url)
    if url.drivername not in ("postgresql", "postgresql+psycopg"):
        raise ValueError("仅支持 PostgreSQL，不能使用内存数据库替代共享模型。")
    url = url.set(drivername="postgresql+psycopg")
    configuration = _alembic_config()
    engine = create_engine(
        url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 10, "application_name": "thalion-migrate"},
    )
    try:
        with engine.begin() as connection:
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK}
            )
            connection.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS thalion")
            configuration.attributes["connection"] = connection
            command.upgrade(configuration, "head")
            return connection.exec_driver_sql(
                "SELECT version_num FROM thalion.alembic_version"
            ).scalars().all()
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Thalion 共享数据库显式迁移")
    parser.add_argument("command", choices=["upgrade"])
    parser.parse_args()
    database_url = os.environ.get("THALION_DATABASE_URL", "").strip()
    if not database_url:
        print("FAIL 请设置 THALION_DATABASE_URL；不自动选择数据库。", file=sys.stderr)
        return 1
    try:
        revisions = upgrade(database_url)
    except (SQLAlchemyError, CommandError) as error:
        code = getattr(getattr(error, "orig", None), "sqlstate", None) or "unknown"
        print(
            f"FAIL 数据库迁移失败：{type(error).__name__}，SQLSTATE={code}。"
            "请检查连接配置和数据库管理员日志。",
            file=sys.stderr,
        )
        return 1
    except ValueError:
        print("FAIL 数据库连接配置无效；仅支持 PostgreSQL。", file=sys.stderr)
        return 1
    print(f"PASS 数据库迁移完成：{', '.join(revisions)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
