from contextlib import contextmanager
import os
import secrets
import subprocess
import time
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest
from sqlalchemy.engine import URL


POSTGRES_IMAGE = (
    "pgvector/pgvector@"
    "sha256:c29f30688a9ad961691bdf0ec1650717cc132a5814619d80f80463d6e4c42e47"
)


@pytest.fixture(scope="session")
def postgres_server():
    name = f"thalion-test-{uuid4().hex}"
    password = secrets.token_urlsafe(24)
    container = subprocess.run(
        [
            "docker", "run", "--detach", "--rm", "--name", name,
            "--label", "thalion.test=database",
            "--publish", "127.0.0.1::5432",
            "--env", f"POSTGRES_PASSWORD={password}",
            POSTGRES_IMAGE,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    try:
        address = subprocess.run(
            ["docker", "port", container, "5432/tcp"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        host, port = address.rsplit(":", 1)
        settings = {
            "host": host,
            "port": int(port),
            "user": "postgres",
            "password": password,
            "connect_timeout": 2,
        }
        for attempt in range(40):
            try:
                with psycopg.connect(dbname="postgres", **settings):
                    break
            except psycopg.OperationalError:
                if attempt == 39:
                    raise
                time.sleep(0.25)
        yield settings
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container],
            check=False,
            capture_output=True,
        )


@contextmanager
def temporary_database(postgres_server, *, template=None):
    name = f"test_{uuid4().hex}"
    with psycopg.connect(
        dbname="postgres", autocommit=True, **postgres_server
    ) as connection:
        if template is None:
            connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        else:
            connection.execute(sql.SQL("CREATE DATABASE {} TEMPLATE {}").format(
                sql.Identifier(name), sql.Identifier(template),
            ))
    url = URL.create(
        "postgresql",
        username=postgres_server["user"],
        password=postgres_server["password"],
        host=postgres_server["host"],
        port=postgres_server["port"],
        database=name,
    ).render_as_string(hide_password=False)
    try:
        yield url
    finally:
        with psycopg.connect(
            dbname="postgres", autocommit=True, **postgres_server
        ) as connection:
            connection.execute(
                sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name))
            )


@pytest.fixture
def database_url(postgres_server):
    with temporary_database(postgres_server) as url:
        yield url


@pytest.fixture
def independent_database_url(postgres_server):
    with temporary_database(postgres_server) as url:
        yield url


@pytest.fixture
def migration_environment(database_url):
    return {
        **{
            key: os.environ[key]
            for key in ("PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
            if key in os.environ
        },
        "THALION_DATABASE_URL": database_url,
        "PYTHONUTF8": "1",
    }
