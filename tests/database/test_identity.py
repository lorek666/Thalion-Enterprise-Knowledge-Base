from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from enterprise_kb import database


@pytest.mark.parametrize(("configured_host", "names", "addresses"), [
    ("127.0.0.1", "127.0.0.1", "127.0.0.1"),
    ("[::1]", "::1", "::1"),
    ("localhost", "localhost,localhost", "127.0.0.1,::1"),
])
def test_local_connection_passes_only_explicit_loopback_addresses(monkeypatch, configured_host, names, addresses):
    connected = object()

    def connect(**options):
        assert options["host"] == names
        assert options.get("hostaddr") == addresses
        return connected

    monkeypatch.setattr(database.psycopg, "connect", connect)
    monkeypatch.setattr(database, "rehearsal_marker", lambda connection: None)
    factory = database.local_connection_factory(f"postgresql://operator@{configured_host}/synthetic")
    assert factory() is connected


def migrate(environment):
    return subprocess.run(
        [sys.executable, "-m", "enterprise_kb.database", "upgrade"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


@pytest.fixture
def migrated_database(database_url, migration_environment):
    result = migrate(migration_environment)
    assert result.returncode == 0, result.stdout + result.stderr
    return database_url


def organization(connection, label):
    return connection.execute(
        "INSERT INTO thalion.organization (name, business_timezone) "
        "VALUES (%s, 'Asia/Shanghai') RETURNING org_id",
        (label,),
    ).fetchone()[0]


def principal(connection, org_id, subject):
    principal_id = connection.execute(
        "INSERT INTO thalion.principal "
        "(org_id, principal_type, authority_issuer, authority_subject_key) "
        "VALUES (%s, 'employee', 'https://synthetic.invalid', %s) "
        "RETURNING principal_id",
        (org_id, subject),
    ).fetchone()[0]
    public_id = connection.execute(
        "INSERT INTO thalion.object_identity (object_type, object_id, org_id) "
        "VALUES ('principal', %s, %s) RETURNING public_id",
        (principal_id, org_id),
    ).fetchone()[0]
    return principal_id, public_id


def space(connection, org_id, owner_id, name="测试空间"):
    space_id = connection.execute(
        "INSERT INTO thalion.space "
        "(org_id, name, classification, owner_principal_id) "
        "VALUES (%s, %s, 'internal', %s) RETURNING space_id",
        (org_id, name, owner_id),
    ).fetchone()[0]
    public_id = connection.execute(
        "INSERT INTO thalion.object_identity "
        "(object_type, object_id, org_id, space_id) "
        "VALUES ('space', %s, %s, %s) RETURNING public_id",
        (space_id, org_id, space_id),
    ).fetchone()[0]
    return space_id, public_id


def test_empty_database_upgrade_is_repeatable(database_url, migration_environment):
    executable = Path(sys.executable).with_name(
        "thalion-db.exe" if sys.platform == "win32" else "thalion-db"
    )
    first = subprocess.run(
        [str(executable), "upgrade"],
        env=migration_environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert first.returncode == 0, first.stdout + first.stderr
    repeated = migrate(migration_environment)
    assert repeated.returncode == 0, repeated.stdout + repeated.stderr
    with psycopg.connect(database_url) as connection:
        assert connection.execute(
            "SELECT version_num FROM thalion.alembic_version"
        ).fetchall() == [("0112_flexible_vector_dimensions",)]
        assert connection.execute(
            "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
        ).fetchone() is not None


def migrate_to_revision(database_url, revision):
    configuration = Config()
    configuration.set_main_option(
        "script_location", str(files("enterprise_kb").joinpath("migrations"))
    )
    engine = create_engine(
        make_url(database_url).set(drivername="postgresql+psycopg"), hide_parameters=True
    )
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE SCHEMA thalion")
            configuration.attributes["connection"] = connection
            command.upgrade(configuration, revision)
    finally:
        engine.dispose()


def test_upgrade_from_identity_revision_preserves_existing_references(
    database_url, migration_environment
):
    migrate_to_revision(database_url, "0001_identity")
    with psycopg.connect(database_url) as connection:
        org_id = organization(connection, "Synthetic travel")
        owner_id, owner_ref = principal(connection, org_id, "existing-owner")
        space_id, space_ref = space(connection, org_id, owner_id)

    result = migrate(migration_environment)
    assert result.returncode == 0, result.stdout + result.stderr
    with psycopg.connect(database_url) as connection:
        assert connection.execute(
            "SELECT version_num FROM thalion.alembic_version"
        ).fetchall() == [("0112_flexible_vector_dimensions",)]
        assert connection.execute(
            "SELECT object_type, object_id, public_id FROM thalion.object_identity "
            "WHERE org_id = %s ORDER BY object_type",
            (org_id,),
        ).fetchall() == [("principal", owner_id, owner_ref), ("space", space_id, space_ref)]


def test_failed_upgrade_does_not_keep_partial_schema_or_revision(
    database_url, migration_environment
):
    with psycopg.connect(database_url) as connection:
        connection.execute("CREATE SCHEMA thalion")
        connection.execute("CREATE TABLE thalion.principal (sentinel text)")
        connection.execute("INSERT INTO thalion.principal VALUES ('preserve')")

    failed = migrate(migration_environment)

    assert failed.returncode == 1
    assert "42P07" in failed.stderr
    with psycopg.connect(database_url) as connection:
        assert connection.execute(
            "SELECT to_regclass('thalion.organization'), "
            "to_regclass('thalion.alembic_version')"
        ).fetchone() == (None, None)
        assert connection.execute(
            "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT sentinel FROM thalion.principal"
        ).fetchone() == ("preserve",)
        connection.execute("DROP TABLE thalion.principal")

    recovered = migrate(migration_environment)
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr


def test_authentication_failure_does_not_print_connection_configuration(
    migration_environment,
):
    password = "synthetic-never-print-this-password"
    url = make_url(migration_environment["THALION_DATABASE_URL"])
    result = migrate({
        **migration_environment,
        "THALION_DATABASE_URL": url.set(password=password).render_as_string(
            hide_password=False
        ),
    })
    assert result.returncode == 1
    assert "数据库迁移失败" in result.stderr
    assert password not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def test_unknown_database_revision_fails_without_echoing_database_contents(
    migrated_database, migration_environment
):
    revision = "unknown_synthetic_revision"
    with psycopg.connect(migrated_database) as connection:
        connection.execute("UPDATE thalion.alembic_version SET version_num = %s", (revision,))

    result = migrate(migration_environment)

    assert result.returncode == 1
    assert "数据库迁移失败" in result.stderr
    assert revision not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def test_competing_migration_processes_share_one_history(
    database_url, migration_environment
):
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(migrate, [migration_environment] * 2))
    assert all(result.returncode == 0 for result in results), [
        result.stderr for result in results
    ]
    with psycopg.connect(database_url) as connection:
        assert connection.execute(
            "SELECT count(*) FROM thalion.alembic_version"
        ).fetchone()[0] == 1


def test_identity_registration_commits_with_entity(migrated_database):
    with psycopg.connect(migrated_database) as connection:
        org_id = organization(connection, "合成组织")
        owner_id, owner_public_id = principal(connection, org_id, "employee-1")
        space_id, space_public_id = space(connection, org_id, owner_id)
    assert isinstance(owner_public_id, UUID)
    assert isinstance(space_public_id, UUID)
    assert owner_public_id != space_public_id
    with psycopg.connect(migrated_database) as connection:
        assert connection.execute(
            "SELECT object_id FROM thalion.object_identity WHERE public_id = %s",
            (space_public_id,),
        ).fetchone()[0] == space_id


def test_space_cannot_assign_another_organization_owner(migrated_database):
    with psycopg.connect(migrated_database) as connection:
        first_org = organization(connection, "合成甲")
        second_org = organization(connection, "合成乙")
        owner_id, _ = principal(connection, first_org, "employee-1")
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with psycopg.connect(migrated_database) as connection:
            space(connection, second_org, owner_id)


def test_entity_without_public_identity_cannot_commit(migrated_database):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with psycopg.connect(migrated_database) as connection:
            org_id = organization(connection, "合成组织")
            connection.execute(
                "INSERT INTO thalion.principal "
                "(org_id, principal_type, authority_issuer, authority_subject_key) "
                "VALUES (%s, 'employee', 'https://synthetic.invalid', 'missing')",
                (org_id,),
            )
    with psycopg.connect(migrated_database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM thalion.organization"
        ).fetchone()[0] == 0


def test_public_identity_without_entity_cannot_commit(migrated_database):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with psycopg.connect(migrated_database) as connection:
            org_id = organization(connection, "合成组织")
            connection.execute(
                "INSERT INTO thalion.object_identity "
                "(object_type, object_id, org_id) VALUES ('principal', 9999, %s)",
                (org_id,),
            )


def test_public_identity_must_match_entity_organization(migrated_database):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with psycopg.connect(migrated_database) as connection:
            first_org = organization(connection, "合成甲")
            second_org = organization(connection, "合成乙")
            principal_id = connection.execute(
                "INSERT INTO thalion.principal "
                "(org_id, principal_type, authority_issuer, authority_subject_key) "
                "VALUES (%s, 'employee', 'https://synthetic.invalid', 'mismatch') "
                "RETURNING principal_id",
                (first_org,),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO thalion.object_identity (object_type, object_id, org_id) "
                "VALUES ('principal', %s, %s)",
                (principal_id, second_org),
            )


def test_authoritative_identity_is_not_duplicated_between_organizations(
    migrated_database,
):
    with psycopg.connect(migrated_database) as connection:
        first_org = organization(connection, "合成甲")
        second_org = organization(connection, "合成乙")
        principal(connection, first_org, "same-subject")
    with pytest.raises(psycopg.errors.UniqueViolation):
        with psycopg.connect(migrated_database) as connection:
            principal(connection, second_org, "same-subject")


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE thalion.object_identity SET public_id = gen_random_uuid()",
        "UPDATE thalion.object_identity SET object_id = object_id + 100",
        "DELETE FROM thalion.object_identity",
        "DELETE FROM thalion.principal",
    ],
)
def test_registered_identity_cannot_drift_or_be_reused(migrated_database, statement):
    with psycopg.connect(migrated_database) as connection:
        org_id = organization(connection, "合成组织")
        _, public_id = principal(connection, org_id, "immutable")
    with pytest.raises((psycopg.errors.ObjectNotInPrerequisiteState,
                        psycopg.errors.ForeignKeyViolation)):
        with psycopg.connect(migrated_database) as connection:
            connection.execute(statement)
    with psycopg.connect(migrated_database) as connection:
        assert connection.execute(
            "SELECT public_id FROM thalion.object_identity"
        ).fetchone()[0] == public_id


def test_unknown_business_timezone_is_rejected(migrated_database):
    with pytest.raises(psycopg.errors.CheckViolation):
        with psycopg.connect(migrated_database) as connection:
            connection.execute(
                "INSERT INTO thalion.organization (name, business_timezone) "
                "VALUES ('合成组织', 'Invalid/Unknown')"
            )
