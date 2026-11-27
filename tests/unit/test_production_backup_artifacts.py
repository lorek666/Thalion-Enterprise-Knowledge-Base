from pathlib import Path
import subprocess


DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
BACKUP = DEPLOY / "backup" / "thalion-backup.sh"


def test_production_backup_has_no_implicit_target_or_default_cluster(tmp_path):
    result = subprocess.run(["bash", str(BACKUP), "backup"], cwd=tmp_path, env={}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "THALION_BACKUP_STANZA" in result.stderr

    result = subprocess.run(["bash", str(BACKUP), "restore", "latest", str(tmp_path / "restore")],
                            env={}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "explicit backup label" in result.stderr
    assert not (tmp_path / "restore").exists()


def test_restore_refuses_an_existing_target_before_accessing_any_repository(tmp_path):
    existing = tmp_path / "existing-cluster"
    existing.mkdir()
    (existing / "untouched").write_text("existing data")
    result = subprocess.run([
        "bash", str(BACKUP), "restore", "20261128-163000F", str(existing),
    ], env={}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "new absolute directory" in result.stderr
    assert (existing / "untouched").read_text() == "existing data"


def test_restore_without_isolation_confirmation_does_not_create_the_target(tmp_path):
    target = tmp_path / "new-cluster"
    result = subprocess.run([
        "bash", str(BACKUP), "restore", "20261128-163000F", str(target),
    ], env={}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "isolated recovery host" in result.stderr
    assert not target.exists()
