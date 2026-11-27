import json
from pathlib import Path

from test_evidence_transport import private_json
from test_identity import migrate_to_revision


def test_thalion_serve_check_config_verifies_full_migration_head(database_url, tmp_path: Path, monkeypatch, capsys):
    from enterprise_kb.database import expected_head_revisions, upgrade
    from enterprise_kb.transport import local

    tmp_path.chmod(0o700)
    (tmp_path / "originals").mkdir(mode=0o700)
    private_json(tmp_path / "credentials.json", [])
    private_json(tmp_path / "source-grants.json", {})

    monkeypatch.setenv("THALION_DATABASE_URL", database_url)
    monkeypatch.delenv("THALION_SOURCE_AUTHORITY_URL", raising=False)
    monkeypatch.delenv("THALION_SOURCE_AUTHORITY_REF", raising=False)

    migrate_to_revision(database_url, "0094_request_ingress")
    monkeypatch.setattr("sys.argv", ["thalion-serve", "--profile", str(tmp_path), "--check-config"])
    assert local.main() == 1
    assert "共享迁移" in capsys.readouterr().err

    heads = upgrade(database_url)
    assert tuple(heads) == expected_head_revisions()
    started = []
    monkeypatch.setattr(local.uvicorn, "run", lambda app, **_: started.append(app))
    assert local.main() == 0
    assert started == []
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "ok"
    assert output["mode"] == "synthetic_local"
    assert tuple(output["schema_revisions"]) == expected_head_revisions()
    assert output["source_authority_configured"] is False
    assert output["backups_configured"] is False
    assert database_url not in json.dumps(output)
