import json
from pathlib import Path
import re
import shutil

from enterprise_kb.transport.local import CREDENTIAL_KEYS, DIGEST, LocalProfile


REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_ROOT = REPO_ROOT / "deploy"
SECRET_PATTERNS = (
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    re.compile(r"\b(?:ghp|gho|ghu|github_pat)_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"postgresql(?:\+psycopg)?://[^:@\s]+:(?!\$\{|REPLACE_WITH_)[^@\s]+@"),
)


def test_deploy_artifacts_exist_and_contain_no_live_secrets():
    expected_files = (
        DEPLOY_ROOT / "Dockerfile",
        DEPLOY_ROOT / "compose.synthetic.yml",
        DEPLOY_ROOT / "env.example",
        DEPLOY_ROOT / "systemd" / "thalion-serve.service.example",
        DEPLOY_ROOT / "systemd" / "thalion-serve-production.service.example",
        DEPLOY_ROOT / "systemd" / "thalion-worker.service.example",
        DEPLOY_ROOT / "systemd" / "thalion-runtime-alerts.service.example",
        DEPLOY_ROOT / "systemd" / "thalion-runtime-alerts.timer.example",
        DEPLOY_ROOT / "synthetic-profile.example" / "credentials.json",
        DEPLOY_ROOT / "synthetic-profile.example" / "source-grants.json",
        DEPLOY_ROOT / "synthetic-profile.example" / "README.md",
    )
    for path in expected_files:
        assert path.is_file(), f"Missing deployment artifact: {path}"
        content = path.read_text(encoding="utf-8")
        assert content.strip(), f"Empty deployment artifact: {path}"
        for pattern in SECRET_PATTERNS:
            assert pattern.search(content) is None, f"Potential secret matched in {path}: {pattern.pattern}"


def test_dockerfile_and_compose_enforce_pinned_images_and_isolation():
    dockerfile = (DEPLOY_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "python@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "--no-index" in dockerfile
    assert "USER thalion" in dockerfile
    assert "HEALTHCHECK" in dockerfile

    compose = (DEPLOY_ROOT / "compose.synthetic.yml").read_text(encoding="utf-8")
    assert "pgvector/pgvector@sha256:c29f30688a9ad961691bdf0ec1650717cc132a5814619d80f80463d6e4c42e47" in compose
    assert "127.0.0.1:" in compose
    assert "0.0.0.0" not in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "${THALION_POSTGRES_PASSWORD:?" in compose


def test_systemd_and_synthetic_profile_examples_match_runtime_contract(tmp_path):
    service_unit = (DEPLOY_ROOT / "systemd" / "thalion-serve.service.example").read_text(encoding="utf-8")
    for hardening in ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes", "UMask=0077", "--check-config"):
        assert hardening in service_unit

    worker_unit = (DEPLOY_ROOT / "systemd" / "thalion-worker.service.example").read_text(encoding="utf-8")
    for setting in (
        "--mode production",
        "--check-config",
        "--interval-seconds 300",
        "--reconcile",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "PrivateTmp=yes",
        "Restart=on-failure",
    ):
        assert setting in worker_unit

    production_unit = (DEPLOY_ROOT / "systemd" / "thalion-serve-production.service.example").read_text(encoding="utf-8")
    for setting in (
        "--mode production",
        "--check-config",
        "Restart=on-failure",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "PrivateTmp=yes",
    ):
        assert setting in production_unit

    credentials = json.loads((DEPLOY_ROOT / "synthetic-profile.example" / "credentials.json").read_text(encoding="utf-8"))
    assert isinstance(credentials, list) and len(credentials) >= 1
    for entry in credentials:
        assert set(entry.keys()) == CREDENTIAL_KEYS
        assert DIGEST.fullmatch(entry["token_sha256"])
        assert entry["token_sha256"] == "0" * 64

    grants = json.loads((DEPLOY_ROOT / "synthetic-profile.example" / "source-grants.json").read_text(encoding="utf-8"))
    assert isinstance(grants, dict) and len(grants) >= 1

    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(mode=0o700)
    profile_dir.chmod(0o700)
    for name in ("credentials.json", "source-grants.json"):
        target = profile_dir / name
        shutil.copyfile(DEPLOY_ROOT / "synthetic-profile.example" / name, target)
        target.chmod(0o600)
    loaded = LocalProfile(profile_dir)
    assert len(loaded.credentials()) == len(credentials)
    assert len(loaded.source_grants()) == len(grants)
