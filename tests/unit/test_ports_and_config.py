from pathlib import Path
from uuid import uuid4

import pytest


def test_production_registry_rejects_synthetic_adapters_and_missing_ports():
    from enterprise_kb.ports.contracts import (
        PortRegistry,
        ProductionIsolationError,
    )

    class FakeSyntheticIdentity:
        admission = "synthetic_local"
        issuer = "https://synthetic.invalid"
        audience = "thalion"

        def verify_bearer_token(self, token: str):
            raise NotImplementedError

    class FakeApprovedIdentity:
        admission = "production_approved"
        issuer = "https://idp.corp.example"
        audience = "thalion-prod"

        def verify_bearer_token(self, token: str):
            raise NotImplementedError

    class FakeApprovedAuthority:
        admission = "production_approved"
        authority_ref = uuid4()

        def authorize_scopes(self, credential, probe):
            raise NotImplementedError

        def checkpoint(self, space_ref):
            raise NotImplementedError

    class FakeApprovedStorage:
        admission = "production_approved"
        storage_kind = "s3_immutable"

        def read_verified(self, storage_key: str, expected_digest: bytes, expected_length: int) -> bytes:
            raise NotImplementedError

        def write_immutable(self, storage_key: str, payload: bytes) -> bytes:
            raise NotImplementedError

    class FakeApprovedAuditLog:
        admission = "production_approved"
        log_ref = uuid4()

        def append_restriction_receipt(self, space_ref, payload: dict):
            raise NotImplementedError

        def verify_checkpoint(self, space_ref, expected_generation: int) -> bool:
            raise NotImplementedError

    class FakeSyntheticEmbedding:
        admission = "synthetic_local"
        model_id = "synthetic-hash-synonym-v1"
        dimension = 64
        distance_metric = "cosine"

        def embed_passages(self, texts):
            raise NotImplementedError

        def embed_query(self, text: str):
            raise NotImplementedError

    with pytest.raises(ProductionIsolationError, match="synthetic_local"):
        PortRegistry(
            mode="production",
            identity=FakeSyntheticIdentity(),
            source_authority=FakeApprovedAuthority(),
            object_storage=FakeApprovedStorage(),
            security_audit_log=FakeApprovedAuditLog(),
        ).validate()

    with pytest.raises(ProductionIsolationError, match="security_audit_log"):
        PortRegistry(
            mode="production",
            identity=FakeApprovedIdentity(),
            source_authority=FakeApprovedAuthority(),
            object_storage=FakeApprovedStorage(),
            security_audit_log=None,
        ).validate()

    with pytest.raises(ProductionIsolationError, match="embedding_provider"):
        PortRegistry(
            mode="production",
            identity=FakeApprovedIdentity(),
            source_authority=FakeApprovedAuthority(),
            object_storage=FakeApprovedStorage(),
            security_audit_log=FakeApprovedAuditLog(),
            embedding_provider=FakeSyntheticEmbedding(),
        ).validate()

    approved = PortRegistry(
        mode="production",
        identity=FakeApprovedIdentity(),
        source_authority=FakeApprovedAuthority(),
        object_storage=FakeApprovedStorage(),
        security_audit_log=FakeApprovedAuditLog(),
    )
    approved.validate()
    assert approved.mode == "production"


def test_production_config_validation_rejects_secrets_http_and_synthetic_issuer():
    from enterprise_kb.runtime.config import ConfigValidationError, validate_deployment_config

    valid_prod = {
        "mode": "production",
        "business_timezone": "Asia/Shanghai",
        "database_url_ref": "env:THALION_DATABASE_URL",
        "allowed_hosts": ["kb.corp.example"],
        "identity": {
            "issuer": "https://idp.corp.example/oauth2",
            "audience": "thalion-kb-api",
            "jwks_url": "https://idp.corp.example/oauth2/jwks",
        },
        "source_authority": {
            "endpoint": "https://authz.corp.example/v1/check",
            "credential_ref": "vault:kv/thalion/authz-client",
        },
        "object_storage": {
            "endpoint": "https://obj.corp.example",
            "bucket": "thalion-originals-prod",
            "credential_ref": "env:THALION_OBJ_CRED",
        },
        "security_audit_log": {
            "endpoint": "https://seclog.corp.example/v1/append",
            "credential_ref": "file:/run/secrets/seclog_token",
        },
    }
    parsed = validate_deployment_config(valid_prod)
    assert parsed.mode == "production"
    assert parsed.identity.issuer == "https://idp.corp.example/oauth2"

    bad_issuer = dict(valid_prod, identity=dict(valid_prod["identity"], issuer="https://synthetic.invalid"))
    with pytest.raises(ConfigValidationError, match="synthetic"):
        validate_deployment_config(bad_issuer)

    plain_http = dict(
        valid_prod,
        source_authority={"endpoint": "http://authz.corp.example/v1/check", "credential_ref": "env:THALION_A"},
    )
    with pytest.raises(ConfigValidationError, match="HTTPS"):
        validate_deployment_config(plain_http)

    raw_secret = dict(valid_prod, database_url_ref="postgresql://user:supersecret@db.corp.example/kb")
    with pytest.raises(ConfigValidationError, match="secret reference"):
        validate_deployment_config(raw_secret)

    bearer_secret = dict(
        valid_prod,
        security_audit_log={"endpoint": "https://seclog.corp.example/v1/append", "credential_ref": "Bearer abcdef123456"},
    )
    with pytest.raises(ConfigValidationError, match="secret reference"):
        validate_deployment_config(bearer_secret)

    unknown_key = dict(valid_prod, unexpected_field=True)
    with pytest.raises(ConfigValidationError, match="Unsupported"):
        validate_deployment_config(unknown_key)


def test_synthetic_config_validation_enforces_loopback_and_disjoint_directories(tmp_path: Path):
    from enterprise_kb.runtime.config import ConfigValidationError, validate_deployment_config

    profile = tmp_path / "profile"
    originals = profile / "originals"
    backups = tmp_path / "backups"
    profile.mkdir(mode=0o700)
    originals.mkdir(mode=0o700)
    backups.mkdir(mode=0o700)

    valid = {
        "mode": "synthetic_local",
        "host": "127.0.0.1",
        "port": 8765,
        "database_url": "postgresql://postgres:test@127.0.0.1:5432/thalion_dev",
        "profile_dir": str(profile),
        "originals_dir": str(originals),
        "backups_dir": str(backups),
    }
    parsed = validate_deployment_config(valid)
    assert parsed.mode == "synthetic_local"
    assert parsed.port == 8765

    with pytest.raises(ConfigValidationError, match="loopback"):
        validate_deployment_config(dict(valid, host="0.0.0.0"))

    with pytest.raises(ConfigValidationError, match="loopback"):
        validate_deployment_config(dict(valid, database_url="postgresql://postgres:test@db.corp.example:5432/prod"))

    nested_backups = originals / "nested_backups"
    nested_backups.mkdir(mode=0o700)
    with pytest.raises(ConfigValidationError, match="overlap"):
        validate_deployment_config(dict(valid, backups_dir=str(nested_backups)))

    with pytest.raises(ConfigValidationError, match="both"):
        validate_deployment_config(dict(valid, source_authority_url="postgresql://postgres:test@127.0.0.1:5432/auth"))
