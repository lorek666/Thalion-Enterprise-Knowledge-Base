from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import re
import stat
from typing import Any, Literal
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


SECRET_REF_PATTERN = re.compile(r"^(env:[A-Z][A-Z0-9_]{1,127}|vault:[A-Za-z0-9_./:-]{3,256}|kms:[A-Za-z0-9_./:-]{3,256}|file:/[A-Za-z0-9_./-]{2,256})$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?$")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
FORBIDDEN_SYNTHETIC_MARKERS = ("synthetic.invalid", "localhost", "127.0.0.1")
S3_BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]")
S3_REGION_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")

PRODUCTION_KEYS = frozenset({
    "mode", "business_timezone", "database_url_ref", "allowed_hosts",
    "identity", "source_authority", "object_storage", "security_audit_log",
    "source_connector", "model_gateway", "embedding_provider",
})
SYNTHETIC_KEYS = frozenset({
    "mode", "host", "port", "database_url", "profile_dir", "originals_dir",
    "backups_dir", "source_authority_url", "source_authority_ref",
})


class ConfigValidationError(ValueError):
    pass


@dataclass(frozen=True)
class IdentityEndpointConfig:
    issuer: str
    audience: str
    jwks_url: str


@dataclass(frozen=True)
class AuthenticatedEndpointConfig:
    endpoint: str
    credential_ref: str


@dataclass(frozen=True)
class ObjectStorageEndpointConfig:
    endpoint: str
    bucket: str
    credential_ref: str
    protocol: Literal["thalion", "s3"] = "thalion"
    region: str | None = None
    s3_provider: Literal["aliyun_oss", "tencent_cos"] | None = None
    addressing_style: Literal["virtual", "path", "bucket"] | None = None

    def __post_init__(self) -> None:
        if self.protocol == "thalion":
            if any(value is not None for value in (self.region, self.s3_provider, self.addressing_style)):
                raise ConfigValidationError("S3 storage options require object_storage.protocol=s3.")
            return
        if self.protocol != "s3":
            raise ConfigValidationError("object_storage.protocol must be thalion or s3.")
        if not isinstance(self.region, str) or len(self.region) > 64 or not S3_REGION_PATTERN.fullmatch(self.region):
            raise ConfigValidationError("S3 object_storage.region must be an explicit region identifier.")
        if self.s3_provider not in (None, "aliyun_oss", "tencent_cos"):
            raise ConfigValidationError("Unsupported object_storage.s3_provider.")
        if self.addressing_style not in (None, "virtual", "path", "bucket"):
            raise ConfigValidationError("Unsupported object_storage.addressing_style.")
        if self.s3_provider == "aliyun_oss" and self.addressing_style == "path":
            raise ConfigValidationError("OSS addressing_style must be virtual or bucket.")
        if not isinstance(self.bucket, str) or not S3_BUCKET_PATTERN.fullmatch(self.bucket):
            raise ConfigValidationError("S3 object_storage.bucket must be a single DNS label of 3 to 63 characters.")
        if self.s3_provider == "tencent_cos" and not self.bucket.rpartition("-")[2].isdigit():
            raise ConfigValidationError("COS bucket must include its numeric APPID suffix.")
        endpoint = _validate_https_url(self.endpoint, "object_storage.endpoint")
        parsed = urlparse(endpoint)
        if parsed.path not in ("", "/") or any(char in endpoint for char in "?#\\") or any(char.isspace() for char in endpoint):
            raise ConfigValidationError("S3 object_storage.endpoint must be an HTTPS origin without a path or query.")
        try:
            parsed.port
        except ValueError:
            raise ConfigValidationError("S3 object_storage.endpoint has an invalid port.") from None


@dataclass(frozen=True)
class ProductionDeploymentConfig:
    mode: Literal["production"]
    business_timezone: str
    database_url_ref: str
    allowed_hosts: tuple[str, ...]
    identity: IdentityEndpointConfig
    source_authority: AuthenticatedEndpointConfig
    object_storage: ObjectStorageEndpointConfig
    security_audit_log: AuthenticatedEndpointConfig
    source_connector: AuthenticatedEndpointConfig | None = None
    model_gateway: AuthenticatedEndpointConfig | None = None
    embedding_provider: AuthenticatedEndpointConfig | None = None


@dataclass(frozen=True)
class SyntheticLocalConfig:
    mode: Literal["synthetic_local"]
    host: str
    port: int
    database_url: str
    profile_dir: Path
    originals_dir: Path
    backups_dir: Path | None = None
    source_authority_url: str | None = None
    source_authority_ref: str | None = None


def _validate_secret_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SECRET_REF_PATTERN.fullmatch(value.strip()):
        raise ConfigValidationError(
            f"{label} must be an indirect secret reference (env:, vault:, kms:, or file:), not a raw secret."
        )
    return value.strip()


def _validate_https_url(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigValidationError(f"{label} must be a non-empty HTTPS URL.")
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigValidationError(f"{label} must use HTTPS with an explicit host.")
    hostname = parsed.hostname.lower()
    if any(marker in hostname for marker in FORBIDDEN_SYNTHETIC_MARKERS):
        raise ConfigValidationError(f"{label} cannot reference synthetic or loopback endpoints in production.")
    if parsed.username or parsed.password:
        raise ConfigValidationError(f"{label} must not embed credentials in URL.")
    return value.strip()


def _validate_authenticated_endpoint(raw: Any, label: str) -> AuthenticatedEndpointConfig:
    if not isinstance(raw, Mapping) or set(raw.keys()) != {"endpoint", "credential_ref"}:
        raise ConfigValidationError(f"{label} requires exact keys: endpoint, credential_ref.")
    return AuthenticatedEndpointConfig(
        endpoint=_validate_https_url(raw["endpoint"], f"{label}.endpoint"),
        credential_ref=_validate_secret_ref(raw["credential_ref"], f"{label}.credential_ref"),
    )


def _paths_overlap(first: Path, second: Path) -> bool:
    resolved_first = first.resolve()
    resolved_second = second.resolve()
    return (
        resolved_first == resolved_second
        or resolved_first in resolved_second.parents
        or resolved_second in resolved_first.parents
    )


def _check_private_dir(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        details = resolved.stat()
    except OSError:
        raise ConfigValidationError(f"{label} directory must exist.") from None
    if not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o077:
        raise ConfigValidationError(f"{label} directory must be private (mode 0700).")
    return resolved


def validate_deployment_config(raw: Mapping[str, Any]) -> SyntheticLocalConfig | ProductionDeploymentConfig:
    if not isinstance(raw, Mapping):
        raise ConfigValidationError("Deployment configuration must be a mapping.")
    mode = raw.get("mode")
    if mode == "production":
        return _validate_production(raw)
    if mode == "synthetic_local":
        return _validate_synthetic(raw)
    raise ConfigValidationError("Deployment mode must be 'synthetic_local' or 'production'.")


def _validate_production(raw: Mapping[str, Any]) -> ProductionDeploymentConfig:
    extra = set(raw.keys()) - PRODUCTION_KEYS
    if extra:
        raise ConfigValidationError(f"Unsupported production config keys: {', '.join(sorted(extra))}.")
    timezone_name = raw.get("business_timezone")
    if not isinstance(timezone_name, str) or not timezone_name:
        raise ConfigValidationError("business_timezone is required.")
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        raise ConfigValidationError(f"Unknown business_timezone: {timezone_name}.") from None
    database_url_ref = _validate_secret_ref(raw.get("database_url_ref"), "database_url_ref")
    hosts = raw.get("allowed_hosts")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(item, str) and HOST_PATTERN.fullmatch(item) for item in hosts):
        raise ConfigValidationError("allowed_hosts must be a non-empty list of valid hostnames.")
    if any(any(marker in host.lower() for marker in FORBIDDEN_SYNTHETIC_MARKERS) for host in hosts):
        raise ConfigValidationError("Production allowed_hosts cannot include synthetic or loopback hosts.")
    identity_raw = raw.get("identity")
    if not isinstance(identity_raw, Mapping) or set(identity_raw.keys()) != {"issuer", "audience", "jwks_url"}:
        raise ConfigValidationError("identity requires exact keys: issuer, audience, jwks_url.")
    audience = identity_raw["audience"]
    if not isinstance(audience, str) or not audience.strip():
        raise ConfigValidationError("identity.audience must be non-empty.")
    identity = IdentityEndpointConfig(
        issuer=_validate_https_url(identity_raw["issuer"], "identity.issuer"),
        audience=audience.strip(),
        jwks_url=_validate_https_url(identity_raw["jwks_url"], "identity.jwks_url"),
    )
    source_authority = _validate_authenticated_endpoint(raw.get("source_authority"), "source_authority")
    storage_raw = raw.get("object_storage")
    storage_required = {"endpoint", "bucket", "credential_ref"}
    storage_optional = {"protocol", "region", "s3_provider", "addressing_style"}
    if not isinstance(storage_raw, Mapping) or not storage_required <= storage_raw.keys() <= storage_required | storage_optional:
        raise ConfigValidationError("object_storage requires endpoint, bucket, credential_ref and accepts only known S3 options.")
    bucket = storage_raw["bucket"]
    if not isinstance(bucket, str) or not bucket.strip():
        raise ConfigValidationError("object_storage.bucket must be non-empty.")
    object_storage = ObjectStorageEndpointConfig(
        endpoint=_validate_https_url(storage_raw["endpoint"], "object_storage.endpoint"),
        bucket=bucket.strip(),
        credential_ref=_validate_secret_ref(storage_raw["credential_ref"], "object_storage.credential_ref"),
        **{key: storage_raw[key] for key in storage_optional & storage_raw.keys()},
    )
    security_audit_log = _validate_authenticated_endpoint(raw.get("security_audit_log"), "security_audit_log")
    source_connector = (
        _validate_authenticated_endpoint(raw["source_connector"], "source_connector")
        if raw.get("source_connector") is not None
        else None
    )
    model_gateway = (
        _validate_authenticated_endpoint(raw["model_gateway"], "model_gateway")
        if raw.get("model_gateway") is not None
        else None
    )
    embedding_provider = (
        _validate_authenticated_endpoint(raw["embedding_provider"], "embedding_provider")
        if raw.get("embedding_provider") is not None
        else None
    )
    return ProductionDeploymentConfig(
        mode="production",
        business_timezone=timezone_name,
        database_url_ref=database_url_ref,
        allowed_hosts=tuple(hosts),
        identity=identity,
        source_authority=source_authority,
        object_storage=object_storage,
        security_audit_log=security_audit_log,
        source_connector=source_connector,
        model_gateway=model_gateway,
        embedding_provider=embedding_provider,
    )


def _validate_synthetic(raw: Mapping[str, Any]) -> SyntheticLocalConfig:
    extra = set(raw.keys()) - SYNTHETIC_KEYS
    if extra:
        raise ConfigValidationError(f"Unsupported synthetic_local config keys: {', '.join(sorted(extra))}.")
    host = raw.get("host", "127.0.0.1")
    if not isinstance(host, str) or host not in LOOPBACK_HOSTS:
        raise ConfigValidationError("synthetic_local mode must bind only to a loopback host.")
    port = raw.get("port", 8765)
    if type(port) is not int or not 0 <= port <= 65535:
        raise ConfigValidationError("synthetic_local port must be an integer between 0 and 65535.")
    database_url = raw.get("database_url")
    if not isinstance(database_url, str) or not database_url.strip():
        raise ConfigValidationError("synthetic_local requires database_url.")
    try:
        parsed_db = make_url(database_url)
    except ArgumentError:
        raise ConfigValidationError("Invalid PostgreSQL database_url.") from None
    if (
        parsed_db.drivername not in {"postgresql", "postgresql+psycopg"}
        or parsed_db.host not in LOOPBACK_HOSTS
        or not parsed_db.database
        or not parsed_db.username
    ):
        raise ConfigValidationError("synthetic_local database_url must target a loopback PostgreSQL instance.")
    profile_raw = raw.get("profile_dir")
    if not isinstance(profile_raw, (str, Path)):
        raise ConfigValidationError("synthetic_local requires profile_dir.")
    profile_dir = _check_private_dir(Path(profile_raw), "profile_dir")
    originals_raw = raw.get("originals_dir")
    originals_dir = _check_private_dir(
        Path(originals_raw) if originals_raw is not None else profile_dir / "originals",
        "originals_dir",
    )
    backups_raw = raw.get("backups_dir")
    backups_dir = None
    if backups_raw is not None:
        backups_dir = _check_private_dir(Path(backups_raw), "backups_dir")
        if _paths_overlap(originals_dir, backups_dir):
            raise ConfigValidationError("synthetic_local originals_dir and backups_dir must not overlap.")
    auth_url = raw.get("source_authority_url")
    auth_ref = raw.get("source_authority_ref")
    if (auth_url is None) != (auth_ref is None):
        raise ConfigValidationError("synthetic_local source authority requires both URL and reference pin.")
    if auth_url is not None:
        try:
            parsed_auth = make_url(str(auth_url))
        except ArgumentError:
            raise ConfigValidationError("Invalid source_authority_url.") from None
        if parsed_auth.host not in LOOPBACK_HOSTS:
            raise ConfigValidationError("synthetic_local source_authority_url must target loopback.")
    return SyntheticLocalConfig(
        mode="synthetic_local",
        host=host,
        port=port,
        database_url=database_url,
        profile_dir=profile_dir,
        originals_dir=originals_dir,
        backups_dir=backups_dir,
        source_authority_url=auth_url,
        source_authority_ref=auth_ref,
    )


def _optional_env_endpoint(
    environ: Mapping[str, str],
    endpoint_key: str,
    credential_key: str,
    label: str,
) -> dict[str, str] | None:
    endpoint = (environ.get(endpoint_key) or "").strip()
    credential_ref = (environ.get(credential_key) or "").strip()
    if not endpoint and not credential_ref:
        return None
    if not endpoint or not credential_ref:
        raise ConfigValidationError(f"{label} requires both {endpoint_key} and {credential_key}.")
    return {"endpoint": endpoint, "credential_ref": credential_ref}


def load_production_config_from_env(environ: Mapping[str, str]) -> ProductionDeploymentConfig:
    mode = (environ.get("THALION_MODE") or "production").strip()
    if mode != "production":
        raise ConfigValidationError("Production config loader requires THALION_MODE=production.")
    raw_hosts = (environ.get("THALION_ALLOWED_HOSTS") or "").strip()
    allowed_hosts = [item.strip() for item in raw_hosts.split(",") if item.strip()]
    raw: dict[str, Any] = {
        "mode": "production",
        "business_timezone": (environ.get("THALION_BUSINESS_TIMEZONE") or "").strip(),
        "database_url_ref": (environ.get("THALION_DATABASE_URL_REF") or "").strip(),
        "allowed_hosts": allowed_hosts,
        "identity": {
            "issuer": (environ.get("THALION_OIDC_ISSUER") or "").strip(),
            "audience": (environ.get("THALION_OIDC_AUDIENCE") or "").strip(),
            "jwks_url": (environ.get("THALION_OIDC_JWKS_URL") or "").strip(),
        },
        "source_authority": {
            "endpoint": (environ.get("THALION_SOURCE_AUTHORITY_ENDPOINT") or "").strip(),
            "credential_ref": (environ.get("THALION_SOURCE_AUTHORITY_CREDENTIAL_REF") or "").strip(),
        },
        "object_storage": {
            "endpoint": (environ.get("THALION_OBJECT_STORAGE_ENDPOINT") or "").strip(),
            "bucket": (environ.get("THALION_OBJECT_STORAGE_BUCKET") or "").strip(),
            "credential_ref": (environ.get("THALION_OBJECT_STORAGE_CREDENTIAL_REF") or "").strip(),
            "protocol": (environ.get("THALION_OBJECT_STORAGE_PROTOCOL") or "").strip() or "thalion",
            "region": (environ.get("THALION_OBJECT_STORAGE_REGION") or "").strip() or None,
            "s3_provider": (environ.get("THALION_OBJECT_STORAGE_S3_PROVIDER") or "").strip() or None,
            "addressing_style": (environ.get("THALION_OBJECT_STORAGE_ADDRESSING_STYLE") or "").strip() or None,
        },
        "security_audit_log": {
            "endpoint": (environ.get("THALION_SECURITY_AUDIT_ENDPOINT") or "").strip(),
            "credential_ref": (environ.get("THALION_SECURITY_AUDIT_CREDENTIAL_REF") or "").strip(),
        },
    }
    connector = _optional_env_endpoint(
        environ,
        "THALION_SOURCE_CONNECTOR_ENDPOINT",
        "THALION_SOURCE_CONNECTOR_CREDENTIAL_REF",
        "source_connector",
    )
    if connector is not None:
        raw["source_connector"] = connector
    model_gateway = _optional_env_endpoint(
        environ,
        "THALION_MODEL_GATEWAY_ENDPOINT",
        "THALION_MODEL_GATEWAY_CREDENTIAL_REF",
        "model_gateway",
    )
    if model_gateway is not None:
        raw["model_gateway"] = model_gateway
    embedding = _optional_env_endpoint(
        environ,
        "THALION_EMBEDDING_ENDPOINT",
        "THALION_EMBEDDING_CREDENTIAL_REF",
        "embedding_provider",
    )
    if embedding is not None:
        raw["embedding_provider"] = embedding
    parsed = validate_deployment_config(raw)
    assert isinstance(parsed, ProductionDeploymentConfig)
    return parsed
