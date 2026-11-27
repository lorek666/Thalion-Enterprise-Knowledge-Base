import argparse
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
from uuid import UUID, uuid4

import psycopg
from sqlalchemy.exc import ArgumentError
import uvicorn

from enterprise_kb.database import local_connection_factory, production_connection_factory, require_current_schema
from enterprise_kb.modules.access.original_download import MAX_PASSAGES as MAX_ORIGINAL_PASSAGES
from enterprise_kb.modules.access.delivery import AuthorityDecision, AuthorizationUnavailable, DeliveryCheck
from enterprise_kb.modules.access.policy import (
    DOCX_PREVIEW_ACCESS, EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS, EMPLOYEE_SOURCE_OPTIONS_ACCESS, EMPLOYEE_TITLE_SUGGESTIONS_ACCESS, MODEL_RULE_OPERATION,
    MODEL_RULE_PURPOSES, ORIGINAL_DOWNLOAD_ACCESS, ORIGINAL_FIELDS, PASSAGE_FIELDS, PDF_PAGE_FIELDS,
    PDF_PAGE_PREVIEW_ACCESS, REPAIR_PREVIEW_ACCESS,
    SYNTHETIC_MODEL_DESTINATION, WIKI_DERIVED_ACCESS,
)
from enterprise_kb.modules.lifecycle import archives
from enterprise_kb.modules.lifecycle.backup_inventory import SyntheticBackupStore
from enterprise_kb.modules.lifecycle.rebuild_format import REBUILD_FIELD
from enterprise_kb.modules.lifecycle.transcripts import REPAIR_HISTORY_FIELD, TRANSCRIPT_FIELD
from enterprise_kb.modules.lifecycle.wiki_archives import WIKI_FIELD
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore
from enterprise_kb.modules.sources.source_revocations import SourceRevocationAuthority
from enterprise_kb.ports.adapters import (
    OpenAiCompatibleEmbeddingProviderAdapter,
    OpenAiCompatibleModelGatewayAdapter,
    build_production_port_registry,
    embedding_options_from_env,
    model_gateway_options_from_env,
    resolve_secret_ref,
)
from enterprise_kb.ports.contracts import IdentityVerifierPort, PortUnavailable, ProductionIsolationError
from enterprise_kb.runtime.config import ConfigValidationError, ProductionDeploymentConfig, load_production_config_from_env

from .api import create_app
from .evidence import EvidenceService, SyntheticCredential, parse_ref
from .oidc_access import OidcBrowserAccess
from .oidc_sso import OidcSsoConfig, OidcSsoManager


MAX_PROFILE_BYTES = 512 * 1024
AUTHORITY_WINDOW = timedelta(seconds=8)
DIGEST = re.compile(r"[0-9a-f]{64}")
CREDENTIAL_KEYS = {
    "token_sha256", "employee_ref", "space_ref", "client_id", "region", "traveler_class", "operations", "expires_at",
}
MODEL_SOURCE_GRANT_KEYS = {"employee_ref", "purpose", "passage_id", "revision", "fields"}
LOCAL_SOURCE_ACCESS = frozenset({
    ("search", "employee_evidence", "employee"), ("read_passage", "employee_evidence", "employee"),
    EMPLOYEE_SOURCE_OPTIONS_ACCESS, EMPLOYEE_DEPARTMENT_OPTIONS_ACCESS, EMPLOYEE_TITLE_SUGGESTIONS_ACCESS,
    *WIKI_DERIVED_ACCESS, REPAIR_PREVIEW_ACCESS, DOCX_PREVIEW_ACCESS,
})


def _private_json(path: Path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            details = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid()
                or details.st_mode & 0o077 or not 0 < details.st_size <= MAX_PROFILE_BYTES
            ):
                raise ValueError("A synthetic profile requires private, bounded files.")
            payload = stream.read(MAX_PROFILE_BYTES + 1)
            if len(payload) != details.st_size:
                raise ValueError("The profile changed while it was read.")
        return json.loads(payload, object_pairs_hook=_unique_keys)
    except (OSError, ValueError, RecursionError):
        raise AuthorizationUnavailable("A synthetic profile file cannot be verified.") from None


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


class LocalProfile:
    admission = "synthetic_local"

    def __init__(self, root: Path, *, revocations: SourceRevocationAuthority | None = None):
        self.root = root.resolve(strict=True)
        details = self.root.stat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise ValueError("The synthetic profile directory must be private.")
        self.credentials()
        self.source_grants()
        self.model_source_grants()
        self.pdf_page_grants()
        self.original_download_grants()
        self.archive_grants()
        self.transcript_archive_grants()
        self.retest_key = self._feedback_retest_key()
        self.revocations = revocations

    def _feedback_retest_key(self) -> bytes | None:
        path = self.root / "feedback-retest-key.json"
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        value = _private_json(path)
        if not isinstance(value, str) or not DIGEST.fullmatch(value):
            raise ValueError("Invalid private feedback retest key.")
        return bytes.fromhex(value)

    def credentials(self) -> dict[str, SyntheticCredential]:
        entries = _private_json(self.root / "credentials.json")
        credentials = {}
        try:
            if not isinstance(entries, list) or len(entries) > 128:
                raise ValueError("Invalid synthetic credentials.")
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != CREDENTIAL_KEYS:
                    raise ValueError("Invalid credential fields.")
                digest = entry["token_sha256"]
                if (
                    not DIGEST.fullmatch(digest) or digest in credentials or not isinstance(entry["operations"], list)
                    or not all(isinstance(op, str) for op in entry["operations"])
                ):
                    raise ValueError("Invalid credential digest or operations.")
                credentials[digest] = SyntheticCredential(
                    parse_ref(entry["employee_ref"]), parse_ref(entry["space_ref"]), entry["client_id"],
                    entry["region"], entry["traveler_class"], frozenset(entry["operations"]),
                    datetime.fromisoformat(entry["expires_at"]),
                )
        except (ValueError, TypeError):
            raise AuthorizationUnavailable("Synthetic credentials cannot be verified.") from None
        return credentials

    def source_grants(self) -> dict[UUID, frozenset[UUID]]:
        return self._grants(self.root / "source-grants.json", max_objects=MAX_ORIGINAL_PASSAGES)

    def model_source_grants(self) -> dict[tuple[UUID, str, UUID, int], frozenset[str]]:
        path = self._optional_grant_file("model-source-grants.json")
        if path is None:
            return {}
        entries = _private_json(path)
        grants = {}
        try:
            if not isinstance(entries, list) or len(entries) > 512:
                raise ValueError("Invalid synthetic model source grant list.")
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != MODEL_SOURCE_GRANT_KEYS:
                    raise ValueError("Invalid synthetic model source grant fields.")
                purpose, revision, fields = entry["purpose"], entry["revision"], entry["fields"]
                if (
                    purpose not in MODEL_RULE_PURPOSES or type(revision) is not int or not 0 < revision < 2**63
                    or not isinstance(fields, list) or not 1 <= len(fields) <= len(PASSAGE_FIELDS)
                ):
                    raise ValueError("Invalid synthetic model source grant scope.")
                field_set = frozenset(fields)
                key = (parse_ref(entry["employee_ref"]), purpose, parse_ref(entry["passage_id"]), revision)
                if key in grants or len(field_set) != len(fields) or not field_set <= PASSAGE_FIELDS:
                    raise ValueError("Duplicate or invalid synthetic model source grant.")
                grants[key] = field_set
        except (ValueError, TypeError):
            raise AuthorizationUnavailable("Synthetic model source grants cannot be verified.") from None
        return grants

    def pdf_page_grants(self) -> dict[UUID, frozenset[UUID]]:
        path = self._optional_grant_file("pdf-page-grants.json")
        return {} if path is None else self._grants(path)

    def original_download_grants(self) -> dict[UUID, frozenset[UUID]]:
        path = self._optional_grant_file("original-download-grants.json")
        return {} if path is None else self._grants(path)

    def archive_grants(self) -> dict[UUID, frozenset[UUID]]:
        path = self._optional_grant_file("archive-grants.json")
        return {} if path is None else self._grants(path)

    def wiki_archive_grants(self) -> dict[UUID, frozenset[UUID]]:
        path = self._optional_grant_file("wiki-archive-grants.json")
        return {} if path is None else self._grants(path)

    def _optional_grant_file(self, name: str) -> Path | None:
        path = self.root / name
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise AuthorizationUnavailable("Synthetic optional grants cannot be verified.") from None
        return path

    def transcript_archive_grants(self) -> dict[UUID, dict[UUID, int]]:
        path = self._optional_grant_file("transcript-archive-grants.json")
        if path is None:
            return {}
        entries = _private_json(path)
        grants = {}
        try:
            if not isinstance(entries, dict) or len(entries) > 128:
                raise ValueError("Invalid synthetic transcript archive grants.")
            for employee, allowed in entries.items():
                actor = parse_ref(employee)
                if actor in grants or not isinstance(allowed, dict) or len(allowed) > 512:
                    raise ValueError("Invalid actor in transcript archive grants.")
                passages = {}
                for passage, revision in allowed.items():
                    ref = parse_ref(passage)
                    if ref in passages or type(revision) is not int or not 0 < revision < 2**63:
                        raise ValueError("Invalid excerpt revision in transcript archive grants.")
                    passages[ref] = revision
                grants[actor] = passages
        except (ValueError, TypeError):
            raise AuthorizationUnavailable("Synthetic transcript archive grants cannot be verified.") from None
        return grants

    def _grants(self, path: Path, *, max_objects: int = 512) -> dict[UUID, frozenset[UUID]]:
        entries = _private_json(path)
        grants = {}
        try:
            if not isinstance(entries, dict) or len(entries) > 128:
                raise ValueError("Invalid synthetic source grants.")
            for employee, allowed in entries.items():
                if not isinstance(allowed, list) or len(allowed) > max_objects:
                    raise ValueError("Invalid sources in a synthetic grant.")
                employee_ref = parse_ref(employee)
                if employee_ref in grants:
                    raise ValueError("Duplicate employee in synthetic source grants.")
                grants[employee_ref] = frozenset(parse_ref(object_ref) for object_ref in allowed)
        except (ValueError, TypeError):
            raise AuthorizationUnavailable("Synthetic source grants cannot be verified.") from None
        return grants

    def verify_token(self, token: str) -> SyntheticCredential | None:
        return self.credentials().get(sha256(token.encode("ascii")).hexdigest())

    def _restrict_source(self, credential, fields, access_use, *, snapshot=None):
        if snapshot is None and self.revocations is None:
            return fields, str(uuid4())
        state = snapshot if snapshot is not None else self.revocations.snapshot(credential.space_ref)
        denied = state.denied_objects(credential.employee_ref, access_use)
        return (
            {scope: frozenset() if scope.object_id in denied else granted for scope, granted in fields.items()},
            f"synthetic-source:{state.authority_ref}:{state.stream_ref}:{state.generation}:{uuid4()}",
        )

    def check_source(self, credential: SyntheticCredential, probe: DeliveryCheck) -> AuthorityDecision:
        return self._check_source(credential, probe)

    @contextmanager
    def check_pinned_original(self, credential: SyntheticCredential, probe: DeliveryCheck):
        context = probe.context
        if (context.operation, context.purpose, context.destination) != ORIGINAL_DOWNLOAD_ACCESS:
            raise AuthorizationUnavailable("The pinned source check is reserved for original downloads.")
        if self.revocations is None:
            yield self._check_source(credential, probe)
            return
        with self.revocations.pinned_snapshot(credential.space_ref) as snapshot:
            yield self._check_source(credential, probe, snapshot=snapshot)

    def _check_source(self, credential: SyntheticCredential, probe: DeliveryCheck, *, snapshot=None) -> AuthorityDecision:
        context = probe.context
        access = (context.operation, context.purpose, context.destination)
        if access == ORIGINAL_DOWNLOAD_ACCESS:
            originals = self.original_download_grants().get(credential.employee_ref, frozenset())
            passages = self.source_grants().get(credential.employee_ref, frozenset())
            granted = {
                scope: scope.fields if scope.object_id in (originals if scope.fields == ORIGINAL_FIELDS else passages)
                and (scope.fields == ORIGINAL_FIELDS or scope.fields <= PASSAGE_FIELDS) else frozenset()
                for scope in probe.scopes
            }
        elif access == PDF_PAGE_PREVIEW_ACCESS:
            allowed = self.pdf_page_grants().get(credential.employee_ref, frozenset())
            allowed_fields = PDF_PAGE_FIELDS
        elif access in LOCAL_SOURCE_ACCESS:
            allowed = self.source_grants().get(credential.employee_ref, frozenset())
            allowed_fields = PASSAGE_FIELDS
        else:
            raise AuthorizationUnavailable("The requested use is not a synthetic local evidence operation.")
        if access != ORIGINAL_DOWNLOAD_ACCESS:
            granted = {
                scope: scope.fields & allowed_fields if scope.object_id in allowed else frozenset()
                for scope in probe.scopes
            }
        fields, proof = self._restrict_source(credential, granted, "evidence", snapshot=snapshot)
        checked_at = datetime.now(UTC)
        return AuthorityDecision(
            probe.check_id, checked_at, min(checked_at + AUTHORITY_WINDOW, credential.expires_at),
            frozenset({probe.context.principal_id}), fields, proof,
        )

    def check_model_source(self, credential: SyntheticCredential, probe: DeliveryCheck) -> AuthorityDecision:
        context = probe.context
        if (
            context.operation != MODEL_RULE_OPERATION or context.purpose not in MODEL_RULE_PURPOSES
            or context.destination != SYNTHETIC_MODEL_DESTINATION or context.client_id != credential.client_id
            or self.revocations is None
        ):
            raise AuthorizationUnavailable("The synthetic model use or independent revocation authority is not configured.")
        employee = credential.employee_ref
        source_readers = self.source_grants().get(employee, frozenset())
        model_grants = self.model_source_grants()
        fields, proof = self._restrict_source(credential, {
            scope: scope.fields & model_grants.get((employee, context.purpose, scope.object_id, scope.revision), frozenset())
            if scope.object_id in source_readers and scope.revision is not None else frozenset()
            for scope in probe.scopes
        }, "evidence")
        checked_at = datetime.now(UTC)
        return AuthorityDecision(
            probe.check_id, checked_at, min(checked_at + AUTHORITY_WINDOW, credential.expires_at, context.deadline),
            frozenset({context.principal_id}), fields, f"model-source:{proof}",
        )

    def check_archive_source(self, credential: SyntheticCredential, probe: DeliveryCheck) -> AuthorityDecision:
        context = probe.context
        if (context.operation, context.purpose, context.destination) != (archives.EXPORT, archives.PURPOSE, archives.ARCHIVE_DESTINATION):
            raise AuthorizationUnavailable("The synthetic archive destination is not recognized.")
        allowed = self.archive_grants().get(credential.employee_ref, frozenset())
        rebuild_path = self._optional_grant_file("rebuild-archive-grants.json") if any(
            REBUILD_FIELD in scope.fields for scope in probe.scopes
        ) else None
        rebuild = self._grants(rebuild_path).get(credential.employee_ref, frozenset()) if rebuild_path else frozenset()
        history_path = self._optional_grant_file("repair-history-archive-grants.json") if any(
            REPAIR_HISTORY_FIELD in scope.fields for scope in probe.scopes
        ) else None
        history = self._grants(history_path).get(credential.employee_ref, frozenset()) if history_path else frozenset()
        transcripts = (
            self.transcript_archive_grants().get(credential.employee_ref, {})
            if any(scope.revision is not None for scope in probe.scopes) else {}
        )
        wiki = (
            self.wiki_archive_grants().get(credential.employee_ref, frozenset())
            if any(WIKI_FIELD in scope.fields for scope in probe.scopes) else frozenset()
        )
        fields = {}
        for scope in probe.scopes:
            if scope.revision is None:
                original_fields = scope.fields & archives.FIELDS if scope.object_id in allowed else frozenset()
                wiki_fields = scope.fields & {WIKI_FIELD} if scope.object_id in wiki else frozenset()
                rebuild_fields = scope.fields & {REBUILD_FIELD} if scope.object_id in rebuild else frozenset()
                fields[scope] = original_fields | wiki_fields | rebuild_fields
            else:
                fields[scope] = scope.fields & {TRANSCRIPT_FIELD} if transcripts.get(scope.object_id) == scope.revision else frozenset()
            if scope.object_id in history:
                fields[scope] |= scope.fields & {REPAIR_HISTORY_FIELD}
        fields, proof = self._restrict_source(credential, fields, "archive")
        checked_at = datetime.now(UTC)
        return AuthorityDecision(
            probe.check_id, checked_at, min(checked_at + AUTHORITY_WINDOW, credential.expires_at),
            frozenset({context.principal_id}), fields, proof,
        )


def _configured_source_revocations():
    url = os.environ.get("THALION_SOURCE_AUTHORITY_URL")
    pin = os.environ.get("THALION_SOURCE_AUTHORITY_REF")
    if url is None and pin is None:
        return None
    if not url or not pin:
        raise ValueError("The synthetic source authority requires both a database URL and an endpoint pin.")
    authority = SourceRevocationAuthority(local_connection_factory(url), parse_ref(pin))
    authority.validate()
    return authority


def _verify_shared_tables(connection) -> tuple[str, ...]:
    revisions = require_current_schema(connection)
    if connection.execute("SELECT to_regclass('thalion.feedback_search_match')").fetchone() == (None,):
        raise ValueError("The shared database migrations have not run.")
    connection.execute("SELECT conclusion_code FROM thalion.feedback_decision LIMIT 0")
    connection.execute("SELECT classification FROM thalion.open_gap_candidate LIMIT 0")
    connection.execute("SELECT gap_ref FROM thalion.gap_feedback_attachment LIMIT 0")
    connection.execute("SELECT empty_fingerprint FROM thalion.search_scope_observation LIMIT 0")
    connection.execute("SELECT finding_ref FROM thalion.lint_finding LIMIT 0")
    connection.execute("SELECT version_id FROM thalion.lifecycle_version_manifest LIMIT 0")
    connection.execute("SELECT action FROM thalion.current_version_hold LIMIT 0")
    connection.execute("SELECT observation_ref FROM thalion.disposition_original_observation LIMIT 0")
    connection.execute("SELECT receipt_ref FROM thalion.disposition_copy_receipt LIMIT 0")
    connection.execute("SELECT backup_ref FROM thalion.synthetic_backup_copy LIMIT 0")
    connection.execute("SELECT archive_digest FROM thalion.synthetic_export_package LIMIT 0")
    connection.execute("SELECT transcript_run_ref FROM thalion.synthetic_export_request LIMIT 0")
    connection.execute("SELECT version_ref FROM thalion.permission_binding LIMIT 0")
    connection.execute("SELECT request_id FROM thalion.original_download_receipt LIMIT 0")
    connection.execute("SELECT source_facets FROM thalion.delivery_record LIMIT 0")
    connection.execute("SELECT request_id FROM thalion.source_audit_request LIMIT 0")
    connection.execute("SELECT release_ref FROM thalion.space_release_config LIMIT 0")
    connection.execute("SELECT export_ref FROM thalion.space_archive_request LIMIT 0")
    connection.execute("SELECT conflict_ref FROM thalion.rule_effectivity_conflict LIMIT 0")
    return revisions


def _build_production_oidc_sso(
    config: ProductionDeploymentConfig, env, connect, identity: IdentityVerifierPort,
) -> tuple[OidcSsoManager | None, IdentityVerifierPort]:
    auth_ep = (env.get("THALION_OIDC_AUTHORIZATION_ENDPOINT") or "").strip()
    token_ep = (env.get("THALION_OIDC_TOKEN_ENDPOINT") or "").strip()
    client_id = (env.get("THALION_OIDC_CLIENT_ID") or "").strip()
    redirect_uri = (env.get("THALION_OIDC_REDIRECT_URI") or "").strip()
    secret_ref = (env.get("THALION_OIDC_CLIENT_SECRET_REF") or "").strip()
    mapping_path = (env.get("THALION_OIDC_ACCESS_MAP_FILE") or "").strip()
    auth_method = (env.get("THALION_OIDC_TOKEN_AUTH_METHOD") or "client_secret_post").strip()
    present = [auth_ep, token_ep, client_id, redirect_uri]
    if not any(present) and not secret_ref and not mapping_path and not env.get("THALION_OIDC_TOKEN_AUTH_METHOD"):
        return None, identity
    if not all(present):
        raise ConfigValidationError(
            "OIDC SSO requires THALION_OIDC_AUTHORIZATION_ENDPOINT, THALION_OIDC_TOKEN_ENDPOINT, "
            "THALION_OIDC_CLIENT_ID, and THALION_OIDC_REDIRECT_URI together."
        )
    client_secret = resolve_secret_ref(secret_ref) if secret_ref else None
    browser_access = None
    if mapping_path:
        path = Path(mapping_path)
        if not path.is_absolute():
            raise ConfigValidationError("THALION_OIDC_ACCESS_MAP_FILE must be an absolute path.")
        browser_access = OidcBrowserAccess(connect, identity, _private_json(path))
    raw_scopes = (env.get("THALION_OIDC_SCOPES") or "openid profile email").strip()
    scopes = tuple(part for part in raw_scopes.replace(",", " ").split() if part)
    sso_config = OidcSsoConfig(
        issuer=config.identity.issuer,
        authorization_endpoint=auth_ep,
        token_endpoint=token_ep,
        jwks_url=config.identity.jwks_url,
        client_id=client_id,
        redirect_uri=redirect_uri,
        client_secret=client_secret,
        scopes=scopes,
        allow_http_loopback=False,
        token_auth_method=auth_method,
    )
    mapper = browser_access.issue if browser_access is not None else None
    return OidcSsoManager(sso_config, token_mapper=mapper), browser_access or identity


def _run_production_mode(arguments) -> int:
    try:
        config = load_production_config_from_env(os.environ)
        source_authority_ref = parse_ref((os.environ.get("THALION_SOURCE_AUTHORITY_REF") or "").strip())
        security_log_ref = parse_ref((os.environ.get("THALION_SECURITY_AUDIT_LOG_REF") or "").strip())
        model_options = model_gateway_options_from_env(os.environ)
        embedding_options = embedding_options_from_env(os.environ)
        registry = build_production_port_registry(
            config,
            source_authority_ref=source_authority_ref,
            security_log_ref=security_log_ref,
            source_connector_system=(os.environ.get("THALION_SOURCE_CONNECTOR_SYSTEM") or "").strip() or None,
            **model_options,
            **embedding_options,
        )
        database_url = resolve_secret_ref(config.database_url_ref)
        connect = production_connection_factory(database_url)
        oidc_sso, identity = _build_production_oidc_sso(config, os.environ, connect, registry.identity)
        registry = replace(registry, identity=identity)
        with connect() as connection:
            revisions = _verify_shared_tables(connection)
    except (
        OSError, ValueError, ArgumentError, ConfigValidationError,
        ProductionIsolationError, PortUnavailable, AuthorizationUnavailable, psycopg.Error,
    ):
        print("FAIL 无法验证生产配置、外部端口注册表或共享数据库迁移头。请核对配置并先执行共享迁移。", file=sys.stderr)
        return 1
    if arguments.check_config:
        ports_summary = {
            "identity": registry.identity.admission if registry.identity is not None else None,
            "source_authority": registry.source_authority.admission if registry.source_authority is not None else None,
            "object_storage": registry.object_storage.admission if registry.object_storage is not None else None,
            "security_audit_log": (
                registry.security_audit_log.admission if registry.security_audit_log is not None else None
            ),
            "source_connector": registry.source_connector.admission if registry.source_connector is not None else None,
            "model_gateway": registry.model_gateway.admission if registry.model_gateway is not None else None,
            "embedding_provider": (
                registry.embedding_provider.admission if registry.embedding_provider is not None else None
            ),
        }
        summary = {
            "status": "ok",
            "mode": "production",
            "business_timezone": config.business_timezone,
            "allowed_hosts": list(config.allowed_hosts),
            "schema_revisions": list(revisions),
            "ports": ports_summary,
            "model_gateway_protocol": (
                "openai_compatible"
                if isinstance(registry.model_gateway, OpenAiCompatibleModelGatewayAdapter)
                else ("thalion" if registry.model_gateway is not None else None)
            ),
            "model_gateway_model": (
                registry.model_gateway.model
                if isinstance(registry.model_gateway, OpenAiCompatibleModelGatewayAdapter)
                else None
            ),
            "embedding_protocol": (
                "openai_compatible"
                if isinstance(registry.embedding_provider, OpenAiCompatibleEmbeddingProviderAdapter)
                else ("thalion" if registry.embedding_provider is not None else None)
            ),
            "embedding_model_id": (
                registry.embedding_provider.model_id
                if registry.embedding_provider is not None
                else None
            ),
            "embedding_dimension": (
                registry.embedding_provider.dimension
                if registry.embedding_provider is not None
                else None
            ),
            "oidc_sso_configured": oidc_sso is not None,
            "oidc_access_mapping_configured": isinstance(identity, OidcBrowserAccess),
            "port": arguments.port,
        }
        print(json.dumps(summary, ensure_ascii=False))
        return 0
    service = EvidenceService.from_port_registry(connect, registry)
    uvicorn.run(
        create_app(service, allowed_hosts=config.allowed_hosts, oidc_sso=oidc_sso),
        host=arguments.host,
        port=arguments.port,
        proxy_headers=False,
        access_log=False,
        limit_concurrency=64,
        timeout_keep_alive=5,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="启动 Thalion 企业知识库取证服务")
    parser.add_argument(
        "--mode",
        choices=("synthetic_local", "production"),
        default="synthetic_local",
        help="运行模式（默认 synthetic_local；production 从环境变量加载外部端口配置）",
    )
    parser.add_argument("--profile", type=Path, help="私有合成权限配置目录（synthetic_local 模式必填）")
    parser.add_argument("--originals", type=Path, help="私有合成原件目录，默认为配置目录下的 originals")
    parser.add_argument("--backups", type=Path, help="已存在的私有合成备份目录；不配置则禁止登记")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（synthetic_local 强制 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--check-config", action="store_true", help="仅校验运行配置、外部端口与数据库迁移状态后退出")
    arguments = parser.parse_args()
    if not 0 <= arguments.port <= 65535:
        parser.error("端口必须在 0 至 65535 之间。")
    if arguments.mode == "production":
        if arguments.profile is not None or arguments.originals is not None or arguments.backups is not None:
            parser.error("production 模式禁止使用合成目录参数（--profile / --originals / --backups）。")
        return _run_production_mode(arguments)
    if arguments.profile is None:
        parser.error("synthetic_local 模式必须提供 --profile。")
    if arguments.host != "127.0.0.1":
        parser.error("synthetic_local 模式仅允许监听 127.0.0.1。")
    try:
        revocations = _configured_source_revocations()
        profile = LocalProfile(arguments.profile, revocations=revocations)
        store = SyntheticOriginalStore(arguments.originals or profile.root / "originals")
        backup_store = SyntheticBackupStore(arguments.backups, store) if arguments.backups is not None else None
        connect = local_connection_factory(os.environ.get("THALION_DATABASE_URL", ""))
        with connect() as connection:
            revisions = _verify_shared_tables(connection)
    except (OSError, ValueError, ArgumentError, AuthorizationUnavailable, psycopg.Error):
        print("FAIL 无法验证私有合成配置、存储目录或本机开发数据库。请检查配置并先执行共享迁移。", file=sys.stderr)
        return 1
    if arguments.check_config:
        summary = {
            "status": "ok",
            "mode": "synthetic_local",
            "schema_revisions": list(revisions),
            "source_authority_configured": revocations is not None,
            "backups_configured": backup_store is not None,
            "retest_key_configured": profile.retest_key is not None,
            "port": arguments.port,
        }
        print(json.dumps(summary, ensure_ascii=False))
        return 0
    service = EvidenceService(
        connect, profile.verify_token, profile.check_source, store, retest_key=profile.retest_key, backup_store=backup_store,
        check_archive_source=profile.check_archive_source, pin_original_source=profile.check_pinned_original,
    )
    uvicorn.run(
        create_app(service), host=arguments.host, port=arguments.port, proxy_headers=False,
        access_log=False, limit_concurrency=32, timeout_keep_alive=5,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
