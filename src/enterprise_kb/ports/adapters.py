from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import stat
from threading import Lock
from time import monotonic
from typing import Any, Literal
from uuid import UUID

import httpx2
import jwt

from enterprise_kb.modules.access.delivery import AuthorityDecision, DeliveryCheck
from enterprise_kb.runtime.config import (
    AuthenticatedEndpointConfig,
    IdentityEndpointConfig,
    ObjectStorageEndpointConfig,
    ProductionDeploymentConfig,
    _validate_https_url,
    _validate_secret_ref,
)

from .contracts import (
    AdmissionMode,
    AuthorityPortUnavailable,
    ConnectorDeltaPage,
    ConnectorInventory,
    ConnectorPortUnavailable,
    EmbeddingPortUnavailable,
    IdentityPortUnavailable,
    ModelGatewayUnavailable,
    ModelGenerationReceipt,
    ModelGenerationRequest,
    ModelOutcomeUnknown,
    ObjectStorageUnavailable,
    PortRegistry,
    PortUnavailable,
    SecurityLogReceipt,
    SecurityLogUnavailable,
    VerifiedIdentity,
)


ALLOWED_JWT_ALGORITHMS = ("RS256", "ES256")
MAX_SECRET_FILE_BYTES = 16 * 1024
MAX_STORAGE_KEY_LEN = 512
HEX_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
STORAGE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
SCOPE_CLAIM_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MAX_AUTHORITY_WINDOW = timedelta(minutes=5)
SecretResolver = Callable[[str], str]


def _parse_json_strict(raw: bytes) -> Any:
    def reject_constant(_value: str):
        raise ValueError("Non-standard JSON constant is forbidden.")

    return json.loads(raw.decode("utf-8"), parse_constant=reject_constant)


def _parse_uuid(value: Any, label: str) -> UUID:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a UUID string.")
    return UUID(value)


def _parse_aware_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 timestamp.")
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError(f"{label} must include timezone offset.")
    return parsed.astimezone(UTC)


def _validate_storage_key(storage_key: str) -> str:
    if (
        not isinstance(storage_key, str)
        or not STORAGE_KEY_PATTERN.fullmatch(storage_key)
        or ".." in storage_key.split("/")
        or "//" in storage_key
    ):
        raise ObjectStorageUnavailable("Invalid immutable object storage key.")
    return storage_key


def resolve_secret_ref(
    secret_ref: str,
    *,
    environ: Mapping[str, str] | None = None,
    external_resolver: SecretResolver | None = None,
) -> str:
    try:
        validated = _validate_secret_ref(secret_ref, "credential_ref")
    except ValueError:
        raise PortUnavailable("Invalid indirect secret reference.") from None

    if validated.startswith("env:"):
        env_map = os.environ if environ is None else environ
        env_name = validated.split(":", 1)[1]
        secret_value = env_map.get(env_name, "").strip()
        if not secret_value:
            raise PortUnavailable(f"Required secret environment variable '{env_name}' is not set.")
        return secret_value

    if validated.startswith("file:"):
        file_path = Path(validated.split(":", 1)[1])
        try:
            descriptor = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                details = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_uid != os.geteuid()
                    or details.st_mode & 0o077
                    or not 0 < details.st_size <= MAX_SECRET_FILE_BYTES
                ):
                    raise PortUnavailable("Secret file must be regular, owner-only (0600), and bounded.")
                payload = stream.read(MAX_SECRET_FILE_BYTES + 1)
        except PortUnavailable:
            raise
        except OSError:
            raise PortUnavailable("Secret file could not be read.") from None
        if len(payload) > MAX_SECRET_FILE_BYTES:
            raise PortUnavailable("Secret file exceeds maximum allowed size.")
        secret_value = payload.decode("utf-8").strip()
        if not secret_value:
            raise PortUnavailable("Secret file is empty.")
        return secret_value

    if external_resolver is None:
        raise PortUnavailable("External vault/kms secret resolver is not configured.")
    resolved = external_resolver(validated)
    if not isinstance(resolved, str) or not resolved.strip():
        raise PortUnavailable("External secret resolver returned an empty credential.")
    return resolved.strip()


class _BaseHttpAdapter:
    def __init__(
        self,
        endpoint: str,
        credential_ref: str,
        *,
        timeout_seconds: float = 5.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        self._endpoint = _validate_https_url(endpoint, "endpoint").rstrip("/")
        self._credential_ref = _validate_secret_ref(credential_ref, "credential_ref")
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._secret_resolver = secret_resolver

    def _auth_headers(self) -> dict[str, str]:
        token = resolve_secret_ref(self._credential_ref, external_resolver=self._secret_resolver)
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _client(self) -> httpx2.Client:
        return httpx2.Client(
            timeout=self._timeout_seconds,
            transport=self._transport,
            follow_redirects=False,
        )


class OidcJwksIdentityVerifier:
    admission: AdmissionMode = "production_approved"

    def __init__(
        self,
        config: IdentityEndpointConfig,
        *,
        timeout_seconds: float = 5.0,
        jwks_ttl_seconds: float = 300.0,
        transport: httpx2.BaseTransport | None = None,
    ):
        self.issuer = _validate_https_url(config.issuer, "identity.issuer")
        if not isinstance(config.audience, str) or not config.audience.strip():
            raise ValueError("identity.audience must be non-empty.")
        self.audience = config.audience.strip()
        self._jwks_url = _validate_https_url(config.jwks_url, "identity.jwks_url")
        self._timeout_seconds = timeout_seconds
        self._jwks_ttl_seconds = jwks_ttl_seconds
        self._transport = transport
        self._lock = Lock()
        self._keys_by_kid: dict[str, tuple[str, Any]] = {}
        self._cache_expires_at = 0.0

    def _refresh_jwks(self) -> dict[str, tuple[str, Any]]:
        try:
            with httpx2.Client(
                timeout=self._timeout_seconds,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = client.get(self._jwks_url, headers={"Accept": "application/json"})
            if response.status_code != 200:
                raise IdentityPortUnavailable(f"JWKS endpoint returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            raw_keys = body.get("keys") if isinstance(body, dict) else None
            if not isinstance(raw_keys, list) or not raw_keys:
                raise IdentityPortUnavailable("JWKS payload contains no keys.")
            parsed: dict[str, tuple[str, Any]] = {}
            for entry in raw_keys:
                if not isinstance(entry, dict):
                    continue
                kid = entry.get("kid")
                kty = entry.get("kty")
                if not isinstance(kid, str) or not kid:
                    continue
                if kty == "RSA":
                    parsed[kid] = ("RS256", jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(entry)))
                elif kty == "EC":
                    parsed[kid] = ("ES256", jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(entry)))
            if not parsed:
                raise IdentityPortUnavailable("JWKS contains no supported asymmetric verification keys.")
        except IdentityPortUnavailable:
            raise
        except (httpx2.HTTPError, ValueError, KeyError, TypeError, jwt.InvalidKeyError):
            raise IdentityPortUnavailable("Failed to fetch or parse JWKS.") from None

        with self._lock:
            self._keys_by_kid = parsed
            self._cache_expires_at = monotonic() + self._jwks_ttl_seconds
        return parsed

    def _resolve_key(self, kid: str) -> tuple[str, Any] | None:
        with self._lock:
            cached = self._keys_by_kid.get(kid) if monotonic() < self._cache_expires_at else None
        if cached is not None:
            return cached
        refreshed = self._refresh_jwks()
        return refreshed.get(kid)

    def verify_bearer_token(self, token: str) -> VerifiedIdentity | None:
        if not isinstance(token, str) or not token.strip() or len(token) > 16_384:
            return None
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return None
        algorithm = header.get("alg")
        kid = header.get("kid")
        if algorithm not in ALLOWED_JWT_ALGORITHMS or not isinstance(kid, str) or not kid:
            return None
        resolved = self._resolve_key(kid)
        if resolved is None:
            return None
        expected_alg, public_key = resolved
        if expected_alg != algorithm:
            return None
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=[expected_alg],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": ["iss", "aud", "sub", "exp", "iat", "nbf"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
            subject_ref = _parse_uuid(claims["sub"], "sub")
            space_ref = _parse_uuid(claims["space_ref"], "space_ref")
            client_id = claims["client_id"]
            operations = claims["operations"]
            if (
                not isinstance(client_id, str)
                or not client_id.strip()
                or not isinstance(operations, list)
                or not all(isinstance(item, str) and item for item in operations)
            ):
                return None
            delegated_ref: UUID | None = None
            actor_claim = claims.get("act")
            if actor_claim is not None:
                if not isinstance(actor_claim, dict) or "sub" not in actor_claim:
                    return None
                delegated_ref = _parse_uuid(actor_claim["sub"], "act.sub")
            region = claims.get("region", "default")
            traveler_class = claims.get("traveler_class", "default")
            if (
                not isinstance(region, str)
                or not SCOPE_CLAIM_PATTERN.fullmatch(region)
                or not isinstance(traveler_class, str)
                or not SCOPE_CLAIM_PATTERN.fullmatch(traveler_class)
            ):
                return None
            expires_at = datetime.fromtimestamp(float(claims["exp"]), tz=UTC)
        except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
            return None

        return VerifiedIdentity(
            issuer=self.issuer,
            subject_ref=subject_ref,
            space_ref=space_ref,
            client_id=client_id.strip(),
            operations=frozenset(operations),
            expires_at=expires_at,
            delegated_subject_ref=delegated_ref,
            region=region,
            traveler_class=traveler_class,
        )


class HttpSourceAuthorityAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"

    def __init__(
        self,
        config: AuthenticatedEndpointConfig,
        *,
        authority_ref: UUID,
        timeout_seconds: float = 5.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        self.authority_ref = authority_ref

    def authorize_scopes(self, credential: Any, probe: DeliveryCheck) -> AuthorityDecision:
        request_body = {
            "check_id": str(probe.check_id),
            "payload_sha256": probe.payload_sha256,
            "principal_id": probe.context.principal_id,
            "operation": probe.context.operation,
            "purpose": probe.context.purpose,
            "destination": probe.context.destination,
            "scopes": [
                {
                    "space_id": scope.space_id,
                    "source_id": scope.source_id,
                    "object_id": str(scope.object_id),
                    "revision": scope.revision,
                    "fields": sorted(scope.fields),
                }
                for scope in probe.scopes
            ],
        }
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.post(f"{self._endpoint}/authorize", headers=headers, json=request_body)
            if response.status_code != 200:
                raise AuthorityPortUnavailable(f"Source authority returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict):
                raise ValueError("Authority response must be a JSON object.")
            if _parse_uuid(body.get("check_id"), "check_id") != probe.check_id:
                raise ValueError("Mismatched check_id in authority response.")
            if _parse_uuid(body.get("authority_ref"), "authority_ref") != self.authority_ref:
                raise ValueError("Mismatched authority_ref in authority response.")
            checked_at = _parse_aware_datetime(body.get("checked_at"), "checked_at")
            valid_until = _parse_aware_datetime(body.get("valid_until"), "valid_until")
            now = datetime.now(UTC)
            if valid_until <= now or valid_until - checked_at > MAX_AUTHORITY_WINDOW:
                raise ValueError("Authority validity window is expired or excessive.")
            proof_ref = body.get("proof_ref")
            if not isinstance(proof_ref, str) or not proof_ref.strip():
                raise ValueError("Missing authority proof_ref.")
            raw_subjects = body.get("subject_ids")
            if raw_subjects is None:
                subject_ids = frozenset({probe.context.principal_id})
            else:
                if (
                    not isinstance(raw_subjects, list)
                    or not raw_subjects
                    or not all(type(item) is int and item > 0 for item in raw_subjects)
                ):
                    raise ValueError("Invalid subject_ids in authority response.")
                subject_ids = frozenset(raw_subjects)
            grants_raw = body.get("grants")
            if not isinstance(grants_raw, list):
                raise ValueError("Missing grants list.")
            grants_by_key: dict[tuple[UUID, int | None], frozenset[str]] = {}
            for entry in grants_raw:
                if not isinstance(entry, dict):
                    raise ValueError("Invalid grant entry.")
                obj_id = _parse_uuid(entry.get("object_id"), "object_id")
                revision = entry.get("revision")
                if revision is not None and (type(revision) is not int or revision < 1):
                    raise ValueError("Invalid grant revision.")
                fields = entry.get("fields")
                if not isinstance(fields, list) or not all(isinstance(item, str) for item in fields):
                    raise ValueError("Invalid grant fields.")
                grants_by_key[(obj_id, revision)] = frozenset(fields)

            permitted_fields = {}
            for scope in probe.scopes:
                returned = grants_by_key.get((scope.object_id, scope.revision), frozenset())
                if not returned <= scope.fields:
                    raise AuthorityPortUnavailable("Upstream authority returned fields outside requested scope.")
                permitted_fields[scope] = returned
        except AuthorityPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, KeyError, TypeError):
            raise AuthorityPortUnavailable("Source authority check failed closed.") from None

        return AuthorityDecision(
            check_id=probe.check_id,
            checked_at=checked_at,
            valid_until=valid_until,
            subject_ids=subject_ids,
            permitted_fields=permitted_fields,
            proof_ref=proof_ref.strip(),
        )

    def checkpoint(self, space_ref: UUID) -> int:
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.get(f"{self._endpoint}/checkpoints/{space_ref}", headers=headers)
            if response.status_code != 200:
                raise AuthorityPortUnavailable(f"Authority checkpoint returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict) or _parse_uuid(body.get("authority_ref"), "authority_ref") != self.authority_ref:
                raise ValueError("Invalid checkpoint response.")
            generation = body.get("generation")
            if type(generation) is not int or generation < 0:
                raise ValueError("Invalid checkpoint generation.")
            return generation
        except AuthorityPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise AuthorityPortUnavailable("Failed to fetch source authority checkpoint.") from None


class HttpSourceConnectorAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"

    def __init__(
        self,
        config: AuthenticatedEndpointConfig,
        *,
        source_system: str,
        timeout_seconds: float = 15.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        if not isinstance(source_system, str) or not source_system.strip():
            raise ValueError("source_system must be non-empty.")
        self.source_system = source_system.strip()

    def fetch_delta_page(self, source_ref: UUID, cursor: str | None) -> ConnectorDeltaPage:
        if cursor is not None and (not isinstance(cursor, str) or not cursor.strip()):
            raise ConnectorPortUnavailable("Connector cursor must be a non-empty string when provided.")
        params = {"source_system": self.source_system}
        if cursor is not None:
            params["cursor"] = cursor.strip()
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.get(
                    f"{self._endpoint}/sources/{source_ref}/deltas",
                    headers=headers,
                    params=params,
                )
            if response.status_code != 200:
                raise ConnectorPortUnavailable(f"Source connector delta returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict):
                raise ValueError("Delta response must be a JSON object.")
            through_cursor = body.get("through_cursor")
            has_more = body.get("has_more")
            raw_items = body.get("items")
            if (
                not isinstance(through_cursor, str)
                or not through_cursor.strip()
                or type(has_more) is not bool
                or not isinstance(raw_items, list)
                or not all(isinstance(item, dict) for item in raw_items)
            ):
                raise ValueError("Malformed delta page payload.")
            normalized_cursor = cursor.strip() if cursor is not None else None
            normalized_through = through_cursor.strip()
            if has_more and normalized_cursor is not None and normalized_through == normalized_cursor:
                raise ConnectorPortUnavailable("Source connector pagination stalled on an unchanged cursor.")
            return ConnectorDeltaPage(
                previous_cursor=normalized_cursor,
                through_cursor=normalized_through,
                items=tuple(raw_items),
                has_more=has_more,
            )
        except ConnectorPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise ConnectorPortUnavailable("Failed to fetch source connector delta page.") from None

    def fetch_full_inventory(self, source_ref: UUID) -> ConnectorInventory:
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.get(
                    f"{self._endpoint}/sources/{source_ref}/inventory",
                    headers=headers,
                    params={"source_system": self.source_system},
                )
            if response.status_code != 200:
                raise ConnectorPortUnavailable(f"Source connector inventory returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict):
                raise ValueError("Inventory response must be a JSON object.")
            snapshot_ref = body.get("snapshot_ref")
            observed_at = _parse_aware_datetime(body.get("observed_at"), "observed_at")
            complete = body.get("complete")
            raw_keys = body.get("stable_object_keys")
            if (
                not isinstance(snapshot_ref, str)
                or not snapshot_ref.strip()
                or type(complete) is not bool
                or not isinstance(raw_keys, list)
                or not all(isinstance(item, str) and item.strip() for item in raw_keys)
            ):
                raise ValueError("Malformed inventory response payload.")
            normalized_keys = [item.strip() for item in raw_keys]
            if len(set(normalized_keys)) != len(normalized_keys):
                raise ConnectorPortUnavailable("Source connector inventory contains duplicate object keys.")
            raw_entries = body.get("entries", [])
            if not isinstance(raw_entries, list) or not all(isinstance(entry, dict) for entry in raw_entries):
                raise ValueError("Malformed inventory entries payload.")
            return ConnectorInventory(
                snapshot_ref=snapshot_ref.strip(),
                observed_at=observed_at,
                stable_object_keys=frozenset(normalized_keys),
                complete=complete,
                entries=tuple(raw_entries),
            )
        except ConnectorPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise ConnectorPortUnavailable("Failed to fetch source connector inventory.") from None

    def fetch_document_bytes(self, source_ref: UUID, object_ref: str, expected_sha256: bytes) -> bytes:
        if (
            not isinstance(object_ref, str)
            or not object_ref.strip()
            or ".." in object_ref
            or "/" in object_ref
            or len(expected_sha256) != 32
        ):
            raise ConnectorPortUnavailable("Invalid source connector object reference or digest.")
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.get(
                    f"{self._endpoint}/sources/{source_ref}/objects/{object_ref.strip()}",
                    headers=headers,
                    params={"source_system": self.source_system},
                )
            if response.status_code != 200:
                raise ConnectorPortUnavailable(f"Source connector object fetch returned HTTP {response.status_code}.")
            payload = response.content
            if sha256(payload).digest() != expected_sha256:
                raise ConnectorPortUnavailable("Source connector object bytes failed SHA-256 verification.")
            return payload
        except ConnectorPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise ConnectorPortUnavailable("Failed to fetch source connector document bytes.") from None


class HttpObjectStorageAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"
    storage_kind: str = "https_object_store"

    def __init__(
        self,
        config: ObjectStorageEndpointConfig,
        *,
        timeout_seconds: float = 10.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        if not isinstance(config.bucket, str) or not config.bucket.strip():
            raise ValueError("object_storage.bucket must be non-empty.")
        self._bucket = config.bucket.strip()

    def read_verified(self, storage_key: str, expected_digest: bytes, expected_length: int) -> bytes:
        clean_key = _validate_storage_key(storage_key)
        if len(expected_digest) != 32 or type(expected_length) is not int or expected_length < 0:
            raise ObjectStorageUnavailable("Invalid expected digest or byte length.")
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.get(f"{self._endpoint}/buckets/{self._bucket}/objects/{clean_key}", headers=headers)
            if response.status_code != 200:
                raise ObjectStorageUnavailable(f"Object read returned HTTP {response.status_code}.")
            payload = response.content
        except ObjectStorageUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError):
            raise ObjectStorageUnavailable("Failed to read verified object bytes.") from None
        if len(payload) != expected_length or sha256(payload).digest() != expected_digest:
            raise ObjectStorageUnavailable("Object payload failed length or SHA-256 verification.")
        return payload

    def write_immutable(self, storage_key: str, payload: bytes) -> bytes:
        clean_key = _validate_storage_key(storage_key)
        digest = sha256(payload).digest()
        digest_hex = digest.hex()
        try:
            headers = self._auth_headers() | {
                "If-None-Match": "*",
                "Content-Type": "application/octet-stream",
                "X-Content-SHA256": digest_hex,
            }
            with self._client() as client:
                response = client.put(
                    f"{self._endpoint}/buckets/{self._bucket}/objects/{clean_key}",
                    headers=headers,
                    content=payload,
                )
            if response.status_code not in {200, 201}:
                raise ObjectStorageUnavailable(f"Immutable object write refused with HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict) or body.get("sha256") != digest_hex:
                raise ObjectStorageUnavailable("Object store write receipt digest mismatch.")
        except ObjectStorageUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError):
            raise ObjectStorageUnavailable("Failed to write immutable object.") from None
        return digest


class HttpSecurityAuditLogAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"

    def __init__(
        self,
        config: AuthenticatedEndpointConfig,
        *,
        log_ref: UUID,
        timeout_seconds: float = 5.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        self.log_ref = log_ref

    def append_restriction_receipt(self, space_ref: UUID, payload: dict[str, Any]) -> SecurityLogReceipt:
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.post(
                    f"{self._endpoint}/spaces/{space_ref}/restrictions",
                    headers=headers,
                    json=payload,
                )
            if response.status_code not in {200, 201}:
                raise SecurityLogUnavailable(f"Security log append returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict):
                raise ValueError("Invalid security log response.")
            returned_log_ref = _parse_uuid(body.get("log_ref"), "log_ref")
            if returned_log_ref != self.log_ref:
                raise ValueError("Mismatched security log_ref.")
            stream_ref = _parse_uuid(body.get("stream_ref"), "stream_ref")
            generation = body.get("generation")
            if type(generation) is not int or generation < 1:
                raise ValueError("Invalid security log generation.")
            recorded_at = _parse_aware_datetime(body.get("recorded_at"), "recorded_at")
            digest_hex = body.get("digest")
            if not isinstance(digest_hex, str) or not HEX_DIGEST_PATTERN.fullmatch(digest_hex):
                raise ValueError("Invalid security log receipt digest.")
            return SecurityLogReceipt(
                log_ref=returned_log_ref,
                stream_ref=stream_ref,
                generation=generation,
                recorded_at=recorded_at,
                digest=bytes.fromhex(digest_hex),
            )
        except SecurityLogUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise SecurityLogUnavailable("Failed to append security restriction receipt.") from None

    def verify_checkpoint(self, space_ref: UUID, expected_generation: int) -> bool:
        if type(expected_generation) is not int or expected_generation < 0:
            raise SecurityLogUnavailable("Expected security log generation must be non-negative.")
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.get(f"{self._endpoint}/spaces/{space_ref}/checkpoint", headers=headers)
            if response.status_code != 200:
                raise SecurityLogUnavailable(f"Security log checkpoint returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict) or _parse_uuid(body.get("log_ref"), "log_ref") != self.log_ref:
                raise ValueError("Mismatched security log checkpoint.")
            generation = body.get("generation")
            if type(generation) is not int or generation < 0:
                raise ValueError("Invalid checkpoint generation.")
            return generation >= expected_generation
        except SecurityLogUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise SecurityLogUnavailable("Failed to verify security log checkpoint.") from None


class HttpModelGatewayAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"

    def __init__(
        self,
        config: AuthenticatedEndpointConfig,
        *,
        destination_id: str,
        allowed_purposes: frozenset[str],
        timeout_seconds: float = 30.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        if not isinstance(destination_id, str) or not destination_id.strip():
            raise ValueError("destination_id must be non-empty.")
        if not allowed_purposes:
            raise ValueError("allowed_purposes must be non-empty.")
        self.destination_id = destination_id.strip()
        self.allowed_purposes = frozenset(allowed_purposes)

    def invoke_generation(self, request: ModelGenerationRequest) -> ModelGenerationReceipt:
        if (
            request.destination_id != self.destination_id
            or request.purpose not in self.allowed_purposes
            or request.max_microunits <= 0
            or len(request.input_manifest_digest) != 32
        ):
            raise ModelGatewayUnavailable("Model request violates gateway destination, purpose, or budget contract.")
        try:
            headers = self._auth_headers() | {"Idempotency-Key": str(request.request_id)}
        except PortUnavailable:
            raise ModelGatewayUnavailable("Model gateway credential could not be resolved.") from None
        payload = {
            "request_id": str(request.request_id),
            "purpose": request.purpose,
            "destination_id": request.destination_id,
            "input_manifest_sha256": request.input_manifest_digest.hex(),
            "max_microunits": request.max_microunits,
            "payload_sha256": sha256(request.payload_bytes).hexdigest(),
            "payload_utf8": request.payload_bytes.decode("utf-8"),
        }
        try:
            with self._client() as client:
                response = client.post(f"{self._endpoint}/generations", headers=headers, json=payload)
        except (httpx2.ReadTimeout, httpx2.ReadError, httpx2.RemoteProtocolError):
            raise ModelOutcomeUnknown("Model gateway response was lost after dispatch; outcome is unknown.") from None
        except httpx2.HTTPError:
            raise ModelGatewayUnavailable("Model gateway could not be reached before completion.") from None

        if response.status_code != 200:
            raise ModelGatewayUnavailable(f"Model gateway rejected request with HTTP {response.status_code}.")
        try:
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict):
                raise ValueError("Invalid gateway receipt.")
            call_id = body.get("provider_call_id")
            accepted = body.get("accepted")
            input_tokens = body.get("input_tokens")
            output_tokens = body.get("output_tokens")
            billed = body.get("billed_microunits")
            digest_hex = body.get("output_digest")
            if (
                not isinstance(call_id, str)
                or not call_id.strip()
                or type(accepted) is not bool
                or type(input_tokens) is not int
                or input_tokens < 0
                or type(output_tokens) is not int
                or output_tokens < 0
                or type(billed) is not int
                or billed < 0
                or not isinstance(digest_hex, str)
                or not HEX_DIGEST_PATTERN.fullmatch(digest_hex)
            ):
                raise ValueError("Malformed gateway receipt fields.")
            output_digest = bytes.fromhex(digest_hex)
            output_utf8 = body.get("output_utf8")
            if output_utf8 is not None:
                if not isinstance(output_utf8, str) or sha256(output_utf8.encode("utf-8")).digest() != output_digest:
                    raise ValueError("Gateway output_utf8 failed digest verification.")
            return ModelGenerationReceipt(
                provider_call_id=call_id.strip(),
                accepted=accepted,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                billed_microunits=billed,
                output_digest=output_digest,
                output_utf8=output_utf8,
            )
        except (ValueError, TypeError):
            raise ModelOutcomeUnknown("Model gateway returned an unverifiable receipt.") from None


def _normalize_openai_chat_url(endpoint: str) -> str:
    stripped = endpoint.rstrip("/")
    if stripped.endswith("/chat/completions"):
        return stripped
    if stripped.endswith("/v1"):
        return f"{stripped}/chat/completions"
    return f"{stripped}/v1/chat/completions"


def _unwrap_json_fence(raw_text: str) -> str:
    stripped = raw_text.strip()
    if stripped.startswith("```") and stripped.endswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].strip() == "```":
            candidate = "\n".join(lines[1:-1]).strip()
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                return stripped
            if isinstance(parsed, dict):
                return candidate
    return stripped


def _build_openai_system_prompt(purpose: str) -> str:
    if purpose == "wiki_compilation":
        return (
            "You are Thalion Enterprise Knowledge Base's controlled policy drafting assistant. "
            "Use ONLY the excerpts supplied in the user JSON payload. Never invent numbers, limits, dates, exceptions, or passage IDs. "
            "Every [passage_uuid, excerpt_revision_int] pair in citations and statements.support_groups must be copied verbatim from allowed_citations, "
            "with excerpt_revision_int as a positive integer. "
            "Output a single valid JSON object matching response_schema with keys title, markdown, citations, and statements. "
            "Output raw JSON only without markdown code fences or extra text."
        )
    return (
        "You are Thalion Enterprise Knowledge Base's controlled policy assistant. "
        "Use ONLY the supplied excerpts without inventing numbers, dates, exceptions, or citations. "
        "If response_schema is provided in the user payload, return a single valid raw JSON object matching it."
    )


def _extract_openai_usage(body: dict[str, Any]) -> tuple[int, int, int]:
    usage = body.get("usage")
    if usage is None:
        return 0, 0, 0
    if not isinstance(usage, dict):
        raise ValueError("Malformed OpenAI usage metadata.")
    input_tokens = usage.get("prompt_tokens", 0)
    output_tokens = usage.get("completion_tokens", 0)
    if (
        type(input_tokens) is not int
        or input_tokens < 0
        or type(output_tokens) is not int
        or output_tokens < 0
    ):
        raise ValueError("Malformed OpenAI token counts.")
    billed_raw = usage.get("billed_microunits")
    if billed_raw is not None:
        if type(billed_raw) is not int or billed_raw < 0:
            raise ValueError("Malformed billed_microunits in usage.")
        return input_tokens, output_tokens, billed_raw
    for key in ("credit", "cost"):
        amount = usage.get(key)
        if amount is not None:
            if isinstance(amount, bool) or not isinstance(amount, (int, float)):
                raise ValueError(f"Malformed {key} in usage.")
            numeric = float(amount)
            if not math.isfinite(numeric) or numeric < 0:
                raise ValueError(f"Non-finite or negative {key} in usage.")
            return input_tokens, output_tokens, round(numeric * 1_000_000)
    return input_tokens, output_tokens, 0


class OpenAiCompatibleModelGatewayAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"

    def __init__(
        self,
        config: AuthenticatedEndpointConfig,
        *,
        model: str,
        destination_id: str,
        allowed_purposes: frozenset[str],
        timeout_seconds: float = 60.0,
        max_tokens: int = 4096,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be non-empty.")
        if not isinstance(destination_id, str) or not destination_id.strip():
            raise ValueError("destination_id must be non-empty.")
        if not allowed_purposes:
            raise ValueError("allowed_purposes must be non-empty.")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 32768:
            raise ValueError("max_tokens must be an integer between 1 and 32768.")
        self.model = model.strip()
        self.destination_id = destination_id.strip()
        self.allowed_purposes = frozenset(allowed_purposes)
        self.max_tokens = max_tokens
        self.chat_completions_url = _normalize_openai_chat_url(self._endpoint)

    def invoke_generation(self, request: ModelGenerationRequest) -> ModelGenerationReceipt:
        if (
            request.destination_id != self.destination_id
            or request.purpose not in self.allowed_purposes
            or request.max_microunits <= 0
            or len(request.input_manifest_digest) != 32
        ):
            raise ModelGatewayUnavailable("Model request violates gateway destination, purpose, or budget contract.")
        try:
            payload_utf8 = request.payload_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ModelGatewayUnavailable("Model request payload must be valid UTF-8.") from None
        try:
            headers = self._auth_headers() | {"Idempotency-Key": str(request.request_id)}
        except PortUnavailable:
            raise ModelGatewayUnavailable("Model gateway credential could not be resolved.") from None

        body_payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _build_openai_system_prompt(request.purpose)},
                {"role": "user", "content": payload_utf8},
            ],
            "temperature": 0,
            "max_tokens": self.max_tokens,
        }
        if request.purpose == "wiki_compilation":
            body_payload["response_format"] = {"type": "json_object"}

        try:
            with self._client() as client:
                response = client.post(self.chat_completions_url, headers=headers, json=body_payload)
        except (httpx2.ReadTimeout, httpx2.ReadError, httpx2.RemoteProtocolError):
            raise ModelOutcomeUnknown("Model gateway response was lost after dispatch; outcome is unknown.") from None
        except httpx2.HTTPError:
            raise ModelGatewayUnavailable("Model gateway could not be reached before completion.") from None

        if response.status_code != 200:
            raise ModelGatewayUnavailable(f"Model gateway rejected request with HTTP {response.status_code}.")

        try:
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict):
                raise ValueError("Invalid OpenAI gateway payload.")
            call_id = body.get("id")
            choices = body.get("choices")
            if (
                not isinstance(call_id, str)
                or not call_id.strip()
                or not isinstance(choices, list)
                or not choices
                or not isinstance(choices[0], dict)
            ):
                raise ValueError("Malformed OpenAI gateway response fields.")
            first_choice = choices[0]
            finish_reason = first_choice.get("finish_reason")
            message = first_choice.get("message")
            if not isinstance(message, dict):
                raise ValueError("Malformed OpenAI choice message.")
            raw_content = message.get("content")
            if not isinstance(raw_content, str) or not raw_content.strip():
                raise ValueError("Empty OpenAI assistant content.")
            output_utf8 = _unwrap_json_fence(raw_content)
            if not output_utf8:
                raise ValueError("Empty normalized OpenAI assistant content.")
            input_tokens, output_tokens, billed = _extract_openai_usage(body)
            output_digest = sha256(output_utf8.encode("utf-8")).digest()
            return ModelGenerationReceipt(
                provider_call_id=call_id.strip(),
                accepted=(finish_reason != "length"),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                billed_microunits=billed,
                output_digest=output_digest,
                output_utf8=output_utf8,
            )
        except (ValueError, TypeError):
            raise ModelOutcomeUnknown("OpenAI-compatible model gateway returned an unverifiable response.") from None


def _normalize_openai_embeddings_url(endpoint: str) -> str:
    stripped = endpoint.rstrip("/")
    if stripped.endswith("/embeddings"):
        return stripped
    if stripped.endswith("/v1"):
        return f"{stripped}/embeddings"
    return f"{stripped}/v1/embeddings"


def _normalize_embedding_vector(raw_values: Any, dimension: int) -> tuple[float, ...]:
    if not isinstance(raw_values, list) or len(raw_values) != dimension:
        raise EmbeddingPortUnavailable("Embedding response vector has unexpected dimension.")
    floats: list[float] = []
    for coord in raw_values:
        if isinstance(coord, bool) or not isinstance(coord, (int, float)):
            raise EmbeddingPortUnavailable("Embedding coordinate must be numeric.")
        val = float(coord)
        if not math.isfinite(val):
            raise EmbeddingPortUnavailable("Embedding coordinate must be finite.")
        floats.append(val)
    norm = math.sqrt(sum(item * item for item in floats))
    if norm <= 1e-12:
        raise EmbeddingPortUnavailable("Embedding vector cannot have zero norm.")
    return tuple(round(item / norm, 6) for item in floats)


def _parse_bool_env(raw: str | None, *, default: bool, name: str) -> bool:
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value (true/false).")


class HttpEmbeddingProviderAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"
    distance_metric: Literal["cosine"] = "cosine"

    def __init__(
        self,
        config: AuthenticatedEndpointConfig,
        *,
        model_id: str,
        dimension: int,
        timeout_seconds: float = 10.0,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError("model_id must be non-empty.")
        if type(dimension) is not int or not 1 <= dimension <= 4096:
            raise ValueError("dimension must be between 1 and 4096.")
        self.model_id = model_id.strip()
        self.dimension = dimension

    def _normalize_vector(self, raw_values: Any) -> tuple[float, ...]:
        return _normalize_embedding_vector(raw_values, self.dimension)

    def embed_passages(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        if not texts or any(not isinstance(item, str) or not item.strip() for item in texts):
            raise EmbeddingPortUnavailable("Embedding inputs must be non-empty strings.")
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.post(
                    f"{self._endpoint}/embeddings",
                    headers=headers,
                    json={"model_id": self.model_id, "inputs": list(texts)},
                )
            if response.status_code != 200:
                raise EmbeddingPortUnavailable(f"Embedding endpoint returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict) or body.get("model_id") != self.model_id:
                raise EmbeddingPortUnavailable("Embedding response model_id mismatch.")
            raw_vectors = body.get("vectors")
            if not isinstance(raw_vectors, list) or len(raw_vectors) != len(texts):
                raise EmbeddingPortUnavailable("Embedding response vector count mismatch.")
            return tuple(self._normalize_vector(item) for item in raw_vectors)
        except EmbeddingPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise EmbeddingPortUnavailable("Failed to compute embeddings from configured provider.") from None

    def embed_query(self, text: str) -> tuple[float, ...]:
        return self.embed_passages((text,))[0]


class OpenAiCompatibleEmbeddingProviderAdapter(_BaseHttpAdapter):
    admission: AdmissionMode = "production_approved"
    distance_metric: Literal["cosine"] = "cosine"

    def __init__(
        self,
        config: AuthenticatedEndpointConfig,
        *,
        model_id: str,
        dimension: int,
        timeout_seconds: float = 30.0,
        request_dimensions: bool = False,
        passage_input_type: str | None = None,
        query_input_type: str | None = None,
        transport: httpx2.BaseTransport | None = None,
        secret_resolver: SecretResolver | None = None,
    ):
        super().__init__(
            config.endpoint,
            config.credential_ref,
            timeout_seconds=timeout_seconds,
            transport=transport,
            secret_resolver=secret_resolver,
        )
        if not isinstance(model_id, str) or not model_id.strip() or ".." in model_id:
            raise ValueError("model_id must be a valid non-empty string.")
        if type(dimension) is not int or not 1 <= dimension <= 4096:
            raise ValueError("dimension must be between 1 and 4096.")
        if type(request_dimensions) is not bool:
            raise ValueError("request_dimensions must be a boolean.")
        if passage_input_type is not None:
            if not isinstance(passage_input_type, str) or not passage_input_type.strip():
                raise ValueError("passage_input_type must be a non-empty string when provided.")
            passage_input_type = passage_input_type.strip()
        if query_input_type is not None:
            if not isinstance(query_input_type, str) or not query_input_type.strip():
                raise ValueError("query_input_type must be a non-empty string when provided.")
            query_input_type = query_input_type.strip()
        self.model_id = model_id.strip()
        self.dimension = dimension
        self.request_dimensions = request_dimensions
        self.passage_input_type = passage_input_type
        self.query_input_type = query_input_type
        self.embeddings_url = _normalize_openai_embeddings_url(self._endpoint)

    def _embed(self, texts: Sequence[str], *, input_type: str | None) -> tuple[tuple[float, ...], ...]:
        if not texts or any(not isinstance(item, str) or not item.strip() for item in texts):
            raise EmbeddingPortUnavailable("Embedding inputs must be non-empty strings.")
        payload: dict[str, Any] = {
            "model": self.model_id,
            "input": list(texts),
        }
        if self.request_dimensions:
            payload["dimensions"] = self.dimension
        if input_type is not None:
            payload["input_type"] = input_type
        try:
            headers = self._auth_headers()
            with self._client() as client:
                response = client.post(
                    self.embeddings_url,
                    headers=headers,
                    json=payload,
                )
            if response.status_code != 200:
                raise EmbeddingPortUnavailable(f"Embedding endpoint returned HTTP {response.status_code}.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict):
                raise EmbeddingPortUnavailable("Embedding response payload must be a JSON object.")
            returned_model = body.get("model")
            if returned_model is not None and (not isinstance(returned_model, str) or not returned_model.strip()):
                raise EmbeddingPortUnavailable("Embedding response contains invalid model field.")
            raw_data = body.get("data")
            if not isinstance(raw_data, list) or len(raw_data) != len(texts):
                raise EmbeddingPortUnavailable("Embedding response data count mismatch.")
            ordered: list[tuple[float, ...] | None] = [None] * len(texts)
            for item in raw_data:
                if not isinstance(item, dict):
                    raise EmbeddingPortUnavailable("Embedding response entry must be a JSON object.")
                idx = item.get("index")
                if type(idx) is not int or not 0 <= idx < len(texts) or ordered[idx] is not None:
                    raise EmbeddingPortUnavailable("Embedding response contains invalid or duplicate index.")
                ordered[idx] = _normalize_embedding_vector(item.get("embedding"), self.dimension)
            if any(vec is None for vec in ordered):
                raise EmbeddingPortUnavailable("Embedding response did not cover all input indices.")
            return tuple(vec for vec in ordered if vec is not None)
        except EmbeddingPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise EmbeddingPortUnavailable("Failed to compute embeddings from configured provider.") from None

    def embed_passages(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        return self._embed(texts, input_type=self.passage_input_type)

    def embed_query(self, text: str) -> tuple[float, ...]:
        return self._embed((text,), input_type=self.query_input_type)[0]


def embedding_options_from_env(environ: Mapping[str, str]) -> dict[str, Any]:
    protocol = (environ.get("THALION_EMBEDDING_PROTOCOL") or "thalion").strip().lower()
    dim_raw = (environ.get("THALION_EMBEDDING_DIMENSION") or "64").strip()
    dimension = int(dim_raw)
    if not 1 <= dimension <= 4096:
        raise ValueError("THALION_EMBEDDING_DIMENSION must be between 1 and 4096.")
    timeout_raw = (environ.get("THALION_EMBEDDING_TIMEOUT_SECONDS") or "30").strip()
    timeout_seconds = float(timeout_raw)
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ValueError("THALION_EMBEDDING_TIMEOUT_SECONDS must be between 0 and 300.")
    request_dimensions = _parse_bool_env(
        environ.get("THALION_EMBEDDING_REQUEST_DIMENSIONS"),
        default=False,
        name="THALION_EMBEDDING_REQUEST_DIMENSIONS",
    )
    return {
        "embedding_protocol": protocol,
        "embedding_model_id": (environ.get("THALION_EMBEDDING_MODEL_ID") or "").strip() or None,
        "embedding_dimension": dimension,
        "embedding_request_dimensions": request_dimensions,
        "embedding_passage_input_type": (environ.get("THALION_EMBEDDING_PASSAGE_INPUT_TYPE") or "").strip() or None,
        "embedding_query_input_type": (environ.get("THALION_EMBEDDING_QUERY_INPUT_TYPE") or "").strip() or None,
        "embedding_timeout_seconds": timeout_seconds,
    }


def model_gateway_options_from_env(environ: Mapping[str, str]) -> dict[str, Any]:
    raw_purposes = (environ.get("THALION_MODEL_GATEWAY_PURPOSES") or "").strip()
    purposes = frozenset(item.strip() for item in raw_purposes.split(",") if item.strip())
    protocol = (environ.get("THALION_MODEL_GATEWAY_PROTOCOL") or "thalion").strip().lower()
    timeout_raw = (environ.get("THALION_MODEL_GATEWAY_TIMEOUT_SECONDS") or "60").strip()
    timeout_seconds = float(timeout_raw)
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ValueError("THALION_MODEL_GATEWAY_TIMEOUT_SECONDS must be between 0 and 300.")
    max_tokens_raw = (environ.get("THALION_MODEL_GATEWAY_MAX_TOKENS") or "4096").strip()
    max_tokens = int(max_tokens_raw)
    if not 1 <= max_tokens <= 32768:
        raise ValueError("THALION_MODEL_GATEWAY_MAX_TOKENS must be between 1 and 32768.")
    return {
        "model_destination_id": (environ.get("THALION_MODEL_GATEWAY_DESTINATION") or "").strip() or None,
        "model_allowed_purposes": purposes,
        "model_gateway_protocol": protocol,
        "model_gateway_model": (environ.get("THALION_MODEL_GATEWAY_MODEL") or "").strip() or None,
        "model_gateway_timeout_seconds": timeout_seconds,
        "model_gateway_max_tokens": max_tokens,
    }


def build_production_port_registry(
    config: ProductionDeploymentConfig,
    *,
    source_authority_ref: UUID,
    security_log_ref: UUID,
    source_connector_system: str | None = None,
    source_connector_map_ref: str | None = None,
    model_destination_id: str | None = None,
    model_allowed_purposes: frozenset[str] = frozenset(),
    model_gateway_protocol: str = "thalion",
    model_gateway_model: str | None = None,
    model_gateway_timeout_seconds: float = 60.0,
    model_gateway_max_tokens: int = 4096,
    embedding_protocol: str = "thalion",
    embedding_model_id: str | None = None,
    embedding_dimension: int = 64,
    embedding_request_dimensions: bool = False,
    embedding_passage_input_type: str | None = None,
    embedding_query_input_type: str | None = None,
    embedding_timeout_seconds: float = 30.0,
    secret_resolver: SecretResolver | None = None,
) -> PortRegistry:
    identity = OidcJwksIdentityVerifier(config.identity)
    source_authority = HttpSourceAuthorityAdapter(
        config.source_authority,
        authority_ref=source_authority_ref,
        secret_resolver=secret_resolver,
    )
    if config.object_storage.protocol == "s3":
        from .s3 import S3CompatibleObjectStorageAdapter

        object_storage = S3CompatibleObjectStorageAdapter(config.object_storage, secret_resolver=secret_resolver)
    else:
        object_storage = HttpObjectStorageAdapter(config.object_storage, secret_resolver=secret_resolver)
    security_audit_log = HttpSecurityAuditLogAdapter(
        config.security_audit_log,
        log_ref=security_log_ref,
        secret_resolver=secret_resolver,
    )
    source_connector = None
    if source_connector_map_ref:
        from .source_connectors import load_source_connector_map

        if config.source_connector is not None or source_connector_system:
            raise ValueError("Use either a source connector map or the global HTTP connector, not both.")
        source_connector = load_source_connector_map(source_connector_map_ref, secret_resolver=secret_resolver)
    elif config.source_connector is not None:
        if not source_connector_system:
            raise ValueError("Configured source_connector requires explicit source_connector_system.")
        source_connector = HttpSourceConnectorAdapter(
            config.source_connector,
            source_system=source_connector_system,
            secret_resolver=secret_resolver,
        )
    model_gateway: HttpModelGatewayAdapter | OpenAiCompatibleModelGatewayAdapter | None = None
    if config.model_gateway is not None:
        if not model_destination_id or not model_allowed_purposes:
            raise ValueError("Configured model_gateway requires explicit destination_id and allowed_purposes.")
        protocol = (model_gateway_protocol or "thalion").strip().lower()
        if protocol == "thalion":
            model_gateway = HttpModelGatewayAdapter(
                config.model_gateway,
                destination_id=model_destination_id,
                allowed_purposes=model_allowed_purposes,
                timeout_seconds=model_gateway_timeout_seconds,
                secret_resolver=secret_resolver,
            )
        elif protocol == "openai_compatible":
            if not model_gateway_model or not model_gateway_model.strip():
                raise ValueError("openai_compatible model_gateway requires explicit model_gateway_model.")
            model_gateway = OpenAiCompatibleModelGatewayAdapter(
                config.model_gateway,
                model=model_gateway_model,
                destination_id=model_destination_id,
                allowed_purposes=model_allowed_purposes,
                timeout_seconds=model_gateway_timeout_seconds,
                max_tokens=model_gateway_max_tokens,
                secret_resolver=secret_resolver,
            )
        else:
            raise ValueError(f"Unsupported model_gateway_protocol: {model_gateway_protocol!r}.")
    embedding_provider: HttpEmbeddingProviderAdapter | OpenAiCompatibleEmbeddingProviderAdapter | None = None
    if config.embedding_provider is not None:
        if not embedding_model_id:
            raise ValueError("Configured embedding_provider requires explicit embedding_model_id.")
        emb_protocol = (embedding_protocol or "thalion").strip().lower()
        if emb_protocol == "thalion":
            embedding_provider = HttpEmbeddingProviderAdapter(
                config.embedding_provider,
                model_id=embedding_model_id,
                dimension=embedding_dimension,
                timeout_seconds=embedding_timeout_seconds,
                secret_resolver=secret_resolver,
            )
        elif emb_protocol == "openai_compatible":
            embedding_provider = OpenAiCompatibleEmbeddingProviderAdapter(
                config.embedding_provider,
                model_id=embedding_model_id,
                dimension=embedding_dimension,
                timeout_seconds=embedding_timeout_seconds,
                request_dimensions=embedding_request_dimensions,
                passage_input_type=embedding_passage_input_type,
                query_input_type=embedding_query_input_type,
                secret_resolver=secret_resolver,
            )
        else:
            raise ValueError(f"Unsupported embedding_protocol: {embedding_protocol!r}.")
    registry = PortRegistry(
        mode="production",
        identity=identity,
        source_authority=source_authority,
        object_storage=object_storage,
        security_audit_log=security_audit_log,
        source_connector=source_connector,
        model_gateway=model_gateway,
        embedding_provider=embedding_provider,
    )
    registry.validate()
    return registry
