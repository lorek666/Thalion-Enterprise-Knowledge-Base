from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable
from uuid import UUID

from enterprise_kb.modules.access.delivery import AuthorizationUnavailable


AdmissionMode = Literal["synthetic_local", "production_approved"]
DeploymentMode = Literal["synthetic_local", "production"]


class PortUnavailable(Exception):
    pass


class IdentityPortUnavailable(PortUnavailable):
    pass


class AuthorityPortUnavailable(PortUnavailable, AuthorizationUnavailable):
    pass


class ConnectorPortUnavailable(PortUnavailable):
    pass


class ModelGatewayUnavailable(PortUnavailable):
    pass


class ModelOutcomeUnknown(PortUnavailable):
    pass


class EmbeddingPortUnavailable(PortUnavailable):
    pass


class ObjectStorageUnavailable(PortUnavailable):
    pass


class SecurityLogUnavailable(PortUnavailable):
    pass


class ProductionIsolationError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject_ref: UUID
    space_ref: UUID
    client_id: str
    operations: frozenset[str]
    expires_at: datetime
    delegated_subject_ref: UUID | None = None
    region: str = "default"
    traveler_class: str = "default"


@dataclass(frozen=True)
class ConnectorDeltaPage:
    previous_cursor: str | None
    through_cursor: str
    items: tuple[dict[str, Any], ...]
    has_more: bool


@dataclass(frozen=True)
class ConnectorInventory:
    snapshot_ref: str
    observed_at: datetime
    stable_object_keys: frozenset[str]
    complete: bool
    entries: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class ModelGenerationRequest:
    request_id: UUID
    purpose: str
    destination_id: str
    input_manifest_digest: bytes
    payload_bytes: bytes
    max_microunits: int


@dataclass(frozen=True)
class ModelGenerationReceipt:
    provider_call_id: str
    accepted: bool
    input_tokens: int
    output_tokens: int
    billed_microunits: int
    output_digest: bytes
    output_utf8: str | None = None


@dataclass(frozen=True)
class SecurityLogReceipt:
    log_ref: UUID
    stream_ref: UUID
    generation: int
    recorded_at: datetime
    digest: bytes


@runtime_checkable
class IdentityVerifierPort(Protocol):
    admission: AdmissionMode
    issuer: str
    audience: str

    def verify_bearer_token(self, token: str) -> VerifiedIdentity | None:
        ...


@runtime_checkable
class SourceAuthorityPort(Protocol):
    admission: AdmissionMode
    authority_ref: UUID

    def authorize_scopes(self, credential: Any, probe: Any) -> Any:
        ...

    def checkpoint(self, space_ref: UUID) -> int:
        ...


@runtime_checkable
class SourceConnectorPort(Protocol):
    admission: AdmissionMode
    source_system: str

    def fetch_delta_page(self, source_ref: UUID, cursor: str | None) -> ConnectorDeltaPage:
        ...

    def fetch_full_inventory(self, source_ref: UUID) -> ConnectorInventory:
        ...


@runtime_checkable
class ModelGatewayPort(Protocol):
    admission: AdmissionMode
    destination_id: str
    allowed_purposes: frozenset[str]

    def invoke_generation(self, request: ModelGenerationRequest) -> ModelGenerationReceipt:
        ...


@runtime_checkable
class EmbeddingProviderPort(Protocol):
    admission: AdmissionMode
    model_id: str
    dimension: int
    distance_metric: Literal["cosine"]

    def embed_passages(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        ...

    def embed_query(self, text: str) -> tuple[float, ...]:
        ...


@runtime_checkable
class ObjectStoragePort(Protocol):
    admission: AdmissionMode
    storage_kind: str

    def read_verified(self, storage_key: str, expected_digest: bytes, expected_length: int) -> bytes:
        ...

    def write_immutable(self, storage_key: str, payload: bytes) -> bytes:
        ...


@runtime_checkable
class SecurityAuditLogPort(Protocol):
    admission: AdmissionMode
    log_ref: UUID

    def append_restriction_receipt(self, space_ref: UUID, payload: dict[str, Any]) -> SecurityLogReceipt:
        ...

    def verify_checkpoint(self, space_ref: UUID, expected_generation: int) -> bool:
        ...


@dataclass(frozen=True)
class PortRegistry:
    mode: DeploymentMode
    identity: IdentityVerifierPort | None = None
    source_authority: SourceAuthorityPort | None = None
    object_storage: ObjectStoragePort | None = None
    security_audit_log: SecurityAuditLogPort | None = None
    source_connector: SourceConnectorPort | None = None
    model_gateway: ModelGatewayPort | None = None
    embedding_provider: EmbeddingProviderPort | None = None

    def validate(self) -> None:
        if self.mode not in {"synthetic_local", "production"}:
            raise ProductionIsolationError(f"Unsupported deployment mode: {self.mode}")
        required = (
            ("identity", self.identity, IdentityVerifierPort),
            ("source_authority", self.source_authority, SourceAuthorityPort),
            ("object_storage", self.object_storage, ObjectStoragePort),
            ("security_audit_log", self.security_audit_log, SecurityAuditLogPort),
        )
        optional = (
            ("source_connector", self.source_connector, SourceConnectorPort),
            ("model_gateway", self.model_gateway, ModelGatewayPort),
            ("embedding_provider", self.embedding_provider, EmbeddingProviderPort),
        )
        for name, adapter, protocol in required:
            if self.mode == "production" and adapter is None:
                raise ProductionIsolationError(f"Production mode requires an approved {name} port.")
            if adapter is not None:
                self._check_adapter(name, adapter, protocol)
        for name, adapter, protocol in optional:
            if adapter is not None:
                self._check_adapter(name, adapter, protocol)

    def _check_adapter(self, name: str, adapter: Any, protocol: type) -> None:
        if not isinstance(adapter, protocol):
            raise ProductionIsolationError(f"Port {name} does not implement {protocol.__name__}.")
        admission = getattr(adapter, "admission", None)
        if admission not in {"synthetic_local", "production_approved"}:
            raise ProductionIsolationError(f"Port {name} has invalid admission marker.")
        if self.mode == "production" and admission != "production_approved":
            raise ProductionIsolationError(
                f"Port {name} with admission '{admission}' is forbidden in production mode."
            )
