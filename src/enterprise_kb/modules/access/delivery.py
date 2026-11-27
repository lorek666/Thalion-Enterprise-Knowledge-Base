from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Literal
from uuid import UUID, uuid4

from .rules import (
    PermissionBinding,
    PermissionRequest,
    evaluate_local_permissions,
    matching_local_bindings,
    require_aware,
)


class AuthorizationUnavailable(Exception):
    pass


@dataclass(frozen=True)
class DeliveryContext:
    request_id: UUID
    org_id: int
    principal_id: int
    client_id: str
    operation: str
    purpose: str
    destination: str
    deadline: datetime
    authority_issuer: str = "https://synthetic.invalid"

    def __post_init__(self):
        require_aware(self.deadline)
        if not isinstance(self.authority_issuer, str) or not self.authority_issuer.strip():
            raise ValueError("DeliveryContext requires a non-empty authority_issuer.")


@dataclass(frozen=True)
class EvidenceScope:
    space_id: int
    source_id: int
    object_id: UUID
    fields: frozenset[str]
    revision: int | None = None

    def __post_init__(self):
        object.__setattr__(self, "fields", frozenset(self.fields))
        if not self.fields:
            raise ValueError("Evidence must declare its protected fields.")
        if self.revision is not None and (type(self.revision) is not int or self.revision < 1):
            raise ValueError("Evidence revisions must be positive integers.")


@dataclass(frozen=True)
class SafetyEpochs:
    organization: int
    space: int
    source: int


@dataclass(frozen=True)
class DeliveryCandidate:
    payload: bytes = field(repr=False)
    dependencies: Mapping[EvidenceScope, SafetyEpochs]

    def __post_init__(self):
        if not self.dependencies:
            raise ValueError("Protected payloads require a complete dependency set.")
        if not isinstance(self.payload, bytes):
            raise TypeError("Delivery candidates require immutable bytes.")
        object.__setattr__(
            self, "dependencies", MappingProxyType(dict(self.dependencies))
        )


@dataclass(frozen=True)
class DeliveryCheck:
    check_id: UUID
    context: DeliveryContext
    payload_sha256: str
    scopes: frozenset[EvidenceScope]


@dataclass(frozen=True)
class AuthorityDecision:
    check_id: UUID
    checked_at: datetime
    valid_until: datetime
    subject_ids: frozenset[int]
    permitted_fields: Mapping[EvidenceScope, frozenset[str]]
    proof_ref: str

    def __post_init__(self):
        require_aware(self.checked_at)
        require_aware(self.valid_until)
        object.__setattr__(self, "subject_ids", frozenset(self.subject_ids))
        object.__setattr__(
            self,
            "permitted_fields",
            MappingProxyType(
                {
                    scope: frozenset(fields)
                    for scope, fields in self.permitted_fields.items()
                }
            ),
        )


@dataclass(frozen=True)
class LocalAuthorization:
    epochs: Mapping[EvidenceScope, SafetyEpochs]
    bindings: tuple[PermissionBinding, ...]
    blocked_scopes: frozenset[EvidenceScope] = frozenset()
    exact_allow_scopes: frozenset[EvidenceScope] = frozenset()
    scoped_subject_expiries: Mapping[tuple[int, int], Mapping[int, datetime]] = field(
        default_factory=lambda: MappingProxyType({}),
    )

    def __post_init__(self):
        object.__setattr__(self, "epochs", MappingProxyType(dict(self.epochs)))
        object.__setattr__(self, "bindings", tuple(self.bindings))
        object.__setattr__(self, "blocked_scopes", frozenset(self.blocked_scopes))
        object.__setattr__(self, "exact_allow_scopes", frozenset(self.exact_allow_scopes))
        normalized_groups = {}
        for scope_key, group_map in self.scoped_subject_expiries.items():
            entries = {}
            for subject_id, expiry in group_map.items():
                require_aware(expiry)
                entries[subject_id] = expiry.astimezone(UTC)
            normalized_groups[scope_key] = MappingProxyType(entries)
        object.__setattr__(self, "scoped_subject_expiries", MappingProxyType(normalized_groups))


@dataclass(frozen=True)
class DeliveryDecision:
    status: Literal["succeeded", "no_evidence", "rejected", "input_changed", "dependency_unavailable"]
    payload: bytes | None = field(default=None, repr=False)
    payload_sha256: str | None = None
    authority_proof_ref: str | None = None
    checked_at: datetime | None = None
    check: DeliveryCheck | None = None
    valid_until: datetime | None = None
    denied_scopes: frozenset[EvidenceScope] = field(default=frozenset(), repr=False)


def authorize_delivery(
    context: DeliveryContext,
    candidate: DeliveryCandidate,
    *,
    check_authority: Callable[[DeliveryCheck], AuthorityDecision],
    load_local: Callable[[DeliveryCheck], LocalAuthorization],
    local_prerequisite: tuple[str, str, str] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> DeliveryDecision:
    """Check immutable bytes and trusted dependencies for immediate delivery."""
    check = DeliveryCheck(
        check_id=uuid4(),
        context=context,
        payload_sha256=sha256(candidate.payload).hexdigest(),
        scopes=frozenset(candidate.dependencies),
    )
    started = clock()
    require_aware(started)
    started = started.astimezone(UTC)
    deadline = context.deadline.astimezone(UTC)
    if started >= deadline:
        return DeliveryDecision("rejected")
    try:
        authority = check_authority(check)
        if (
            authority.check_id != check.check_id
            or authority.permitted_fields.keys() != check.scopes
            or not authority.proof_ref.strip()
        ):
            return DeliveryDecision("dependency_unavailable")
        local = load_local(check)
    except AuthorizationUnavailable:
        return DeliveryDecision("dependency_unavailable")

    now = clock()
    require_aware(now)
    now = now.astimezone(UTC)
    if not started <= authority.checked_at.astimezone(UTC) <= now:
        return DeliveryDecision("dependency_unavailable")
    if now >= authority.valid_until.astimezone(UTC) or local.epochs.keys() != check.scopes:
        return DeliveryDecision("dependency_unavailable")
    if (
        now >= deadline
        or context.principal_id not in authority.subject_ids
        or check.scopes & local.blocked_scopes
    ):
        return DeliveryDecision("rejected")
    if local.epochs != candidate.dependencies:
        return DeliveryDecision("input_changed")
    valid_until = min(deadline, authority.valid_until)
    denied_scopes = set()
    for scope in check.scopes:
        scope_groups = {
            subject_id: expiry
            for subject_id, expiry in local.scoped_subject_expiries.get((scope.space_id, scope.source_id), {}).items()
            if now < expiry
        }
        effective_subjects = authority.subject_ids | frozenset(scope_groups)
        request = PermissionRequest(
            org_id=context.org_id,
            space_id=scope.space_id,
            source_id=scope.source_id,
            object_id=scope.object_id,
            subject_ids=effective_subjects,
            operation=context.operation,
            purpose=context.purpose,
            destination=context.destination,
            fields=scope.fields,
            checked_at=now,
        )
        if not scope.fields <= authority.permitted_fields[scope]:
            denied_scopes.add(scope)
            continue
        requests = (request,)
        if local_prerequisite is not None:
            operation, purpose, destination = local_prerequisite
            requests += (replace(request, operation=operation, purpose=purpose, destination=destination),)
        for required in requests:
            matching = tuple(
                binding for binding in matching_local_bindings(required, local.bindings)
                if scope not in local.exact_allow_scopes or binding.effect == "deny" or binding.object_id == scope.object_id
            )
            if evaluate_local_permissions(required, matching) != scope.fields:
                denied_scopes.add(scope)
                break
            for binding in matching:
                if not scope.fields.intersection(binding.fields):
                    continue
                if binding.effect == "deny" and now < binding.valid_from:
                    valid_until = min(valid_until, binding.valid_from)
                if (
                    binding.effect == "allow" and binding.valid_until is not None
                    and binding.valid_from <= now < binding.valid_until
                ):
                    valid_until = min(valid_until, binding.valid_until)
                if (
                    binding.effect == "allow"
                    and binding.subject_id in scope_groups
                    and binding.valid_from <= now
                    and (binding.valid_until is None or now < binding.valid_until)
                ):
                    valid_until = min(valid_until, scope_groups[binding.subject_id])
    if denied_scopes:
        return DeliveryDecision("rejected", denied_scopes=frozenset(denied_scopes))
    return DeliveryDecision(
        "succeeded",
        payload=candidate.payload,
        payload_sha256=check.payload_sha256,
        authority_proof_ref=authority.proof_ref,
        checked_at=now,
        check=check,
        valid_until=valid_until,
    )
