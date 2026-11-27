from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Literal
from uuid import UUID


def require_aware(value: datetime):
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("授权判定必须使用带时区的时刻。")


@dataclass(frozen=True)
class PermissionRequest:
    org_id: int
    space_id: int
    source_id: int
    object_id: UUID
    subject_ids: frozenset[int]
    operation: str
    purpose: str
    destination: str
    fields: frozenset[str]
    checked_at: datetime

    def __post_init__(self):
        require_aware(self.checked_at)
        object.__setattr__(self, "subject_ids", frozenset(self.subject_ids))
        object.__setattr__(self, "fields", frozenset(self.fields))


@dataclass(frozen=True)
class PermissionBinding:
    org_id: int
    space_id: int | None
    source_id: int | None
    object_id: UUID | None
    subject_id: int
    operation: str
    effect: Literal["allow", "deny"]
    purposes: frozenset[str]
    destinations: frozenset[str]
    fields: frozenset[str]
    valid_from: datetime
    valid_until: datetime | None = None

    def __post_init__(self):
        require_aware(self.valid_from)
        if self.valid_until is not None:
            require_aware(self.valid_until)
            if self.valid_until <= self.valid_from:
                raise ValueError("授权结束时刻必须晚于开始时刻。")
        if self.effect not in ("allow", "deny"):
            raise ValueError("授权效果只能是 allow 或 deny。")
        for name in ("purposes", "destinations", "fields"):
            object.__setattr__(self, name, frozenset(getattr(self, name)))


def matching_local_bindings(
    request: PermissionRequest, bindings: Iterable[PermissionBinding],
) -> Iterable[PermissionBinding]:
    return (
        binding for binding in bindings
        if binding.org_id == request.org_id
        and binding.subject_id in request.subject_ids
        and binding.operation == request.operation
        and request.purpose in binding.purposes
        and request.destination in binding.destinations
        and not any(
            getattr(binding, name) is not None and getattr(binding, name) != getattr(request, name)
            for name in ("space_id", "source_id", "object_id")
        )
    )


def evaluate_local_permissions(
    request: PermissionRequest, bindings: Iterable[PermissionBinding]
) -> frozenset[str]:
    allowed = set()
    denied = set()
    for binding in matching_local_bindings(request, bindings):
        if request.checked_at < binding.valid_from or (
            binding.valid_until is not None and request.checked_at >= binding.valid_until
        ):
            continue
        if binding.effect == "deny":
            denied.update(binding.fields)
        else:
            allowed.update(binding.fields)
    return frozenset((allowed - denied) & request.fields)
