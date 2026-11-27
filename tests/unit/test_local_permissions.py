from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from enterprise_kb.modules.access.rules import (
    PermissionBinding,
    PermissionRequest,
    evaluate_local_permissions,
)
from enterprise_kb.transport import local
from enterprise_kb.transport.evidence import MAX_REQUEST_TIME


NOW = datetime(2026, 11, 21, 8, tzinfo=timezone.utc)
OBJECT = UUID("2d49bc39-34c2-42bd-9988-b0de13791e89")


def test_authority_window_covers_the_full_request_deadline():
    assert local.AUTHORITY_WINDOW >= MAX_REQUEST_TIME


@pytest.fixture
def request_scope():
    return PermissionRequest(
        org_id=1,
        space_id=10,
        source_id=100,
        object_id=OBJECT,
        subject_ids=frozenset({1, 2}),
        operation="read_passage",
        purpose="internal_view",
        destination="internal",
        fields=frozenset({"title", "body", "unit"}),
        checked_at=NOW,
    )


@pytest.fixture
def grant():
    return PermissionBinding(
        org_id=1,
        space_id=10,
        source_id=100,
        object_id=None,
        subject_id=2,
        operation="read_passage",
        effect="allow",
        purposes=frozenset({"internal_view"}),
        destinations=frozenset({"internal"}),
        fields=frozenset({"title", "body", "unit"}),
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
    )


def test_current_authoritative_group_can_grant_fields(request_scope, grant):
    assert evaluate_local_permissions(request_scope, [grant]) == {
        "title", "body", "unit"
    }


def test_missing_policy_does_not_grant_reading(request_scope):
    assert evaluate_local_permissions(request_scope, []) == frozenset()


def test_removed_group_has_no_remaining_path(request_scope, grant):
    changed = replace(request_scope, subject_ids=frozenset({1}))
    assert evaluate_local_permissions(changed, [grant]) == frozenset()


@pytest.mark.parametrize(
    "changes",
    [
        {"org_id": 2},
        {"space_id": 20},
        {"source_id": 200},
        {"object_id": UUID("44c014c2-c1a2-4bdf-8c68-0b3bcdbe6fa4")},
        {"subject_id": 3},
        {"operation": "manage_space"},
        {"purposes": frozenset({"wiki_compilation"})},
        {"destinations": frozenset({"unapproved-model"})},
        {"valid_from": NOW + timedelta(seconds=1)},
        {"valid_until": NOW},
    ],
)
def test_unmatched_or_expired_policy_grants_nothing(request_scope, grant, changes):
    assert evaluate_local_permissions(
        request_scope, [replace(grant, **changes)]
    ) == frozenset()


def test_explicit_deny_overrides_union_of_grants(request_scope, grant):
    deny = replace(grant, effect="deny", fields=frozenset({"unit"}))
    for bindings in ([grant, deny], [deny, grant, grant]):
        assert evaluate_local_permissions(request_scope, bindings) == {"title", "body"}


def test_multiple_allowed_paths_union_only_requested_fields(request_scope, grant):
    first = replace(grant, fields=frozenset({"title", "secret"}))
    second = replace(grant, fields=frozenset({"body", "unit"}))
    assert evaluate_local_permissions(request_scope, [first, second]) == {
        "title", "body", "unit"
    }


def test_internal_read_does_not_authorize_model_destination(request_scope, grant):
    model_request = replace(
        request_scope, purpose="model_qa", destination="approved-test-gateway"
    )
    assert evaluate_local_permissions(model_request, [grant]) == frozenset()
    model_grant = replace(
        grant,
        purposes=frozenset({"model_qa"}),
        destinations=frozenset({"approved-test-gateway"}),
    )
    assert evaluate_local_permissions(model_request, [grant, model_grant]) == {
        "title", "body", "unit"
    }


def test_naive_authorization_time_is_rejected(request_scope, grant):
    with pytest.raises(ValueError):
        changed = replace(request_scope, checked_at=NOW.replace(tzinfo=None))
        evaluate_local_permissions(changed, [grant])


def test_invalid_policy_interval_is_rejected(request_scope, grant):
    with pytest.raises(ValueError):
        changed = replace(grant, valid_until=grant.valid_from)
        evaluate_local_permissions(request_scope, [changed])


def test_unknown_effect_cannot_be_interpreted_as_allow(request_scope, grant):
    with pytest.raises(ValueError):
        changed = replace(grant, effect="administrator")
        evaluate_local_permissions(request_scope, [changed])
