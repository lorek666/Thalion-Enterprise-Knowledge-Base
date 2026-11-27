from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID

import pytest

from enterprise_kb.modules.access.delivery import (
    AuthorityDecision,
    AuthorizationUnavailable,
    DeliveryCandidate,
    DeliveryContext,
    EvidenceScope,
    LocalAuthorization,
    SafetyEpochs,
    authorize_delivery,
)
from enterprise_kb.modules.access.rules import PermissionBinding


NOW = datetime(2026, 11, 21, 8, tzinfo=timezone.utc)
SCOPE = EvidenceScope(
    space_id=10,
    source_id=100,
    object_id=UUID("2d49bc39-34c2-42bd-9988-b0de13791e89"),
    fields=frozenset({"amount", "unit"}),
)
OTHER = replace(
    SCOPE,
    source_id=101,
    object_id=UUID("b0e3dd89-602e-4dcb-9aec-24dbeb37cb4f"),
    fields=frozenset({"exception"}),
)
EPOCHS = SafetyEpochs(organization=1, space=2, source=3)
PAYLOAD = b'{"amount":600,"unit":"CNY/night"}'


@pytest.fixture
def context():
    return DeliveryContext(
        request_id=UUID("806f451c-cdc5-4fac-bcd4-0eef6d3b7517"),
        org_id=1,
        principal_id=1,
        client_id="synthetic-reader",
        operation="read_passage",
        purpose="internal_view",
        destination="internal",
        deadline=NOW + timedelta(seconds=30),
    )


@pytest.fixture
def candidate():
    return DeliveryCandidate(payload=PAYLOAD, dependencies={SCOPE: EPOCHS})


@pytest.fixture
def policy():
    return PermissionBinding(
        org_id=1,
        space_id=10,
        source_id=None,
        object_id=None,
        subject_id=2,
        operation="read_passage",
        effect="allow",
        purposes=frozenset({"internal_view"}),
        destinations=frozenset({"internal"}),
        fields=frozenset({"amount", "unit", "exception"}),
        valid_from=NOW - timedelta(days=1),
    )


def current_authority(check):
    return AuthorityDecision(
        check_id=check.check_id,
        checked_at=NOW,
        valid_until=NOW + timedelta(seconds=5),
        subject_ids=frozenset({1, 2}),
        permitted_fields={scope: scope.fields for scope in check.scopes},
        proof_ref="synthetic-authority-decision",
    )


def evaluate(context, candidate, policy, authority=current_authority, **changes):
    return authorize_delivery(
        context,
        candidate,
        check_authority=authority,
        load_local=lambda check: LocalAuthorization(
            epochs={scope: EPOCHS for scope in check.scopes},
            bindings=(policy,),
            **changes,
        ),
        clock=lambda: NOW,
    )


def test_final_decision_binds_current_context_and_exact_payload(
    context, candidate, policy
):
    calls = []

    def authority(check):
        calls.append(check)
        return current_authority(check)

    result = evaluate(context, candidate, policy, authority)

    assert result.status == "succeeded"
    assert result.payload == PAYLOAD
    assert result.payload_sha256 == sha256(PAYLOAD).hexdigest()
    assert result.authority_proof_ref == "synthetic-authority-decision"
    assert result.checked_at == NOW
    assert calls[0].context == context
    assert calls[0].payload_sha256 == result.payload_sha256
    assert calls[0].scopes == frozenset({SCOPE})


def test_source_revocation_before_delivery_does_not_reuse_previous_allow(
    context, candidate, policy
):
    assert evaluate(context, candidate, policy).status == "succeeded"

    def revoked(check):
        return replace(
            current_authority(check), permitted_fields={SCOPE: frozenset()}
        )

    result = evaluate(context, candidate, policy, revoked)
    assert result.status == "rejected"
    assert result.payload is None


def test_removed_membership_cannot_be_supplied_by_a_prior_context(
    context, candidate, policy
):
    def removed_group(check):
        return replace(current_authority(check), subject_ids=frozenset({1}))

    result = evaluate(context, candidate, policy, removed_group)
    assert result.status == "rejected"
    assert result.payload is None


def test_authority_outage_is_not_a_denial_or_cached_success(context, candidate, policy):
    def unavailable(check):
        raise AuthorizationUnavailable

    result = evaluate(context, candidate, policy, unavailable)
    assert result.status == "dependency_unavailable"
    assert result.payload is None


def test_replayed_authority_proof_cannot_authorize_a_later_check(
    context, candidate, policy
):
    saved = []

    def first_check(check):
        saved.append(current_authority(check))
        return saved[-1]

    assert evaluate(context, candidate, policy, first_check).status == "succeeded"
    result = evaluate(context, candidate, policy, lambda check: saved[0])
    assert result.status == "dependency_unavailable"
    assert result.payload is None


@pytest.mark.parametrize(
    "changes",
    [
        {"checked_at": NOW - timedelta(microseconds=1)},
        {"checked_at": NOW + timedelta(microseconds=1)},
        {"valid_until": NOW},
        {"permitted_fields": {}},
        {"proof_ref": ""},
    ],
)
def test_missing_or_invalid_current_proof_does_not_release_payload(
    context, candidate, policy, changes
):
    def bad_proof(check):
        return replace(current_authority(check), **changes)

    result = evaluate(context, candidate, policy, bad_proof)
    assert result.status == "dependency_unavailable"
    assert result.payload is None


def test_partial_field_approval_cannot_release_unchanged_payload(
    context, candidate, policy
):
    def only_amount(check):
        return replace(
            current_authority(check),
            permitted_fields={SCOPE: frozenset({"amount"})},
        )

    result = evaluate(context, candidate, policy, only_amount)
    assert result.status == "rejected"
    assert result.payload is None


def test_hidden_wiki_input_is_checked_alongside_cited_fields(
    context, candidate, policy
):
    candidate = replace(candidate, dependencies={SCOPE: EPOCHS, OTHER: EPOCHS})

    def hidden_input_revoked(check):
        proof = current_authority(check)
        return replace(
            proof,
            permitted_fields={SCOPE: SCOPE.fields, OTHER: frozenset()},
        )

    assert evaluate(context, candidate, policy).status == "succeeded"
    result = evaluate(context, candidate, policy, hidden_input_revoked)
    assert result.status == "rejected"
    assert result.payload is None


def test_local_generation_is_read_after_the_authority_call(context, candidate, policy):
    epochs = {SCOPE: EPOCHS}

    def authority(check):
        epochs[SCOPE] = replace(EPOCHS, source=4)
        return current_authority(check)

    result = authorize_delivery(
        context,
        candidate,
        check_authority=authority,
        load_local=lambda check: LocalAuthorization(epochs=epochs, bindings=(policy,)),
        clock=lambda: NOW,
    )
    assert result.status == "input_changed"
    assert result.payload is None


def test_local_block_overrides_allow_without_waiting_for_cleanup(
    context, candidate, policy
):
    result = evaluate(context, candidate, policy, blocked_scopes=frozenset({SCOPE}))
    assert result.status == "rejected"
    assert result.payload is None


def test_local_read_policy_does_not_allow_same_bytes_to_model(
    context, candidate, policy
):
    model_context = replace(context, purpose="model_qa", destination="synthetic-gateway")
    result = evaluate(model_context, candidate, policy)
    assert result.status == "rejected"
    assert result.payload is None


def test_proof_expiring_during_local_check_blocks_release(context, candidate, policy):
    moments = iter((NOW, NOW + timedelta(seconds=5)))
    result = authorize_delivery(
        context,
        candidate,
        check_authority=current_authority,
        load_local=lambda check: LocalAuthorization(
            epochs={SCOPE: EPOCHS}, bindings=(policy,)
        ),
        clock=lambda: next(moments),
    )
    assert result.status == "dependency_unavailable"
    assert result.payload is None


def test_payload_without_registered_inputs_is_rejected():
    with pytest.raises(ValueError):
        DeliveryCandidate(payload=PAYLOAD, dependencies={})
