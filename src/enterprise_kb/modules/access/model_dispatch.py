from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from time import monotonic
from typing import Literal
from uuid import UUID

from psycopg import Connection, Error
from psycopg.pq import TransactionStatus

from enterprise_kb.modules.sources.originals import SyntheticOriginalStore
from enterprise_kb.runtime import external
from enterprise_kb.runtime.audit import finish_open_request
from enterprise_kb.runtime.jobs import ExternalCallPending, JobLease, LeaseLost, _lock_current_job

from .delivery import AuthorityDecision, AuthorizationUnavailable, DeliveryCheck, DeliveryContext, DeliveryDecision
from .policy import SYNTHETIC_MODEL_DESTINATION
from .travel import prepare_synthetic_model_excerpts


MODEL_JOB_STAGE = "synthetic_model_excerpts"
PROVIDER_NAMESPACE = "thalion-local"


@dataclass(frozen=True)
class SyntheticModelDispatch:
    status: Literal["succeeded", "rejected", "no_evidence", "input_changed", "dependency_unavailable", "lease_lost", "outcome_unknown"]
    call_id: UUID | None = None
    input_digest: bytes | None = None


def synthetic_model_job_digest(
    context: DeliveryContext, references: tuple[tuple[UUID, int], ...], *, region: str, traveler_class: str,
) -> bytes:
    material = (str(context.request_id), context.purpose, region, traveler_class,
                [(str(ref), revision) for ref, revision in references])
    return sha256(json.dumps(material, separators=(",", ":")).encode()).digest()


def dispatch_synthetic_model_excerpts(
    connection: Connection, context: DeliveryContext, lease: JobLease,
    references: tuple[tuple[UUID, int], ...], store: SyntheticOriginalStore, *,
    region: str, traveler_class: str, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> SyntheticModelDispatch:
    """Run a single in-process receipt check, with no network or inference."""
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Model dispatch requires independent committed transactions.")
    spec = lease.spec
    references = tuple(references)
    digest = synthetic_model_job_digest(context, references, region=region, traveler_class=traveler_class)
    if (spec.stage, spec.org_id, spec.input_digest) != (MODEL_JOB_STAGE, context.org_id, digest):
        return SyntheticModelDispatch("rejected")
    started = monotonic()
    call_id = None

    def seal(transaction: Connection, decision: DeliveryDecision):
        nonlocal call_id
        if transaction.execute(
            """
            SELECT 1 FROM thalion.request_job AS link
            JOIN thalion.request_record AS request USING (org_id, request_id)
            WHERE (link.org_id, link.request_id, link.job_id) = (%s, %s, %s)
              AND request.scope_space_id = %s AND request.configuration_revision = %s
            FOR SHARE OF link
            """,
            (context.org_id, context.request_id, lease.job_id, spec.space_id, spec.configuration_revision),
        ).fetchone() is None:
            raise external.ExternalCallConflict("The request is not bound to this model job.")
        dispatch = {
            "route": SYNTHETIC_MODEL_DESTINATION, "provider_namespace": PROVIDER_NAMESPACE,
            "input_digest": bytes.fromhex(decision.payload_sha256),
        }
        reserved = external.reserve_external_call(transaction, lease, **dispatch, maximum_microunits=0)
        if not external._register_dispatch(transaction, lease, reserved, **dispatch):
            raise external.ExternalCallConflict("The model dispatch has already been registered.")
        call_id = reserved

    try:
        decision = prepare_synthetic_model_excerpts(
            connection, context, spec.space_id, references, store,
            region=region, traveler_class=traveler_class, check_authority=check_authority, seal=seal,
        )
    except LeaseLost:
        return SyntheticModelDispatch("lease_lost")
    except (external.CallBudgetExceeded, external.ExternalCallConflict, ExternalCallPending):
        return SyntheticModelDispatch("rejected")
    if call_id is None:
        return SyntheticModelDispatch(decision.status)
    if decision.status == "succeeded":
        try:
            with connection.transaction():
                connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                connection.execute("SET LOCAL synchronous_commit = on")
                if _current_delivery(connection, decision, lease) and external.lock_pending_dispatch(connection, lease, call_id):
                    valid_until = _confirm_source(decision, lease, check_authority)
                    if valid_until is not None:
                        _lock_current_job(connection, lease)
                    if valid_until is not None and datetime.now(UTC) < valid_until:
                        digest = _receive_synthetic_payload(decision.payload)
                        if digest != bytes.fromhex(decision.payload_sha256):
                            raise external.ExternalCallConflict("The receiver did not acknowledge the authorized bytes.")
                        external.record_call_receipt(
                            connection, context.org_id, call_id, external.UsageReceipt(call_id, str(call_id), True, 0, 0, 0),
                        )
                        if not finish_open_request(connection, context.org_id, context.request_id, "succeeded",
                                                   int((monotonic() - started) * 1000)):
                            raise external.ExternalCallConflict("The model request closed before acknowledgement.")
                        return SyntheticModelDispatch("succeeded", call_id, digest)
        except (Error, AuthorizationUnavailable, LeaseLost, external.ExternalCallConflict):
            pass
    try:
        external.mark_call_unknown(connection, context.org_id, call_id)
    except external.ExternalCallConflict:
        return SyntheticModelDispatch(decision.status)
    except Error:
        pass
    return SyntheticModelDispatch("outcome_unknown", call_id)


def _current_delivery(connection: Connection, decision: DeliveryDecision, lease: JobLease) -> bool:
    rows = connection.execute(
        """
        SELECT request.outcome IS NULL AND NOT employee.disabled
           AND request.configuration_revision = organization.config_revision
           AND (organization.safety_epoch, space.safety_epoch, source.safety_epoch, source.local_policy_revision)
             = (part.organization_epoch, part.space_epoch, part.source_epoch, part.policy_revision) AS current
        FROM thalion.delivery_record AS delivery
        JOIN thalion.request_record AS request USING (org_id, request_id)
        JOIN thalion.principal AS employee USING (org_id, principal_id)
        JOIN thalion.delivery_dependency AS part USING (org_id, check_id)
        JOIN thalion.organization AS organization USING (org_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (part.org_id, part.space_id)
        JOIN thalion.source AS source ON (source.org_id, source.space_id, source.source_id)
          = (part.org_id, part.space_id, part.source_id)
        WHERE delivery.org_id = %s AND delivery.check_id = %s AND request.scope_space_id = %s
        ORDER BY part.position
        FOR UPDATE OF request FOR SHARE OF employee, organization, space, source
        """,
        (lease.spec.org_id, decision.check.check_id, lease.spec.space_id),
    ).fetchall()
    return len(rows) == len(decision.check.scopes) and all(current for (current,) in rows)


def _confirm_source(
    decision: DeliveryDecision, lease: JobLease, check_authority: Callable[[DeliveryCheck], AuthorityDecision],
) -> datetime | None:
    deadline = min(decision.valid_until, lease.expires_at)
    started = datetime.now(UTC)
    if started >= deadline:
        return None
    check = decision.check
    authority = check_authority(check)
    now = datetime.now(UTC)
    validity = min(deadline, authority.valid_until)
    if (
        authority.check_id == check.check_id and bool(authority.proof_ref.strip())
        and started <= authority.checked_at <= now < validity
        and authority.subject_ids == frozenset({check.context.principal_id})
        and authority.permitted_fields.keys() == check.scopes
        and all(scope.fields <= authority.permitted_fields[scope] for scope in check.scopes)
    ):
        return validity
    return None


def _receive_synthetic_payload(payload: bytes) -> bytes:
    return sha256(payload).digest()
