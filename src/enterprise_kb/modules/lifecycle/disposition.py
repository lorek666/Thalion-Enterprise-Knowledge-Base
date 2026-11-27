from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from typing import NamedTuple
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.access.rules import require_aware
from enterprise_kb.modules.lifecycle.inventory import LOCAL_INVENTORY
from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, append_space_event, command_for, require_scope
from enterprise_kb.modules.sources.registry import sql_admitted_admission, sql_issuer_matches_admission
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


DESTINATION = "internal_lifecycle"
PLAN = "plan_disposition"
REGISTER = "register_retention_policy"
SUBMIT = "submit_disposition_case"
REJECT = "reject_disposition_case"
APPROVE = "approve_disposition_case"
REGISTER_TOMBSTONE = "register_deletion_tombstone"
ACTIONS = frozenset({"archive", "destroy"})
REASONS = frozenset({"retention_expiry", "withdrawal"})
UNVERIFIED_COPY_KINDS = ("page_image", "index", "cache", "audit_sample", "export", "backup", "external_copy")
MAX_LOCAL_COPIES = 500
MAX_LOCAL_FACTS = 4000
WIKI_COPY_KINDS = frozenset({"wiki_input_manifest", "wiki_revision"})
WIKI_PROTECTIONS = frozenset({"wiki_base_input", "wiki_review", "wiki_publication", "conflict_evidence"})


class DispositionConflict(Exception):
    pass


class DispositionInventoryUnavailable(Exception):
    pass


class ReviewTarget(NamedTuple):
    ref: UUID
    source: int
    contract: int
    version: int
    action: str
    reason: str
    sealed: bytes
    submitter: int


def _source_for(connection, call, ref, *, operation, version=False):
    if require_scope(connection, call, operation, destination=DESTINATION) != call.principal_id:
        raise OperationsNotAdmitted("Current space ownership is required for local retention work.")
    if version:
        subject = """
            JOIN thalion.document_version AS version USING (org_id, space_id, source_id)
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                 (version.org_id, version.space_id, 'document_version', version.version_id)
        """
        selected, lock = "version.version_id", "FOR SHARE OF source"
    else:
        subject = """
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                 (source.org_id, source.space_id, 'source', source.source_id)
        """
        selected, lock = "NULL", "FOR NO KEY UPDATE OF source"
    row = connection.execute(
        f"""
        SELECT source.source_id, source.contract_revision, {selected}
        FROM thalion.source AS source {subject}
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS owner
          ON (owner.org_id, owner.principal_id) = (source.org_id, source.owner_principal_id)
        WHERE (source.org_id, source.space_id, source.owner_principal_id, identity.public_id) = (%s, %s, %s, %s)
          AND {sql_admitted_admission('contract.admission')}
          AND {sql_issuer_matches_admission('owner.authority_issuer', 'contract.admission')}
          AND (%s OR source.lifecycle = 'active')
        {lock}
        """, (call.org_id, call.space_id, call.principal_id, ref, version),
    ).fetchone()
    if row is None:
        raise OperationsNotAdmitted("Only a source in the caller's current synthetic ownership scope is available.")
    return row


def register_retention_policy(
    connection: Connection, call: OperationsCall, ref: UUID, expected: int, days: int, action: str, basis: UUID,
) -> dict:
    if (type(expected) is not int or not 0 <= expected < 2**63 - 1 or type(days) is not int
            or not 0 <= days <= 36500 or action not in ACTIONS | {"retain_only"}):
        raise ValueError("Invalid retention policy revision, duration or action.")
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        source, contract, _ = _source_for(connection, call, ref, operation=REGISTER)
        command = command_for(call, REGISTER, (str(ref), contract, expected, days, action, str(basis)))
        scope = (call.org_id, call.space_id, source)

        def apply(transaction):
            current, = transaction.execute(
                "SELECT coalesce(max(revision), 0) FROM thalion.retention_policy_revision "
                "WHERE (org_id, space_id, source_id) = (%s, %s, %s)", scope,
            ).fetchone()
            if current != expected:
                raise DispositionConflict("The retention policy revision changed.")
            policy, = transaction.execute(
                """
                INSERT INTO thalion.retention_policy_revision (
                    org_id, space_id, source_id, contract_revision, revision, decided_by, request_id, basis_ref, keep_days, action
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING policy_ref
                """, (*scope, contract, expected + 1, call.principal_id, call.request_id, basis, days, action),
            ).fetchone()
            append_space_event(transaction, call, "lifecycle.retention_policy.registered")
            return policy

        policy = execute_command(connection, command, apply).result_ref
        return {"policy_id": str(policy), "revision": expected + 1}


def _validate_action(action, reason):
    if action not in ACTIONS or reason not in REASONS:
        raise ValueError("Invalid disposition action or reason.")


def _load_inventory(connection, call, ref, source, contract, version):
    row = connection.execute(
        LOCAL_INVENTORY, {
            "org": call.org_id, "space": call.space_id, "version": version, "ref": ref,
            "source": source, "contract": contract, "copy_bound": MAX_LOCAL_COPIES + 1,
            "fact_bound": MAX_LOCAL_FACTS + 1,
        },
    ).fetchone()
    if row is None:
        raise DispositionInventoryUnavailable("The version inventory is unavailable.")
    if len(row[-2]) > MAX_LOCAL_COPIES or len(row[-1]) > MAX_LOCAL_FACTS:
        raise DispositionInventoryUnavailable("The local inventory or its protection facts exceed the preview limit.")
    return row


def _inventory(connection, call, ref, action, reason, source, contract, version):
    safety, policy, allowed, days, age, copies, facts = _load_inventory(connection, call, ref, source, contract, version)
    related = {}
    stops = set()
    backup_expiry = {}
    held = current = False
    for kind, copy_ref, evidence in facts:
        if kind in WIKI_PROTECTIONS:
            related.setdefault(copy_ref, set()).add(kind)
        elif kind == "rule_stop":
            stops.add(evidence[1])
        elif kind == "rule_interval":
            current = current or evidence[2]
        elif kind == "hold":
            held = evidence[1] == "establish"
        elif kind == "backup_expiry":
            backup_expiry[copy_ref] = evidence
    protections = {protection for values in related.values() for protection in values}
    if any(kind in WIKI_COPY_KINDS for kind, _ in copies):
        protections.add("wiki_full_input")
    if held:
        protections.add("custody_hold")
    if current and not stops:
        protections.add("current_effectivity")
    if "deletion_blocked" in stops:
        decision = "restore_blocked"
    elif reason == "withdrawal" and "withdrawn" not in stops:
        decision = "reason_not_satisfied"
    elif protections:
        decision = "protected"
    elif policy is None:
        decision = "policy_missing"
    elif age < days:
        decision = "retention_active"
    elif action != allowed:
        decision = "policy_disallows"
    else:
        decision = "review_required"
    local_state = "protected" if protections else decision
    local = []
    for index, (kind, identity) in enumerate(copies, 1):
        copy = {"item": index, "kind": kind, "state": local_state}
        if kind == "backup":
            expiry = backup_expiry.get(identity[0])
            if stops & {"withdrawn", "deletion_blocked"}:
                copy["restore_prohibited"] = True
            if expiry is not None:
                _, expected, due, observation, observed_at = expiry
                copy["expected_expiry_at"] = expected
                if observation is not None:
                    copy["absence_observed_at"] = observed_at
            if not protections:
                if expiry is None:
                    copy["state"] = "registered_backup"
                elif observation is not None:
                    copy["state"] = "backup_absence_observed"
                elif due:
                    copy["state"] = "backup_expiry_verification_due"
                else:
                    copy["state"] = "backup_pending_expiry_verification"
        elif kind == "export" and not protections:
            copy["state"] = "sealed_export"
        if kind in WIKI_COPY_KINDS:
            copy["protections"] = sorted({"wiki_full_input"} | related.get(identity[0], set()))
        local.append(copy)
    material = json.dumps((
        "local_disposition_inventory.v1", call.org_id, call.space_id, call.configuration_revision, str(ref),
        source, contract, safety, policy, allowed, days, action, reason, decision, copies, facts, UNVERIFIED_COPY_KINDS,
    ), separators=(",", ":")).encode()
    return {
        "version_id": str(ref), "policy_revision": policy, "action": action, "reason": reason,
        "decision": decision, "protections": sorted(protections), "approval_required": True, "executable": False,
        "copies": local, "inventory_snapshot": sha256(material).hexdigest(), "unverified_copy_kinds": list(UNVERIFIED_COPY_KINDS),
    }, material


def plan_disposition(connection: Connection, call: OperationsCall, ref: UUID, action: str, reason: str) -> dict:
    _validate_action(action, reason)
    with connection.transaction():
        target = _source_for(connection, call, ref, operation=PLAN, version=True)
        preview, _ = _inventory(connection, call, ref, action, reason, *target)
        return preview


def matching_inventory(connection, call, ref, action, reason, snapshot, source, contract, version):
    preview, material = _inventory(connection, call, ref, action, reason, source, contract, version)
    if preview["decision"] != "review_required" or preview["inventory_snapshot"] != snapshot.hex():
        raise DispositionConflict("The local disposition inventory changed or is not eligible for review.")
    return preview["policy_revision"], material


def submit_disposition_case(
    connection: Connection, call: OperationsCall, ref: UUID, action: str, reason: str, snapshot: bytes,
) -> dict:
    _validate_action(action, reason)
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        source, contract, version = _source_for(connection, call, ref, operation=SUBMIT, version=True)
        command = command_for(call, SUBMIT, (str(ref), action, reason, snapshot.hex()))

        def apply(transaction):
            policy, material = matching_inventory(transaction, call, ref, action, reason, snapshot, source, contract, version)
            case, = transaction.execute(
                """
                INSERT INTO thalion.disposition_case (
                    org_id, space_id, source_id, contract_revision, version_id, policy_revision, action, reason,
                    inventory_material, inventory_snapshot, submitted_by, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING case_ref
                """, (call.org_id, call.space_id, source, contract, version, policy, action, reason,
                      material, snapshot, call.principal_id, call.request_id),
            ).fetchone()
            append_event(transaction, call.org_id, "lifecycle.disposition_case.submitted", ref, space_id=call.space_id)
            return case

        case = execute_command(connection, command, apply).result_ref
        return {"case_id": str(case), "inventory_snapshot": snapshot.hex(), "state": "submitted", "executable": False}


def lock_review_target(connection: Connection, call: OperationsCall, case: UUID, operation: str) -> ReviewTarget:
    require_scope(connection, call, operation, destination=DESTINATION)
    target = connection.execute(
        "SELECT * FROM thalion.lock_local_disposition_review(%s, %s, %s, %s)",
        (call.org_id, call.space_id, case, call.principal_id),
    ).fetchone()
    if target is None:
        raise OperationsNotAdmitted("A current independent synthetic reviewer is required for the disposition case.")
    return ReviewTarget(*target)


def decide_disposition_case(
    connection: Connection, call: OperationsCall, case: UUID, snapshot: bytes, basis: UUID,
    expires_at: datetime | None = None,
) -> dict:
    operation, state = REJECT, "rejected"
    inputs = (str(case), snapshot.hex(), str(basis))
    if expires_at is not None:
        require_aware(expires_at)
        expires_at = expires_at.astimezone(UTC)
        operation, state = APPROVE, "approved"
        inputs += (expires_at.isoformat(),)
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        scope = (call.org_id, call.space_id, case)
        ref, source, contract, version, action, reason, sealed, submitter = lock_review_target(connection, call, case, operation)
        command = command_for(call, operation, inputs)

        def check_inventory(transaction):
            if snapshot != sealed:
                raise DispositionConflict("The decision does not identify the submitted inventory.")
            matching_inventory(transaction, call, ref, action, reason, snapshot, source, contract, version)

        if expires_at is not None:
            connection.execute("SELECT thalion.lock_synthetic_export_target(%s, %s, %s)", (*scope[:2], version))
            check_inventory(connection)
            now, = connection.execute("SELECT clock_timestamp()").fetchone()
            if expires_at <= now:
                raise DispositionConflict("The disposition approval has expired.")
            if expires_at > now + timedelta(minutes=15):
                raise ValueError("A disposition approval must expire within fifteen minutes.")

        def apply(transaction):
            if expires_at is None:
                check_inventory(transaction)
            result = transaction.execute(
                """
                INSERT INTO thalion.disposition_decision (
                    org_id, space_id, case_ref, inventory_snapshot, submitted_by, decided_by, request_id,
                    basis_ref, outcome, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (case_ref) DO NOTHING RETURNING decision_ref
                """, (*scope, snapshot, submitter, call.principal_id, call.request_id, basis, state, expires_at),
            ).fetchone()
            if result is None:
                raise DispositionConflict("A decision already exists for this disposition case.")
            append_event(transaction, call.org_id, f"lifecycle.disposition_case.{state}", ref, space_id=call.space_id)
            return result[0]

        decision = execute_command(connection, command, apply).result_ref
        result = {"case_id": str(case), "decision_id": str(decision), "inventory_snapshot": snapshot.hex(),
                  "state": state, "executable": False}
        if expires_at is not None:
            result["expires_at"] = expires_at.isoformat()
        return result


def register_deletion_tombstone(
    connection: Connection, call: OperationsCall, case: UUID, approval: UUID, snapshot: bytes,
) -> dict:
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        target = lock_review_target(connection, call, case, REGISTER_TOMBSTONE)
        scope = (call.org_id, call.space_id, target.version)
        command = command_for(call, REGISTER_TOMBSTONE, (str(case), str(approval), snapshot.hex()))

        def apply(transaction):
            if target.action != "destroy" or snapshot != target.sealed:
                raise DispositionConflict("A matching destroy disposition is required.")
            document, = transaction.execute("""
                SELECT document.document_id
                FROM thalion.document_version AS version
                JOIN thalion.document USING (org_id, space_id, source_id, document_id)
                WHERE (version.org_id, version.space_id, version.version_id) = (%s, %s, %s)
                FOR UPDATE OF document
                """, scope).fetchone()
            matching_inventory(
                transaction, call, target.ref, target.action, target.reason, snapshot,
                target.source, target.contract, target.version,
            )
            applied = transaction.execute("""
                INSERT INTO thalion.rule_use_stop (
                    org_id, space_id, source_id, document_id, version_id, contract_revision, decided_by, kind, basis_ref,
                    disposition_case_ref, disposition_request_id
                )
                SELECT org_id, space_id, %s, %s, %s, %s, decided_by, 'deletion_blocked', basis_ref, case_ref, %s
                FROM thalion.disposition_decision
                WHERE (org_id, space_id, case_ref, decision_ref, decided_by, inventory_snapshot) = (%s, %s, %s, %s, %s, %s)
                  AND outcome = 'approved' AND expires_at > clock_timestamp()
                ON CONFLICT (version_id, kind) DO NOTHING RETURNING decision_ref
                """, (target.source, document, target.version, target.contract, call.request_id,
                      call.org_id, call.space_id, case, approval, call.principal_id, snapshot)).fetchone()
            if applied is None:
                raise DispositionConflict("The destroy approval is invalid, expired or already recorded.")
            append_event(transaction, call.org_id, "lifecycle.deletion_tombstone.registered", target.ref, space_id=call.space_id)
            return applied[0]

        tombstone = execute_command(connection, command, apply).result_ref
        return {"case_id": str(case), "tombstone_id": str(tombstone), "inventory_snapshot": snapshot.hex(),
                "state": "restore_blocked", "executable": False}
