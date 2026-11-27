from datetime import UTC
import json
from uuid import UUID

from psycopg import Connection
from psycopg.types.json import Jsonb

from enterprise_kb.modules.lifecycle.backup_inventory import SyntheticBackupStore, backup_key
from enterprise_kb.modules.lifecycle.disposition import (
    DispositionConflict, DispositionInventoryUnavailable, _load_inventory, lock_review_target,
)
from enterprise_kb.modules.operations.context import OperationsCall, command_for
from enterprise_kb.modules.sources.originals import ObjectStorageOriginalStore, OriginalAsset, OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.modules.sources.registry import store_storage_kind
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


OBSERVE = "record_disposition_copy_observations"


def _original_state(connection, scope, asset_id, store):
    expected_storage_kind = store_storage_kind(store)
    asset = connection.execute("""
        SELECT asset.storage_key, asset.content_digest, asset.byte_length
        FROM thalion.document_version AS version
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        WHERE (version.org_id, version.space_id, version.version_id, asset.asset_id) = (%s, %s, %s, %s)
          AND asset.storage_kind = %s
        """, (*scope, asset_id, expected_storage_kind)).fetchone()
    if asset is not None:
        try:
            store.read(OriginalAsset(*asset))
        except OriginalIntegrityError:
            pass
        else:
            return "present_verified"
    return "unobserved"


def _observe_backups(items, store):
    if store is None or not items:
        return {}
    try:
        identity = store.identity()
    except (OSError, ValueError):
        raise DispositionInventoryUnavailable("The configured backup directory could not be identified.") from None
    expected = {
        backup_key(UUID(ref)): (identity, bytes.fromhex(digest), length)
        for ref, _, digest, length, bound in items if bound == identity.hex()
    }
    if not expected:
        return {}
    actual, observations, _ = store.audit(expected)
    if actual != identity:
        raise DispositionInventoryUnavailable("The configured backup directory changed identity.")
    return observations


def _item_key(item):
    return json.dumps(item, separators=(",", ":"))


def _capture(connection, call, target, sealed, store, backup_store):
    *_, registered, facts = _load_inventory(connection, call, target.ref, target.source, target.contract, target.version)
    current = {_item_key(item) for item in registered}
    approved = {_item_key(item) for item in sealed}
    expiry = {ref: fact[3] for kind, ref, fact in facts if kind == "backup_expiry" and fact[3] is not None}
    available = _observe_backups(
        [identity for kind, identity in sealed if kind == "backup" and _item_key([kind, identity]) in current], backup_store,
    )
    version_scope = (call.org_id, call.space_id, target.version)
    copies = []
    for kind, identity in sealed:
        state, witness = "unobserved", None
        if _item_key([kind, identity]) in current:
            if kind == "original":
                state = _original_state(connection, version_scope, identity[0], store)
            elif kind == "backup":
                disk_state = available.get(backup_key(UUID(identity[0])))
                prior = expiry.get(identity[0])
                if disk_state == "missing":
                    state, witness = ("absence_verified", prior) if prior else ("missing_unverified", None)
                elif disk_state in {"verified", "invalid"}:
                    if prior:
                        state, witness = "reappeared", prior
                    else:
                        state = "present_verified" if disk_state == "verified" else "present_invalid"
            else:
                state = "present_in_database"
        copies.append([kind, state, witness])
    return copies, len(current - approved)


def record_copy_observations(
    connection: Connection, call: OperationsCall, case: UUID, tombstone: UUID, snapshot: bytes,
    store: SyntheticOriginalStore, backup_store: SyntheticBackupStore | None,
) -> dict:
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        target = lock_review_target(connection, call, case, OBSERVE)
        if target.action != "destroy" or snapshot != target.sealed:
            raise DispositionConflict("The observation must identify the sealed destroy inventory.")
        scope = (call.org_id, call.space_id, case)
        version_scope = (*scope[:2], target.version)
        connection.execute("SELECT thalion.lock_synthetic_export_target(%s, %s, %s)", version_scope)
        case_material = connection.execute("""
            SELECT candidate.inventory_material FROM thalion.disposition_case AS candidate
            JOIN thalion.rule_use_stop AS stop ON (stop.org_id, stop.space_id, stop.disposition_case_ref) =
                                                  (candidate.org_id, candidate.space_id, candidate.case_ref)
            WHERE (candidate.org_id, candidate.space_id, candidate.case_ref) = (%s, %s, %s)
              AND (stop.decision_ref, stop.kind, stop.source_id, stop.contract_revision, stop.version_id) =
                  (%s, 'deletion_blocked', %s, %s, %s)
              AND NOT EXISTS (
                  SELECT 1 FROM thalion.current_version_hold AS hold
                  WHERE (hold.org_id, hold.space_id, hold.version_id) = (stop.org_id, stop.space_id, stop.version_id)
                    AND hold.action = 'establish'
              )
            """, (*scope, tombstone, target.source, target.contract, target.version)).fetchone()
        if case_material is None:
            raise DispositionConflict("Copy observations require the exact local tombstone and no current hold.")
        try:
            sealed = json.loads(case_material[0])
            if len(sealed) != 17 or sealed[0] != "local_disposition_inventory.v1" or not sealed[14]:
                raise ValueError()
        except (TypeError, ValueError, KeyError):
            raise DispositionInventoryUnavailable("The case inventory cannot be verified.") from None
        command = command_for(call, OBSERVE, (str(case), str(tombstone), snapshot.hex()))

        def apply(transaction):
            copies, additional = _capture(transaction, call, target, sealed[14], store, backup_store)
            receipt, = transaction.execute("""
                INSERT INTO thalion.disposition_copy_receipt (
                    org_id, space_id, case_ref, submitted_by, inventory_snapshot, tombstone_ref,
                    observed_by, request_id, copies, additional_registered_count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING receipt_ref
                """, (*scope, target.submitter, snapshot, tombstone, call.principal_id, call.request_id,
                      Jsonb(copies), additional)).fetchone()
            append_event(transaction, call.org_id, "lifecycle.disposition_copies.observed", target.ref, space_id=call.space_id)
            return receipt

        receipt = execute_command(connection, command, apply).result_ref
        observed, copies, additional = connection.execute("""
            SELECT observed_at, copies, additional_registered_count FROM thalion.disposition_copy_receipt
            WHERE (org_id, space_id, case_ref, receipt_ref) = (%s, %s, %s, %s)
            """, (*scope, receipt)).fetchone()
        items = [{"item": position, "kind": kind, "presence": state}
                 for position, (kind, state, _) in enumerate(copies, 1)]
        return {
            "case_id": str(case), "tombstone_id": str(tombstone), "inventory_snapshot": snapshot.hex(),
            "receipt_id": str(receipt), "observed_at": observed.astimezone(UTC).isoformat(),
            "copies": items, "additional_registered_count": additional, "unverified_copy_kinds": sealed[16],
            "remaining_items": [item["item"] for item in items if item["presence"] != "absence_verified"],
            "restore_blocked_locally": True, "executable": False,
        }
