from hashlib import sha256
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.lifecycle.disposition import (
    DispositionConflict, DispositionInventoryUnavailable, lock_review_target, matching_inventory,
)
from enterprise_kb.modules.operations.context import OperationsCall, command_for
from enterprise_kb.modules.sources.originals import ObjectStorageOriginalStore, OriginalAsset, OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.modules.sources.registry import store_storage_kind
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


VERIFY_ORIGINAL = "verify_disposition_original"


def verify_disposition_original(
    connection: Connection, call: OperationsCall, case: UUID, snapshot: bytes, store: SyntheticOriginalStore,
) -> dict:
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit = on")
        target = lock_review_target(connection, call, case, VERIFY_ORIGINAL)
        scope = (call.org_id, call.space_id, case)
        if snapshot != target.sealed or connection.execute(
            "SELECT 1 FROM thalion.disposition_rejection WHERE (org_id, space_id, case_ref) = (%s, %s, %s)", scope,
        ).fetchone() is not None:
            raise DispositionConflict("Only the sealed inventory of a non-rejected case can be verified.")
        command = command_for(call, VERIFY_ORIGINAL, (str(case), snapshot.hex()))

        def apply(transaction):
            inventory = (call, target.ref, target.action, target.reason, snapshot, target.source, target.contract, target.version)
            matching_inventory(transaction, *inventory)
            expected_storage_kind = store_storage_kind(store)
            asset = transaction.execute(
                """
                SELECT asset.asset_id, asset.storage_key, asset.content_digest, asset.byte_length
                FROM thalion.document_version AS version
                JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
                WHERE (version.org_id, version.space_id, version.version_id) = (%s, %s, %s)
                  AND asset.storage_kind = %s
                """, (call.org_id, call.space_id, target.version, expected_storage_kind),
            ).fetchone()
            if asset is None:
                raise DispositionInventoryUnavailable("No registered synthetic original can be verified.")
            asset_id, key, digest, length = asset
            try:
                payload = store.read(OriginalAsset(key, digest, length))
            except OriginalIntegrityError:
                raise DispositionInventoryUnavailable("The registered original could not be verified.") from None
            matching_inventory(transaction, *inventory)
            observation, = transaction.execute(
                """
                INSERT INTO thalion.disposition_original_observation (
                    org_id, space_id, case_ref, submitted_by, inventory_snapshot, asset_id,
                    content_digest, byte_length, observed_by, request_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING observation_ref
                """, (*scope, target.submitter, snapshot, asset_id, sha256(payload).digest(), len(payload),
                      call.principal_id, call.request_id),
            ).fetchone()
            append_event(transaction, call.org_id, "lifecycle.disposition_original.verified", target.ref, space_id=call.space_id)
            return observation

        observation = execute_command(connection, command, apply).result_ref
        observed_at, = connection.execute(
            """
            SELECT observed_at FROM thalion.disposition_original_observation
            WHERE (org_id, space_id, case_ref, observation_ref) = (%s, %s, %s, %s)
            """, (*scope, observation),
        ).fetchone()
        return {
            "case_id": str(case), "verification_id": str(observation), "inventory_snapshot": snapshot.hex(),
            "observed_at": observed_at.isoformat(), "copy_kind": "original", "state": "verified", "executable": False,
        }
