from datetime import UTC, datetime, timedelta
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.access.rules import require_aware
from enterprise_kb.modules.lifecycle.backup_inventory import SyntheticBackupStore
from enterprise_kb.modules.lifecycle.disposition import DESTINATION, DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, command_for, require_scope
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


SCHEDULE = "schedule_synthetic_backup_expiry"
OBSERVE = "observe_synthetic_backup_expiry"


def _lock_target(connection, call, operation, backup):
    require_scope(connection, call, operation, destination=DESTINATION)
    scope = (call.org_id, call.space_id, backup)
    target = connection.execute("""
        SELECT version_id, content_digest, byte_length, identity.public_id, store_identity
        FROM thalion.synthetic_backup_copy AS copy
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (copy.org_id, copy.space_id, 'document_version', copy.version_id)
        WHERE (copy.org_id, copy.space_id, copy.backup_ref) = (%s, %s, %s)
        """, scope).fetchone()
    if target is None or not connection.execute(
        "SELECT thalion.lock_local_hold_target(%s, %s, %s, %s)", (*scope[:2], target[0], call.principal_id),
    ).fetchone()[0]:
        raise OperationsNotAdmitted("A current independent synthetic backup custodian is required.")
    version_scope = (*scope[:2], target[0])
    state = connection.execute("""
        SELECT decision_ref, recorded_at, clock_timestamp() FROM thalion.rule_use_stop AS stop
        WHERE (stop.org_id, stop.space_id, stop.version_id) = (%s, %s, %s) AND stop.kind = 'withdrawn'
          AND NOT EXISTS (
              SELECT 1 FROM thalion.current_version_hold AS hold
              WHERE (hold.org_id, hold.space_id, hold.version_id) = (stop.org_id, stop.space_id, stop.version_id)
                AND hold.action = 'establish'
          )
        """, version_scope).fetchone()
    if state is None:
        raise DispositionConflict("Backup expiry requires a withdrawn version without an active hold.")
    if target[4] is None:
        raise DispositionInventoryUnavailable("The backup registration does not identify the original storage directory.")
    return scope, target, state


def schedule_expiry(
    connection: Connection, call: OperationsCall, backup: UUID, expected: datetime, store: SyntheticBackupStore | None,
) -> dict:
    require_aware(expected)
    try:
        expected = expected.astimezone(UTC)
    except OverflowError:
        raise ValueError("Invalid backup expiry date.") from None
    scope, (version, digest, length, version_ref, store_identity), (withdrawal, withdrew_at, now) = _lock_target(
        connection, call, SCHEDULE, backup,
    )
    if not withdrew_at <= expected <= now + timedelta(days=366):
        raise ValueError("The expected expiry must be on or after withdrawal and within the scheduling horizon.")
    command = command_for(call, SCHEDULE, (str(backup), expected.isoformat()))

    def apply(transaction):
        if store is None:
            raise DispositionInventoryUnavailable("No private synthetic backup directory is configured.")
        if store.verify(backup, digest, length) != store_identity:
            raise DispositionInventoryUnavailable("The backup does not match the registered storage directory.")
        scheduled = transaction.execute("""
            INSERT INTO thalion.synthetic_backup_expiry_plan (
                org_id, space_id, backup_ref, version_id, withdrawal_ref, expected_expiry_at, recorded_by, request_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (backup_ref) DO NOTHING RETURNING schedule_ref
            """, (*scope, version, withdrawal, expected, call.principal_id, call.request_id)).fetchone()
        if scheduled is None:
            raise DispositionConflict("An expiry plan already exists for the backup.")
        append_event(transaction, call.org_id, "lifecycle.synthetic_backup.expiry_scheduled", version_ref, space_id=call.space_id)
        return scheduled[0]

    result = execute_command(connection, command, apply).result_ref
    return {"schedule_id": str(result), "state": "pending_expiry_verification", "restore_prohibited": True,
            "expected_expiry_at": expected.isoformat(), "executable": False}


def observe_expiry(
    connection: Connection, call: OperationsCall, backup: UUID, store: SyntheticBackupStore | None,
) -> dict:
    scope, (_, _, _, version_ref, store_identity), (_, _, now) = _lock_target(connection, call, OBSERVE, backup)
    plan = connection.execute("""
        SELECT schedule_ref, expected_expiry_at FROM thalion.synthetic_backup_expiry_plan
        WHERE (org_id, space_id, backup_ref) = (%s, %s, %s)
        """, scope).fetchone()
    if plan is None or now < plan[1]:
        raise DispositionConflict("No due backup expiry plan is available.")
    schedule, _ = plan
    command = command_for(call, OBSERVE, (str(backup), str(schedule)))

    def apply(transaction):
        if store is None:
            raise DispositionInventoryUnavailable("No private synthetic backup directory is configured.")
        if not store.is_absent(backup, store_identity):
            raise DispositionConflict("The exact backup entry is still present.")
        observation = transaction.execute("""
            INSERT INTO thalion.synthetic_backup_expiry_observation (
                org_id, space_id, backup_ref, schedule_ref, recorded_by, request_id
            ) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (backup_ref) DO NOTHING RETURNING observation_ref
            """, (*scope, schedule, call.principal_id, call.request_id)).fetchone()
        if observation is None:
            raise DispositionConflict("An absence has already been observed for this backup.")
        append_event(transaction, call.org_id, "lifecycle.synthetic_backup.absence_observed", version_ref, space_id=call.space_id)
        return observation[0]

    result = execute_command(connection, command, apply).result_ref
    observed_at, = connection.execute("""
        SELECT observed_at FROM thalion.synthetic_backup_expiry_observation
        WHERE (org_id, space_id, backup_ref, observation_ref) = (%s, %s, %s, %s)
        """, (*scope, result)).fetchone()
    return {"observation_id": str(result), "state": "absence_observed", "observed_at": observed_at.astimezone(UTC).isoformat(),
            "restore_prohibited": True, "executable": False}
