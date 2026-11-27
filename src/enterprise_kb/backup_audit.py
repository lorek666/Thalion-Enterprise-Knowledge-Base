import argparse
from collections import Counter
from datetime import UTC
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
from uuid import UUID, uuid4

import psycopg
from sqlalchemy.exc import ArgumentError

from enterprise_kb.database import local_connection_factory, rehearsal_marker
from enterprise_kb.modules.lifecycle.backup_catalogue import MAX_STORES, pinned_manifest
from enterprise_kb.modules.lifecycle.backup_inventory import MAX_AUDIT_BYTES, MAX_AUDIT_ENTRIES, SyntheticBackupStore, backup_key
from enterprise_kb.modules.lifecycle.disposition import DispositionInventoryUnavailable
from enterprise_kb.modules.sources.originals import SyntheticOriginalStore
from enterprise_kb.modules.sources.registry import sql_admitted_admission, sql_storage_matches_admission
from enterprise_kb.modules.sources.restriction_log import _log_ref


ACCEPTED_STATES = frozenset({"verified", "absence_observed"})


def _iso(timestamp):
    return timestamp.astimezone(UTC).isoformat() if timestamp is not None else None


def _registrations(connection, scope=None):
    rows = connection.execute("""
            SELECT copy.backup_ref, copy.org_id, copy.space_id, identity.public_id, copy.store_identity,
                   copy.content_digest, copy.byte_length, observed.observed_at, plan.expected_expiry_at,
                   EXISTS (SELECT 1 FROM thalion.rule_use_stop AS stop
                           WHERE (stop.org_id, stop.space_id, stop.version_id) = (copy.org_id, copy.space_id, copy.version_id)
                             AND stop.kind = 'withdrawn'),
                   coalesce(hold.action = 'establish', false)
            FROM thalion.synthetic_backup_copy AS copy
            LEFT JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
                 (copy.org_id, copy.space_id, 'document_version', copy.version_id)
            LEFT JOIN thalion.synthetic_backup_expiry_plan AS plan
              ON (plan.org_id, plan.space_id, plan.backup_ref) = (copy.org_id, copy.space_id, copy.backup_ref)
            LEFT JOIN thalion.synthetic_backup_expiry_observation AS observed
              ON (observed.org_id, observed.space_id, observed.backup_ref, observed.schedule_ref) =
                 (plan.org_id, plan.space_id, plan.backup_ref, plan.schedule_ref)
            LEFT JOIN thalion.current_version_hold AS hold
              ON (hold.org_id, hold.space_id, hold.version_id) = (copy.org_id, copy.space_id, copy.version_id)
            WHERE %s::bigint IS NULL OR (copy.org_id, copy.space_id, copy.version_id) = (%s, %s, %s)
            ORDER BY copy.backup_ref LIMIT %s
            """, ((scope or (None,))[0], *(scope or (None, None, None)), MAX_AUDIT_ENTRIES + 1)).fetchall()
    if len(rows) > MAX_AUDIT_ENTRIES or any(row[3] is None for row in rows):
        raise DispositionInventoryUnavailable("The backup registrations exceed their bounded audit scope.")
    return rows


def reconcile(connection, store):
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        connection.execute("SET LOCAL row_security = off")
        started, = connection.execute("SELECT transaction_timestamp()").fetchone()
        rows = _registrations(connection)
        registered = {backup_key(ref): (identity, digest, length) for ref, _, _, _, identity, digest, length, *_ in rows}
        identity, states, unknown = store.audit(registered)
        finished, = connection.execute("SELECT clock_timestamp()").fetchone()
    records = []
    for ref, org, space, version, bound, digest, length, observed, expiry, withdrawn, held in rows:
        disk_state = states.get(backup_key(ref))
        if bound is None:
            state = "unbound_registration"
        elif bound != identity:
            state = "other_directory"
        elif observed is not None:
            state = "absence_observed" if disk_state == "missing" else "reappeared"
        else:
            state = disk_state
        records.append({
            "backup_id": str(ref), "organization": org, "space": space, "version_id": str(version),
            "expected_sha256": digest.hex(), "expected_byte_length": length, "state": state, "disk_state": disk_state,
            "withdrawn": withdrawn, "held": held, "expected_expiry_at": _iso(expiry), "absence_observed_at": _iso(observed),
        })
    counts = Counter(record["state"] for record in records)
    if unknown:
        counts["unregistered"] = len(unknown)
    return {
        "format": "thalion.synthetic-backup-reconciliation.v1", "scope": "single_local_directory_and_selected_database",
        "status": "matched" if counts.keys() <= ACCEPTED_STATES else "discrepancies", "counts": dict(counts),
        "store_identity_sha256": identity.hex(), "started_at": _iso(started), "finished_at": _iso(finished),
        "registrations": records, "unregistered_name_sha256": unknown, "executable": False, "restore_authorized": False,
    }


def _catalogue_target(connection, space_ref, version_ref, manifest):
    target = connection.execute(f"""
        SELECT version.org_id, version.space_id, version.version_id, asset.content_digest, asset.byte_length,
               EXISTS (SELECT 1 FROM thalion.rule_use_stop AS stop
                       WHERE (stop.org_id, stop.space_id, stop.version_id) =
                             (version.org_id, version.space_id, version.version_id)
                         AND stop.kind IN ('withdrawn', 'deletion_blocked')),
               EXISTS (SELECT 1 FROM thalion.current_version_hold AS hold
                       WHERE (hold.org_id, hold.space_id, hold.version_id) =
                             (version.org_id, version.space_id, version.version_id) AND hold.action = 'establish')
        FROM thalion.document_version AS version
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (version.org_id, version.space_id, 'document_version', version.version_id)
        JOIN thalion.object_identity AS space
          ON (space.org_id, space.object_type, space.object_id) = (version.org_id, 'space', version.space_id)
        JOIN thalion.asset AS asset
          ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id) =
             (version.org_id, version.space_id, version.source_id, version.document_id, version.asset_id)
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.source_id) = (version.org_id, version.space_id, version.source_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        WHERE (space.public_id, identity.public_id) = (%s, %s)
          AND {sql_admitted_admission('contract.admission')}
          AND {sql_storage_matches_admission('asset.storage_kind', 'contract.admission')}
        """, (space_ref, version_ref)).fetchone()
    if target is None or target[3:5] != (manifest.digest, manifest.byte_length):
        raise DispositionInventoryUnavailable("The catalogue does not match the exact registered synthetic version.")
    return target


def _scan_catalogue(stores, manifest, rows):
    expected = {bound: {} for bound in manifest.stores}
    for ref, bound in manifest.copies:
        expected[bound][backup_key(ref)] = (bound, manifest.digest, manifest.byte_length)
    for ref, _, _, _, bound, digest, length, *_ in rows:
        if (digest, length) != (manifest.digest, manifest.byte_length):
            raise DispositionInventoryUnavailable("A local registration disagrees with the exact version bytes.")
        if bound in expected:
            expected[bound][backup_key(ref)] = (bound, digest, length)
    total = sum(map(len, expected.values()))
    if total > MAX_AUDIT_ENTRIES or total * manifest.byte_length > MAX_AUDIT_BYTES:
        raise DispositionInventoryUnavailable("The declared backup set exceeds the reconciliation limit.")
    observations, unregistered, roots = {}, {}, []
    for store in stores:
        if any(store.root.is_relative_to(root) or root.is_relative_to(store.root) for root in roots):
            raise ValueError("The reconciliation roots must be distinct and non-nested.")
        roots.append(store.root)
        bound = store.identity()
        if bound not in expected or bound in observations:
            raise DispositionInventoryUnavailable("A supplied backup directory is outside the pinned catalogue.")
        actual, states, unknown = store.audit(expected[bound])
        if actual != bound:
            raise DispositionInventoryUnavailable("The declared backup directory changed identity.")
        observations[bound] = states
        if unknown:
            unregistered[bound.hex()] = unknown
    return observations, unregistered


def reconcile_catalogue(connection, authority, stores, *, authority_ref, space_ref, version_ref, manifest_ref):
    if not 1 <= len(stores) <= MAX_STORES:
        raise ValueError("Invalid number of backup directories.")
    with pinned_manifest(authority, authority_ref, space_ref, version_ref, manifest_ref) as manifest, connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        connection.execute("SET LOCAL row_security = off")
        if connection.info.hostaddr not in {"127.0.0.1", "::1"} or rehearsal_marker(connection) is not None or _log_ref(connection) == authority_ref:
            raise DispositionInventoryUnavailable("The business and catalogue endpoints must be distinct local databases.")
        started, = connection.execute("SELECT transaction_timestamp()").fetchone()
        target = _catalogue_target(connection, space_ref, version_ref, manifest)
        rows = _registrations(connection, target[:3])
        observations, unregistered = _scan_catalogue(stores, manifest, rows)
        finished, = connection.execute("SELECT clock_timestamp()").fetchone()
    local = {row[0]: row for row in rows}
    declared = dict(manifest.copies)
    unobserved = sorted(bound.hex() for bound in set(manifest.stores) - observations.keys())
    records = []
    for ref in sorted(local.keys() | declared.keys()):
        catalogue_binding = declared.get(ref)
        current = local.get(ref)
        registered_binding = current[4] if current else None
        key = backup_key(ref)
        catalogue_state = observations.get(catalogue_binding, {}).get(key)
        registered_state = observations.get(registered_binding, {}).get(key)
        observed, expiry = current[7:9] if current else (None, None)
        if current is None:
            state = "catalogue_only"
        elif catalogue_binding is None:
            state = "local_only"
        elif registered_binding != catalogue_binding:
            state = "binding_mismatch"
        elif catalogue_state is None:
            state = "unobserved"
        elif observed is not None:
            state = "absence_observed" if catalogue_state == "missing" else "reappeared"
        else:
            state = catalogue_state
        records.append({
            "backup_id": str(ref), "state": state, "catalogue_observation": catalogue_state,
            "registered_observation": registered_state,
            "catalogue_store_sha256": catalogue_binding.hex() if catalogue_binding is not None else None,
            "registered_store_sha256": registered_binding.hex() if registered_binding is not None else None,
            "expected_expiry_at": _iso(expiry), "absence_observed_at": _iso(observed),
        })
    counts = Counter(record["state"] for record in records)
    if unobserved:
        counts["unobserved_store"] = len(unobserved)
    if unregistered:
        counts["unregistered"] = sum(map(len, unregistered.values()))
    return {
        "format": "thalion.synthetic-backup-catalogue-reconciliation.v1", "scope": "one_synthetic_version_and_declared_directories",
        "status": "matched" if counts.keys() <= ACCEPTED_STATES else "discrepancies", "counts": dict(counts),
        "catalogue_ref": str(authority_ref), "manifest_id": str(manifest.ref), "generation": manifest.generation,
        "manifest_expires_at": _iso(manifest.expires_at), "space_id": str(space_ref), "version_id": str(version_ref),
        "expected_sha256": manifest.digest.hex(), "expected_byte_length": manifest.byte_length,
        "started_at": _iso(started), "finished_at": _iso(finished), "restore_prohibited": target[5], "held": target[6],
        "registrations": records, "unobserved_stores": unobserved, "unregistered_name_sha256": unregistered,
        "remaining_copy_ids": [record["backup_id"] for record in records if record["state"] != "absence_observed"],
        "executable": False, "restore_authorized": False,
    }


def _write_report(directory, name, payload):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise ValueError("The report directory must be private.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        report = os.open(name, flags, 0o600, dir_fd=descriptor)
        try:
            with os.fdopen(report, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(descriptor)
        except OSError:
            os.unlink(name, dir_fd=descriptor)
            raise
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description="对账隔离开发环境中的本机合成备份")
    parser.add_argument("--originals", type=Path, required=True)
    parser.add_argument("--backups", type=Path, action="append", required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--catalogue-ref", type=UUID)
    parser.add_argument("--manifest-id", type=UUID)
    parser.add_argument("--space-id", type=UUID)
    parser.add_argument("--version-id", type=UUID)
    arguments = parser.parse_args()
    try:
        pins = (arguments.catalogue_ref, arguments.manifest_id, arguments.space_id, arguments.version_id)
        if any(pins) and not all(pins) or (not any(pins) and len(arguments.backups) != 1) or len(arguments.backups) > MAX_STORES:
            raise ValueError("Multiple backup roots require all catalogue scope pins.")
        originals = SyntheticOriginalStore(arguments.originals)
        stores = tuple(SyntheticBackupStore(root, originals) for root in arguments.backups)
        directory = arguments.report_dir.resolve(strict=True)
        if any(directory.is_relative_to(root) for root in (originals.root, *(store.root for store in stores))):
            raise ValueError("Audit reports must not be written to the repositories being audited.")
        details = directory.stat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise ValueError("The report directory must be private.")
        connect = local_connection_factory(os.environ.get("THALION_DATABASE_URL", ""))
        with connect() as connection:
            if all(pins):
                connect_authority = local_connection_factory(os.environ.get("THALION_BACKUP_CATALOGUE_URL", ""))
                with connect_authority() as authority:
                    detail = reconcile_catalogue(
                        connection, authority, stores, authority_ref=arguments.catalogue_ref,
                        space_ref=arguments.space_id, version_ref=arguments.version_id, manifest_ref=arguments.manifest_id,
                    )
            else:
                detail = reconcile(connection, stores[0])
        report_id = uuid4().hex
        payload = json.dumps(detail, sort_keys=True, separators=(",", ":")).encode()
        _write_report(directory, f"backup-audit-{report_id}.json", payload)
    except (OSError, ValueError, ArgumentError, psycopg.Error, DispositionInventoryUnavailable):
        print("FAIL 无法完成合成备份对账。请核对私有目录、只读数据库权限、迁移状态和扫描上限。", file=sys.stderr)
        return 1
    print(json.dumps({"report_id": report_id, "report_sha256": sha256(payload).hexdigest(),
                      "status": detail["status"], "counts": detail["counts"]}, sort_keys=True))
    return 0 if detail["status"] == "matched" else 2


if __name__ == "__main__":
    sys.exit(main())
