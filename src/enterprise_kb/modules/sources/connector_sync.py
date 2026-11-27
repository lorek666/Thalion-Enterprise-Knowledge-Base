from base64 import b64decode
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from hashlib import sha256
from time import monotonic
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from psycopg import Connection, Error
from psycopg.pq import TransactionStatus

from enterprise_kb.ports.contracts import (
    ConnectorPortUnavailable,
    SourceConnectorPort,
)
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.runtime.audit_sink import SecurityAuditDispatcher, SecurityAuditEvent, metadata_digest
from enterprise_kb.runtime.commands import IdempotencyConflict

from . import permission_checkpoints, reconciliation, registry, source_restrictions, sync
from .originals import ObjectStorageOriginalStore, OriginalIntegrityError, SyntheticOriginalStore
from .source_revocations import SourceRevocationAuthority


WORKER_CLIENT_ID = "thalion-connector-sync"
DEFAULT_MAX_PAGES = 20
_CURSOR_NAMESPACE = uuid5(NAMESPACE_URL, "thalion.source.cursor.v1")
_SNAPSHOT_NAMESPACE = uuid5(NAMESPACE_URL, "thalion.source.snapshot.v1")


class ConnectorSyncError(Exception):
    pass


@dataclass(frozen=True)
class ConnectorSyncReport:
    source_ref: UUID
    status: str
    pages_committed: int = 0
    versions_registered: tuple[UUID, ...] = ()
    restrictions_acknowledged: tuple[UUID, ...] = ()
    content_position: UUID | None = None
    permission_checkpoint_ref: UUID | None = None
    permission_generation: int | None = None
    reconciliation_status: str = "skipped"
    reconciliation_snapshot_ref: UUID | None = None
    reconciliation_matched: int = 0
    reconciliation_differences: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": str(self.source_ref),
            "status": self.status,
            "pages_committed": self.pages_committed,
            "versions_registered": [str(ref) for ref in self.versions_registered],
            "restrictions_acknowledged": [str(ref) for ref in self.restrictions_acknowledged],
            "content_position": str(self.content_position) if self.content_position else None,
            "permission_checkpoint_id": str(self.permission_checkpoint_ref) if self.permission_checkpoint_ref else None,
            "permission_generation": self.permission_generation,
            "reconciliation_status": self.reconciliation_status,
            "reconciliation_snapshot_id": str(self.reconciliation_snapshot_ref) if self.reconciliation_snapshot_ref else None,
            "reconciliation_matched": self.reconciliation_matched,
            "reconciliation_differences": self.reconciliation_differences,
            "error": self.error,
        }


def _opaque_uuid(raw: str, namespace: UUID, scope_prefix: str) -> UUID:
    cleaned = raw.strip()
    try:
        return UUID(cleaned)
    except ValueError:
        return uuid5(namespace, f"{scope_prefix}:{cleaned}")


def _resolve_source_binding(connection: Connection, source_ref: UUID):
    with connection.transaction():
        row = connection.execute(
            """
            SELECT src.org_id, src.space_id, src.source_id, src.contract_revision,
                   contract.collector_id, org.config_revision, space_id_obj.public_id,
                   contract.admission
            FROM thalion.object_identity AS id
            JOIN thalion.source AS src
              ON (src.org_id, src.space_id, src.identity_type, src.source_id)
               = (id.org_id, id.space_id, id.object_type, id.object_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            JOIN thalion.principal AS collector
              ON (collector.org_id, collector.principal_id) = (contract.org_id, contract.collector_id)
            JOIN thalion.organization AS org ON org.org_id = src.org_id
            JOIN thalion.object_identity AS space_id_obj
              ON (space_id_obj.org_id, space_id_obj.space_id, space_id_obj.object_type, space_id_obj.object_id)
               = (src.org_id, src.space_id, 'space', src.space_id)
            WHERE id.object_type = 'source' AND id.public_id = %s
              AND collector.principal_type = 'service' AND NOT collector.disabled
            """,
            (source_ref,),
        ).fetchone()
    return row


def _open_internal_write(
    connection: Connection,
    org_id: int,
    space_id: int,
    collector_id: int,
    config_revision: int,
    operation: str,
    *,
    business_day: date,
    idempotency_key: str | None = None,
) -> tuple[registry.SourceWrite, float]:
    request_id = uuid4()
    started = monotonic()
    start_request(
        connection,
        RequestStart(
            org_id,
            request_id,
            collector_id,
            None,
            WORKER_CLIENT_ID,
            operation,
            "internal_sources",
            business_day,
            config_revision,
            space_id=space_id,
            ingress="internal",
        ),
    )
    return registry.SourceWrite(org_id, collector_id, request_id, idempotency_key or str(request_id)), started


def _decode_upsert_item(
    item: dict[str, Any],
    *,
    space_id: int,
    source_ref: UUID,
    contract_revision: int,
    connector: SourceConnectorPort,
) -> sync.PageOriginal:
    object_key = item.get("object_key")
    incarnation = item.get("incarnation", "v1")
    source_version_key = item.get("source_version_key")
    display_name = item.get("display_name")
    version_label = item.get("version_label")
    media_type = item.get("media_type", "text/markdown")
    digest_hex = item.get("content_sha256")
    if (
        not isinstance(object_key, str)
        or not isinstance(incarnation, str)
        or not isinstance(source_version_key, str)
        or not isinstance(display_name, str)
        or not isinstance(version_label, str)
        or not isinstance(media_type, str)
        or not isinstance(digest_hex, str)
        or len(digest_hex) != 64
    ):
        raise ValueError("Malformed connector upsert item fields.")
    expected_digest = bytes.fromhex(digest_hex)

    if "content_base64" in item and item["content_base64"] is not None:
        raw_b64 = item["content_base64"]
        if not isinstance(raw_b64, str):
            raise ValueError("content_base64 must be a string.")
        payload = b64decode(raw_b64.encode("ascii"), validate=True)
    elif "download_ref" in item and item["download_ref"] is not None:
        download_ref = item["download_ref"]
        fetcher = getattr(connector, "fetch_document_bytes", None)
        if not callable(fetcher) or not isinstance(download_ref, str):
            raise ConnectorPortUnavailable("Connector does not support fetch_document_bytes for download_ref.")
        payload = fetcher(source_ref, download_ref, expected_digest)
    else:
        raise ValueError("Connector upsert item requires content_base64 or download_ref.")

    if sha256(payload).digest() != expected_digest:
        raise OriginalIntegrityError("Connector document payload failed SHA-256 verification.")

    version = registry.SourceVersion(
        space_id=space_id,
        source_ref=source_ref,
        contract_revision=contract_revision,
        object_key=object_key,
        incarnation=incarnation,
        display_name=display_name,
        source_version_key=source_version_key,
        version_label=version_label,
        digest=expected_digest,
        media_type=media_type,
    )
    return sync.PageOriginal(version=version, payload=payload)


def sync_source_from_connector(
    connection: Connection,
    source_ref: UUID,
    connector: SourceConnectorPort,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
    *,
    revocation_authority: SourceRevocationAuthority | None = None,
    reconcile: bool = False,
    max_pages: int = DEFAULT_MAX_PAGES,
    business_day: date | None = None,
    audit_dispatcher: SecurityAuditDispatcher | None = None,
) -> ConnectorSyncReport:
    """Pull incremental deltas, restriction receipts, permission checkpoints, and optional reconciliation."""
    if not connection.autocommit or connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Connector sync requires an idle autocommit connection.")
    if type(max_pages) is not int or not 1 <= max_pages <= 500:
        raise ValueError("max_pages must be between 1 and 500.")

    binding = _resolve_source_binding(connection, source_ref)
    if binding is None:
        return ConnectorSyncReport(source_ref, "source_not_admitted", error="Source or active collector not found.")
    org_id, space_id, source_id, contract_revision, collector_id, config_revision, space_ref, contract_admission = binding
    try:
        connector_admission = registry.port_admission_to_contract(getattr(connector, "admission", None))
        resolved_store_admission = registry.store_admission(store)
    except ValueError as exc:
        return ConnectorSyncReport(source_ref, "source_not_admitted", error=str(exc))
    if connector_admission != contract_admission or resolved_store_admission != contract_admission:
        return ConnectorSyncReport(
            source_ref,
            "source_not_admitted",
            error="Connector or original store admission mode does not match source contract admission.",
        )
    day = business_day or datetime.now(UTC).date()
    sync_source = sync.SyncSource(space_id, source_ref, contract_revision)
    scope_prefix = f"{source_ref}:{contract_revision}"

    # 1. Read current content sync cursor
    read_ctx, read_started = _open_internal_write(
        connection, org_id, space_id, collector_id, config_revision, sync.READ, business_day=day
    )
    try:
        current_position, saved_cursor = sync.read_content_checkpoint(connection, read_ctx, sync_source)
        finish_request(connection, org_id, read_ctx.request_id, "succeeded", int((monotonic() - read_started) * 1000))
    except (Error, ValueError, registry.SourceNotAdmitted) as exc:
        finish_request(connection, org_id, read_ctx.request_id, "rejected", int((monotonic() - read_started) * 1000))
        return ConnectorSyncReport(source_ref, "rejected", error=str(exc))

    pages_committed = 0
    versions_registered: list[UUID] = []
    restrictions_ack: list[UUID] = []
    cursor_str = saved_cursor or (str(current_position) if current_position is not None else None)
    pending_pages = False

    # 2. Pull bounded incremental delta pages
    for _ in range(max_pages):
        try:
            delta_page = connector.fetch_delta_page(source_ref, cursor_str)
            if delta_page.previous_cursor != cursor_str or not sync.is_connector_cursor(delta_page.through_cursor):
                raise ConnectorPortUnavailable("Source connector returned an invalid cursor.")
            through_uuid = _opaque_uuid(delta_page.through_cursor, _CURSOR_NAMESPACE, scope_prefix)
            if through_uuid == current_position and (delta_page.items or delta_page.has_more):
                raise ConnectorPortUnavailable("Source connector returned changes without advancing its cursor.")
        except ConnectorPortUnavailable as exc:
            return ConnectorSyncReport(
                source_ref,
                "dependency_unavailable",
                pages_committed=pages_committed,
                versions_registered=tuple(versions_registered),
                restrictions_acknowledged=tuple(restrictions_ack),
                content_position=current_position,
                error=str(exc),
            )

        if through_uuid == current_position and not delta_page.items and not delta_page.has_more:
            pending_pages = False
            break

        originals: list[sync.PageOriginal] = []
        removals: list[source_restrictions.Removal] = []
        revocations: list[UUID] = []
        try:
            for item in delta_page.items:
                action = item.get("action", "upsert")
                if action == "upsert":
                    originals.append(
                        _decode_upsert_item(
                            item,
                            space_id=space_id,
                            source_ref=source_ref,
                            contract_revision=contract_revision,
                            connector=connector,
                        )
                    )
                elif action in ("withdrawn", "deleted"):
                    removals.append(
                        source_restrictions.Removal(
                            event_ref=UUID(str(item["event_ref"])),
                            object_key=str(item["object_key"]),
                            incarnation=str(item.get("incarnation", "v1")),
                            version_key=str(item["version_key"]),
                            kind=action,
                            decision_ref=UUID(str(item["decision_ref"])),
                        )
                    )
                elif action == "permission_revoked":
                    if revocation_authority is None:
                        raise ConnectorPortUnavailable("Source connector revocation requires an authority receipt.")
                    revocations.append(UUID(str(item["decision_ref"])))
                else:
                    raise ValueError(f"Unsupported connector delta action: {action}")
        except (ConnectorPortUnavailable, OriginalIntegrityError, ValueError, KeyError) as exc:
            status = "dependency_unavailable" if isinstance(exc, ConnectorPortUnavailable) else "rejected"
            return ConnectorSyncReport(
                source_ref,
                status,
                pages_committed=pages_committed,
                versions_registered=tuple(versions_registered),
                restrictions_acknowledged=tuple(restrictions_ack),
                content_position=current_position,
                error=str(exc),
            )

        # Acknowledge any explicit removal / revocation items on this page
        for removal in removals:
            rem_ctx, rem_started = _open_internal_write(
                connection,
                org_id,
                space_id,
                collector_id,
                config_revision,
                source_restrictions.COMMIT,
                business_day=day,
                idempotency_key=f"restrict:{source_ref}:{removal.event_ref}",
            )
            try:
                rec = source_restrictions.acknowledge_removal(connection, rem_ctx, sync_source, removal)
                finish_request(
                    connection, org_id, rem_ctx.request_id, "succeeded", int((monotonic() - rem_started) * 1000)
                )
                restrictions_ack.append(rec.event_ref)
                if audit_dispatcher is not None:
                    audit_dispatcher.emit(
                        SecurityAuditEvent(
                            event_type=f"security.source_{removal.kind}_acknowledged",
                            request_id=rem_ctx.request_id,
                            org_id=org_id,
                            space_ref=space_ref,
                            actor_principal_id=collector_id,
                            operation=source_restrictions.COMMIT,
                            outcome="succeeded",
                            resource_ref=str(rec.target_ref),
                            detail_digest=metadata_digest(source_ref, removal.event_ref, removal.kind),
                        )
                    )
            except (source_restrictions.RestrictionConflict, IdempotencyConflict, ValueError, Error) as exc:
                finish_request(
                    connection, org_id, rem_ctx.request_id, "rejected", int((monotonic() - rem_started) * 1000)
                )
                return ConnectorSyncReport(
                    source_ref,
                    "rejected",
                    pages_committed=pages_committed,
                    versions_registered=tuple(versions_registered),
                    restrictions_acknowledged=tuple(restrictions_ack),
                    content_position=current_position,
                    error=str(exc),
                )

        if revocations and revocation_authority is not None:
            for decision_ref in revocations:
                rev_ctx, rev_started = _open_internal_write(
                    connection,
                    org_id,
                    space_id,
                    collector_id,
                    config_revision,
                    source_restrictions.COMMIT,
                    business_day=day,
                    idempotency_key=f"revoke:{source_ref}:{decision_ref}",
                )
                try:
                    rec = source_restrictions.acknowledge_revocation(
                        connection, rev_ctx, sync_source, decision_ref, revocation_authority
                    )
                    finish_request(
                        connection, org_id, rev_ctx.request_id, "succeeded", int((monotonic() - rev_started) * 1000)
                    )
                    restrictions_ack.append(rec.event_ref)
                except (source_restrictions.RestrictionConflict, IdempotencyConflict, ValueError, Error) as exc:
                    finish_request(
                        connection, org_id, rev_ctx.request_id, "rejected", int((monotonic() - rev_started) * 1000)
                    )
                    return ConnectorSyncReport(
                        source_ref,
                        "rejected",
                        pages_committed=pages_committed,
                        versions_registered=tuple(versions_registered),
                        restrictions_acknowledged=tuple(restrictions_ack),
                        content_position=current_position,
                        error=str(exc),
                    )

        commit_ctx, commit_started = _open_internal_write(
            connection, org_id, space_id, collector_id, config_revision, sync.COMMIT,
            business_day=day, idempotency_key=f"sync:{source_ref}:{contract_revision}:{through_uuid}",
        )
        try:
            receipt = sync.commit_content_page(
                connection, commit_ctx, sync_source,
                sync.SourcePage(current_position, through_uuid, tuple(originals), delta_page.through_cursor), store,
            )
            finish_request(connection, org_id, commit_ctx.request_id, "succeeded", int((monotonic() - commit_started) * 1000))
            pages_committed += 1
            versions_registered.extend(receipt.version_refs)
            current_position = receipt.through
            cursor_str = delta_page.through_cursor
        except (
            sync.CursorConflict, registry.SourceDeletedConflict, registry.SourceNotAdmitted, IdempotencyConflict,
            OriginalIntegrityError, ValueError, Error,
        ) as exc:
            finish_request(connection, org_id, commit_ctx.request_id, "rejected", int((monotonic() - commit_started) * 1000))
            return ConnectorSyncReport(
                source_ref, "rejected", pages_committed=pages_committed, versions_registered=tuple(versions_registered),
                restrictions_acknowledged=tuple(restrictions_ack), content_position=current_position, error=str(exc),
            )

        pending_pages = delta_page.has_more
        if not pending_pages:
            break

    # 3. Acknowledge any pending revocations from authority & advance permission checkpoint
    perm_checkpoint_ref: UUID | None = None
    perm_generation: int | None = None
    if revocation_authority is not None:
        try:
            snapshot = revocation_authority.snapshot(space_ref)
            with connection.transaction():
                existing_acks = {
                    row[0]
                    for row in connection.execute(
                        """
                        SELECT event_ref FROM thalion.source_restriction_receipt
                        WHERE (org_id, space_id, source_id, kind) = (%s, %s, %s, 'permission_revoked')
                        """,
                        (org_id, space_id, source_id),
                    ).fetchall()
                }
                pending_decisions = []
                for dec in sorted(snapshot.decisions, key=lambda d: d.generation):
                    if dec.decision_ref in existing_acks:
                        continue
                    belongs = connection.execute(
                        "SELECT thalion.source_restriction_version(%s, %s, %s, %s)",
                        (org_id, space_id, source_id, dec.object_ref),
                    ).fetchone()
                    if belongs is not None and belongs[0] is not None:
                        pending_decisions.append(dec.decision_ref)

            for decision_ref in pending_decisions:
                rev_ctx, rev_started = _open_internal_write(
                    connection,
                    org_id,
                    space_id,
                    collector_id,
                    config_revision,
                    source_restrictions.COMMIT,
                    business_day=day,
                    idempotency_key=f"revoke-catchup:{source_ref}:{decision_ref}",
                )
                try:
                    rec = source_restrictions.acknowledge_revocation(
                        connection, rev_ctx, sync_source, decision_ref, revocation_authority
                    )
                    finish_request(
                        connection, org_id, rev_ctx.request_id, "succeeded", int((monotonic() - rev_started) * 1000)
                    )
                    restrictions_ack.append(rec.event_ref)
                except (source_restrictions.RestrictionConflict, IdempotencyConflict, ValueError, Error):
                    finish_request(
                        connection, org_id, rev_ctx.request_id, "rejected", int((monotonic() - rev_started) * 1000)
                    )
                    raise

            cp_read_ctx, cp_read_started = _open_internal_write(
                connection, org_id, space_id, collector_id, config_revision, permission_checkpoints.READ, business_day=day
            )
            current_cp = permission_checkpoints.read_permission_checkpoint(connection, cp_read_ctx, sync_source)
            finish_request(
                connection, org_id, cp_read_ctx.request_id, "succeeded", int((monotonic() - cp_read_started) * 1000)
            )
            if current_cp is None or snapshot.generation > current_cp.authority_generation:
                new_cp_ref = uuid4()
                cp_ctx, cp_started = _open_internal_write(
                    connection,
                    org_id,
                    space_id,
                    collector_id,
                    config_revision,
                    permission_checkpoints.COMMIT,
                    business_day=day,
                    idempotency_key=f"perm-cp:{source_ref}:{snapshot.authority_ref}:{snapshot.generation}",
                )
                try:
                    cp_receipt = permission_checkpoints.record_permission_checkpoint(
                        connection,
                        cp_ctx,
                        sync_source,
                        new_cp_ref,
                        current_cp.checkpoint_ref if current_cp is not None else None,
                        revocation_authority,
                    )
                    finish_request(
                        connection, org_id, cp_ctx.request_id, "succeeded", int((monotonic() - cp_started) * 1000)
                    )
                    perm_checkpoint_ref = cp_receipt.checkpoint_ref
                    perm_generation = cp_receipt.authority_generation
                except (
                    permission_checkpoints.PermissionCheckpointConflict,
                    IdempotencyConflict,
                    ValueError,
                    Error,
                ):
                    finish_request(
                        connection, org_id, cp_ctx.request_id, "rejected", int((monotonic() - cp_started) * 1000)
                    )
                    raise
            else:
                perm_checkpoint_ref = current_cp.checkpoint_ref
                perm_generation = current_cp.authority_generation
        except Exception as exc:
            return ConnectorSyncReport(
                source_ref,
                "dependency_unavailable",
                pages_committed=pages_committed,
                versions_registered=tuple(versions_registered),
                restrictions_acknowledged=tuple(restrictions_ack),
                content_position=current_position,
                error=f"permission_checkpoint_error: {exc}",
            )

    # 4. Optional full inventory reconciliation
    rec_status = "skipped"
    rec_snapshot_ref: UUID | None = None
    rec_matched = 0
    rec_diffs = 0
    if reconcile and not pending_pages:
        try:
            inventory = connector.fetch_full_inventory(source_ref)
        except ConnectorPortUnavailable as exc:
            return ConnectorSyncReport(
                source_ref,
                "dependency_unavailable",
                pages_committed=pages_committed,
                versions_registered=tuple(versions_registered),
                restrictions_acknowledged=tuple(restrictions_ack),
                content_position=current_position,
                permission_checkpoint_ref=perm_checkpoint_ref,
                permission_generation=perm_generation,
                reconciliation_status="dependency_unavailable",
                error=str(exc),
            )
        if not inventory.complete:
            return ConnectorSyncReport(
                source_ref,
                "rejected",
                pages_committed=pages_committed,
                versions_registered=tuple(versions_registered),
                restrictions_acknowledged=tuple(restrictions_ack),
                content_position=current_position,
                permission_checkpoint_ref=perm_checkpoint_ref,
                permission_generation=perm_generation,
                reconciliation_status="incomplete_inventory",
                error="Source connector returned an incomplete inventory snapshot.",
            )
        try:
            entries = tuple(
                reconciliation.InventoryEntry(
                    object_key=str(entry["object_key"]),
                    incarnation=str(entry.get("incarnation", "v1")),
                    source_version_key=str(entry["source_version_key"]),
                    digest=bytes.fromhex(str(entry["content_sha256"])),
                )
                for entry in inventory.entries
            )
            if {entry.object_key for entry in entries} != inventory.stable_object_keys:
                raise ValueError("Inventory entries do not exactly match stable_object_keys.")
            snapshot_uuid = _opaque_uuid(inventory.snapshot_ref, _SNAPSHOT_NAMESPACE, scope_prefix)
            inv_read_ctx, inv_read_started = _open_internal_write(
                connection, org_id, space_id, collector_id, config_revision, reconciliation.READ, business_day=day
            )
            prev_snapshot = reconciliation.read_inventory_position(connection, inv_read_ctx, sync_source)
            finish_request(
                connection, org_id, inv_read_ctx.request_id, "succeeded", int((monotonic() - inv_read_started) * 1000)
            )
            if prev_snapshot == snapshot_uuid:
                rec_status = "up_to_date"
                rec_snapshot_ref = prev_snapshot
            else:
                manifest = reconciliation.InventoryManifest(
                    snapshot_ref=snapshot_uuid,
                    previous=prev_snapshot,
                    content_position=current_position,
                    expected_count=len(entries),
                    expected_digest=reconciliation.inventory_digest(entries),
                )
                inv_ctx, inv_started = _open_internal_write(
                    connection,
                    org_id,
                    space_id,
                    collector_id,
                    config_revision,
                    reconciliation.COMMIT,
                    business_day=day,
                    idempotency_key=f"reconcile:{source_ref}:{contract_revision}:{snapshot_uuid}",
                )
                try:
                    inv_receipt = reconciliation.reconcile_inventory(
                        connection, inv_ctx, sync_source, manifest, entries
                    )
                    finish_request(
                        connection, org_id, inv_ctx.request_id, "succeeded", int((monotonic() - inv_started) * 1000)
                    )
                    rec_status = "reconciled"
                    rec_snapshot_ref = inv_receipt.snapshot_ref
                    rec_matched = inv_receipt.matched_count
                    rec_diffs = len(inv_receipt.differences)
                except (reconciliation.InventoryConflict, IdempotencyConflict, ValueError, Error) as exc:
                    finish_request(
                        connection, org_id, inv_ctx.request_id, "rejected", int((monotonic() - inv_started) * 1000)
                    )
                    return ConnectorSyncReport(
                        source_ref,
                        "rejected",
                        pages_committed=pages_committed,
                        versions_registered=tuple(versions_registered),
                        restrictions_acknowledged=tuple(restrictions_ack),
                        content_position=current_position,
                        permission_checkpoint_ref=perm_checkpoint_ref,
                        permission_generation=perm_generation,
                        reconciliation_status="rejected",
                        error=str(exc),
                    )
        except (ValueError, KeyError) as exc:
            return ConnectorSyncReport(
                source_ref,
                "rejected",
                pages_committed=pages_committed,
                versions_registered=tuple(versions_registered),
                restrictions_acknowledged=tuple(restrictions_ack),
                content_position=current_position,
                permission_checkpoint_ref=perm_checkpoint_ref,
                permission_generation=perm_generation,
                reconciliation_status="rejected",
                error=str(exc),
            )

    return ConnectorSyncReport(
        source_ref=source_ref,
        status=("pending_pages" if pending_pages else "succeeded"
                if pages_committed > 0 or restrictions_ack or rec_status == "reconciled" else "up_to_date"),
        pages_committed=pages_committed,
        versions_registered=tuple(versions_registered),
        restrictions_acknowledged=tuple(restrictions_ack),
        content_position=current_position,
        permission_checkpoint_ref=perm_checkpoint_ref,
        permission_generation=perm_generation,
        reconciliation_status=rec_status,
        reconciliation_snapshot_ref=rec_snapshot_ref,
        reconciliation_matched=rec_matched,
        reconciliation_differences=rec_diffs,
    )
