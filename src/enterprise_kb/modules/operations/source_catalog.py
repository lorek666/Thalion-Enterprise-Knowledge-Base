from datetime import UTC
from uuid import UUID

from psycopg import Connection

from enterprise_kb.modules.sources.registry import sql_issuer_matches_admission
from enterprise_kb.runtime.commands import execute_command

from .context import OperationsCall, OperationsNotAdmitted, command_for, require_scope


READ_CATALOG = "read_source_catalog"
SYNC_CONNECTOR = "trigger_connector_sync"
DESTINATION = "internal_management"
OPERATIONS = frozenset({READ_CATALOG, SYNC_CONNECTOR})


def read_catalog(
    connection: Connection,
    call: OperationsCall,
    *,
    connector_configured: bool = False,
) -> dict:
    space_owner = require_scope(connection, call, READ_CATALOG, destination=DESTINATION)
    if space_owner != call.principal_id:
        raise OperationsNotAdmitted("Source catalog requires the current space owner.")

    observed_at, = connection.execute("SELECT statement_timestamp()").fetchone()

    space_row = connection.execute(
        """
        SELECT sid.public_id, sp.name, sp.classification, sp.lifecycle,
               cfg.generation, cfg.wiki_delivery_enabled, cfg.lexical_index_mode, cfg.vector_model_id
        FROM thalion.space AS sp
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (sp.org_id, sp.space_id, 'space', sp.space_id)
        LEFT JOIN thalion.current_space_release_config AS cfg
          ON (cfg.org_id, cfg.space_id) = (sp.org_id, sp.space_id)
        WHERE (sp.org_id, sp.space_id) = (%s, %s)
        """,
        (call.org_id, call.space_id),
    ).fetchone()
    if space_row is None:
        raise OperationsNotAdmitted("Active space not found.")

    source_rows = connection.execute(
        f"""
        SELECT src.source_id, sid.public_id, src.source_key, src.lifecycle,
               src.contract_revision, contract.admission,
               (SELECT count(*) FROM thalion.document AS d
                WHERE (d.org_id, d.space_id, d.source_id) = (src.org_id, src.space_id, src.source_id)) AS doc_count,
               (SELECT count(*) FROM thalion.document_version AS v
                WHERE (v.org_id, v.space_id, v.source_id) = (src.org_id, src.space_id, src.source_id)) AS ver_count,
               sync_page.sequence, sync_page.through_cursor, sync_page.item_count, sync_page.committed_at,
               inv.sequence, inv.snapshot_ref, inv.entry_count, inv.matched_count, inv.committed_at,
               perm.authority_generation, perm.committed_at
        FROM thalion.source AS src
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (src.org_id, src.space_id, 'source', src.source_id)
        JOIN thalion.principal AS actor
          ON (actor.org_id, actor.principal_id) = (src.org_id, %s)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (src.org_id, src.space_id, src.source_id, src.contract_revision)
        LEFT JOIN LATERAL (
            SELECT sequence, through_cursor, item_count, committed_at
            FROM thalion.source_sync_page
            WHERE (org_id, space_id, source_id, contract_revision)
                = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            ORDER BY sequence DESC LIMIT 1
        ) AS sync_page ON TRUE
        LEFT JOIN LATERAL (
            SELECT sequence, snapshot_ref, entry_count, matched_count, committed_at
            FROM thalion.source_inventory_receipt
            WHERE (org_id, space_id, source_id, contract_revision)
                = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            ORDER BY sequence DESC LIMIT 1
        ) AS inv ON TRUE
        LEFT JOIN LATERAL (
            SELECT authority_generation, committed_at
            FROM thalion.source_permission_checkpoint
            WHERE (org_id, space_id, source_id) = (src.org_id, src.space_id, src.source_id)
            ORDER BY sequence DESC LIMIT 1
        ) AS perm ON TRUE
        WHERE (src.org_id, src.space_id) = (%s, %s)
          AND {sql_issuer_matches_admission("actor.authority_issuer", "contract.admission")}
        ORDER BY src.source_id ASC
        """,
        (call.principal_id, call.org_id, call.space_id),
    ).fetchall()

    sources = []
    for row in source_rows:
        sources.append({
            "source_id": str(row[1]),
            "source_key": row[2],
            "lifecycle": row[3],
            "contract_revision": row[4],
            "admission": row[5],
            "document_count": row[6],
            "version_count": row[7],
            "content_sync": None if row[8] is None else {
                "sequence": row[8],
                "through_cursor": str(row[9]),
                "item_count": row[10],
                "committed_at": row[11].astimezone(UTC).isoformat(),
            },
            "inventory_reconciliation": None if row[12] is None else {
                "sequence": row[12],
                "snapshot_ref": str(row[13]),
                "entry_count": row[14],
                "matched_count": row[15],
                "committed_at": row[16].astimezone(UTC).isoformat(),
            },
            "permission_checkpoint": None if row[17] is None else {
                "authority_generation": row[17],
                "committed_at": row[18].astimezone(UTC).isoformat(),
            },
        })

    doc_rows = connection.execute(
        f"""
        SELECT did.public_id, sid.public_id, doc.source_object_key, doc.incarnation, doc.display_name,
               lv.version_ref, lv.version_label, lv.media_type, lv.registered_at,
               dept.department_code, dept.department_name, dept.recorded_at
        FROM thalion.document AS doc
        JOIN thalion.object_identity AS did
          ON (did.org_id, did.space_id, did.object_type, did.object_id)
           = (doc.org_id, doc.space_id, 'document', doc.document_id)
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (doc.org_id, doc.space_id, 'source', doc.source_id)
        JOIN thalion.source AS src
          ON (src.org_id, src.space_id, src.source_id)
           = (doc.org_id, doc.space_id, doc.source_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (src.org_id, src.space_id, src.source_id, src.contract_revision)
        JOIN thalion.principal AS actor
          ON (actor.org_id, actor.principal_id) = (doc.org_id, %s)
        LEFT JOIN LATERAL (
            SELECT vid.public_id AS version_ref, ver.version_label, asset.media_type, ver.registered_at
            FROM thalion.document_version AS ver
            JOIN thalion.object_identity AS vid
              ON (vid.org_id, vid.space_id, vid.object_type, vid.object_id)
               = (ver.org_id, ver.space_id, 'document_version', ver.version_id)
            JOIN thalion.asset AS asset
              ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
               = (ver.org_id, ver.space_id, ver.source_id, ver.document_id, ver.asset_id)
            WHERE (ver.org_id, ver.space_id, ver.source_id, ver.document_id)
                = (doc.org_id, doc.space_id, doc.source_id, doc.document_id)
            ORDER BY ver.registration_sequence DESC LIMIT 1
        ) AS lv ON TRUE
        LEFT JOIN thalion.document_department AS dept
          ON (dept.org_id, dept.space_id, dept.source_id, dept.document_id)
           = (doc.org_id, doc.space_id, doc.source_id, doc.document_id)
        WHERE (doc.org_id, doc.space_id) = (%s, %s)
          AND {sql_issuer_matches_admission("actor.authority_issuer", "contract.admission")}
        ORDER BY doc.document_id DESC
        LIMIT 200
        """,
        (call.principal_id, call.org_id, call.space_id),
    ).fetchall()

    documents = []
    for row in doc_rows:
        documents.append({
            "document_id": str(row[0]),
            "source_id": str(row[1]),
            "source_object_key": row[2],
            "incarnation": row[3],
            "display_name": row[4],
            "latest_version_id": str(row[5]) if row[5] is not None else None,
            "latest_version_label": row[6],
            "latest_media_type": row[7],
            "registered_at": row[8].astimezone(UTC).isoformat() if row[8] is not None else None,
            "department_code": row[9],
            "department_name": row[10],
            "department_recorded_at": row[11].astimezone(UTC).isoformat() if row[11] is not None else None,
        })

    return {
        "observed_at": observed_at.astimezone(UTC).isoformat(),
        "connector_configured": connector_configured,
        "space": {
            "space_id": str(space_row[0]),
            "name": space_row[1],
            "classification": space_row[2],
            "lifecycle": space_row[3],
            "release": {
                "generation": space_row[4] or 0,
                "wiki_delivery_enabled": True if space_row[5] is None else bool(space_row[5]),
                "lexical_index_mode": space_row[6] or "indexed",
                "vector_model_id": space_row[7],
            },
        },
        "sources": sources,
        "documents": documents,
    }


def authorize_connector_sync(
    connection: Connection,
    call: OperationsCall,
    source_ref: UUID,
    *,
    reconcile: bool,
    max_pages: int,
) -> UUID:
    command = command_for(call, SYNC_CONNECTOR, (str(source_ref), reconcile, max_pages))

    def apply(transaction):
        space_owner = require_scope(transaction, call, SYNC_CONNECTOR, destination=DESTINATION)
        if space_owner != call.principal_id:
            raise OperationsNotAdmitted("Connector sync requires the current space owner.")
        source = transaction.execute(
            f"""
            SELECT src.source_id, src.lifecycle
            FROM thalion.object_identity AS identity
            JOIN thalion.source AS src
              ON (src.org_id, src.space_id, src.identity_type, src.source_id)
               = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
               = (src.org_id, src.space_id, src.source_id, src.contract_revision)
            JOIN thalion.principal AS actor
              ON (actor.org_id, actor.principal_id) = (src.org_id, %s)
            WHERE (identity.org_id, identity.space_id, identity.public_id) = (%s, %s, %s)
              AND src.owner_principal_id = %s
              AND {sql_issuer_matches_admission("actor.authority_issuer", "contract.admission")}
            FOR SHARE OF src
            """,
            (call.principal_id, call.org_id, call.space_id, source_ref, call.principal_id),
        ).fetchone()
        if source is None:
            raise OperationsNotAdmitted("Connector sync requires an active source owned by the caller.")
        if source[1] != "active":
            raise OperationsNotAdmitted("Connector sync requires an active source.")
        return source_ref

    return execute_command(connection, command, apply).result_ref
