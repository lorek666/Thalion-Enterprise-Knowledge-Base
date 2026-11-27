from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
from uuid import UUID
from zipfile import ZipFile, ZipInfo

from psycopg.rows import dict_row

from enterprise_kb.modules.access.delivery import (
    AuthorizationUnavailable, DeliveryCandidate, DeliveryContext, EvidenceScope, LocalAuthorization, SafetyEpochs, authorize_delivery,
)
from enterprise_kb.modules.access.rules import PermissionBinding, require_aware
from enterprise_kb.modules.evidence.docx_evidence import MEDIA_TYPE as DOCX_MEDIA_TYPE
from enterprise_kb.modules.evidence.pdf_evidence import MEDIA_TYPE as PDF_MEDIA_TYPE
from enterprise_kb.modules.lifecycle.disposition import DESTINATION, DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.lifecycle.docx_transcripts import (
    DOCX_REPAIR_TRANSCRIPT_FORMAT, DOCX_TRANSCRIPT_FORMAT, archive_docx_transcription, docx_repair_history, docx_transcript_scopes,
)
from enterprise_kb.modules.lifecycle.pdf_transcripts import (
    PDF_REPAIR_TRANSCRIPT_FORMAT, PDF_TRANSCRIPT_FORMAT, archive_pdf_transcription, pdf_repair_history,
)
from enterprise_kb.modules.lifecycle.rebuild_format import (
    DOCX_REBUILD_FORMAT, DOCX_REPAIR_REBUILD_FORMAT, PDF_REBUILD_FORMAT, PDF_REPAIR_REBUILD_FORMAT,
    REBUILD_FIELD, REBUILD_FORMAT, REBUILD_SCOPE, REPAIR_REBUILD_FORMAT, rebuild_metadata,
)
from enterprise_kb.modules.lifecycle.transcripts import (
    TRANSCRIPT_SCOPE, archive_transcription, current_transcript, repair_history, transcript_scopes,
)
from enterprise_kb.modules.lifecycle.wiki_archives import WIKI_SCOPE, archive_wiki, require_current_wiki, select_wiki
from enterprise_kb.modules.lifecycle.wiki_rebuild import (
    WIKI_REBUILD_FORMAT, WIKI_REBUILD_SCOPE, canonical_json, wiki_rebuild_material,
)
from enterprise_kb.modules.operations.context import OperationsNotAdmitted, command_for, require_scope
from enterprise_kb.modules.sources.originals import OriginalAsset, OriginalIntegrityError
from enterprise_kb.modules.sources.registry import sql_admitted_issuer, sql_issuers_same_mode
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event


REQUEST = "request_original_export"
APPROVE = "approve_original_export"
EXPORT = "export_original_archive"
PURPOSE = "original_archive"
ARCHIVE_DESTINATION = "private_synthetic_archive"
FIELDS = frozenset({"original_bytes", "version_manifest"})
SCOPE = "original_only"
FORMAT = "thalion.synthetic-original-archive.v1"
TRANSCRIPT_FORMAT = "thalion.synthetic-transcript-archive.v1"
REPAIR_TRANSCRIPT_FORMAT = "thalion.synthetic-transcript-archive.v2"
WIKI_FORMAT = "thalion.synthetic-wiki-archive.v1"
MAX_ARCHIVE_BYTES = 16781312
ORIGINAL_MEMBERS = {"text/markdown": "original.md", PDF_MEDIA_TYPE: "original.pdf", DOCX_MEDIA_TYPE: "original.docx"}


def _one(connection, query, params):
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(query, params).fetchone()


def _target(connection, call, export_id):
    data = _one(connection, """
        SELECT request.version_id AS requested_version, request.requester_id, request.snapshot AS requested_snapshot,
               request.export_ref, request.transcript_run_ref, request.wiki_publication_ref,
               request.rebuild_metadata_digest, request.wiki_rebuild_digest, request.repair_history_digest, target.*
        FROM thalion.synthetic_export_request AS request
        LEFT JOIN thalion.synthetic_original_export_target AS target
          USING (org_id, space_id, version_id)
        WHERE (request.org_id, request.space_id, request.export_ref) = (%s, %s, %s)
        """, (call.org_id, call.space_id, export_id))
    if data is None:
        raise OperationsNotAdmitted("The archive request is not in the caller's space.")
    return data


def _require_owner(target, actor):
    if target["owner_id"] != actor or target["space_owner_id"] != actor:
        raise OperationsNotAdmitted("Current source and space ownership are required.")


def _require_current(target):
    if target["snapshot"] is None or target["blocked"] or target["snapshot"] != target["requested_snapshot"]:
        raise DispositionConflict("The selected version or its archive scope has changed.")


def _lock_version(connection, call, version):
    connection.execute("SELECT thalion.lock_synthetic_export_target(%s, %s, %s)", (call.org_id, call.space_id, version))


def _metadata_digest(metadata):
    return sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).digest()


def _load_repair_history(connection, org_id, space_id, target, run_ref, *, payload=None):
    if target["media_type"] == PDF_MEDIA_TYPE:
        return pdf_repair_history(connection, org_id, space_id, target, run_ref)
    if target["media_type"] == DOCX_MEDIA_TYPE:
        return docx_repair_history(connection, org_id, space_id, target, run_ref)
    return repair_history(connection, org_id, space_id, target, run_ref, payload=payload)


def _verify_repair_history(connection, org_id, space_id, target, *, payload=None):
    expected = target.get("repair_history_digest")
    if expected is None:
        return None, ()
    material, scopes = _load_repair_history(connection, org_id, space_id, target, target["transcript_run_ref"], payload=payload)
    if material is None or sha256(material).digest() != expected:
        raise DispositionConflict("The repair history changed after enrollment.")
    return material, scopes


def _check_transcript(connection, call, target):
    if target["transcript_run_ref"] is None:
        return None
    transcript = current_transcript(connection, call.org_id, call.space_id, target["version_id"], target["transcript_run_ref"])
    _verify_repair_history(connection, call.org_id, call.space_id, target)
    if target["rebuild_metadata_digest"] is None:
        return None
    metadata = rebuild_metadata(
        connection, call.org_id, call.space_id, target["version_id"], transcript[1],
        repaired=target["repair_history_digest"] is not None, media_type=target["media_type"],
    )
    if _metadata_digest(metadata) != target["rebuild_metadata_digest"]:
        raise DispositionConflict("Archive rebuild metadata differs from the enrolled scope.")
    return metadata


def _check_wiki(connection, call, target, *, lock=False):
    publication = target["wiki_publication_ref"]
    if publication is None:
        return None
    require_current_wiki(connection, call.org_id, call.space_id, target["version_id"], publication, lock=lock)
    if target["wiki_rebuild_digest"] is None:
        return None
    digest, *material = wiki_rebuild_material(connection, call.org_id, call.space_id, publication)
    if digest != target["wiki_rebuild_digest"]:
        raise DispositionConflict("Wiki rebuild inputs differ from the enrolled scope.")
    return material


def request_export(connection, call, version_ref: UUID, scope: str, wiki_revision: UUID | None = None) -> dict:
    wiki_scopes = (WIKI_SCOPE, WIKI_REBUILD_SCOPE)
    if scope not in (SCOPE, TRANSCRIPT_SCOPE, REBUILD_SCOPE, *wiki_scopes) or (scope in wiki_scopes) != (wiki_revision is not None):
        raise ValueError("Invalid archive scope.")
    require_scope(connection, call, REQUEST, destination=DESTINATION)
    target = _one(connection, """
        SELECT version_id, version_ref, source_id, content_digest, owner_id, space_owner_id, snapshot, blocked, media_type
        FROM thalion.synthetic_original_export_target
        WHERE (org_id, space_id, version_ref) = (%s, %s, %s)
        """, (call.org_id, call.space_id, version_ref))
    if target is None:
        raise OperationsNotAdmitted("The version is not available for archive requests.")
    _require_owner(target, call.principal_id)
    if target["blocked"]:
        raise DispositionConflict("The selected version is blocked.")
    command_args = (str(version_ref), scope)
    if wiki_revision is not None:
        command_args += (str(wiki_revision),)
    command = command_for(call, REQUEST, command_args)

    def apply(transaction):
        _lock_version(transaction, call, target["version_id"])
        current = transaction.execute("""
            SELECT 1 FROM thalion.synthetic_original_export_target
            WHERE (org_id, space_id, version_id, snapshot) = (%s, %s, %s, %s::bigint[])
              AND NOT blocked
            """, (call.org_id, call.space_id, target["version_id"], target["snapshot"])).fetchone()
        if current is None:
            raise DispositionConflict("Archive scope changed before enrollment.")
        transcript = current_transcript(
            transaction, call.org_id, call.space_id, target["version_id"],
        ) if scope in (TRANSCRIPT_SCOPE, REBUILD_SCOPE) else None
        history_digest = None
        if transcript is not None:
            history, _ = _load_repair_history(transaction, call.org_id, call.space_id, target, transcript[0])
            history_digest = sha256(history).digest() if history is not None else None
        metadata_digest = None
        if scope == REBUILD_SCOPE:
            metadata_digest = _metadata_digest(
                rebuild_metadata(transaction, call.org_id, call.space_id, target["version_id"], transcript[1],
                                 repaired=history_digest is not None, media_type=target["media_type"]),
            )
        publication = select_wiki(transaction, call.org_id, call.space_id, target["version_id"], wiki_revision) if wiki_revision is not None else None
        wiki_digest = wiki_rebuild_material(transaction, call.org_id, call.space_id, publication)[0] if scope == WIKI_REBUILD_SCOPE else None
        result, = transaction.execute("""
            INSERT INTO thalion.synthetic_export_request (
                org_id, space_id, version_id, requester_id, snapshot, request_id,
                transcript_run_ref, wiki_publication_ref, rebuild_metadata_digest, wiki_rebuild_digest, repair_history_digest
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING export_ref
            """, (call.org_id, call.space_id, target["version_id"], call.principal_id, target["snapshot"],
                  call.request_id, transcript[0] if transcript else None, publication, metadata_digest,
                  wiki_digest, history_digest)).fetchone()
        append_event(transaction, call.org_id, "lifecycle.synthetic_export.requested", version_ref, space_id=call.space_id)
        return result

    result = execute_command(connection, command, apply).result_ref
    return {"export_id": str(result), "state": "requested", "scope": scope}


def approve_export(connection, call, export_id: UUID, expires_at: datetime) -> dict:
    require_scope(connection, call, APPROVE, destination=DESTINATION)
    target = _target(connection, call, export_id)
    requester = target["requester_id"]
    if call.principal_id != target["approver_id"] or call.principal_id in (requester, target["owner_id"], target["space_owner_id"]):
        raise OperationsNotAdmitted("Current independent source approval is required.")
    _lock_version(connection, call, target["requested_version"])
    current = _target(connection, call, export_id)
    _require_current(current)
    _require_owner(current, requester)
    if current["approver_id"] != call.principal_id:
        raise OperationsNotAdmitted("Source approval authority changed.")
    _check_transcript(connection, call, current)
    _check_wiki(connection, call, current, lock=True)
    require_aware(expires_at)
    expires_at = expires_at.astimezone(UTC)
    command = command_for(call, APPROVE, (str(export_id), expires_at.isoformat()))

    def apply(transaction):
        now = datetime.now(UTC)
        if not now < expires_at <= now + timedelta(minutes=15):
            raise ValueError("An archive approval must expire within fifteen minutes.")
        result = transaction.execute("""
            INSERT INTO thalion.synthetic_export_approval (org_id, space_id, export_ref, requester_id, approver_id, request_id, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (export_ref) DO NOTHING RETURNING approval_ref
            """, (call.org_id, call.space_id, export_id, requester, call.principal_id, call.request_id, expires_at)).fetchone()
        if result is None:
            raise DispositionConflict("An approval already exists for this request.")
        append_event(transaction, call.org_id, "lifecycle.synthetic_export.approved", target["version_ref"], space_id=call.space_id)
        return result[0]

    result = execute_command(connection, command, apply).result_ref
    return {"export_id": str(export_id), "approval_id": str(result), "state": "approved", "expires_at": expires_at.isoformat()}


def _approval(connection, call, export_id, approver, *, lock=False):
    suffix = "FOR SHARE OF actor" if lock else ""
    return _one(connection, f"""
        SELECT approval.approval_ref, approval.expires_at FROM thalion.synthetic_export_approval AS approval
        JOIN thalion.principal AS actor ON (actor.org_id, actor.principal_id) = (approval.org_id, approval.approver_id)
        JOIN thalion.principal AS caller ON (caller.org_id, caller.principal_id) = (approval.org_id, %s)
        WHERE (approval.org_id, approval.space_id, approval.export_ref, approval.approver_id) = (%s, %s, %s, %s)
          AND NOT actor.disabled AND actor.principal_type = 'employee'
          AND {sql_admitted_issuer('actor.authority_issuer')}
          AND {sql_issuers_same_mode('actor.authority_issuer', 'caller.authority_issuer')}
        {suffix}
        """, (call.principal_id, call.org_id, call.space_id, export_id, approver))


def archive_files(connection, org_id, space_id, target, payload, metadata=None):
    pdf = target["media_type"] == PDF_MEDIA_TYPE
    docx = target["media_type"] == DOCX_MEDIA_TYPE
    if target["transcript_run_ref"] is not None:
        if pdf:
            members, scopes = archive_pdf_transcription(connection, org_id, space_id, target)
        elif docx:
            members, scopes = archive_docx_transcription(connection, org_id, space_id, target, payload)
        else:
            members, scopes = archive_transcription(connection, org_id, space_id, target, payload)
        scope = REBUILD_SCOPE if metadata is not None else TRANSCRIPT_SCOPE
    elif target["wiki_publication_ref"] is not None:
        members, scopes = archive_wiki(connection, org_id, space_id, target)
        scope = WIKI_SCOPE
    else:
        members, scopes, scope = {}, (), SCOPE
    transcript_format = PDF_TRANSCRIPT_FORMAT if pdf else DOCX_TRANSCRIPT_FORMAT if docx else TRANSCRIPT_FORMAT
    manifest = {
        "format": {SCOPE: FORMAT, TRANSCRIPT_SCOPE: transcript_format, WIKI_SCOPE: WIKI_FORMAT,
                   REBUILD_SCOPE: PDF_REBUILD_FORMAT if pdf else DOCX_REBUILD_FORMAT if docx else REBUILD_FORMAT}[scope], "scope": scope,
        "restorable": False, "version_id": str(target["version_ref"]),
        "original_sha256": target["content_digest"].hex(), "byte_length": target["byte_length"],
        "format_media_type": target["media_type"], "safety_snapshot": target["snapshot"],
    }
    if scope in (TRANSCRIPT_SCOPE, REBUILD_SCOPE):
        manifest["transcription_sha256"] = sha256(members["transcription.json"]).hexdigest()
    if scope in (TRANSCRIPT_SCOPE, REBUILD_SCOPE) and target.get("repair_history_digest") is not None:
        history, history_scopes = _verify_repair_history(connection, org_id, space_id, target, payload=payload)
        if scope == REBUILD_SCOPE:
            repair_format = PDF_REPAIR_REBUILD_FORMAT if pdf else DOCX_REPAIR_REBUILD_FORMAT if docx else REPAIR_REBUILD_FORMAT
        else:
            repair_format = PDF_REPAIR_TRANSCRIPT_FORMAT if pdf else DOCX_REPAIR_TRANSCRIPT_FORMAT if docx else REPAIR_TRANSCRIPT_FORMAT
        manifest.update(format=repair_format, repair_history_sha256=target["repair_history_digest"].hex())
        members["repair-history.json"] = history
        scopes = (*scopes, *history_scopes)
    if scope == REBUILD_SCOPE:
        manifest.update(org_id=org_id, space_id=space_id, export_id=str(target["export_ref"]), rebuild=metadata)
        scopes = (*scopes, EvidenceScope(space_id, target["source_id"], target["version_ref"], frozenset({REBUILD_FIELD})))
    if scope == WIKI_SCOPE:
        manifest["wiki_dependencies_sha256"] = sha256(members["wiki/dependencies.json"]).hexdigest()
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return {"manifest.json": manifest_bytes, ORIGINAL_MEMBERS[target["media_type"]]: payload, **members}, scopes, scope


def _archive(files):
    result = BytesIO()
    with ZipFile(result, "w") as archive:
        for name, content in files.items():
            archive.writestr(ZipInfo(name), content)
    return result.getvalue()


def _wiki_rebuild_files(connection, call, target, store, material):
    org_id, space_id = call.org_id, call.space_id
    topic_key, graph, versions = material
    files, wiki_scopes = archive_wiki(connection, org_id, space_id, target)
    scopes = list(wiki_scopes)
    graph_bytes = canonical_json({"manifests": graph})
    files["wiki/manifests.json"] = graph_bytes
    entries = []
    total = sum(map(len, files.values()))
    for version in versions:
        original = store.read(OriginalAsset(version["storage_key"], version["content_digest"], version["byte_length"]))
        nested = version | {"export_ref": target["export_ref"]}
        members, part_scopes, _ = archive_files(connection, org_id, space_id, nested, original, version["metadata"])
        packed = _archive(members)
        total += len(packed)
        if total >= MAX_ARCHIVE_BYTES:
            raise DispositionConflict("The complete Wiki rebuild archive exceeds the configured size limit.")
        ref = version["version_ref"]
        files[f"versions/{ref}.zip"] = packed
        entries.append({"version_id": str(ref), "sha256": sha256(packed).hexdigest()})
        scopes.append(EvidenceScope(space_id, version["source_id"], ref, FIELDS))
        scopes.extend(part_scopes)
    files["manifest.json"] = canonical_json({
        "format": WIKI_REBUILD_FORMAT, "scope": WIKI_REBUILD_SCOPE, "restorable": False,
        "org_id": org_id, "space_id": space_id, "export_id": str(target["export_ref"]),
        "version_id": str(target["version_ref"]), "topic_key": topic_key,
        "manifest_graph_sha256": sha256(graph_bytes).hexdigest(),
        "wiki_dependencies_sha256": sha256(files["wiki/dependencies.json"]).hexdigest(),
        "versions": entries,
    })
    return files, scopes, WIKI_REBUILD_SCOPE


def seal_export(connection, call, export_id: UUID, store, context: DeliveryContext, check_authority) -> dict:
    require_scope(connection, call, EXPORT, destination=DESTINATION)
    target = _target(connection, call, export_id)
    if target["requester_id"] != call.principal_id:
        raise OperationsNotAdmitted("Only the requesting principal can seal this archive.")
    _require_current(target)
    _require_owner(target, call.principal_id)
    approval = _approval(connection, call, export_id, target["approver_id"])
    approval_seen_at = datetime.now(UTC)
    if approval is None or approval["expires_at"] <= approval_seen_at:
        raise DispositionConflict("A live independent approval is required before sealing the archive.")
    scope = EvidenceScope(call.space_id, target["source_id"], target["version_ref"], FIELDS)
    epochs = SafetyEpochs(*target["snapshot"][:3])

    def check(payload, scopes, *, lock):
        def load_local(_check):
            if lock:
                _lock_version(connection, call, target["version_id"])
            current = _target(connection, call, export_id)
            _require_current(current)
            _require_owner(current, call.principal_id)
            _check_transcript(connection, call, current)
            _check_wiki(connection, call, current, lock=lock)
            live = _approval(connection, call, export_id, current["approver_id"], lock=lock)
            if live != approval:
                raise DispositionConflict("The independent approval changed during sealing.")
            bindings = tuple(
                PermissionBinding(
                    call.org_id, call.space_id, item.source_id, item.object_id, call.principal_id, EXPORT, "allow",
                    frozenset({PURPOSE}), frozenset({ARCHIVE_DESTINATION}), item.fields, approval_seen_at, live["expires_at"],
                ) for item in scopes
            )
            return LocalAuthorization(dict.fromkeys(scopes, SafetyEpochs(*current["snapshot"][:3])), bindings)

        decision = authorize_delivery(
            context, DeliveryCandidate(payload, dict.fromkeys(scopes, epochs)), check_authority=check_authority, load_local=load_local,
        )
        if decision.status == "dependency_unavailable":
            raise AuthorizationUnavailable("Current source archive permission could not be verified.")
        if decision.status == "input_changed":
            raise DispositionConflict("Archive scope changed during the authority check.")
        if decision.status != "succeeded":
            raise OperationsNotAdmitted("Current source archive permission is required.")
        return decision

    wiki_material = None
    if target["media_type"] == DOCX_MEDIA_TYPE or target["wiki_publication_ref"] is not None:
        preflight_scopes = (scope,)
        if target["wiki_publication_ref"] is not None:
            _, wiki_scopes = archive_wiki(connection, call.org_id, call.space_id, target)
            preflight_scopes += tuple(wiki_scopes)
        if target["wiki_rebuild_digest"] is not None:
            wiki_material = _check_wiki(connection, call, target)
            for version in wiki_material[2]:
                preflight_scopes += (EvidenceScope(
                    call.space_id, version["source_id"], version["version_ref"], FIELDS | {REBUILD_FIELD},
                ), *transcript_scopes(connection, call.org_id, call.space_id, version))
        if target["transcript_run_ref"] is not None:
            preflight_scopes += docx_transcript_scopes(connection, call.org_id, call.space_id, target)
            _, history_scopes = _verify_repair_history(connection, call.org_id, call.space_id, target)
            preflight_scopes += history_scopes
        if target["rebuild_metadata_digest"] is not None:
            preflight_scopes += (EvidenceScope(
                call.space_id, target["source_id"], target["version_ref"], frozenset({REBUILD_FIELD}),
            ),)
        preflight = canonical_json({"operation": "archive_preflight", "version_id": str(target["version_ref"])})
        check(preflight, preflight_scopes, lock=False)
    try:
        if wiki_material is not None:
            files, extra_scopes, selected_scope = _wiki_rebuild_files(connection, call, target, store, wiki_material)
        else:
            payload = store.read(OriginalAsset(target["storage_key"], target["content_digest"], target["byte_length"]))
            metadata = _check_transcript(connection, call, target)
            files, extra_scopes, selected_scope = archive_files(connection, call.org_id, call.space_id, target, payload, metadata)
    except OriginalIntegrityError:
        raise DispositionInventoryUnavailable("The approved original bytes could not be verified.") from None
    archive = _archive(files)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise DispositionConflict("The complete archive exceeds the configured size limit.")
    decision = check(archive, (scope, *extra_scopes), lock=True)
    command = command_for(call, EXPORT, (str(export_id),))

    def apply(transaction):
        if datetime.now(UTC) >= decision.valid_until:
            raise DispositionConflict("Archive sealing authorization expired.")
        result = transaction.execute("""
            INSERT INTO thalion.synthetic_export_package (
                org_id, space_id, export_ref, requester_id, approval_ref, request_id, archive_bytes, proof_digest, authority_valid_until
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (export_ref) DO NOTHING RETURNING package_ref
            """, (call.org_id, call.space_id, export_id, call.principal_id, approval["approval_ref"], call.request_id,
                   decision.payload, sha256(decision.authority_proof_ref.encode()).digest(), decision.valid_until)).fetchone()
        if result is None:
            raise DispositionConflict("An archive has already been sealed for this request.")
        append_event(transaction, call.org_id, "lifecycle.synthetic_export.sealed", target["version_ref"], space_id=call.space_id)
        return result[0]

    result = execute_command(connection, command, apply).result_ref
    digest, = connection.execute("""
        SELECT archive_digest FROM thalion.synthetic_export_package
        WHERE (org_id, space_id, export_ref, package_ref) = (%s, %s, %s, %s)
        """, (call.org_id, call.space_id, export_id, result)).fetchone()
    if digest.hex() != decision.payload_sha256 or datetime.now(UTC) >= decision.valid_until:
        raise DispositionConflict("The authorized bytes or validity window changed before completion.")
    return {"export_id": str(export_id), "package_id": str(result), "state": "sealed", "scope": selected_scope,
            "archive_sha256": digest.hex(), "restorable": False}
