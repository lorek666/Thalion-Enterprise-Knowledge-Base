from base64 import b64decode
from binascii import Error as Base64Error
from datetime import datetime
from hashlib import sha256
import json
from time import monotonic
from uuid import UUID, uuid4

from psycopg import Error

from enterprise_kb.modules.sources import ingest, registry
from enterprise_kb.runtime.audit import RequestAuditConflict, RequestStart, finish_request, start_request
from enterprise_kb.runtime.commands import IdempotencyConflict

from .evidence import EmployeeCall, EvidenceReply, EvidenceService, encode, error_reply


UPLOAD = ingest.UPLOAD
DESTINATION = ingest.DESTINATION
MAX_FILES = ingest.MAX_BATCH_FILES
MAX_TOTAL_BYTES = ingest.MAX_BATCH_BYTES
MAX_FILE_BYTES = ingest.MAX_FILE_BYTES


class UploadTooLarge(Exception):
    pass


def upload_files(body: object) -> tuple[ingest.IngestFile, ...]:
    if not isinstance(body, dict) or set(body) != {"files"} or not isinstance(body["files"], list):
        raise ValueError("Invalid upload batch.")
    entries = body["files"]
    if not 1 <= len(entries) <= MAX_FILES:
        raise ValueError("A batch requires between 1 and 20 files.")
    files = []
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "name", "title", "version", "identifier", "content", "confirm_new_version",
        }:
            raise ValueError("Invalid upload file metadata.")
        name, title, version = entry["name"], entry["title"], entry["version"]
        identifier, content, confirm = entry["identifier"], entry["content"], entry["confirm_new_version"]
        if (
            not isinstance(name, str) or not 1 <= len(name) <= 255
            or not isinstance(title, str) or not 1 <= len(title) <= 300 or not title.strip()
            or not isinstance(version, str) or not 1 <= len(version) <= 128 or not version.strip()
            or not isinstance(identifier, str) or registry.SOURCE_KEY.fullmatch(identifier) is None
            or not isinstance(content, str) or not isinstance(confirm, bool)
        ):
            raise ValueError("Invalid upload file metadata.")
        if len(content) > (MAX_FILE_BYTES + 2) // 3 * 4:
            raise UploadTooLarge()
        try:
            payload = b64decode(content, validate=True)
        except (Base64Error, ValueError):
            raise ValueError("The upload content is not base64.") from None
        total += len(payload)
        if total > MAX_TOTAL_BYTES:
            raise UploadTooLarge()
        files.append(ingest.IngestFile(
            title, version, identifier, "upload",
            "upload-" + sha256(version.encode()).hexdigest()[:24],
            payload, confirm, file_name=name,
        ))
    return tuple(files)


def _owner_source(connection, caller, source_ref: UUID, authority_issuer: str):
    expected_admission = registry.admission_for_issuer(authority_issuer)
    if expected_admission is None:
        return None
    return connection.execute(
        f"""
        SELECT source.source_id, contract.collector_id
        FROM thalion.object_identity AS identity
        JOIN thalion.source AS source
          ON (source.org_id, source.space_id, source.identity_type, source.source_id)
           = (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.organization AS organization ON organization.org_id = source.org_id
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS collector
          ON (collector.org_id, collector.principal_id) = (contract.org_id, contract.collector_id)
        WHERE (identity.org_id, identity.space_id, identity.public_id, identity.object_type)
            = (%s, %s, %s, 'source')
          AND source.owner_principal_id = %s AND space.owner_principal_id = %s
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND organization.config_revision = %s
          AND contract.admission = %s
          AND collector.principal_type = 'service' AND NOT collector.disabled
          AND {registry.sql_issuer_matches_admission('collector.authority_issuer', 'contract.admission')}
        """,
        (
            caller.org_id, caller.space_id, source_ref, caller.principal_id, caller.principal_id,
            caller.configuration_revision, expected_admission,
        ),
    ).fetchone()


def execute(
    service: EvidenceService, caller: EmployeeCall, source_ref: UUID, body: object, key: str,
) -> EvidenceReply:
    request_id = uuid4()
    if UPLOAD not in caller.credential.operations:
        return error_reply("forbidden", request_id)
    try:
        files = upload_files(body)
    except UploadTooLarge:
        return error_reply("request_too_large", request_id)
    except ValueError:
        return error_reply("invalid_arguments", request_id)
    try:
        return _run(service, caller, source_ref, files, key, request_id)
    except (Error, RequestAuditConflict):
        return error_reply("dependency_unavailable", request_id)


def _run(service, caller, source_ref, files, key, request_id):
    started = monotonic()
    admin_started = False
    service_started = False
    service_request = uuid4()
    with service.connect() as connection:
        try:
            owner = _owner_source(connection, caller, source_ref, service.authority_issuer)
            if owner is None:
                return error_reply("forbidden", request_id)
            _, collector_id = owner
            business_date = datetime.now(caller.business_timezone).date()
            start_request(connection, RequestStart(
                caller.org_id, request_id, caller.principal_id, None, caller.credential.client_id,
                UPLOAD, DESTINATION, business_date, caller.configuration_revision, space_id=caller.space_id,
                ingress=caller.ingress,
            ))
            admin_started = True
            start_request(connection, RequestStart(
                caller.org_id, service_request, collector_id, None, "synthetic-ingest",
                "register_version", DESTINATION, business_date, caller.configuration_revision,
                space_id=caller.space_id, ingress="internal",
            ))
            service_started = True
            outcomes = ingest.ingest_batch(
                connection,
                registry.SourceWrite(caller.org_id, collector_id, service_request, key),
                caller.space_id, source_ref, files, service.store, actor_id=caller.principal_id, upload_request_id=request_id,
            )
        except IdempotencyConflict:
            _finish(connection, service_started, service_request, admin_started, request_id, "rejected", "rejected", started, caller)
            return error_reply("ingest_conflict", request_id)
        except (ingest.BatchNotAdmitted, ValueError):
            _finish(connection, service_started, service_request, admin_started, request_id, "rejected", "rejected", started, caller)
            return error_reply("invalid_arguments", request_id)
        except registry.SourceNotAdmitted:
            _finish(connection, service_started, service_request, admin_started, request_id, "rejected", "rejected", started, caller)
            return error_reply("forbidden", request_id)
        except (Error, RequestAuditConflict):
            _finish(
                connection, service_started, service_request, admin_started, request_id,
                "dependency_unavailable", "dependency_unavailable", started, caller,
            )
            return error_reply("dependency_unavailable", request_id)
        outcome = "succeeded" if any(item.status != "rejected" for item in outcomes) else "rejected"
        _finish(connection, service_started, service_request, admin_started, request_id, outcome, "succeeded", started, caller)
        return EvidenceReply(request_id, 200, encode({
            "request_id": str(request_id),
            "ingestion_request_id": str(service_request),
            "files": [{
                "position": item.position,
                "status": item.status,
                "media_type": item.media_type,
                "digest": item.digest.hex() if item.digest else None,
                "document_id": str(item.document_ref) if item.document_ref else None,
                "version_id": str(item.version_ref) if item.version_ref else None,
                "reason": item.reason,
            } for item in outcomes],
        }))


def _finish(connection, service_started, service_request, admin_started, request_id, admin_outcome, service_outcome,
            started, caller):
    elapsed = int((monotonic() - started) * 1000)
    try:
        if service_started:
            finish_request(connection, caller.org_id, service_request, service_outcome, elapsed)
        if admin_started:
            finish_request(connection, caller.org_id, request_id, admin_outcome, elapsed)
    except (Error, RequestAuditConflict):
        pass
