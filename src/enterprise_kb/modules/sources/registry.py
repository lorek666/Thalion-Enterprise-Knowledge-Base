from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus

from enterprise_kb.modules.evidence import csv_evidence, docx_evidence, multiformat_evidence, pdf_evidence
from enterprise_kb.runtime.audit import require_open_request
from enterprise_kb.runtime.commands import CommandEnvelope, execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job

from .originals import ObjectStorageOriginalStore, OriginalAsset, SyntheticOriginalStore, verify_payload


SOURCE_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
SYNTHETIC_ISSUER = "https://synthetic.invalid"
SYNTHETIC_ADMISSION = "synthetic_only"
PRODUCTION_ADMISSION = "production_approved"
ADMITTED_ADMISSIONS = frozenset({SYNTHETIC_ADMISSION, PRODUCTION_ADMISSION})
SYNTHETIC_STORAGE_KIND = "synthetic_file"
PRODUCTION_STORAGE_KIND = "https_object_store"


def is_admitted_issuer(issuer: str | None) -> bool:
    return isinstance(issuer, str) and issuer.startswith("https://") and len(issuer.strip()) > 8


def is_production_issuer(issuer: str | None) -> bool:
    return is_admitted_issuer(issuer) and issuer != SYNTHETIC_ISSUER


def admission_for_issuer(issuer: str | None) -> str | None:
    if issuer == SYNTHETIC_ISSUER:
        return SYNTHETIC_ADMISSION
    if is_production_issuer(issuer):
        return PRODUCTION_ADMISSION
    return None


def storage_kind_for_admission(admission: str) -> str:
    if admission == SYNTHETIC_ADMISSION:
        return SYNTHETIC_STORAGE_KIND
    if admission == PRODUCTION_ADMISSION:
        return PRODUCTION_STORAGE_KIND
    raise ValueError(f"Unsupported contract admission mode: {admission!r}.")


def issuer_matches_admission(issuer: str | None, admission: str) -> bool:
    return admission in ADMITTED_ADMISSIONS and admission_for_issuer(issuer) == admission


def storage_matches_admission(storage_kind: str | None, admission: str) -> bool:
    return (
        (admission == SYNTHETIC_ADMISSION and storage_kind == SYNTHETIC_STORAGE_KIND)
        or (admission == PRODUCTION_ADMISSION and storage_kind == PRODUCTION_STORAGE_KIND)
    )


def issuers_same_mode(issuer_a: str | None, issuer_b: str | None) -> bool:
    mode_a = admission_for_issuer(issuer_a)
    return mode_a is not None and mode_a == admission_for_issuer(issuer_b)


def port_admission_to_contract(port_admission: str | None) -> str:
    if port_admission == "production_approved":
        return PRODUCTION_ADMISSION
    if port_admission == "synthetic_local":
        return SYNTHETIC_ADMISSION
    raise ValueError(f"Unsupported port admission mode: {port_admission!r}.")


def store_admission(store: SyntheticOriginalStore | ObjectStorageOriginalStore) -> str:
    admission = getattr(store, "contract_admission", None)
    if admission not in ADMITTED_ADMISSIONS:
        raise ValueError(f"Original store lacks a valid contract_admission: {admission!r}.")
    return admission


def store_storage_kind(store: SyntheticOriginalStore | ObjectStorageOriginalStore) -> str:
    kind = getattr(store, "storage_kind", None)
    admission = store_admission(store)
    if not storage_matches_admission(kind, admission):
        raise ValueError(f"Original store storage_kind {kind!r} does not match admission {admission!r}.")
    return kind


def sql_admitted_admission(admission_col: str) -> str:
    return f"{admission_col} IN ('synthetic_only', 'production_approved')"


def sql_admitted_issuer(col: str) -> str:
    return f"(left({col}, 8) = 'https://' AND char_length(btrim({col})) > 8)"


def sql_issuer_matches_admission(issuer_col: str, admission_col: str) -> str:
    return (
        f"(({admission_col} = 'synthetic_only' AND {issuer_col} = 'https://synthetic.invalid')"
        f" OR ({admission_col} = 'production_approved'"
        f" AND left({issuer_col}, 8) = 'https://' AND char_length(btrim({issuer_col})) > 8"
        f" AND {issuer_col} <> 'https://synthetic.invalid'))"
    )


def sql_issuer_matches_value(issuer_col: str, admission: str) -> str:
    if admission == SYNTHETIC_ADMISSION:
        return f"({issuer_col} = 'https://synthetic.invalid')"
    if admission == PRODUCTION_ADMISSION:
        return (
            f"(left({issuer_col}, 8) = 'https://' AND char_length(btrim({issuer_col})) > 8"
            f" AND {issuer_col} <> 'https://synthetic.invalid')"
        )
    raise ValueError(f"Unsupported contract admission mode: {admission!r}.")


def sql_storage_matches_admission(storage_col: str, admission_col: str) -> str:
    return (
        f"(({admission_col} = 'synthetic_only' AND {storage_col} = 'synthetic_file')"
        f" OR ({admission_col} = 'production_approved' AND {storage_col} = 'https_object_store'))"
    )


def sql_issuers_same_mode(col_a: str, col_b: str) -> str:
    return (
        f"(({col_a} = 'https://synthetic.invalid' AND {col_b} = 'https://synthetic.invalid')"
        f" OR (left({col_a}, 8) = 'https://' AND char_length(btrim({col_a})) > 8 AND {col_a} <> 'https://synthetic.invalid'"
        f" AND left({col_b}, 8) = 'https://' AND char_length(btrim({col_b})) > 8 AND {col_b} <> 'https://synthetic.invalid'))"
    )


class SourceNotAdmitted(Exception):
    pass


class VersionConflict(Exception):
    pass


class SourceDeletedConflict(VersionConflict):
    pass


@dataclass(frozen=True)
class SourceWrite:
    org_id: int
    principal_id: int
    request_id: UUID
    idempotency_key: str = field(repr=False)


@dataclass(frozen=True)
class SyntheticSource:
    source_key: str
    object_namespace: str
    collector_id: int
    approver_id: int | None = None
    processor_id: int | None = None
    quality_reviewer_id: int | None = None
    csv_amount_layout: csv_evidence.AmountLayout | None = field(default=None, repr=False)
    model_policy_approver_id: int | None = None
    docx_amount_columns: tuple[str, str, str, str] | None = field(default=None, repr=False)


@dataclass(frozen=True)
class SourceVersion:
    space_id: int
    source_ref: UUID
    contract_revision: int
    object_key: str = field(repr=False)
    incarnation: str = field(repr=False)
    source_version_key: str = field(repr=False)
    display_name: str = field(repr=False)
    version_label: str
    digest: bytes
    media_type: str = "text/markdown"


@dataclass(frozen=True)
class VersionRegistration:
    document_ref: UUID
    version_ref: UUID
    sequence: int
    digest: bytes
    created: bool


@dataclass(frozen=True)
class _RegisteredOriginal:
    document_ref: UUID
    version_ref: UUID
    sequence: int
    media_type: str
    asset: OriginalAsset


def _digest(*parts) -> bytes:
    return sha256(json.dumps(parts, separators=(",", ":")).encode("utf-8")).digest()


def _validate_keys(*keys: str):
    if any(SOURCE_KEY.fullmatch(key) is None for key in keys):
        raise ValueError("Expected bounded, opaque source identifiers, not names or paths.")


def _command(context: SourceWrite, operation: str, configuration_revision: int, digest: bytes):
    return CommandEnvelope(
        context.org_id, context.principal_id, None, context.request_id, operation,
        context.idempotency_key, digest, configuration_revision, None,
    )


def _register_identity(connection, org_id, space_id, object_type, object_id, *, public_id=None) -> UUID:
    return connection.execute(
        """
        INSERT INTO thalion.object_identity (org_id, space_id, object_type, object_id, public_id)
        VALUES (%s, %s, %s, %s, COALESCE(%s::uuid, gen_random_uuid()))
        RETURNING public_id
        """,
        (org_id, space_id, object_type, object_id, public_id),
    ).fetchone()[0]


def register_synthetic_source(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    spec: SyntheticSource,
    *,
    admission: str = SYNTHETIC_ADMISSION,
) -> UUID:
    if admission not in ADMITTED_ADMISSIONS:
        raise ValueError(f"Unsupported contract admission mode: {admission!r}.")
    _validate_keys(spec.source_key, spec.object_namespace)
    roles = (spec.processor_id, spec.quality_reviewer_id)
    role_input = roles if any(role is not None for role in roles) else ()
    layout = spec.csv_amount_layout
    if layout is not None and (not isinstance(layout, csv_evidence.AmountLayout) or None in roles):
        raise ValueError("A CSV layout requires the admitted processor and independent quality reviewer.")
    layout_input = (("csv_amount_layout.v1", layout.headers),) if layout else ()
    if layout and layout.exception_link:
        layout_input += (("csv_exception_link.v1", layout.exception_link),)
    if layout and layout.alternate_columns:
        layout_input += (("csv_alternate_columns.v1", layout.alternate_columns),)
    docx_columns = spec.docx_amount_columns
    if docx_columns is not None:
        if not isinstance(docx_columns, tuple) or len(docx_columns) != len(csv_evidence.AMOUNT_ROLES) or None in roles:
            raise ValueError("A DOCX layout requires four columns, an admitted processor and a quality reviewer.")
        csv_evidence.AmountLayout(*docx_columns)
        if len({header.strip().casefold() for header in docx_columns}) != len(docx_columns):
            raise ValueError("A DOCX layout requires unambiguous literal column headers.")
        layout_input += (("docx_amount_columns.v1", docx_columns),)
    policy_input = (
        (("model_policy_approver.v1", spec.model_policy_approver_id),) if spec.model_policy_approver_id is not None else ()
    )
    admission_input = (("admission.v1", admission),) if admission != SYNTHETIC_ADMISSION else ()
    command = _command(
        context, "register_source_contract", 1,
        _digest(space_id, spec.source_key, spec.object_namespace, spec.collector_id,
                spec.approver_id, *role_input, *layout_input, *policy_input, *admission_input),
    )
    owner_match = sql_issuer_matches_value("owner.authority_issuer", admission)
    collector_match = sql_issuer_matches_value("collector.authority_issuer", admission)
    role_match = sql_issuer_matches_value("authority_issuer", admission)
    with connection.transaction():
        require_open_request(
            connection, context.org_id, context.request_id, context.principal_id, None,
            operation=command.operation,
        )
        admitted = connection.execute(
            f"""
            SELECT 1
            FROM thalion.space AS space
            JOIN thalion.principal AS owner ON (owner.org_id, owner.principal_id) =
                (space.org_id, space.owner_principal_id)
            JOIN thalion.principal AS collector ON collector.org_id = space.org_id
                AND collector.principal_id = %s
            WHERE space.org_id = %s AND space.space_id = %s AND space.lifecycle = 'active'
              AND owner.principal_id = %s AND owner.principal_type = 'employee'
              AND collector.principal_type = 'service'
              AND {owner_match} AND {collector_match}
              AND NOT owner.disabled AND NOT collector.disabled
            FOR SHARE OF space, owner, collector
            """,
            (spec.collector_id, context.org_id, space_id, context.principal_id),
        ).fetchone()
        if admitted is None:
            raise SourceNotAdmitted("Source enrollment requires an active space owner and collector matching admission.")
        if spec.model_policy_approver_id == context.principal_id:
            raise SourceNotAdmitted("A model policy approver must be independent of the source owner.")
        for principal_id, principal_type in (
            (spec.approver_id, "employee"), (spec.processor_id, "service"),
            (spec.quality_reviewer_id, "employee"), (spec.model_policy_approver_id, "employee"),
        ):
            if principal_id is not None and connection.execute(
                f"""
                SELECT 1 FROM thalion.principal
                WHERE org_id = %s AND principal_id = %s AND principal_type = %s
                  AND {role_match} AND NOT disabled
                FOR SHARE
                """,
                (context.org_id, principal_id, principal_type),
            ).fetchone() is None:
                raise SourceNotAdmitted("Source roles require active principals matching the source admission mode.")
        receipt = execute_command(
            connection, command, lambda tx: _enroll(tx, context, space_id, spec, admission=admission),
        )
        if receipt.result_ref is None:
            raise RuntimeError("Source registration did not produce an identity.")
        return receipt.result_ref


def register_source(
    connection: Connection,
    context: SourceWrite,
    space_id: int,
    spec: SyntheticSource,
    *,
    admission: str = PRODUCTION_ADMISSION,
) -> UUID:
    return register_synthetic_source(connection, context, space_id, spec, admission=admission)


def _enroll(connection, context, space_id, spec, *, admission: str = SYNTHETIC_ADMISSION):
    scope = (context.org_id, space_id)
    layout = spec.csv_amount_layout
    columns = list(layout.headers) if layout else None
    link_columns = list(layout.exception_link) if layout and layout.exception_link else None
    alternate_columns = list(layout.alternate_columns) if layout and layout.alternate_columns else None
    docx_columns = list(spec.docx_amount_columns) if spec.docx_amount_columns is not None else None
    inserted = connection.execute(
        """
        INSERT INTO thalion.source (org_id, space_id, source_key, owner_principal_id)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (org_id, space_id, source_key) DO NOTHING
        RETURNING source_id
        """,
        (*scope, spec.source_key, context.principal_id),
    ).fetchone()
    if inserted is None:
        existing = connection.execute(
            """
            SELECT identity.public_id, contract.admission, contract.collector_id, contract.object_namespace,
                   contract.approver_id, contract.processor_id, contract.quality_reviewer_id,
                   to_jsonb(contract)->'csv_amount_columns', to_jsonb(contract)->'csv_exception_link_columns',
                   to_jsonb(contract)->'csv_alternate_columns', to_jsonb(contract)->'model_policy_approver_id',
                   to_jsonb(contract)->'docx_amount_columns'
            FROM thalion.source AS source
            JOIN thalion.source_contract_revision AS contract
              ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
                 = (source.org_id, source.space_id, source.source_id, source.contract_revision)
            JOIN thalion.object_identity AS identity
              ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
                 = (source.org_id, source.space_id, 'source', source.source_id)
            WHERE source.org_id = %s AND source.space_id = %s AND source.source_key = %s
            """,
            (*scope, spec.source_key),
        ).fetchone()
        if existing is None or existing[1:] != (
            admission, spec.collector_id, spec.object_namespace, spec.approver_id,
            spec.processor_id, spec.quality_reviewer_id, columns, link_columns, alternate_columns,
            spec.model_policy_approver_id, docx_columns,
        ):
            raise VersionConflict("An enrolled source cannot be rebound by replay.")
        return existing[0]
    source_id = inserted[0]
    optional_fields = tuple((name, value) for name, value in (
        ("csv_amount_columns", columns), ("csv_exception_link_columns", link_columns),
        ("csv_alternate_columns", alternate_columns),
        ("model_policy_approver_id", spec.model_policy_approver_id),
        ("docx_amount_columns", docx_columns),
    ) if value is not None)
    optional_columns = "".join(f", {name}" for name, _ in optional_fields)
    optional_parameters = tuple(value for _, value in optional_fields)
    optional_values = ", %s" * len(optional_parameters)
    connection.execute(
        f"""
        INSERT INTO thalion.source_contract_revision (
            org_id, space_id, source_id, revision, admission, collector_id, object_namespace,
            approver_id, processor_id, quality_reviewer_id{optional_columns}
        ) VALUES (%s, %s, %s, 1, %s, %s, %s, %s, %s, %s{optional_values})
        """,
        (*scope, source_id, admission, spec.collector_id, spec.object_namespace, spec.approver_id,
         spec.processor_id, spec.quality_reviewer_id, *optional_parameters),
    )
    return _register_identity(connection, *scope, "source", source_id)


def _admit_version(
    connection: Connection,
    context: SourceWrite,
    version: SourceVersion,
    *,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore | None = None,
):
    require_open_request(
        connection, context.org_id, context.request_id, context.principal_id, None,
        operation="register_version",
    )
    expected_admission = store_admission(store) if store is not None else None
    return _current_collector_scope(
        connection,
        context,
        version.space_id,
        version.source_ref,
        version.contract_revision,
        expected_admission=expected_admission,
    )


def _lock_source_content(connection, source_ref):
    connection.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"thalion.source.content:{source_ref}",),
    )


def _current_collector_scope(
    connection,
    context,
    space_id,
    source_ref,
    contract_revision,
    *,
    expected_admission: str | None = None,
):
    if expected_admission is not None and expected_admission not in ADMITTED_ADMISSIONS:
        raise SourceNotAdmitted("Unsupported source admission mode.")
    admission_clause = (
        f"AND {sql_admitted_admission('contract.admission')}"
        if expected_admission is None
        else "AND contract.admission = %s"
    )
    params: list[object] = [context.org_id, space_id, source_ref, contract_revision]
    if expected_admission is not None:
        params.append(expected_admission)
    params.append(context.principal_id)
    row = connection.execute(
        f"""
        SELECT source.source_id, contract.object_namespace
        FROM thalion.source AS source
        JOIN thalion.space AS space ON (space.org_id, space.space_id) = (source.org_id, source.space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
             = (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.principal AS worker ON (worker.org_id, worker.principal_id)
             = (contract.org_id, contract.collector_id)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id)
             = (source.org_id, source.space_id, 'source', source.source_id)
        WHERE source.org_id = %s AND source.space_id = %s AND identity.public_id = %s
          AND source.contract_revision = %s {admission_clause}
          AND source.lifecycle = 'active' AND space.lifecycle = 'active'
          AND worker.principal_id = %s AND worker.principal_type = 'service'
          AND {sql_issuer_matches_admission('worker.authority_issuer', 'contract.admission')}
          AND NOT worker.disabled
        FOR SHARE OF source, space, worker
        """,
        tuple(params),
    ).fetchone()
    if row is None:
        raise SourceNotAdmitted("The current source does not admit this collector, storage mode, or revision.")
    return row


def _find_version(connection, document_scope, source_version_key) -> _RegisteredOriginal | None:
    row = connection.execute(
        """
        SELECT doc_ref.public_id, ver_ref.public_id, ver.registration_sequence, asset.media_type,
               asset.storage_key, asset.content_digest, asset.byte_length
        FROM thalion.document AS doc
        JOIN thalion.document_version AS ver ON (ver.org_id, ver.space_id, ver.source_id, ver.document_id)
             = (doc.org_id, doc.space_id, doc.source_id, doc.document_id)
        JOIN thalion.asset AS asset ON (asset.org_id, asset.space_id, asset.asset_id)
             = (ver.org_id, ver.space_id, ver.asset_id)
        JOIN thalion.object_identity AS doc_ref
          ON (doc_ref.org_id, doc_ref.space_id, doc_ref.object_type, doc_ref.object_id)
             = (doc.org_id, doc.space_id, 'document', doc.document_id)
        JOIN thalion.object_identity AS ver_ref
          ON (ver_ref.org_id, ver_ref.space_id, ver_ref.object_type, ver_ref.object_id)
             = (ver.org_id, ver.space_id, 'document_version', ver.version_id)
        WHERE (doc.org_id, doc.space_id, doc.source_id, doc.source_object_key, doc.incarnation)
              = (%s, %s, %s, %s, %s) AND ver.source_version_key = %s
        """,
        (*document_scope, source_version_key),
    ).fetchone()
    return _RegisteredOriginal(*row[:4], OriginalAsset(*row[4:])) if row else None


def _same_original(known: _RegisteredOriginal, version: SourceVersion, size: int):
    if (known.asset.digest, known.asset.byte_length, known.media_type) != (version.digest, size, version.media_type):
        raise VersionConflict("This source version already names different bytes or an original media type.")


def has_source_delete_isolation(connection: Connection) -> bool:
    return connection.execute(
        "SELECT to_regprocedure('thalion.document_source_deleted(bigint,bigint,bigint,bigint)') IS NOT NULL"
    ).fetchone()[0]


def _is_document_source_deleted(connection, scope, object_key: str, incarnation: str) -> bool:
    if not has_source_delete_isolation(connection):
        return False
    return connection.execute(
        """
        SELECT 1 FROM thalion.document AS doc
        WHERE (doc.org_id, doc.space_id, doc.source_id, doc.source_object_key, doc.incarnation)
            = (%s, %s, %s, %s, %s)
          AND thalion.document_source_deleted(doc.org_id, doc.space_id, doc.source_id, doc.document_id)
        """,
        (*scope, object_key, incarnation),
    ).fetchone() is not None


def register_synthetic_version(
    connection: Connection,
    context: SourceWrite,
    version: SourceVersion,
    payload: bytes,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
) -> VersionRegistration:
    with _synthetic_version_registration(connection, context, version, payload, store) as registered:
        return registered


def register_version(
    connection: Connection,
    context: SourceWrite,
    version: SourceVersion,
    payload: bytes,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
) -> VersionRegistration:
    return register_synthetic_version(connection, context, version, payload, store)


@contextmanager
def _synthetic_version_registration(
    connection: Connection,
    context: SourceWrite,
    version: SourceVersion,
    payload: bytes,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
):
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("Original storage must occur outside business transactions.")
    _validate_original(version, payload)
    storage_kind = store_storage_kind(store)
    with connection.transaction():
        admission = _admit_version(connection, context, version, store=store)
        source_id, object_namespace = admission
        scope = (context.org_id, version.space_id, source_id)
        document_scope = (*scope, version.object_key, version.incarnation)
        known = _find_version(connection, document_scope, version.source_version_key)
        if known is None and _is_document_source_deleted(connection, scope, version.object_key, version.incarnation):
            raise SourceDeletedConflict(
                "The source document incarnation was explicitly deleted and cannot be re-registered.",
            )
    material = _original_identity(*scope[:2], object_namespace, version)
    asset = _stage_original(known, material, version, payload, store)
    command = _command(
        context, "register_version", version.contract_revision,
        _digest(*material, version.display_name, version.version_label),
    )
    created = False

    def apply(transaction):
        nonlocal created
        saved = _record_original(transaction, context, scope, version, asset, storage_kind=storage_kind)
        created = saved.created
        return saved.version_ref

    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        _lock_source_content(connection, version.source_ref)
        if _admit_version(connection, context, version, store=store) != admission:
            raise SourceNotAdmitted("Source admission changed during storage.")
        receipt = execute_command(connection, command, apply)
        saved = _find_version(connection, document_scope, version.source_version_key)
        if saved is None or saved.version_ref != receipt.result_ref:
            raise RuntimeError("Original registration did not produce the scoped version identity.")
        yield VersionRegistration(saved.document_ref, saved.version_ref, saved.sequence, saved.asset.digest, created)


def _validate_original(version, payload):
    _validate_keys(version.object_key, version.incarnation, version.source_version_key)
    if version.media_type not in ({"text/markdown", "text/csv", pdf_evidence.MEDIA_TYPE, docx_evidence.MEDIA_TYPE} | multiformat_evidence.STRUCTURED_MEDIA_TYPES):
        raise ValueError("The synthetic original media type is not supported.")
    if not (
        1 <= len(version.display_name.strip()) <= 300
        and 1 <= len(version.version_label.strip()) <= 128
    ):
        raise ValueError("A version requires a bounded display name and label.")
    verify_payload(payload, version.digest)


def _original_identity(org_id, space_id, object_namespace, version):
    material = (
        org_id, space_id, str(version.source_ref), object_namespace,
        version.object_key, version.incarnation, version.source_version_key, version.digest.hex(),
    )
    if version.media_type != "text/markdown":
        material += (version.media_type,)
    return material


def _stage_original(known, material, version, payload, store):
    if known is not None:
        _same_original(known, version, len(payload))
        store.read(known.asset)
        return known.asset
    return store.stage(_digest("synthetic_original.v1", *material).hex(), version.digest, payload)


def _record_original(
    connection, context, scope, version, asset, *, storage_kind: str = SYNTHETIC_STORAGE_KIND,
):
    document_scope = (*scope, version.object_key, version.incarnation)
    document_id = _lock_document(connection, document_scope, version.display_name)
    if has_source_delete_isolation(connection) and connection.execute(
        "SELECT thalion.document_source_deleted(%s, %s, %s, %s)", (*scope, document_id),
    ).fetchone()[0]:
        raise SourceDeletedConflict(
            "The source document incarnation was explicitly deleted and cannot be re-registered.",
        )
    saved = _find_version(connection, document_scope, version.source_version_key)
    created = saved is None
    if created:
        _write_version(connection, context, scope, document_id, version, asset, storage_kind=storage_kind)
        saved = _find_version(connection, document_scope, version.source_version_key)
    _same_original(saved, version, asset.byte_length)
    return VersionRegistration(saved.document_ref, saved.version_ref, saved.sequence, saved.asset.digest, created)


def _lock_document(connection, scope, display_name):
    inserted = connection.execute(
        """
        INSERT INTO thalion.document (org_id, space_id, source_id, source_object_key, incarnation, display_name)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (org_id, space_id, source_id, source_object_key, incarnation) DO NOTHING
        RETURNING document_id
        """,
        (*scope, display_name),
    ).fetchone()
    if inserted:
        document_id = inserted[0]
        _register_identity(connection, *scope[:2], "document", document_id)
        return document_id
    return connection.execute(
        """
        SELECT document_id FROM thalion.document
        WHERE (org_id, space_id, source_id, source_object_key, incarnation) = (%s, %s, %s, %s, %s)
        FOR UPDATE
        """,
        scope,
    ).fetchone()[0]


def _write_version(
    connection, context, scope, document_id, version, asset, *, storage_kind: str = SYNTHETIC_STORAGE_KIND,
):
    configuration = 1
    profile_spec = {
        "text/csv": (csv_evidence.PARSER_VERSION, csv_evidence.PROFILE, csv_evidence.LOCATOR_REVISION),
        pdf_evidence.MEDIA_TYPE: (pdf_evidence.PARSER_VERSION, pdf_evidence.PROFILE, pdf_evidence.LOCATOR_REVISION),
        docx_evidence.MEDIA_TYPE: (docx_evidence.PARSER_VERSION, docx_evidence.PROFILE, docx_evidence.LOCATOR_REVISION),
        **{
            mt: (multiformat_evidence.PARSER_VERSION, prof, multiformat_evidence.LOCATOR_REVISION)
            for mt, prof in multiformat_evidence.PROFILES.items()
        },
    }.get(version.media_type)
    if profile_spec is not None:
        config = connection.execute("""
            SELECT configuration_revision FROM thalion.processing_config_revision
            WHERE (parser_version, profile, locator_revision) = (%s, %s, %s)
            ORDER BY configuration_revision DESC LIMIT 1
        """, profile_spec).fetchone()
        if config is None:
            raise SourceNotAdmitted("No admitted processing profile for this original is installed.")
        configuration = config[0]
    asset_id = _write_asset(
        connection, (*scope, document_id), asset, media_type=version.media_type, storage_kind=storage_kind,
    )
    version_id = connection.execute(
        """
        INSERT INTO thalion.document_version (
            org_id, space_id, source_id, document_id, contract_revision, asset_id,
            source_version_key, version_label, registration_sequence
        )
        SELECT %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(max(registration_sequence), 0) + 1
        FROM thalion.document_version WHERE document_id = %s
        RETURNING version_id
        """,
        (
            *scope, document_id, version.contract_revision, asset_id,
            version.source_version_key, version.version_label, document_id,
        ),
    ).fetchone()[0]
    org_id, space_id, _ = scope
    version_ref = _register_identity(connection, org_id, space_id, "document_version", version_id)
    append_event(connection, org_id, "sources.version.registered", version_ref, space_id=space_id)
    enqueue_job(
        connection, JobSpec(org_id, space_id, version_ref, "parse", version.digest, configuration),
        request_id=context.request_id,
    )
    return version_ref


def _write_asset(
    connection, document_scope, asset, *, media_type="text/markdown", storage_kind: str = SYNTHETIC_STORAGE_KIND,
):
    return connection.execute(
        """
        INSERT INTO thalion.asset (
            org_id, space_id, source_id, document_id,
            storage_kind, storage_key, media_type, byte_length, content_digest
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING asset_id
        """,
        (*document_scope, storage_kind, asset.key, media_type, asset.byte_length, asset.digest),
    ).fetchone()[0]


def _rebuild_source(connection, scope, metadata, *, admission: str = SYNTHETIC_ADMISSION):
    org_id, space_id, owner, worker = scope
    source_id, = connection.execute("""
        INSERT INTO thalion.source (org_id, space_id, source_key, owner_principal_id)
        VALUES (%s, %s, %s, %s) RETURNING source_id
        """, (org_id, space_id, metadata["source_key"], owner)).fetchone()
    _register_identity(connection, org_id, space_id, "source", source_id, public_id=metadata["source_id"])
    source_scope = (org_id, space_id, source_id)
    connection.execute("""
        INSERT INTO thalion.source_contract_revision (
            org_id, space_id, source_id, revision, admission, collector_id, object_namespace, processor_id
        ) VALUES (%s, %s, %s, 1, %s, %s, %s, %s)
        """, (*source_scope, admission, worker, metadata["object_namespace"], worker))
    return source_scope


def _rebuild_document(connection, source_scope, metadata):
    org_id, space_id, _ = source_scope
    document_id, = connection.execute("""
        INSERT INTO thalion.document (org_id, space_id, source_id, source_object_key, incarnation, display_name)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING document_id
        """, (*source_scope, metadata["object_key"], metadata["incarnation"], metadata["display_name"])).fetchone()
    _register_identity(connection, org_id, space_id, "document", document_id, public_id=metadata["document_id"])
    return (*source_scope, document_id)


def _rebuild_original(
    connection,
    doc_scope,
    version_ref,
    metadata,
    asset,
    *,
    media_type="text/markdown",
    storage_kind: str = SYNTHETIC_STORAGE_KIND,
):
    org_id, space_id, *_ = doc_scope
    asset_id = _write_asset(connection, doc_scope, asset, media_type=media_type, storage_kind=storage_kind)
    version_id, = connection.execute("""
        INSERT INTO thalion.document_version (
            org_id, space_id, source_id, document_id, contract_revision, asset_id,
            source_version_key, version_label, registration_sequence
        ) VALUES (%s, %s, %s, %s, 1, %s, %s, %s, %s) RETURNING version_id
        """, (*doc_scope, asset_id, metadata["version_key"], metadata["version_label"], metadata["registration_sequence"])).fetchone()
    _register_identity(connection, org_id, space_id, "document_version", version_id, public_id=version_ref)
