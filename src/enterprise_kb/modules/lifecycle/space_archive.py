from collections.abc import Callable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Literal
from uuid import UUID, uuid4
from zipfile import BadZipFile, ZipFile, ZipInfo

from psycopg import Connection, Error, OperationalError
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from enterprise_kb.database import rehearsal_marker
from enterprise_kb.modules.access import delivery, governance, policy, rules, travel
from enterprise_kb.modules.evidence import docx_evidence, markdown, processing
from enterprise_kb.modules.evidence.docx_evidence import MEDIA_TYPE as DOCX_MEDIA_TYPE
from enterprise_kb.modules.evidence.pdf_evidence import MEDIA_TYPE as PDF_MEDIA_TYPE
from enterprise_kb.modules.evidence.quality_restrictions import check_pinned_history
from enterprise_kb.modules.lifecycle.archive_rehearsal import (
    ArchiveRejected,
    _begin_empty_rebuild,
    _check_input,
    _check_package,
    _decode_rebuild,
    _json_object,
    _read_member,
)
from enterprise_kb.modules.lifecycle.archives import (
    ARCHIVE_DESTINATION,
    FIELDS,
    ORIGINAL_MEMBERS,
    PURPOSE,
    _archive,
    _load_repair_history,
    _metadata_digest,
    archive_files,
)
from enterprise_kb.modules.lifecycle.disposition import DESTINATION, DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.lifecycle.rebuild_format import (
    DOCX_REBUILD_FORMAT,
    PDF_REBUILD_FORMAT,
    REBUILD_FIELD,
    REBUILD_FORMAT,
    rebuild_metadata,
)
from enterprise_kb.modules.lifecycle.transcripts import MAX_TRANSCRIPT_PASSAGES, TRANSCRIPT_FIELD, current_transcript
from enterprise_kb.modules.lifecycle.wiki_archives import WIKI_FIELD
from enterprise_kb.modules.lifecycle.wiki_rebuild import (
    MAX_WIKI_INPUTS,
    _manifest_graph,
    canonical_json,
    canonical_ref,
    verify_manifest_graph,
)
from enterprise_kb.modules.operations import release
from enterprise_kb.modules.operations.context import OperationsCall, OperationsNotAdmitted, command_for, require_scope
from enterprise_kb.modules.retrieval import lexical
from enterprise_kb.modules.sources import effectivity, restriction_log
from enterprise_kb.modules.sources.originals import (
    MAX_SYNTHETIC_BYTES,
    OriginalAsset,
    OriginalIntegrityError,
    SyntheticOriginalStore,
    verify_payload,
)
from enterprise_kb.modules.sources.registry import (
    SYNTHETIC_ISSUER,
    sql_admitted_issuer,
    sql_issuers_same_mode,
    SourceWrite,
    _digest,
    _rebuild_document,
    _rebuild_original,
    _register_identity,
    _validate_keys,
)
from enterprise_kb.modules.sources.source_revocations import SourceRevocationAuthority, SourceRevocationSnapshot
from enterprise_kb.modules.wiki import drafts, inputs as wiki_inputs, publication, templates
from enterprise_kb.runtime.audit import RequestStart, finish_request, start_request
from enterprise_kb.runtime.commands import execute_command
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import JobSpec, LeaseLost, claim_job, enqueue_job


REQUEST = "request_space_archive"
APPROVE = "approve_space_archive"
EXPORT = "seal_space_archive"
LIST = "list_space_archives"
VERIFY = "verify_space_archive"
OPERATIONS = frozenset({REQUEST, APPROVE, EXPORT, LIST, VERIFY})
SPACE_ARCHIVE_FORMAT = "thalion.synthetic-space-archive.v1"
SPACE_ARCHIVE_SCOPE = "space_multisource_archive"
MAX_SPACE_ARCHIVE_BYTES = 33_554_432
MAX_SPACE_SOURCES = 20
MAX_SPACE_VERSIONS = 100
MAX_SPACE_WIKIS = 40
AUTH_FIELD = "authorization_rules"
SAFETY_FIELD = "safety_decisions"
AFFECTED_SERVICES = ("search_api", "mcp_server", "lexical_index", "wiki_delivery", "parse_worker")
REBUILD_DATASET_KIND = "synthetic_local"


@dataclass(frozen=True)
class SpaceArchivePermit:
    org_id: int
    space_id: int
    space_ref: UUID
    export_ref: UUID
    digest: bytes
    database: str


@dataclass(frozen=True)
class OldReferenceCheck:
    label: str
    kind: Literal["passage", "wiki"]
    principal_ref: UUID
    business_date: date
    region: str
    traveler_class: str
    expected_accessible: bool
    passage_ref: UUID | None = None
    excerpt_revision: int = 1
    version_ref: UUID | None = None
    query: str | None = field(default=None, repr=False)
    topic_key: str | None = None

    def __post_init__(self):
        if not self.label.strip():
            raise ValueError("OldReferenceCheck requires a non-empty label.")
        if self.kind == "passage" and self.passage_ref is None:
            raise ValueError("Passage reference check requires passage_ref.")
        if self.kind == "wiki" and (not self.topic_key or not self.topic_key.strip()):
            raise ValueError("Wiki reference check requires topic_key.")


@dataclass(frozen=True)
class VerifiedSpaceArchive:
    export_ref: UUID
    space_ref: UUID
    format_version: str
    source_refs: tuple[UUID, ...]
    version_refs: tuple[UUID, ...]
    wiki_revision_refs: tuple[UUID, ...]
    recovery_watermark: dict
    authorization_rules: dict
    safety_decisions: dict


@dataclass(frozen=True)
class _DecodedSpaceArchive:
    verified: VerifiedSpaceArchive
    manifest: dict
    sources: list[dict]
    versions: dict[UUID, dict]
    effectivity_records: dict[UUID, list[dict]]
    wikis: list[dict]


@dataclass(frozen=True)
class SpaceRebuildReport:
    rebuild_ref: UUID
    org_id: int
    space_id: int
    space_ref: UUID
    export_ref: UUID
    format_version: str
    archive_sha256: str
    dataset_kind: str
    recovery_watermark: dict
    rule_generation: int
    source_generation: int
    alternate_model_profile: str
    lexical_index_mode: str
    rebuilt_sources: int
    rebuilt_versions: int
    rebuilt_wikis: int
    indexed_versions: tuple[UUID, ...]
    replayed_stops: int
    replayed_deletions: int
    replayed_revocations: int
    reference_results: tuple[dict, ...]
    duration_ms: int
    scratch_bytes: int
    affected_services: tuple[str, ...]
    store: SyntheticOriginalStore = field(repr=False)
    principal_ids: dict[UUID, int] = field(repr=False)

    def to_dict(self) -> dict:
        return {
            "rebuild_id": str(self.rebuild_ref),
            "space_id": str(self.space_ref),
            "export_id": str(self.export_ref),
            "format_version": self.format_version,
            "archive_sha256": self.archive_sha256,
            "dataset_kind": self.dataset_kind,
            "recovery_watermark": self.recovery_watermark,
            "rule_generation": self.rule_generation,
            "source_generation": self.source_generation,
            "alternate_model_profile": self.alternate_model_profile,
            "lexical_index_mode": self.lexical_index_mode,
            "rebuilt_sources": self.rebuilt_sources,
            "rebuilt_versions": self.rebuilt_versions,
            "rebuilt_wikis": self.rebuilt_wikis,
            "indexed_versions": [str(item) for item in self.indexed_versions],
            "replayed_stops": self.replayed_stops,
            "replayed_deletions": self.replayed_deletions,
            "replayed_revocations": self.replayed_revocations,
            "verified_references": sum(1 for item in self.reference_results if item["actual_accessible"]),
            "blocked_references": sum(1 for item in self.reference_results if not item["actual_accessible"]),
            "reference_results": list(self.reference_results),
            "duration_ms": self.duration_ms,
            "scratch_bytes": self.scratch_bytes,
            "affected_services": list(self.affected_services),
        }


def _one(connection: Connection, query: str, params: tuple):
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(query, params).fetchone()


def _all(connection: Connection, query: str, params: tuple) -> list[dict]:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(query, params).fetchall()


def _principal_ref_map(connection: Connection, org_id: int, principal_ids: set[int]) -> dict[int, dict]:
    if not principal_ids:
        return {}
    rows = _all(
        connection,
        """
        SELECT p.principal_id, oi.public_id AS principal_ref, p.principal_type, p.disabled
        FROM thalion.principal AS p
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.object_type, oi.object_id) = (p.org_id, 'principal', p.principal_id)
        WHERE p.org_id = %s AND p.principal_id = ANY(%s)
        ORDER BY oi.public_id
        """,
        (org_id, sorted(principal_ids)),
    )
    return {
        row["principal_id"]: {
            "principal_id": str(row["principal_ref"]),
            "principal_type": row["principal_type"],
            "disabled": bool(row["disabled"]),
        }
        for row in rows
    }


def _collect_recovery_watermark(
    connection: Connection,
    org_id: int,
    space_id: int,
    source_rows: list[dict],
    *,
    rule_log: Connection | None = None,
    source_authority: SourceRevocationAuthority | None = None,
) -> dict:
    org_epoch, space_epoch, space_ref = connection.execute(
        """
        SELECT o.safety_epoch, s.safety_epoch, oi.public_id
        FROM thalion.organization AS o
        JOIN thalion.space AS s USING (org_id)
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (s.org_id, s.space_id, 'space', s.space_id)
        WHERE (s.org_id, s.space_id) = (%s, %s)
        """,
        (org_id, space_id),
    ).fetchone()
    source_ids = [row["source_id"] for row in source_rows]
    checkpoints = {}
    if connection.execute("SELECT to_regclass('thalion.source_permission_checkpoint') IS NOT NULL").fetchone()[0]:
        cp_rows = _all(
            connection,
            """
            SELECT DISTINCT ON (cp.source_id)
                   src_oi.public_id AS source_ref, cp.sequence, cp.checkpoint_ref,
                   cp.authority_ref, cp.authority_stream_ref, cp.authority_generation, cp.acknowledged_count
            FROM thalion.source_permission_checkpoint AS cp
            JOIN thalion.object_identity AS src_oi
              ON (src_oi.org_id, src_oi.space_id, src_oi.object_type, src_oi.object_id)
               = (cp.org_id, cp.space_id, 'source', cp.source_id)
            WHERE (cp.org_id, cp.space_id) = (%s, %s) AND cp.source_id = ANY(%s)
            ORDER BY cp.source_id, cp.sequence DESC
            """,
            (org_id, space_id, source_ids),
        )
        for row in cp_rows:
            checkpoints[str(row["source_ref"])] = {
                "sequence": row["sequence"],
                "checkpoint_id": str(row["checkpoint_ref"]),
                "authority_id": str(row["authority_ref"]),
                "authority_stream_id": str(row["authority_stream_ref"]),
                "authority_generation": row["authority_generation"],
                "acknowledged_count": row["acknowledged_count"],
            }
    stop_count, = connection.execute(
        "SELECT count(*) FROM thalion.rule_use_stop WHERE (org_id, space_id) = (%s, %s) AND source_id = ANY(%s)",
        (org_id, space_id, source_ids),
    ).fetchone()
    receipt_count = 0
    if connection.execute("SELECT to_regclass('thalion.source_restriction_receipt') IS NOT NULL").fetchone()[0]:
        receipt_count, = connection.execute(
            "SELECT count(*) FROM thalion.source_restriction_receipt WHERE (org_id, space_id) = (%s, %s) AND source_id = ANY(%s)",
            (org_id, space_id, source_ids),
        ).fetchone()
    watermark: dict = {
        "space_id": str(space_ref),
        "org_safety_epoch": int(org_epoch),
        "space_safety_epoch": int(space_epoch),
        "source_epochs": {
            str(row["source_ref"]): {
                "safety_epoch": int(row["safety_epoch"]),
                "local_policy_revision": int(row["local_policy_revision"]),
                "contract_revision": int(row["contract_revision"]),
            }
            for row in source_rows
        },
        "permission_checkpoints": checkpoints,
        "recorded_rule_stops": int(stop_count),
        "recorded_source_restrictions": int(receipt_count),
    }
    if rule_log is not None:
        stream_ref = connection.execute(
            "SELECT stream_ref FROM thalion.rule_restriction_stream WHERE org_id = %s",
            (org_id,),
        ).fetchone()
        if stream_ref is not None:
            head = rule_log.execute(
                "SELECT coalesce(max(generation), 0) FROM thalion.rule_log_entry WHERE stream_ref = %s",
                (stream_ref[0],),
            ).fetchone()[0]
            watermark["rule_log_stream_id"] = str(stream_ref[0])
            watermark["rule_log_generation"] = int(head)
        else:
            watermark["rule_log_stream_id"] = None
            watermark["rule_log_generation"] = 0
    if source_authority is not None:
        with source_authority.pinned_snapshot(space_ref) as snap:
            watermark["source_authority_id"] = str(snap.authority_ref)
            watermark["source_authority_stream_id"] = str(snap.stream_ref)
            watermark["source_authority_generation"] = int(snap.generation)
    return watermark


def _collect_authorization_rules(
    connection: Connection, org_id: int, space_id: int, source_rows: list[dict],
) -> dict:
    source_ids = [row["source_id"] for row in source_rows]
    src_ref_by_id = {row["source_id"]: str(row["source_ref"]) for row in source_rows}
    owner_id, space_ref = connection.execute(
        """
        SELECT s.owner_principal_id, oi.public_id
        FROM thalion.space AS s
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (s.org_id, s.space_id, 'space', s.space_id)
        WHERE (s.org_id, s.space_id) = (%s, %s)
        """,
        (org_id, space_id),
    ).fetchone()
    principal_ids: set[int] = {owner_id}
    for row in source_rows:
        for key in ("owner_principal_id", "collector_id", "approver_id", "processor_id", "quality_reviewer_id"):
            if row.get(key) is not None:
                principal_ids.add(row[key])

    binding_rows = _all(
        connection,
        """
        SELECT pb.source_id, pb.revision, pb.subject_id, pb.passage_ref, pb.version_ref,
               pb.operation, pb.effect, pb.purpose, pb.destination, pb.fields,
               pb.valid_from, pb.valid_until
        FROM thalion.source AS s
        JOIN thalion.permission_binding AS pb
          ON (pb.org_id, pb.space_id, pb.source_id, pb.revision)
           = (s.org_id, s.space_id, s.source_id, s.local_policy_revision)
        WHERE (s.org_id, s.space_id) = (%s, %s) AND s.source_id = ANY(%s)
        ORDER BY pb.source_id, pb.binding_id
        """,
        (org_id, space_id, source_ids),
    )
    for row in binding_rows:
        principal_ids.add(row["subject_id"])

    shared_groups: list[dict] = []
    if connection.execute("SELECT to_regclass('thalion.shared_group') IS NOT NULL").fetchone()[0]:
        group_rows = _all(
            connection,
            """
            SELECT g.group_ref, g.target_source_id, g.group_principal_id, g.name, g.purpose,
                   g.scope_summary, g.created_by, g.basis_ref, g.starts_at, g.review_at, g.expires_at,
                   (r.group_ref IS NOT NULL) AS revoked
            FROM thalion.shared_group AS g
            LEFT JOIN thalion.shared_group_revocation AS r USING (group_ref)
            WHERE (g.org_id, g.owner_space_id, g.target_space_id) = (%s, %s, %s)
              AND g.target_source_id = ANY(%s)
            ORDER BY g.recorded_at, g.group_ref
            """,
            (org_id, space_id, space_id, source_ids),
        )
        for grp in group_rows:
            principal_ids.add(grp["group_principal_id"])
            principal_ids.add(grp["created_by"])
            members = _all(
                connection,
                """
                SELECT m.membership_ref, m.member_principal_id, m.starts_at, m.expires_at,
                       (mr.membership_ref IS NOT NULL) AS revoked
                FROM thalion.shared_group_member AS m
                LEFT JOIN thalion.shared_group_member_revocation AS mr USING (membership_ref)
                WHERE (m.org_id, m.owner_space_id, m.group_ref) = (%s, %s, %s)
                ORDER BY m.recorded_at, m.membership_ref
                """,
                (org_id, space_id, grp["group_ref"]),
            )
            for mem in members:
                principal_ids.add(mem["member_principal_id"])
            grp["members"] = members
        shared_groups = group_rows

    principals = _principal_ref_map(connection, org_id, principal_ids)

    release_cfg = None
    if connection.execute("SELECT to_regclass('thalion.current_space_release_config') IS NOT NULL").fetchone()[0]:
        cfg_row = _one(
            connection,
            """
            SELECT generation, action, wiki_delivery_enabled, lexical_index_mode,
                   template_key, template_revision_ref, rollback_trigger_summary, reason_code
            FROM thalion.current_space_release_config
            WHERE (org_id, space_id) = (%s, %s)
            """,
            (org_id, space_id),
        )
        if cfg_row is not None:
            release_cfg = {
                "generation": cfg_row["generation"],
                "action": cfg_row["action"],
                "wiki_delivery_enabled": bool(cfg_row["wiki_delivery_enabled"]),
                "lexical_index_mode": cfg_row["lexical_index_mode"],
                "template_key": cfg_row["template_key"],
                "template_revision_id": str(cfg_row["template_revision_ref"]) if cfg_row["template_revision_ref"] else None,
                "rollback_trigger_summary": cfg_row["rollback_trigger_summary"],
                "reason_code": cfg_row["reason_code"],
            }

    return {
        "space_id": str(space_ref),
        "space_owner_id": principals[owner_id]["principal_id"],
        "principals": sorted(principals.values(), key=lambda item: item["principal_id"]),
        "source_roles": [
            {
                "source_id": str(row["source_ref"]),
                "owner_id": principals[row["owner_principal_id"]]["principal_id"],
                "collector_id": principals[row["collector_id"]]["principal_id"],
                "approver_id": principals[row["approver_id"]]["principal_id"] if row.get("approver_id") else None,
                "processor_id": principals[row["processor_id"]]["principal_id"] if row.get("processor_id") else None,
                "quality_reviewer_id": principals[row["quality_reviewer_id"]]["principal_id"]
                if row.get("quality_reviewer_id") else None,
            }
            for row in source_rows
        ],
        "bindings": [
            {
                "source_id": src_ref_by_id[row["source_id"]],
                "policy_revision": int(row["revision"]),
                "subject_id": principals[row["subject_id"]]["principal_id"],
                "passage_id": str(row["passage_ref"]) if row["passage_ref"] else None,
                "version_id": str(row["version_ref"]) if row["version_ref"] else None,
                "operation": row["operation"],
                "effect": row["effect"],
                "purpose": row["purpose"],
                "destination": row["destination"],
                "fields": sorted(row["fields"]),
                "valid_from": row["valid_from"].astimezone(UTC).isoformat(),
                "valid_until": row["valid_until"].astimezone(UTC).isoformat() if row["valid_until"] else None,
            }
            for row in binding_rows
        ],
        "shared_groups": [
            {
                "group_id": str(grp["group_ref"]),
                "target_source_id": src_ref_by_id[grp["target_source_id"]],
                "group_principal_id": principals[grp["group_principal_id"]]["principal_id"],
                "name": grp["name"],
                "purpose": grp["purpose"],
                "scope_summary": grp["scope_summary"],
                "basis_id": str(grp["basis_ref"]),
                "starts_at": grp["starts_at"].astimezone(UTC).isoformat(),
                "review_at": grp["review_at"].astimezone(UTC).isoformat(),
                "expires_at": grp["expires_at"].astimezone(UTC).isoformat(),
                "revoked": bool(grp["revoked"]),
                "members": [
                    {
                        "membership_id": str(mem["membership_ref"]),
                        "member_principal_id": principals[mem["member_principal_id"]]["principal_id"],
                        "starts_at": mem["starts_at"].astimezone(UTC).isoformat(),
                        "expires_at": mem["expires_at"].astimezone(UTC).isoformat(),
                        "revoked": bool(mem["revoked"]),
                    }
                    for mem in grp["members"]
                ],
            }
            for grp in shared_groups
        ],
        "space_release": release_cfg,
    }


def _collect_safety_decisions(
    connection: Connection, org_id: int, space_id: int, source_rows: list[dict],
) -> dict:
    source_ids = [row["source_id"] for row in source_rows]
    stops = _all(
        connection,
        """
        SELECT st.decision_ref, src_oi.public_id AS source_ref, doc_oi.public_id AS document_ref,
               ver_oi.public_id AS version_ref, st.kind, st.basis_ref, st.recorded_at
        FROM thalion.rule_use_stop AS st
        JOIN thalion.object_identity AS src_oi
          ON (src_oi.org_id, src_oi.space_id, src_oi.object_type, src_oi.object_id)
           = (st.org_id, st.space_id, 'source', st.source_id)
        JOIN thalion.object_identity AS doc_oi
          ON (doc_oi.org_id, doc_oi.space_id, doc_oi.object_type, doc_oi.object_id)
           = (st.org_id, st.space_id, 'document', st.document_id)
        JOIN thalion.object_identity AS ver_oi
          ON (ver_oi.org_id, ver_oi.space_id, ver_oi.object_type, ver_oi.object_id)
           = (st.org_id, st.space_id, 'document_version', st.version_id)
        WHERE (st.org_id, st.space_id) = (%s, %s) AND st.source_id = ANY(%s)
        ORDER BY st.recorded_at, st.decision_ref
        """,
        (org_id, space_id, source_ids),
    )
    receipts = []
    if connection.execute("SELECT to_regclass('thalion.source_restriction_receipt') IS NOT NULL").fetchone()[0]:
        receipts = _all(
            connection,
            """
            SELECT r.event_ref, src_oi.public_id AS source_ref, r.kind, r.target_ref,
                   r.decision_ref, r.local_stop_ref, r.authority_generation, r.committed_at
            FROM thalion.source_restriction_receipt AS r
            JOIN thalion.object_identity AS src_oi
              ON (src_oi.org_id, src_oi.space_id, src_oi.object_type, src_oi.object_id)
               = (r.org_id, r.space_id, 'source', r.source_id)
            WHERE (r.org_id, r.space_id) = (%s, %s) AND r.source_id = ANY(%s)
            ORDER BY r.committed_at, r.event_ref
            """,
            (org_id, space_id, source_ids),
        )
    wiki_stops = _all(
        connection,
        """
        SELECT ev.publication_ref, ev.reason, ev.cause_ref, ev.recorded_at, pub.topic_key, pub.revision_ref
        FROM thalion.wiki_availability_event AS ev
        JOIN thalion.wiki_publication_event AS pub
          ON (pub.org_id, pub.space_id, pub.publication_ref) = (ev.org_id, ev.space_id, ev.publication_ref)
        WHERE (ev.org_id, ev.space_id) = (%s, %s)
        ORDER BY ev.recorded_at, ev.publication_ref, ev.reason
        """,
        (org_id, space_id),
    )
    return {
        "rule_use_stops": [
            {
                "decision_id": str(row["decision_ref"]),
                "source_id": str(row["source_ref"]),
                "document_id": str(row["document_ref"]),
                "version_id": str(row["version_ref"]),
                "kind": row["kind"],
                "basis_id": str(row["basis_ref"]),
                "recorded_at": row["recorded_at"].astimezone(UTC).isoformat(),
            }
            for row in stops
        ],
        "source_restriction_receipts": [
            {
                "event_id": str(row["event_ref"]),
                "source_id": str(row["source_ref"]),
                "kind": row["kind"],
                "target_id": str(row["target_ref"]),
                "decision_id": str(row["decision_ref"]),
                "local_stop_id": str(row["local_stop_ref"]) if row["local_stop_ref"] else None,
                "authority_generation": row["authority_generation"],
                "committed_at": row["committed_at"].astimezone(UTC).isoformat(),
            }
            for row in receipts
        ],
        "wiki_availability_events": [
            {
                "publication_id": str(row["publication_ref"]),
                "revision_id": str(row["revision_ref"]),
                "topic_key": row["topic_key"],
                "reason": row["reason"],
                "cause_id": str(row["cause_ref"]),
                "recorded_at": row["recorded_at"].astimezone(UTC).isoformat(),
            }
            for row in wiki_stops
        ],
    }


def _collect_space_scope(
    connection: Connection,
    org_id: int,
    space_id: int,
    requester_id: int,
    source_refs: Sequence[UUID],
    version_refs: Sequence[UUID],
    wiki_revisions: Sequence[UUID],
    *,
    lock: bool = False,
) -> dict:
    if not 1 <= len(source_refs) <= MAX_SPACE_SOURCES or len(set(source_refs)) != len(source_refs):
        raise ValueError("Space archive requires 1 to 20 unique source identifiers.")
    if not 1 <= len(version_refs) <= MAX_SPACE_VERSIONS or len(set(version_refs)) != len(version_refs):
        raise ValueError("Space archive requires 1 to 100 unique version identifiers.")
    if len(wiki_revisions) > MAX_SPACE_WIKIS or len(set(wiki_revisions)) != len(wiki_revisions):
        raise ValueError("Space archive supports up to 40 unique Wiki revisions.")

    source_rows = _all(
        connection,
        f"""
        SELECT s.source_id, oi.public_id AS source_ref, s.source_key, s.owner_principal_id,
               s.contract_revision, s.local_policy_revision, s.safety_epoch,
               c.object_namespace, c.collector_id, c.approver_id, c.processor_id,
               c.quality_reviewer_id, c.docx_amount_columns
        FROM thalion.source AS s
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id) = (s.org_id, s.space_id, 'source', s.source_id)
        JOIN thalion.source_contract_revision AS c
          ON (c.org_id, c.space_id, c.source_id, c.revision) = (s.org_id, s.space_id, s.source_id, s.contract_revision)
        WHERE (s.org_id, s.space_id) = (%s, %s) AND oi.public_id = ANY(%s)
        ORDER BY s.source_id
        {"FOR UPDATE OF s" if lock else ""}
        """,
        (org_id, space_id, list(source_refs)),
    )
    if len(source_rows) != len(source_refs):
        raise OperationsNotAdmitted("One or more selected sources do not belong to this space.")
    if any(row["owner_principal_id"] != requester_id for row in source_rows):
        raise OperationsNotAdmitted("Requester must currently own every selected source.")
    source_id_set = {row["source_id"] for row in source_rows}

    version_rows = _all(
        connection,
        """
        SELECT target.*
        FROM thalion.synthetic_original_export_target AS target
        WHERE (target.org_id, target.space_id) = (%s, %s) AND target.version_ref = ANY(%s)
        ORDER BY target.version_id
        """,
        (org_id, space_id, list(version_refs)),
    )
    if len(version_rows) != len(version_refs):
        raise OperationsNotAdmitted("One or more selected versions are unavailable in this space.")
    for row in version_rows:
        if lock:
            connection.execute("SELECT thalion.lock_synthetic_export_target(%s, %s, %s)", (org_id, space_id, row["version_id"]))
        if row["source_id"] not in source_id_set:
            raise OperationsNotAdmitted("Every archived version must belong to a selected source.")
        if row["blocked"]:
            raise DispositionConflict("An archived version is currently blocked by a hold, stop, or deletion.")
        if row["media_type"] not in ("text/markdown", PDF_MEDIA_TYPE, DOCX_MEDIA_TYPE):
            raise DispositionConflict("An archived version has an unsupported reconstruction media type.")
        transcript = current_transcript(connection, org_id, space_id, row["version_id"])
        history, _ = _load_repair_history(connection, org_id, space_id, row, transcript[0])
        repaired = history is not None
        metadata = rebuild_metadata(
            connection, org_id, space_id, row["version_id"], transcript[1],
            repaired=repaired, media_type=row["media_type"],
        )
        row["transcript_run_ref"] = transcript[0]
        row["transcript_config_rev"] = transcript[1]
        row["transcript_manifest_digest"] = transcript[2]
        row["repair_history_digest"] = sha256(history).digest() if history is not None else None
        row["rebuild_metadata"] = metadata
        row["rebuild_metadata_digest"] = _metadata_digest(metadata)

    version_by_ref = {row["version_ref"]: row for row in version_rows}
    admitted_source_ids = [row["source_id"] for row in source_rows]
    admitted_version_ids = [row["version_id"] for row in version_rows]

    def _space_wiki_material(pub_ref: UUID, topic_key: str) -> tuple[bytes, list[dict], list[dict]]:
        root, = connection.execute(
            """
            SELECT revision.manifest_ref
            FROM thalion.wiki_publication_event AS pub
            JOIN thalion.wiki_revision AS revision USING (org_id, space_id, revision_ref)
            WHERE (pub.org_id, pub.space_id, pub.publication_ref) = (%s, %s, %s)
            """,
            (org_id, space_id, pub_ref),
        ).fetchone()
        graph = _manifest_graph(connection, org_id, space_id, root)
        deps = _all(
            connection,
            """
            SELECT DISTINCT target.version_id, target.version_ref, target.source_id, target.snapshot,
                            target.storage_key, target.content_digest, target.byte_length, target.media_type,
                            input.run_ref AS transcript_run_ref, run.replaces_run_ref
            FROM thalion.wiki_archive_input AS input
            JOIN thalion.synthetic_original_export_target AS target USING (org_id, space_id, version_id)
            JOIN thalion.processing_run AS run ON run.run_ref = input.run_ref
            WHERE (input.org_id, input.space_id, input.publication_ref) = (%s, %s, %s) AND NOT target.blocked
            ORDER BY target.version_ref
            """,
            (org_id, space_id, pub_ref),
        )
        if not 1 <= len(deps) <= MAX_WIKI_INPUTS or len({item["version_ref"] for item in deps}) != len(deps):
            raise DispositionConflict("The Wiki archive requires bounded unique source versions.")
        if any(
            item["media_type"] not in {"text/markdown", PDF_MEDIA_TYPE, DOCX_MEDIA_TYPE}
            or item["replaces_run_ref"] is not None
            for item in deps
        ):
            raise DispositionConflict("Wiki rebuild requires every input to have a supported reconstruction format.")
        dep_refs = {item["version_ref"] for item in deps}
        if not dep_refs <= set(version_by_ref):
            raise DispositionConflict(
                "Wiki dependency closure requires every input version to be admitted in the archive scope."
            )
        pin_versions = []
        passage_count = 0
        for dep in deps:
            transcript = current_transcript(connection, org_id, space_id, dep["version_id"], dep["transcript_run_ref"])
            passage_count += transcript[3]
            if passage_count > MAX_TRANSCRIPT_PASSAGES:
                raise DispositionConflict("The complete Wiki transcript scope exceeds the archive limit.")
            dep_meta = rebuild_metadata(
                connection, org_id, space_id, dep["version_id"], transcript[1], media_type=dep["media_type"],
            )
            pin_versions.append((
                str(dep["version_ref"]), dep["snapshot"], dep["content_digest"].hex(),
                dep["byte_length"], str(transcript[0]), transcript[2].hex(), dep_meta,
            ))
        digest = sha256(canonical_json([str(pub_ref), topic_key, graph, pin_versions])).digest()
        return digest, graph, deps

    def _require_space_current_wiki(pub_ref: UUID):
        if lock:
            connection.execute("SELECT thalion.lock_synthetic_wiki_export(%s, %s, %s)", (org_id, space_id, pub_ref))
        is_current = connection.execute(
            "SELECT thalion.space_archive_wiki_is_current(%s, %s, %s, %s, %s)",
            (org_id, space_id, admitted_source_ids, admitted_version_ids, pub_ref),
        ).fetchone()[0]
        if not is_current:
            raise DispositionConflict("The Wiki publication or its complete multi-source input scope is no longer available.")

    wiki_entries: list[dict] = []
    for rev_ref in sorted(wiki_revisions):
        selected = connection.execute(
            """
            SELECT pub.publication_ref, pub.topic_key, w.wiki_ref, pub.revision_ref,
                   rev.author_id, rev.reviewer_id, req.business_date
            FROM thalion.available_wiki_publication AS pub
            JOIN thalion.wiki AS w USING (org_id, space_id, topic_key)
            JOIN thalion.wiki_revision AS rev USING (org_id, space_id, topic_key, revision_ref)
            JOIN thalion.delivery_record AS del ON (del.org_id, del.check_id) = (pub.org_id, pub.check_id)
            JOIN thalion.request_record AS req ON (req.org_id, req.request_id) = (del.org_id, del.request_id)
            WHERE (pub.org_id, pub.space_id, pub.revision_ref) = (%s, %s, %s)
            """,
            (org_id, space_id, rev_ref),
        ).fetchone()
        if selected is None:
            raise DispositionConflict("A selected Wiki revision is not currently available for export.")
        pub_ref, topic_key, wiki_ref, _, author_id, reviewer_id, wiki_business_date = selected
        digest, graph, deps = _space_wiki_material(pub_ref, topic_key)
        dep_refs = {item["version_ref"] for item in deps}
        anchor_version = version_by_ref[sorted(dep_refs)[0]]
        _require_space_current_wiki(pub_ref)
        wiki_entries.append({
            "publication_ref": pub_ref,
            "revision_ref": rev_ref,
            "wiki_ref": wiki_ref,
            "topic_key": topic_key,
            "author_id": author_id,
            "reviewer_id": reviewer_id,
            "business_date": wiki_business_date,
            "anchor_version": anchor_version,
            "material_digest": digest,
            "graph": graph,
            "dep_versions": deps,
        })

    effectivity_rows = _all(
        connection,
        """
        SELECT oi.public_id AS version_ref, re.decision_ref, re.region, re.traveler_class,
               re.valid_from, re.valid_to, re.basis_ref, re.replaces_ref
        FROM thalion.rule_effectivity AS re
        JOIN thalion.object_identity AS oi
          ON (oi.org_id, oi.space_id, oi.object_type, oi.object_id)
           = (re.org_id, re.space_id, 'document_version', re.version_id)
        WHERE (re.org_id, re.space_id) = (%s, %s) AND re.version_id = ANY(%s)
        ORDER BY oi.public_id, re.valid_from, re.decision_ref
        """,
        (org_id, space_id, [row["version_id"] for row in version_rows]),
    )
    eff_by_version: dict[str, list[dict]] = {str(row["version_ref"]): [] for row in version_rows}
    for row in effectivity_rows:
        eff_by_version[str(row["version_ref"])].append({
            "decision_id": str(row["decision_ref"]),
            "region": row["region"],
            "traveler_class": row["traveler_class"],
            "valid_from": row["valid_from"].isoformat(),
            "valid_to": row["valid_to"].isoformat() if row["valid_to"] else None,
            "basis_id": str(row["basis_ref"]),
            "replaces_id": str(row["replaces_ref"]) if row["replaces_ref"] else None,
        })

    watermark = _collect_recovery_watermark(connection, org_id, space_id, source_rows)
    scope_pin = canonical_json({
        "sources": [str(row["source_ref"]) for row in source_rows],
        "versions": [
            [
                str(row["version_ref"]),
                row["snapshot"],
                row["content_digest"].hex(),
                str(row["transcript_run_ref"]),
                row["transcript_manifest_digest"].hex(),
                row["rebuild_metadata_digest"].hex(),
                row["repair_history_digest"].hex() if row["repair_history_digest"] else None,
            ]
            for row in version_rows
        ],
        "wikis": [[str(item["publication_ref"]), str(item["revision_ref"]), item["material_digest"].hex()] for item in wiki_entries],
    })
    org_epoch = watermark["org_safety_epoch"]
    space_epoch = watermark["space_safety_epoch"]
    max_source_epoch = max(row["safety_epoch"] for row in source_rows)
    return {
        "sources": source_rows,
        "versions": version_rows,
        "wikis": wiki_entries,
        "effectivity": eff_by_version,
        "watermark": watermark,
        "scope_digest": sha256(scope_pin).digest(),
        "watermark_digest": sha256(canonical_json(watermark)).digest(),
        "safety_snapshot": [org_epoch, space_epoch, max_source_epoch],
    }


def request_space_archive(
    connection: Connection,
    call: OperationsCall,
    *,
    source_refs: Sequence[UUID],
    version_refs: Sequence[UUID],
    wiki_revisions: Sequence[UUID] = (),
) -> dict:
    owner_id = require_scope(connection, call, REQUEST, destination=DESTINATION)
    if owner_id != call.principal_id:
        raise OperationsNotAdmitted("Only the active space owner may request a space archive.")
    command = command_for(
        call, REQUEST, (
            [str(item) for item in sorted(source_refs)],
            [str(item) for item in sorted(version_refs)],
            [str(item) for item in sorted(wiki_revisions)],
        ),
    )

    def apply(transaction):
        collected = _collect_space_scope(
            transaction, call.org_id, call.space_id, call.principal_id,
            source_refs, version_refs, wiki_revisions, lock=True,
        )
        export_ref, = transaction.execute(
            """
            INSERT INTO thalion.space_archive_request (
                org_id, space_id, requester_id, source_ids, version_ids, wiki_publication_refs,
                scope_digest, watermark_digest, safety_snapshot, request_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING export_ref
            """,
            (
                call.org_id, call.space_id, call.principal_id,
                [row["source_id"] for row in collected["sources"]],
                [row["version_id"] for row in collected["versions"]],
                [item["publication_ref"] for item in collected["wikis"]],
                collected["scope_digest"], collected["watermark_digest"],
                collected["safety_snapshot"], call.request_id,
            ),
        ).fetchone()
        space_ref = UUID(collected["watermark"]["space_id"])
        append_event(transaction, call.org_id, "lifecycle.space_archive.requested", space_ref, space_id=call.space_id)
        return export_ref

    export_ref = execute_command(connection, command, apply).result_ref
    return {
        "export_id": str(export_ref),
        "state": "requested",
        "scope": SPACE_ARCHIVE_SCOPE,
        "format_version": SPACE_ARCHIVE_FORMAT,
        "source_count": len(source_refs),
        "version_count": len(version_refs),
        "wiki_count": len(wiki_revisions),
    }


def _load_request_record(connection: Connection, org_id: int, space_id: int, export_id: UUID) -> dict:
    req = _one(
        connection,
        """
        SELECT req.*,
               ARRAY(
                   SELECT oi.public_id FROM thalion.object_identity AS oi
                   WHERE (oi.org_id, oi.space_id, oi.object_type) = (req.org_id, req.space_id, 'source')
                     AND oi.object_id = ANY(req.source_ids)
                   ORDER BY oi.object_id
               ) AS source_refs,
               ARRAY(
                   SELECT oi.public_id FROM thalion.object_identity AS oi
                   WHERE (oi.org_id, oi.space_id, oi.object_type) = (req.org_id, req.space_id, 'document_version')
                     AND oi.object_id = ANY(req.version_ids)
                   ORDER BY oi.object_id
               ) AS version_refs,
               ARRAY(
                   SELECT pub.revision_ref FROM thalion.wiki_publication_event AS pub
                   WHERE (pub.org_id, pub.space_id) = (req.org_id, req.space_id)
                     AND pub.publication_ref = ANY(req.wiki_publication_refs)
                   ORDER BY pub.revision_ref
               ) AS wiki_revisions,
               s.owner_principal_id AS space_owner_id,
               sp_oi.public_id AS space_ref
        FROM thalion.space_archive_request AS req
        JOIN thalion.space AS s USING (org_id, space_id)
        JOIN thalion.object_identity AS sp_oi
          ON (sp_oi.org_id, sp_oi.space_id, sp_oi.object_type, sp_oi.object_id) = (s.org_id, s.space_id, 'space', s.space_id)
        WHERE (req.org_id, req.space_id, req.export_ref) = (%s, %s, %s)
        """,
        (org_id, space_id, export_id),
    )
    if req is None:
        raise OperationsNotAdmitted("The space archive request does not belong to this space.")
    return req


def approve_space_archive(
    connection: Connection, call: OperationsCall, export_id: UUID, expires_at: datetime,
) -> dict:
    require_scope(connection, call, APPROVE, destination=DESTINATION)
    req = _load_request_record(connection, call.org_id, call.space_id, export_id)
    if call.principal_id in (req["requester_id"], req["space_owner_id"]):
        raise OperationsNotAdmitted("Independent approval by a non-owner employee is required.")
    rules.require_aware(expires_at)
    expires_at = expires_at.astimezone(UTC)
    command = command_for(call, APPROVE, (str(export_id), expires_at.isoformat()))

    def apply(transaction):
        now = datetime.now(UTC)
        if not now < expires_at <= now + timedelta(minutes=15):
            raise ValueError("A space archive approval must expire within fifteen minutes.")
        collected = _collect_space_scope(
            transaction, call.org_id, call.space_id, req["requester_id"],
            req["source_refs"], req["version_refs"], req["wiki_revisions"], lock=True,
        )
        if collected["scope_digest"] != bytes(req["scope_digest"]):
            raise DispositionConflict("Space archive scope changed after the request was enrolled.")
        if any(row["approver_id"] != call.principal_id for row in collected["sources"]):
            raise OperationsNotAdmitted("Approver must hold approval authority over every selected source.")
        inserted = transaction.execute(
            """
            INSERT INTO thalion.space_archive_approval (
                org_id, space_id, export_ref, requester_id, approver_id, request_id, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (export_ref) DO NOTHING
            RETURNING approval_ref
            """,
            (call.org_id, call.space_id, export_id, req["requester_id"], call.principal_id, call.request_id, expires_at),
        ).fetchone()
        if inserted is None:
            raise DispositionConflict("An approval already exists for this space archive request.")
        append_event(transaction, call.org_id, "lifecycle.space_archive.approved", req["space_ref"], space_id=call.space_id)
        return inserted[0]

    approval_ref = execute_command(connection, command, apply).result_ref
    return {
        "export_id": str(export_id),
        "approval_id": str(approval_ref),
        "state": "approved",
        "expires_at": expires_at.isoformat(),
    }


def seal_space_archive(
    connection: Connection,
    call: OperationsCall,
    export_id: UUID,
    store: SyntheticOriginalStore,
    context: delivery.DeliveryContext,
    check_authority: Callable[[delivery.DeliveryCheck], delivery.AuthorityDecision],
    *,
    rule_log: Connection | None = None,
    source_authority: SourceRevocationAuthority | None = None,
) -> dict:
    require_scope(connection, call, EXPORT, destination=DESTINATION)
    req = _load_request_record(connection, call.org_id, call.space_id, export_id)
    if req["requester_id"] != call.principal_id or req["space_owner_id"] != call.principal_id:
        raise OperationsNotAdmitted("Only the active requesting space owner may seal the space archive.")
    approval = _one(
        connection,
        f"""
        SELECT a.approval_ref, a.approver_id, a.expires_at
        FROM thalion.space_archive_approval AS a
        JOIN thalion.principal AS p ON (p.org_id, p.principal_id) = (a.org_id, a.approver_id)
        JOIN thalion.principal AS caller ON (caller.org_id, caller.principal_id) = (a.org_id, %s)
        WHERE (a.org_id, a.space_id, a.export_ref) = (%s, %s, %s)
          AND NOT p.disabled AND p.principal_type = 'employee'
          AND {sql_admitted_issuer('p.authority_issuer')}
          AND {sql_issuers_same_mode('p.authority_issuer', 'caller.authority_issuer')}
        """,
        (call.principal_id, call.org_id, call.space_id, export_id),
    )
    seen_at = datetime.now(UTC)
    if approval is None or approval["expires_at"] <= seen_at:
        raise DispositionConflict("A live independent approval is required before sealing the space archive.")

    collected = _collect_space_scope(
        connection, call.org_id, call.space_id, call.principal_id,
        req["source_refs"], req["version_refs"], req["wiki_revisions"], lock=False,
    )
    if collected["scope_digest"] != bytes(req["scope_digest"]):
        raise DispositionConflict("Space archive scope changed before sealing.")

    auth_rules = _collect_authorization_rules(connection, call.org_id, call.space_id, collected["sources"])
    safety_decisions = _collect_safety_decisions(connection, call.org_id, call.space_id, collected["sources"])
    watermark = _collect_recovery_watermark(
        connection, call.org_id, call.space_id, collected["sources"],
        rule_log=rule_log, source_authority=source_authority,
    )
    auth_bytes = canonical_json(auth_rules)
    safety_bytes = canonical_json(safety_decisions)
    effectivity_bytes = canonical_json({"versions": collected["effectivity"]})

    files: dict[str, bytes] = {
        "authorization/rules.json": auth_bytes,
        "safety/decisions.json": safety_bytes,
        "versions/effectivity.json": effectivity_bytes,
    }
    scopes_epochs: dict[delivery.EvidenceScope, delivery.SafetyEpochs] = {}
    version_entries: list[dict] = []
    wiki_manifest_entries: list[dict] = []
    source_epochs = {
        row["source_id"]: delivery.SafetyEpochs(
            watermark["org_safety_epoch"], watermark["space_safety_epoch"], int(row["safety_epoch"]),
        )
        for row in collected["sources"]
    }
    for row in collected["sources"]:
        src_scope = delivery.EvidenceScope(
            call.space_id, row["source_id"], row["source_ref"], frozenset({AUTH_FIELD, SAFETY_FIELD}),
        )
        scopes_epochs[src_scope] = source_epochs[row["source_id"]]

    try:
        for row in collected["versions"]:
            original = store.read(OriginalAsset(row["storage_key"], row["content_digest"], row["byte_length"]))
            nested_target = row | {"export_ref": export_id}
            members, part_scopes, _ = archive_files(
                connection, call.org_id, call.space_id, nested_target, original, row["rebuild_metadata"],
            )
            packed = _archive(members)
            ref = row["version_ref"]
            files[f"versions/{ref}.zip"] = packed
            version_entries.append({
                "version_id": str(ref),
                "source_id": str(row["rebuild_metadata"]["source_id"]),
                "document_id": str(row["rebuild_metadata"]["document_id"]),
                "media_type": row["media_type"],
                "repaired": row["repair_history_digest"] is not None,
                "sha256": sha256(packed).hexdigest(),
            })
            ep = source_epochs[row["source_id"]]
            scopes_epochs[delivery.EvidenceScope(call.space_id, row["source_id"], ref, FIELDS)] = ep
            for part_scope in part_scopes:
                scopes_epochs[part_scope] = source_epochs[part_scope.source_id]
    except OriginalIntegrityError:
        raise DispositionInventoryUnavailable("Approved original bytes could not be verified.") from None

    admitted_source_ids = [row["source_id"] for row in collected["sources"]]
    admitted_version_ids = [row["version_id"] for row in collected["versions"]]
    for item in collected["wikis"]:
        pub_ref = item["publication_ref"]
        if not connection.execute(
            "SELECT thalion.space_archive_wiki_is_current(%s, %s, %s, %s, %s)",
            (call.org_id, call.space_id, admitted_source_ids, admitted_version_ids, pub_ref),
        ).fetchone()[0]:
            raise DispositionConflict("The Wiki publication or its complete multi-source input scope is no longer available.")
        revision, content, digest, manifest_ref, format_revision, input_digest, direct_count, parents, dep_count = connection.execute(
            """
            SELECT revision.revision_ref, revision.content, revision.content_digest, manifest.manifest_ref,
                   manifest.format_revision, revision.input_digest, manifest.direct_count, manifest.parent_refs, seal.dependency_count
            FROM thalion.wiki_publication_event AS publication
            JOIN thalion.wiki_revision AS revision USING (org_id, space_id, revision_ref)
            JOIN thalion.input_manifest AS manifest USING (manifest_ref)
            JOIN thalion.delivery_record AS seal ON seal.check_id = manifest.check_id
            WHERE (publication.org_id, publication.space_id, publication.publication_ref) = (%s, %s, %s)
            """,
            (call.org_id, call.space_id, pub_ref),
        ).fetchone()
        parts = connection.execute(
            """
            SELECT position, source_id, version_ref, passage_ref, excerpt_revision, run_ref, content_digest
            FROM thalion.wiki_archive_input WHERE (org_id, space_id, publication_ref) = (%s, %s, %s)
            ORDER BY position LIMIT 21
            """,
            (call.org_id, call.space_id, pub_ref),
        ).fetchall()
        if not 1 <= dep_count <= 20 or len(parts) != dep_count or sha256(content).digest() != digest:
            raise DispositionInventoryUnavailable("The exact Wiki content or sealed input manifest could not be verified.")
        wiki_scopes = [delivery.EvidenceScope(call.space_id, item["anchor_version"]["source_id"], revision, frozenset({WIKI_FIELD}))]
        dependencies = []
        for position, part_source_id, part_version, passage, excerpt_revision, run, excerpt_digest in parts:
            wiki_scopes.append(delivery.EvidenceScope(call.space_id, part_source_id, passage, frozenset({TRANSCRIPT_FIELD}), excerpt_revision))
            dependencies.append({
                "position": position, "version_id": str(part_version), "passage_id": str(passage),
                "excerpt_revision": excerpt_revision, "run_id": str(run), "excerpt_sha256": excerpt_digest.hex(),
            })
        deps_bytes = canonical_json({
            "revision_id": str(revision), "publication_id": str(pub_ref), "content_sha256": digest.hex(),
            "manifest_id": str(manifest_ref), "manifest_format_revision": format_revision, "input_sha256": input_digest.hex(),
            "direct_count": direct_count, "parent_manifest_ids": [str(parent) for parent in parents], "inputs": dependencies,
        })
        md_bytes = json.loads(content)["markdown"].encode("utf-8")
        rev_str = str(item["revision_ref"])
        graph_bytes = canonical_json({"manifests": item["graph"]})
        files[f"wikis/{rev_str}/revision.json"] = content
        files[f"wikis/{rev_str}/content.md"] = md_bytes
        files[f"wikis/{rev_str}/dependencies.json"] = deps_bytes
        files[f"wikis/{rev_str}/manifests.json"] = graph_bytes
        wiki_manifest_entries.append({
            "wiki_id": str(item["wiki_ref"]),
            "topic_key": item["topic_key"],
            "revision_id": rev_str,
            "publication_id": str(item["publication_ref"]),
            "business_date": item["business_date"].isoformat(),
            "revision_sha256": sha256(content).hexdigest(),
            "dependencies_sha256": sha256(deps_bytes).hexdigest(),
            "manifests_sha256": sha256(graph_bytes).hexdigest(),
        })
        for w_scope in wiki_scopes:
            scopes_epochs[w_scope] = source_epochs[w_scope.source_id]

    source_manifest_entries = [
        {
            "source_id": str(row["source_ref"]),
            "source_key": row["source_key"],
            "object_namespace": row["object_namespace"],
            "contract_revision": int(row["contract_revision"]),
            "docx_amount_columns": list(row["docx_amount_columns"]) if row.get("docx_amount_columns") else None,
        }
        for row in collected["sources"]
    ]
    manifest_bytes = canonical_json({
        "format": SPACE_ARCHIVE_FORMAT,
        "scope": SPACE_ARCHIVE_SCOPE,
        "restorable": False,
        "org_id": call.org_id,
        "space_id": call.space_id,
        "space_ref": str(req["space_ref"]),
        "export_id": str(export_id),
        "recovery_watermark": watermark,
        "sources": source_manifest_entries,
        "versions": version_entries,
        "wikis": wiki_manifest_entries,
        "effectivity_sha256": sha256(effectivity_bytes).hexdigest(),
        "authorization_rules_sha256": sha256(auth_bytes).hexdigest(),
        "safety_decisions_sha256": sha256(safety_bytes).hexdigest(),
    })
    files["manifest.json"] = manifest_bytes
    archive_bytes = _archive(files)
    if len(archive_bytes) > MAX_SPACE_ARCHIVE_BYTES:
        raise DispositionConflict("The space archive exceeds the configured size limit.")

    def load_local(_check):
        live_collected = _collect_space_scope(
            connection, call.org_id, call.space_id, call.principal_id,
            req["source_refs"], req["version_refs"], req["wiki_revisions"], lock=True,
        )
        if live_collected["scope_digest"] != bytes(req["scope_digest"]):
            raise DispositionConflict("Space archive scope changed during authority verification.")
        live_approval = _one(
            connection,
            f"""
            SELECT a.approval_ref, a.approver_id, a.expires_at
            FROM thalion.space_archive_approval AS a
            JOIN thalion.principal AS p ON (p.org_id, p.principal_id) = (a.org_id, a.approver_id)
            JOIN thalion.principal AS caller ON (caller.org_id, caller.principal_id) = (a.org_id, %s)
            WHERE (a.org_id, a.space_id, a.export_ref) = (%s, %s, %s)
              AND NOT p.disabled AND p.principal_type = 'employee'
              AND {sql_admitted_issuer('p.authority_issuer')}
              AND {sql_issuers_same_mode('p.authority_issuer', 'caller.authority_issuer')}
            FOR SHARE OF p
            """,
            (call.principal_id, call.org_id, call.space_id, export_id),
        )
        if live_approval != approval:
            raise DispositionConflict("Independent approval changed during sealing.")
        live_wm = live_collected["watermark"]
        live_src_epochs = {
            row["source_id"]: delivery.SafetyEpochs(
                live_wm["org_safety_epoch"], live_wm["space_safety_epoch"], int(row["safety_epoch"]),
            )
            for row in live_collected["sources"]
        }
        live_epochs = {sc: live_src_epochs[sc.source_id] for sc in scopes_epochs}
        bindings = tuple(
            rules.PermissionBinding(
                call.org_id, call.space_id, sc.source_id, sc.object_id, call.principal_id,
                EXPORT, "allow", frozenset({PURPOSE}), frozenset({ARCHIVE_DESTINATION}),
                sc.fields, seen_at, live_approval["expires_at"],
            )
            for sc in scopes_epochs
        )
        return delivery.LocalAuthorization(live_epochs, bindings)

    decision = delivery.authorize_delivery(
        context,
        delivery.DeliveryCandidate(archive_bytes, scopes_epochs),
        check_authority=check_authority,
        load_local=load_local,
    )
    if decision.status == "dependency_unavailable":
        raise delivery.AuthorizationUnavailable("Current archive authority could not be verified.")
    if decision.status == "input_changed":
        raise DispositionConflict("Space archive safety epochs changed during sealing.")
    if decision.status != "succeeded":
        raise OperationsNotAdmitted("Current source archive authority is required across all archived sources.")

    command = command_for(call, EXPORT, (str(export_id),))

    def apply(transaction):
        if datetime.now(UTC) >= decision.valid_until:
            raise DispositionConflict("Archive sealing authorization expired.")
        inserted = transaction.execute(
            """
            INSERT INTO thalion.space_archive_package (
                org_id, space_id, export_ref, requester_id, approval_ref, request_id,
                format_version, archive_bytes, recovery_watermark, proof_digest, authority_valid_until
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (export_ref) DO NOTHING
            RETURNING package_ref
            """,
            (
                call.org_id, call.space_id, export_id, call.principal_id, approval["approval_ref"],
                call.request_id, SPACE_ARCHIVE_FORMAT, decision.payload, Jsonb(watermark),
                sha256(decision.authority_proof_ref.encode("utf-8")).digest(), decision.valid_until,
            ),
        ).fetchone()
        if inserted is None:
            raise DispositionConflict("A package has already been sealed for this space archive request.")
        append_event(transaction, call.org_id, "lifecycle.space_archive.sealed", req["space_ref"], space_id=call.space_id)
        return inserted[0]

    package_ref = execute_command(connection, command, apply).result_ref
    digest, = connection.execute(
        """
        SELECT archive_digest FROM thalion.space_archive_package
        WHERE (org_id, space_id, export_ref, package_ref) = (%s, %s, %s, %s)
        """,
        (call.org_id, call.space_id, export_id, package_ref),
    ).fetchone()
    if digest.hex() != decision.payload_sha256 or datetime.now(UTC) >= decision.valid_until:
        raise DispositionConflict("Sealed archive bytes or validity window changed before completion.")
    return {
        "export_id": str(export_id),
        "package_id": str(package_ref),
        "state": "sealed",
        "scope": SPACE_ARCHIVE_SCOPE,
        "format_version": SPACE_ARCHIVE_FORMAT,
        "archive_sha256": digest.hex(),
        "recovery_watermark": watermark,
        "source_count": len(source_manifest_entries),
        "version_count": len(version_entries),
        "wiki_count": len(wiki_manifest_entries),
        "restorable": False,
    }


def _decode_embedded_version(permit: SpaceArchivePermit, version_ref: UUID, packed: bytes, media_type: str) -> dict:
    with ZipFile(BytesIO(packed)) as archive:
        entries = archive.infolist()
        members = {entry.filename: entry for entry in entries}
        if len(members) != len(entries) or "manifest.json" not in members:
            raise ArchiveRejected("Malformed embedded version archive.")
        manifest, _ = _json_object(archive, members["manifest.json"], max_bytes=32_768, ensure_ascii=True)
        if (
            manifest.get("restorable") is not False
            or manifest.get("org_id") != permit.org_id
            or manifest.get("space_id") != permit.space_id
            or manifest.get("export_id") != str(permit.export_ref)
            or manifest.get("version_id") != str(version_ref)
            or manifest.get("format_media_type") != media_type
        ):
            raise ArchiveRejected("Embedded version manifest does not match space archive permit.")
        original_name = ORIGINAL_MEMBERS[media_type]
        original = _read_member(archive, members[original_name], manifest["byte_length"])
        digest = sha256(original).digest()
        if digest.hex() != manifest["original_sha256"]:
            raise ArchiveRejected("Embedded original bytes do not match manifest digest.")
        transcript, raw_transcript = _json_object(
            archive, members["transcription.json"], max_bytes=3_145_728, ensure_ascii=False,
        )
        if sha256(raw_transcript).hexdigest() != manifest["transcription_sha256"]:
            raise ArchiveRejected("Embedded transcription does not match manifest digest.")
        repair_history_data = None
        if "repair_history_sha256" in manifest:
            repair_history_data, raw_repair = _json_object(
                archive, members["repair-history.json"], max_bytes=3_145_728, ensure_ascii=False,
            )
            if sha256(raw_repair).hexdigest() != manifest["repair_history_sha256"]:
                raise ArchiveRejected("Embedded repair history does not match manifest digest.")

        metadata = dict(manifest["rebuild"])
        metadata["source_id"] = canonical_ref(metadata["source_id"])
        metadata["document_id"] = canonical_ref(metadata["document_id"])
        _validate_keys(*(metadata[key] for key in ("source_key", "object_namespace", "object_key", "incarnation", "version_key")))

        if media_type == "text/markdown":
            candidate = markdown.parse_markdown(original)
            if candidate.outcome != "pending_review":
                raise ArchiveRejected("Archived Markdown cannot be parsed cleanly.")
            passage_entries = transcript["passages"]
            if len(passage_entries) != len(candidate.passages):
                raise ArchiveRejected("Archived Markdown passages do not match parser output.")
            passage_refs = tuple(canonical_ref(item["passage_id"]) for item in passage_entries)
            passage_revisions = {canonical_ref(item["passage_id"]): int(item["excerpt_revision"]) for item in passage_entries}
            passage_digests = {canonical_ref(item["passage_id"]): item["sha256"] for item in passage_entries}
            for item, part in zip(passage_entries, candidate.passages, strict=True):
                member_bytes = _read_member(archive, members[item["member"]], part.byte_end - part.byte_start)
                if member_bytes != original[part.byte_start:part.byte_end] or part.digest.hex() != item["sha256"]:
                    raise ArchiveRejected("Archived Markdown passage bytes do not match original.")
            return {
                "media_type": media_type,
                "version_ref": version_ref,
                "metadata": metadata,
                "original": original,
                "digest": digest,
                "run_ref": canonical_ref(transcript["run_id"]),
                "candidate": candidate,
                "passage_refs": passage_refs,
                "passage_revisions": passage_revisions,
                "passage_digests": passage_digests,
                "transcription": transcript,
                "repair_history": repair_history_data,
            }
        if media_type == DOCX_MEDIA_TYPE:
            amount_cols = tuple(metadata["docx_amount_columns"]) if metadata.get("docx_amount_columns") else None
            candidate = docx_evidence.parse_docx(original, amount_columns=amount_cols)
            if candidate.outcome != "pending_review":
                raise ArchiveRejected("Archived DOCX cannot be parsed cleanly.")
            para_entries = transcript["paragraphs"]
            cell_entries = [
                cell
                for table in transcript["tables"]
                for row in table["rows"]
                for cell in row["cells"]
            ]
            passage_refs = tuple(canonical_ref(item["passage_id"]) for item in para_entries)
            cell_refs = tuple(canonical_ref(item["passage_id"]) for item in cell_entries)
            passage_revisions = {}
            passage_digests = {}
            for item in (*para_entries, *cell_entries):
                pid = canonical_ref(item["passage_id"])
                passage_revisions[pid] = int(item["excerpt_revision"])
                passage_digests[pid] = item["sha256"]
                member_name = f"transcript/{pid}.txt"
                if member_name not in members:
                    raise ArchiveRejected("Missing DOCX transcript member.")
                raw_txt = _read_member(archive, members[member_name], members[member_name].file_size)
                if sha256(raw_txt).hexdigest() != item["sha256"]:
                    raise ArchiveRejected("DOCX transcript member digest mismatch.")
            return {
                "media_type": media_type,
                "version_ref": version_ref,
                "metadata": metadata,
                "original": original,
                "digest": digest,
                "run_ref": canonical_ref(transcript["run_id"]),
                "candidate": candidate,
                "passage_refs": passage_refs,
                "cell_refs": cell_refs,
                "passage_revisions": passage_revisions,
                "passage_digests": passage_digests,
                "transcription": transcript,
                "repair_history": repair_history_data,
            }
        if media_type == PDF_MEDIA_TYPE:
            pages = transcript["pages"]
            passage_refs = tuple(canonical_ref(p["passage_id"]) for p in pages if "passage_id" in p)
            passage_revisions = {canonical_ref(p["passage_id"]): int(p["excerpt_revision"]) for p in pages if "passage_id" in p}
            passage_digests = {canonical_ref(p["passage_id"]): p["sha256"] for p in pages if "passage_id" in p}
            page_texts = tuple(
                _read_member(archive, members[p["member"]], members[p["member"]].file_size) if "member" in p else None
                for p in pages
            )
            return {
                "media_type": media_type,
                "version_ref": version_ref,
                "metadata": metadata,
                "original": original,
                "digest": digest,
                "run_ref": canonical_ref(transcript["run_id"]),
                "passage_refs": passage_refs,
                "passage_revisions": passage_revisions,
                "passage_digests": passage_digests,
                "transcription": transcript,
                "page_transcripts": page_texts,
                "repair_history": repair_history_data,
            }
        raise ArchiveRejected("Unsupported archived media type.")


def _decode_space_archive(permit: SpaceArchivePermit, payload: bytes) -> _DecodedSpaceArchive:
    if len(payload) > MAX_SPACE_ARCHIVE_BYTES:
        raise ArchiveRejected("Space archive exceeds maximum permitted size.")
    _check_package(payload, permit.digest)
    try:
        with ZipFile(BytesIO(payload)) as archive:
            entries = archive.infolist()
            members = {entry.filename: entry for entry in entries}
            if len(entries) != len(members) or "manifest.json" not in members:
                raise ArchiveRejected("Malformed space archive ZIP membership.")
            manifest, _ = _json_object(archive, members["manifest.json"], max_bytes=262_144, ensure_ascii=True)
            expected_keys = {
                "format", "scope", "restorable", "org_id", "space_id", "space_ref", "export_id",
                "recovery_watermark", "sources", "versions", "wikis",
                "effectivity_sha256", "authorization_rules_sha256", "safety_decisions_sha256",
            }
            if (
                set(manifest) != expected_keys
                or (manifest["format"], manifest["scope"]) != (SPACE_ARCHIVE_FORMAT, SPACE_ARCHIVE_SCOPE)
                or manifest["restorable"] is not False
                or (manifest["org_id"], manifest["space_id"]) != (permit.org_id, permit.space_id)
                or manifest["space_ref"] != str(permit.space_ref)
                or manifest["export_id"] != str(permit.export_ref)
                or not isinstance(manifest["recovery_watermark"], dict)
            ):
                raise ArchiveRejected("Space archive manifest does not match approved format or permit.")

            eff_obj, eff_raw = _json_object(archive, members["versions/effectivity.json"], max_bytes=1_048_576, ensure_ascii=False)
            auth_obj, auth_raw = _json_object(archive, members["authorization/rules.json"], max_bytes=2_097_152, ensure_ascii=False)
            safety_obj, safety_raw = _json_object(archive, members["safety/decisions.json"], max_bytes=2_097_152, ensure_ascii=False)
            if (
                sha256(eff_raw).hexdigest() != manifest["effectivity_sha256"]
                or sha256(auth_raw).hexdigest() != manifest["authorization_rules_sha256"]
                or sha256(safety_raw).hexdigest() != manifest["safety_decisions_sha256"]
            ):
                raise ArchiveRejected("Space archive metadata or safety decision digest mismatch.")

            expected_members = {
                "manifest.json", "versions/effectivity.json", "authorization/rules.json", "safety/decisions.json",
            }
            sources = manifest["sources"]
            if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SPACE_SOURCES:
                raise ArchiveRejected("Invalid archived sources list.")
            source_by_ref: dict[UUID, dict] = {}
            for src in sources:
                sref = canonical_ref(src["source_id"])
                if sref in source_by_ref:
                    raise ArchiveRejected("Duplicate source identifier in space archive.")
                _validate_keys(src["source_key"], src["object_namespace"])
                source_by_ref[sref] = src

            versions_decl = manifest["versions"]
            if not isinstance(versions_decl, list) or not 1 <= len(versions_decl) <= MAX_SPACE_VERSIONS:
                raise ArchiveRejected("Invalid archived versions list.")
            versions: dict[UUID, dict] = {}
            all_passages: dict[UUID, tuple[UUID, int, str]] = {}
            used_ids: set[UUID] = {permit.export_ref, permit.space_ref, *source_by_ref.keys()}
            doc_descriptors: dict[UUID, tuple] = {}
            for decl in versions_decl:
                vref = canonical_ref(decl["version_id"])
                if vref in versions or vref in used_ids:
                    raise ArchiveRejected("Duplicate version or identity collision in space archive.")
                member_name = f"versions/{vref}.zip"
                expected_members.add(member_name)
                packed = _read_member(archive, members[member_name], members[member_name].file_size)
                if sha256(packed).hexdigest() != decl["sha256"]:
                    raise ArchiveRejected("Embedded version zip digest mismatch.")
                decoded = _decode_embedded_version(permit, vref, packed, decl["media_type"])
                meta = decoded["metadata"]
                if meta["source_id"] not in source_by_ref or str(meta["source_id"]) != decl["source_id"]:
                    raise ArchiveRejected("Embedded version references an undeclared source.")
                doc_ref = meta["document_id"]
                desc = (meta["source_id"], meta["object_key"], meta["incarnation"], meta["display_name"])
                if doc_descriptors.setdefault(doc_ref, desc) != desc:
                    raise ArchiveRejected("Embedded versions disagree on document identity or metadata.")
                if decoded["run_ref"] in used_ids:
                    raise ArchiveRejected("Processing run identity collision in space archive.")
                used_ids.add(vref)
                used_ids.add(decoded["run_ref"])
                for pid, rev_num in decoded["passage_revisions"].items():
                    if pid in all_passages or pid in used_ids:
                        raise ArchiveRejected("Passage identity collision across archived versions.")
                    all_passages[pid] = (vref, rev_num, decoded["passage_digests"][pid])
                    used_ids.add(pid)
                versions[vref] = decoded

            wikis_decoded: list[dict] = []
            for w_decl in manifest["wikis"]:
                rev_ref = canonical_ref(w_decl["revision_id"])
                pub_ref = canonical_ref(w_decl["publication_id"])
                wiki_ref = canonical_ref(w_decl["wiki_id"])
                prefix = f"wikis/{rev_ref}"
                expected_members.update({
                    f"{prefix}/revision.json", f"{prefix}/content.md",
                    f"{prefix}/dependencies.json", f"{prefix}/manifests.json",
                })
                rev_bytes = _read_member(archive, members[f"{prefix}/revision.json"], members[f"{prefix}/revision.json"].file_size)
                md_bytes = _read_member(archive, members[f"{prefix}/content.md"], members[f"{prefix}/content.md"].file_size)
                deps, deps_raw = _json_object(archive, members[f"{prefix}/dependencies.json"], max_bytes=262_144, ensure_ascii=True)
                graph_obj, graph_raw = _json_object(archive, members[f"{prefix}/manifests.json"], max_bytes=524_288, ensure_ascii=True)
                if (
                    sha256(rev_bytes).hexdigest() != w_decl["revision_sha256"]
                    or sha256(deps_raw).hexdigest() != w_decl["dependencies_sha256"]
                    or sha256(graph_raw).hexdigest() != w_decl["manifests_sha256"]
                ):
                    raise ArchiveRejected("Archived Wiki member digest mismatch.")
                rev_obj = json.loads(rev_bytes.decode("utf-8"))
                if rev_obj.get("markdown", "").encode("utf-8") != md_bytes:
                    raise ArchiveRejected("Archived Wiki markdown does not match revision JSON.")
                root_manifest = canonical_ref(deps["manifest_id"])
                _, expanded = verify_manifest_graph(root_manifest, graph_obj["manifests"])
                if len(deps["inputs"]) != len(expanded):
                    raise ArchiveRejected("Archived Wiki dependency list does not cover expanded manifest.")
                for (pid, rev_num), item in zip(expanded.items(), deps["inputs"], strict=True):
                    if pid not in all_passages:
                        raise ArchiveRejected("Archived Wiki depends on an unarchived passage.")
                    p_ver, p_rev, p_sha = all_passages[pid]
                    if (
                        item["version_id"] != str(p_ver)
                        or item["passage_id"] != str(pid)
                        or int(item["excerpt_revision"]) != p_rev
                        or rev_num != p_rev
                        or item["excerpt_sha256"] != p_sha
                    ):
                        raise ArchiveRejected("Archived Wiki input does not match archived version passage.")
                wikis_decoded.append({
                    "wiki_ref": wiki_ref,
                    "topic_key": w_decl["topic_key"],
                    "revision_ref": rev_ref,
                    "publication_ref": pub_ref,
                    "business_date": date.fromisoformat(w_decl["business_date"]),
                    "revision": rev_obj,
                    "dependencies": deps,
                    "manifests": graph_obj["manifests"],
                    "expanded": expanded,
                })

            if set(members) != expected_members:
                raise ArchiveRejected("Unexpected or missing members in space archive ZIP.")

            eff_map: dict[UUID, list[dict]] = {}
            raw_eff = eff_obj.get("versions", {})
            if not isinstance(raw_eff, dict):
                raise ArchiveRejected("Invalid effectivity archive format.")
            for vref in versions:
                entries_list = raw_eff.get(str(vref), [])
                if not isinstance(entries_list, list):
                    raise ArchiveRejected("Invalid version effectivity entries.")
                eff_map[vref] = entries_list

            verified = VerifiedSpaceArchive(
                export_ref=permit.export_ref,
                space_ref=permit.space_ref,
                format_version=SPACE_ARCHIVE_FORMAT,
                source_refs=tuple(sorted(source_by_ref)),
                version_refs=tuple(sorted(versions)),
                wiki_revision_refs=tuple(sorted(item["revision_ref"] for item in wikis_decoded)),
                recovery_watermark=manifest["recovery_watermark"],
                authorization_rules=auth_obj,
                safety_decisions=safety_obj,
            )
            return _DecodedSpaceArchive(verified, manifest, sources, versions, eff_map, wikis_decoded)
    except ArchiveRejected:
        raise
    except (BadZipFile, KeyError, TypeError, ValueError, AttributeError, OSError, RecursionError, NotImplementedError):
        raise ArchiveRejected("The space archive could not be verified offline.") from None


def verify_space_archive(permit: SpaceArchivePermit, payload: bytes) -> VerifiedSpaceArchive:
    """Verify a sealed multi-source space archive offline without importing or granting access."""
    return _decode_space_archive(permit, payload).verified


def _dir_size_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _rehearsal_request(
    connection: Connection,
    org_id: int,
    space_id: int,
    principal_id: int,
    operation: str,
    destination: str,
    business_day: date,
) -> SourceWrite:
    req_id = uuid4()
    start_request(
        connection,
        RequestStart(
            org_id, req_id, principal_id, None, "space-archive-rehearsal",
            operation, destination, business_day, 1, space_id=space_id, ingress="internal",
        ),
    )
    return SourceWrite(org_id, principal_id, req_id, str(uuid4()))


def _authority_from_snapshot(
    snapshot: SourceRevocationSnapshot,
    principal_ref_by_id: dict[int, UUID],
    *,
    purpose_kind: Literal["evidence", "archive"] = "evidence",
) -> Callable[[delivery.DeliveryCheck], delivery.AuthorityDecision]:
    def check(probe: delivery.DeliveryCheck) -> delivery.AuthorityDecision:
        now = datetime.now(UTC)
        principal_id = probe.context.principal_id
        subject_ref = principal_ref_by_id[principal_id]
        denied = snapshot.denied_objects(subject_ref, purpose_kind)
        permitted = {}
        for sc in probe.scopes:
            if sc.object_id in denied:
                permitted[sc] = frozenset()
            else:
                permitted[sc] = sc.fields
        return delivery.AuthorityDecision(
            probe.check_id, now, now + timedelta(minutes=5),
            frozenset({principal_id}), permitted, f"rehearsal-revocation-gen-{snapshot.generation}",
        )
    return check


def rebuild_space_archive_in_rehearsal(
    connection: Connection,
    permit: SpaceArchivePermit,
    payload: bytes,
    scratch_root: Path,
    *,
    authority: Connection,
    log: Connection,
    authority_ref: UUID,
    log_ref: UUID,
    source_authority: SourceRevocationAuthority,
    alternate_model_profile: str,
    lexical_index_mode: Literal["indexed", "direct_scan", "hybrid_vector"] = "indexed",
    reference_checks: Sequence[OldReferenceCheck] = (),
) -> SpaceRebuildReport:
    """Reconstruct a multi-source space archive in a fenced empty database.

    Requires independent rule/quality logs and source revocation authority, replays all latest
    withdrawals, deletions, tombstones, and revocations before indexing under an alternate
    model profile, and verifies saved old references before returning the migration report.
    """
    started = monotonic()
    if not isinstance(alternate_model_profile, str) or not 1 <= len(alternate_model_profile.strip()) <= 128:
        raise ValueError("alternate_model_profile must be a non-empty string up to 128 characters.")
    if lexical_index_mode not in release.LEXICAL_MODES:
        raise ValueError("lexical_index_mode must be 'indexed' or 'direct_scan'.")
    _check_input(connection, payload, permit.digest)
    if permit.database != connection.info.dbname:
        raise ArchiveRejected("The permit does not match this rehearsal database.")
    if authority is None or log is None or source_authority is None:
        raise ArchiveRejected("Independent rule log and source authority are mandatory for safe rebuild.")
    if source_authority.authority_ref in {authority_ref, log_ref} or authority_ref == log_ref:
        raise ArchiveRejected("Rule authority, rule log, and source revocation authority must be distinct endpoints.")

    decoded = _decode_space_archive(permit, payload)
    parent_store = SyntheticOriginalStore(scratch_root)

    try:
        with ExitStack() as stack:
            checked = stack.enter_context(
                restriction_log.pinned_replay_input(
                    authority, log, permit.org_id, authority_ref=authority_ref, log_ref=log_ref,
                )
            )
            if checked.status != "verified":
                raise ArchiveRejected("Independent rule restriction log is missing, lagging, or mismatched.")
            quality = check_pinned_history(authority, log, permit.org_id, authority_ref)
            if quality is None:
                raise ArchiveRejected("Independent quality restriction log could not be verified.")
            try:
                source_snap = stack.enter_context(source_authority.pinned_snapshot(permit.space_ref))
            except delivery.AuthorizationUnavailable:
                raise ArchiveRejected("Independent source revocation authority is unavailable.") from None

            # Query primary authority for all source-deleted documents across archived sources
            # (including deletions confirmed after the backup was sealed).
            source_deleted_docs: set[UUID] = set()
            if authority.execute("SELECT to_regclass('thalion.source_restriction_receipt') IS NOT NULL").fetchone()[0]:
                del_rows = authority.execute(
                    """
                    SELECT DISTINCT doc_oi.public_id
                    FROM thalion.source_restriction_receipt AS r
                    JOIN thalion.rule_use_stop AS st ON st.decision_ref = r.local_stop_ref
                    JOIN thalion.object_identity AS doc_oi
                      ON (doc_oi.org_id, doc_oi.space_id, doc_oi.object_type, doc_oi.object_id)
                       = (st.org_id, st.space_id, 'document', st.document_id)
                    WHERE (r.org_id, r.space_id, r.kind) = (%s, %s, 'deleted')
                      AND st.kind = 'deletion_blocked'
                    """,
                    (permit.org_id, permit.space_id),
                ).fetchall()
                source_deleted_docs = {row[0] for row in del_rows}

            # Also include any source-deleted documents explicitly recorded inside the archive safety log.
            stop_doc_by_id = {
                item["decision_id"]: UUID(item["document_id"])
                for item in decoded.verified.safety_decisions.get("rule_use_stops", [])
            }
            for rec in decoded.verified.safety_decisions.get("source_restriction_receipts", []):
                if rec.get("kind") == "deleted" and rec.get("local_stop_id") in stop_doc_by_id:
                    source_deleted_docs.add(stop_doc_by_id[rec["local_stop_id"]])

            # Verify the rehearsal database is fenced and empty before writing anything.
            with connection.transaction():
                _begin_empty_rebuild(connection, permit.database, parent_store)

            staged_dir = TemporaryDirectory(dir=parent_store.root, prefix="space-rehearsal-", delete=False)
            cleanup_dir = True
            store = SyntheticOriginalStore(Path(staged_dir.name))
            try:
                auth_data = decoded.verified.authorization_rules
                shared_group_principal_refs = {
                    canonical_ref(grp["group_principal_id"])
                    for grp in auth_data.get("shared_groups", [])
                }
                with connection.transaction():
                    org_id, = connection.execute(
                        "INSERT INTO thalion.organization (name, business_timezone) VALUES ('Space archive rehearsal', 'UTC') RETURNING org_id",
                    ).fetchone()
                    principal_id_by_ref: dict[UUID, int] = {}
                    principal_ref_by_id: dict[int, UUID] = {}
                    for p_info in auth_data["principals"]:
                        p_ref = canonical_ref(p_info["principal_id"])
                        if p_ref in shared_group_principal_refs:
                            continue
                        p_type = p_info["principal_type"]
                        pid, = connection.execute(
                            """
                            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key, disabled)
                            VALUES (%s, %s, %s, %s, %s) RETURNING principal_id
                            """,
                            (org_id, p_type, SYNTHETIC_ISSUER, str(p_ref), bool(p_info.get("disabled", False))),
                        ).fetchone()
                        _register_identity(connection, org_id, None, "principal", pid, public_id=p_ref)
                        principal_id_by_ref[p_ref] = pid
                        principal_ref_by_id[pid] = p_ref

                    owner_ref = canonical_ref(auth_data["space_owner_id"])
                    owner_id = principal_id_by_ref[owner_ref]
                    space_id, = connection.execute(
                        """
                        INSERT INTO thalion.space (org_id, name, classification, owner_principal_id)
                        VALUES (%s, 'Rebuilt Space Rehearsal', 'internal', %s) RETURNING space_id
                        """,
                        (org_id, owner_id),
                    ).fetchone()
                    _register_identity(connection, org_id, space_id, "space", space_id, public_id=permit.space_ref)

                    # Ensure a dedicated fallback service worker and independent reviewer exist.
                    role_by_source = {canonical_ref(item["source_id"]): item for item in auth_data["source_roles"]}
                    fallback_approver_id: int | None = None
                    for r_item in role_by_source.values():
                        if r_item.get("approver_id"):
                            cand_id = principal_id_by_ref[canonical_ref(r_item["approver_id"])]
                            if cand_id != owner_id:
                                fallback_approver_id = cand_id
                                break
                    if fallback_approver_id is None:
                        fallback_approver_id, = connection.execute(
                            """
                            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
                            VALUES (%s, 'employee', %s, %s) RETURNING principal_id
                            """,
                            (org_id, SYNTHETIC_ISSUER, f"rehearsal-approver-{uuid4()}"),
                        ).fetchone()
                        fallback_app_ref = _register_identity(connection, org_id, None, "principal", fallback_approver_id)
                        principal_id_by_ref[fallback_app_ref] = fallback_approver_id
                        principal_ref_by_id[fallback_approver_id] = fallback_app_ref

                    # Reconstruct every source with its original public_id and contract roles.
                    source_scope_by_ref: dict[UUID, tuple[int, int, int]] = {}
                    source_roles_ids: dict[UUID, dict[str, int]] = {}
                    for src in decoded.sources:
                        sref = canonical_ref(src["source_id"])
                        roles = role_by_source[sref]
                        src_contract_rev = int(src["contract_revision"])
                        s_owner = principal_id_by_ref[canonical_ref(roles["owner_id"])]
                        s_collector = principal_id_by_ref[canonical_ref(roles["collector_id"])]
                        s_approver = principal_id_by_ref[canonical_ref(roles["approver_id"])] if roles.get("approver_id") else fallback_approver_id
                        s_processor = principal_id_by_ref[canonical_ref(roles["processor_id"])] if roles.get("processor_id") else s_collector
                        s_qrev = principal_id_by_ref[canonical_ref(roles["quality_reviewer_id"])] if roles.get("quality_reviewer_id") else s_owner
                        source_id, = connection.execute(
                            """
                            INSERT INTO thalion.source (org_id, space_id, source_key, owner_principal_id, contract_revision)
                            VALUES (%s, %s, %s, %s, %s) RETURNING source_id
                            """,
                            (org_id, space_id, src["source_key"], s_owner, src_contract_rev),
                        ).fetchone()
                        _register_identity(connection, org_id, space_id, "source", source_id, public_id=sref)
                        src_scope = (org_id, space_id, source_id)
                        connection.execute(
                            """
                            INSERT INTO thalion.source_contract_revision (
                                org_id, space_id, source_id, revision, admission, collector_id,
                                object_namespace, approver_id, processor_id, quality_reviewer_id, docx_amount_columns
                            ) VALUES (%s, %s, %s, %s, 'synthetic_only', %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                *src_scope, src_contract_rev, s_collector, src["object_namespace"], s_approver,
                                s_processor, s_qrev, src.get("docx_amount_columns"),
                            ),
                        )
                        for entry in checked.entries:
                            if entry.version_ref not in decoded.versions:
                                continue
                            if decoded.versions[entry.version_ref]["metadata"]["source_id"] != sref:
                                continue
                            if entry.contract_revision == src_contract_rev:
                                continue
                            if entry.approver_ref not in principal_id_by_ref:
                                extra_pid, = connection.execute(
                                    """
                                    INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
                                    VALUES (%s, 'employee', %s, %s) RETURNING principal_id
                                    """,
                                    (org_id, SYNTHETIC_ISSUER, str(entry.approver_ref)),
                                ).fetchone()
                                _register_identity(connection, org_id, None, "principal", extra_pid, public_id=entry.approver_ref)
                                principal_id_by_ref[entry.approver_ref] = extra_pid
                                principal_ref_by_id[extra_pid] = entry.approver_ref
                            connection.execute(
                                """
                                INSERT INTO thalion.source_contract_revision (
                                    org_id, space_id, source_id, revision, admission, collector_id,
                                    object_namespace, approver_id, processor_id, quality_reviewer_id, docx_amount_columns
                                ) VALUES (%s, %s, %s, %s, 'synthetic_only', %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (org_id, space_id, source_id, revision) DO NOTHING
                                """,
                                (
                                    *src_scope, entry.contract_revision, s_collector, src["object_namespace"],
                                    principal_id_by_ref[entry.approver_ref], s_processor, s_qrev, src.get("docx_amount_columns"),
                                ),
                            )
                        source_scope_by_ref[sref] = src_scope
                        source_roles_ids[sref] = {
                            "owner": s_owner, "collector": s_collector, "approver": s_approver,
                            "processor": s_processor, "quality_reviewer": s_qrev,
                            "contract_revision": src_contract_rev,
                        }

                    # Reconstruct documents, versions, originals, transcripts, quality approvals & effectivity.
                    doc_scope_by_ref: dict[UUID, tuple[int, int, int, int]] = {}
                    version_info_by_ref: dict[UUID, dict] = {}
                    staged_assets: list[tuple[OriginalAsset, bytes]] = []
                    default_day = date(2026, 6, 1)
                    for vref, vdata in decoded.versions.items():
                        meta = vdata["metadata"]
                        sref = meta["source_id"]
                        dref = meta["document_id"]
                        src_scope = source_scope_by_ref[sref]
                        if dref not in doc_scope_by_ref:
                            doc_scope_by_ref[dref] = _rebuild_document(connection, src_scope, meta)
                        doc_scope = doc_scope_by_ref[dref]
                        media_type = vdata["media_type"]
                        profile = (
                            DOCX_REBUILD_FORMAT if media_type == DOCX_MEDIA_TYPE
                            else PDF_REBUILD_FORMAT if media_type == PDF_MEDIA_TYPE
                            else REBUILD_FORMAT
                        )
                        asset_key = _digest(profile, str(vref), vdata["digest"].hex()).hex()
                        asset = OriginalAsset(asset_key, vdata["digest"], len(vdata["original"]))
                        _rebuild_original(connection, doc_scope, vref, meta, asset, media_type=media_type)
                        staged_assets.append((asset, vdata["original"]))
                        version_id, = connection.execute(
                            """
                            SELECT object_id FROM thalion.object_identity
                            WHERE (org_id, space_id, object_type, public_id) = (%s, %s, 'document_version', %s)
                            """,
                            (org_id, space_id, vref),
                        ).fetchone()
                        version_info_by_ref[vref] = {
                            "version_id": version_id,
                            "source_ref": sref,
                            "source_id": src_scope[2],
                            "document_ref": dref,
                            "document_id": doc_scope[3],
                            "media_type": media_type,
                            "run_ref": vdata["run_ref"],
                            "roles": source_roles_ids[sref],
                        }
                        if media_type == "text/markdown":
                            md_cfg_rev, = connection.execute(
                                """
                                SELECT configuration_revision FROM thalion.processing_config_revision
                                WHERE (parser_version, profile, locator_revision) = (%s, %s, %s)
                                ORDER BY configuration_revision DESC LIMIT 1
                                """,
                                (markdown.PARSER_VERSION, markdown.PROFILE, markdown.LOCATOR_REVISION),
                            ).fetchone()
                            job_id = enqueue_job(connection, JobSpec(org_id, space_id, vref, "parse", vdata["digest"], md_cfg_rev))
                            lease = claim_job(connection, org_id, "parse", source_roles_ids[sref]["processor"], timedelta(minutes=1))
                            if lease is None or lease.job_id != job_id:
                                raise ArchiveRejected("Could not claim parse lease for rebuilt Markdown version.")
                            prepared = processing._prepare_original(connection, lease)
                            run = processing._record_markdown_candidate(
                                connection, lease, prepared, vdata["candidate"],
                                passage_refs=vdata["passage_refs"], restored_run_ref=vdata["run_ref"],
                            )
                            version_info_by_ref[vref]["run_manifest_digest"] = run.manifest_digest
                        elif media_type == DOCX_MEDIA_TYPE:
                            docx_cfg_rev, = connection.execute(
                                """
                                SELECT configuration_revision FROM thalion.processing_config_revision
                                WHERE (parser_version, profile, locator_revision) = (%s, %s, %s)
                                ORDER BY configuration_revision DESC LIMIT 1
                                """,
                                (docx_evidence.PARSER_VERSION, docx_evidence.PROFILE, docx_evidence.LOCATOR_REVISION),
                            ).fetchone()
                            job_id = enqueue_job(connection, JobSpec(org_id, space_id, vref, "parse", vdata["digest"], docx_cfg_rev))
                            lease = claim_job(connection, org_id, "parse", source_roles_ids[sref]["processor"], timedelta(minutes=1))
                            if lease is None or lease.job_id != job_id:
                                raise ArchiveRejected("Could not claim parse lease for rebuilt DOCX version.")
                            prepared = processing._prepare_original(connection, lease)
                            run = processing._record_docx_candidate(
                                connection, lease, prepared, vdata["candidate"],
                                passage_refs=vdata["passage_refs"], cell_refs=vdata["cell_refs"],
                                restored_run_ref=vdata["run_ref"],
                            )
                            version_info_by_ref[vref]["run_manifest_digest"] = run.manifest_digest

                    # Stage originals onto disk before quality review / Wiki / lexical indexing reads them.
                    for asset, raw_bytes in staged_assets:
                        store.stage(asset.key, asset.digest, raw_bytes)

                # Quality approvals & rule effectivity via standard module commands.
                for vref, info in version_info_by_ref.items():
                    if info["media_type"] in ("text/markdown", DOCX_MEDIA_TYPE):
                        q_ctx = _rehearsal_request(
                            connection, org_id, space_id, info["roles"]["quality_reviewer"],
                            "decide_evidence_quality", "internal_sources", default_day,
                        )
                        processing.decide_quality(
                            connection, q_ctx, space_id, info["run_ref"],
                            info["run_manifest_digest"], "approved", uuid4(),
                        )

                pending_eff: list[tuple[UUID, dict]] = [
                    (vref, eff)
                    for vref in version_info_by_ref
                    for eff in decoded.effectivity_records.get(vref, [])
                ]
                archived_decision_ids = {eff["decision_id"] for _, eff in pending_eff}
                decision_ref_map: dict[str, UUID] = {}
                while pending_eff:
                    ready = [
                        item for item in pending_eff
                        if not item[1].get("replaces_id")
                        or item[1]["replaces_id"] not in archived_decision_ids
                        or item[1]["replaces_id"] in decision_ref_map
                    ]
                    if not ready:
                        raise ArchiveRejected("Cyclic or unresolvable rule effectivity replacement chain in archive.")
                    ready.sort(key=lambda item: (item[1]["valid_from"], item[1]["decision_id"]))
                    ready_ids = {item[1]["decision_id"] for item in ready}
                    for vref, eff in ready:
                        info = version_info_by_ref[vref]
                        e_ctx = _rehearsal_request(
                            connection, org_id, space_id, info["roles"]["approver"],
                            effectivity.APPROVE, "internal_sources", default_day,
                        )
                        replaces_id = eff.get("replaces_id")
                        mapped_replaces = decision_ref_map.get(replaces_id) if replaces_id else None
                        replayed_decision = effectivity.approve_synthetic_rule(
                            connection, e_ctx, space_id, vref,
                            effectivity.Approval(
                                valid_from=date.fromisoformat(eff["valid_from"]),
                                valid_to=date.fromisoformat(eff["valid_to"]) if eff["valid_to"] else None,
                                region=eff["region"],
                                traveler_class=eff["traveler_class"],
                                basis_ref=UUID(eff["basis_id"]),
                                replaces_ref=mapped_replaces,
                            ),
                        )
                        decision_ref_map[eff["decision_id"]] = replayed_decision
                    pending_eff = [item for item in pending_eff if item[1]["decision_id"] not in ready_ids]

                # Restore local authorization rules (permission bindings + non-expired, non-revoked shared groups).
                now_ts = datetime.now(UTC)
                active_group_principal_map: dict[UUID, UUID] = {}
                for grp in auth_data.get("shared_groups", []):
                    expires_dt = datetime.fromisoformat(grp["expires_at"]).astimezone(UTC)
                    if grp.get("revoked") or expires_dt <= now_ts:
                        continue
                    starts_dt = datetime.fromisoformat(grp["starts_at"]).astimezone(UTC)
                    review_dt = datetime.fromisoformat(grp["review_at"]).astimezone(UTC)
                    if review_dt < starts_dt:
                        review_dt = starts_dt
                    if review_dt > expires_dt:
                        review_dt = expires_dt
                    g_ctx = _rehearsal_request(
                        connection, org_id, space_id, owner_id,
                        governance.MANAGE_SHARED_GROUP, governance.DESTINATION, default_day,
                    )
                    created_grp = governance.create_shared_group(
                        connection, g_ctx, space_id,
                        target_source_ref=canonical_ref(grp["target_source_id"]),
                        name=grp["name"], purpose=grp["purpose"], scope_summary=grp["scope_summary"],
                        starts_at=starts_dt, review_at=review_dt, expires_at=expires_dt,
                        basis_ref=UUID(grp["basis_id"]),
                    )
                    new_group_principal_ref = UUID(created_grp["group_principal_id"])
                    active_group_principal_map[canonical_ref(grp["group_principal_id"])] = new_group_principal_ref
                    for mem in grp.get("members", []):
                        m_exp = datetime.fromisoformat(mem["expires_at"]).astimezone(UTC)
                        if mem.get("revoked") or m_exp <= now_ts:
                            continue
                        m_start = datetime.fromisoformat(mem["starts_at"]).astimezone(UTC)
                        m_ctx = _rehearsal_request(
                            connection, org_id, space_id, owner_id,
                            governance.MANAGE_SHARED_GROUP, governance.DESTINATION, default_day,
                        )
                        governance.add_shared_group_member(
                            connection, m_ctx, space_id, UUID(created_grp["group_id"]),
                            member_ref=canonical_ref(mem["member_principal_id"]),
                            starts_at=m_start, expires_at=m_exp, basis_ref=uuid4(),
                        )

                bindings_by_source: dict[UUID, list[policy.LocalRule]] = {sref: [] for sref in source_scope_by_ref}
                for b in auth_data.get("bindings", []):
                    sref = canonical_ref(b["source_id"])
                    if sref not in bindings_by_source:
                        continue
                    orig_subj = canonical_ref(b["subject_id"])
                    if orig_subj in shared_group_principal_refs and orig_subj not in active_group_principal_map:
                        continue
                    mapped_subj = active_group_principal_map.get(orig_subj, orig_subj)
                    if orig_subj not in active_group_principal_map and mapped_subj not in principal_id_by_ref:
                        continue
                    v_from = datetime.fromisoformat(b["valid_from"]).astimezone(UTC)
                    v_until = datetime.fromisoformat(b["valid_until"]).astimezone(UTC) if b["valid_until"] else None
                    if v_until is not None and v_until <= now_ts:
                        continue
                    if b["operation"] == policy.MODEL_RULE_OPERATION:
                        continue
                    bindings_by_source[sref].append(
                        policy.LocalRule(
                            subject_id=mapped_subj,
                            operation=b["operation"],
                            effect=b["effect"],
                            purpose=b["purpose"],
                            destination=b["destination"],
                            fields=frozenset(b["fields"]),
                            valid_from=v_from,
                            valid_until=v_until,
                            passage_ref=UUID(b["passage_id"]) if b["passage_id"] else None,
                            version_ref=UUID(b["version_id"]) if b["version_id"] else None,
                        )
                    )

                # Grant temporary workspace Wiki compilation/review/publication rules for owner & reviewer during rebuild,
                # alongside all archived employee rules, without widening employee read rights.
                for sref, rule_list in bindings_by_source.items():
                    augmented = list(rule_list)
                    existing_keys = {
                        (r.subject_id, r.operation, r.effect, r.purpose, r.destination, r.passage_ref)
                        for r in augmented
                        if policy.WORKSPACE_EVIDENCE_FIELDS <= r.fields
                    }
                    for subj_ref, access in (
                        (owner_ref, policy.WIKI_INPUT_ACCESS),
                        (principal_ref_by_id[fallback_approver_id], policy.WIKI_REVIEW_ACCESS),
                        (principal_ref_by_id[fallback_approver_id], policy.WIKI_PUBLISH_ACCESS),
                    ):
                        key = (subj_ref, access[0], "allow", access[1], access[2], None)
                        if key not in existing_keys:
                            augmented.append(
                                policy.LocalRule(
                                    subject_id=subj_ref,
                                    operation=access[0], effect="allow", purpose=access[1], destination=access[2],
                                    fields=policy.WORKSPACE_EVIDENCE_FIELDS,
                                    valid_from=now_ts - timedelta(hours=1),
                                    valid_until=None,
                                )
                            )
                    if augmented:
                        p_ctx = _rehearsal_request(
                            connection, org_id, space_id, source_roles_ids[sref]["owner"],
                            policy.REPLACE, policy.DESTINATION, default_day,
                        )
                        cur_epoch, = connection.execute(
                            "SELECT safety_epoch FROM thalion.source WHERE (org_id, space_id, source_id) = (%s, %s, %s)",
                            source_scope_by_ref[sref],
                        ).fetchone()
                        policy.replace_synthetic_policy(
                            connection, p_ctx, space_id, sref, cur_epoch, tuple(augmented), uuid4(),
                        )

                # Reconstruct archived Wiki revisions & publications via standard workflow (preserving topic_key & full inputs).
                fallback_wiki_day = (
                    reference_checks[0].business_date if reference_checks else default_day
                )
                fallback_wiki_region = reference_checks[0].region if reference_checks else "default"
                fallback_wiki_traveler = reference_checks[0].traveler_class if reference_checks else "standard"
                rebuilt_wiki_count = 0

                def _allow_rehearsal_wiki(probe: delivery.DeliveryCheck) -> delivery.AuthorityDecision:
                    now_t = datetime.now(UTC)
                    return delivery.AuthorityDecision(
                        probe.check_id, now_t, now_t + timedelta(minutes=5),
                        frozenset({probe.context.principal_id}), {sc: sc.fields for sc in probe.scopes},
                        "rehearsal-wiki-stage",
                    )

                for w_item in decoded.wikis:
                    direct_inputs = tuple(w_item["expanded"].items())
                    dep_vrefs = {canonical_ref(dep["version_id"]) for dep in w_item["dependencies"]["inputs"]}
                    wiki_business_day = w_item["business_date"]
                    wiki_region, wiki_traveler = fallback_wiki_region, fallback_wiki_traveler
                    common_scopes: list[tuple[str | None, str | None, date, date | None]] | None = None
                    for dep_vref in sorted(dep_vrefs, key=str):
                        recs = [
                            (
                                r["region"], r["traveler_class"],
                                date.fromisoformat(r["valid_from"]),
                                date.fromisoformat(r["valid_to"]) if r["valid_to"] else None,
                            )
                            for r in decoded.effectivity_records.get(dep_vref, [])
                        ]
                        if common_scopes is None:
                            common_scopes = recs
                        else:
                            next_scopes = []
                            for reg, cls, s1, e1 in common_scopes:
                                for reg2, cls2, s2, e2 in recs:
                                    if (reg is None or reg2 is None or reg == reg2) and (
                                        cls is None or cls2 is None or cls == cls2
                                    ):
                                        lo = max(s1, s2)
                                        hi = min(e1, e2) if (e1 and e2) else (e1 or e2)
                                        if hi is None or lo < hi:
                                            next_scopes.append((
                                                reg if reg is not None else reg2,
                                                cls if cls is not None else cls2,
                                                lo, hi,
                                            ))
                            common_scopes = next_scopes
                    if common_scopes:
                        matching_scopes = [
                            sc for sc in common_scopes
                            if sc[2] <= wiki_business_day and (sc[3] is None or wiki_business_day < sc[3])
                        ]
                        sel_region, sel_traveler, _, _ = matching_scopes[0] if matching_scopes else common_scopes[0]
                        wiki_region = sel_region or fallback_wiki_region
                        wiki_traveler = sel_traveler or fallback_wiki_traveler
                    rev_json = w_item["revision"]
                    citations = tuple((UUID(ref), int(rev)) for ref, rev in rev_json["citations"])
                    statements = tuple(
                        drafts.WikiStatement(
                            st["text"],
                            tuple(
                                tuple((UUID(ref), int(rev)) for ref, rev in group)
                                for group in st["support_groups"]
                            ),
                        )
                        for st in rev_json.get("statements", [])
                    )
                    # 1. Assemble sealed input manifest
                    in_req = uuid4()
                    start_request(connection, RequestStart(
                        org_id, in_req, owner_id, None, "rehearsal-wiki",
                        policy.WIKI_INPUT_ACCESS[0], policy.WIKI_INPUT_ACCESS[2], wiki_business_day, 1, space_id=space_id,
                    ))
                    in_ctx = delivery.DeliveryContext(
                        in_req, org_id, owner_id, "rehearsal-wiki",
                        *policy.WIKI_INPUT_ACCESS, datetime.now(UTC) + timedelta(minutes=2),
                    )
                    assembled = wiki_inputs.prepare_wiki_inputs(
                        connection, in_ctx, space_id, direct_inputs, (), store,
                        region=wiki_region, traveler_class=wiki_traveler, check_authority=_allow_rehearsal_wiki,
                    )
                    if assembled.status != "succeeded":
                        raise ArchiveRejected(f"Could not reconstruct Wiki input manifest: {assembled.status}")
                    # 2. Create candidate revision
                    dr_req = uuid4()
                    start_request(connection, RequestStart(
                        org_id, dr_req, owner_id, None, "rehearsal-wiki",
                        policy.WIKI_CANDIDATE_ACCESS[0], policy.WIKI_CANDIDATE_ACCESS[2], wiki_business_day, 1, space_id=space_id,
                    ))
                    dr_ctx = delivery.DeliveryContext(
                        dr_req, org_id, owner_id, "rehearsal-wiki",
                        *policy.WIKI_CANDIDATE_ACCESS, datetime.now(UTC) + timedelta(minutes=2),
                    )
                    draft_res = drafts.create_manual_candidate(
                        connection, dr_ctx, space_id,
                        drafts.ManualCandidate(
                            topic_key=w_item["topic_key"],
                            title=rev_json["title"],
                            markdown=rev_json["markdown"],
                            manifest_ref=assembled.manifest_ref,
                            reviewer_id=fallback_approver_id,
                            basis_ref=uuid4(),
                            citations=citations,
                            statements=statements,
                        ),
                        str(uuid4()),
                        region=wiki_region, traveler_class=wiki_traveler,
                        check_authority=_allow_rehearsal_wiki,
                    )
                    if draft_res.status != "succeeded":
                        raise ArchiveRejected(f"Could not reconstruct Wiki draft: {draft_res.status}")
                    # 3. Independent preview & approval
                    pv_req = uuid4()
                    start_request(connection, RequestStart(
                        org_id, pv_req, fallback_approver_id, None, "rehearsal-wiki",
                        policy.WIKI_PREVIEW_ACCESS[0], policy.WIKI_PREVIEW_ACCESS[2], wiki_business_day, 1, space_id=space_id,
                    ))
                    pv_ctx = delivery.DeliveryContext(
                        pv_req, org_id, fallback_approver_id, "rehearsal-wiki",
                        *policy.WIKI_PREVIEW_ACCESS, datetime.now(UTC) + timedelta(minutes=2),
                    )
                    preview = drafts.read_candidate_for_review(
                        connection, pv_ctx, space_id, draft_res.ref,
                        region=wiki_region, traveler_class=wiki_traveler, check_authority=_allow_rehearsal_wiki,
                    )
                    if preview.status != "succeeded":
                        raise ArchiveRejected(f"Could not preview rebuilt Wiki candidate: {preview.status}")
                    rv_req = uuid4()
                    start_request(connection, RequestStart(
                        org_id, rv_req, fallback_approver_id, None, "rehearsal-wiki",
                        policy.WIKI_REVIEW_ACCESS[0], policy.WIKI_REVIEW_ACCESS[2], wiki_business_day, 1, space_id=space_id,
                    ))
                    rv_ctx = delivery.DeliveryContext(
                        rv_req, org_id, fallback_approver_id, "rehearsal-wiki",
                        *policy.WIKI_REVIEW_ACCESS, datetime.now(UTC) + timedelta(minutes=2),
                    )
                    reviewed = drafts.submit_review(
                        connection, rv_ctx, space_id, draft_res.ref,
                        sha256(preview.payload).digest(), preview.input_digest,
                        "approved", "rebuilt_archive_review", uuid4(), str(uuid4()),
                        region=wiki_region, traveler_class=wiki_traveler,
                        check_authority=_allow_rehearsal_wiki, review_material_ref=preview.review_material_ref,
                    )
                    if reviewed.status != "succeeded":
                        raise ArchiveRejected(f"Could not approve rebuilt Wiki candidate: {reviewed.status}")
                    # 4. Publish revision
                    pb_req = uuid4()
                    start_request(connection, RequestStart(
                        org_id, pb_req, fallback_approver_id, None, "rehearsal-wiki",
                        policy.WIKI_PUBLISH_ACCESS[0], policy.WIKI_PUBLISH_ACCESS[2], wiki_business_day, 1, space_id=space_id,
                    ))
                    pb_ctx = delivery.DeliveryContext(
                        pb_req, org_id, fallback_approver_id, "rehearsal-wiki",
                        *policy.WIKI_PUBLISH_ACCESS, datetime.now(UTC) + timedelta(minutes=2),
                    )
                    published = publication.publish_revision(
                        connection, pb_ctx, space_id, draft_res.ref, reviewed.ref, str(uuid4()),
                        region=wiki_region, traveler_class=wiki_traveler, check_authority=_allow_rehearsal_wiki,
                    )
                    if published.status != "succeeded":
                        raise ArchiveRejected(f"Could not publish rebuilt Wiki revision: {published.status}")
                    rebuilt_wiki_count += 1

                # MANDATORY: Replay all latest safety decisions BEFORE indexing or opening any reference access!
                replayed_stops = 0
                replayed_deletions = 0
                stopped_version_refs: set[UUID] = set()
                with connection.transaction():
                    # 1. Replay every confirmed entry in the independent rule restriction log (withdrawals, suspensions, tombstones).
                    for entry in checked.entries:
                        if entry.version_ref not in version_info_by_ref:
                            continue
                        info = version_info_by_ref[entry.version_ref]
                        stopped_version_refs.add(entry.version_ref)
                        already = connection.execute(
                            "SELECT 1 FROM thalion.rule_use_stop WHERE version_id = %s AND kind = %s",
                            (info["version_id"], entry.kind),
                        ).fetchone()
                        if already is not None:
                            continue
                        restriction_log._apply_restriction(connection, org_id, entry, checked.log_ref)
                        if entry.kind == "deletion_blocked":
                            replayed_deletions += 1
                        else:
                            replayed_stops += 1
                    # 2. Enforce document-level source deletion isolation across all versions of source-deleted documents.
                    for vref, info in version_info_by_ref.items():
                        if info["document_ref"] not in source_deleted_docs:
                            continue
                        stopped_version_refs.add(vref)
                        inserted = connection.execute(
                            """
                            INSERT INTO thalion.rule_use_stop (
                                org_id, space_id, source_id, document_id, version_id,
                                contract_revision, decided_by, kind, basis_ref, replay_log_ref
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'deletion_blocked', %s, %s)
                            ON CONFLICT (version_id, kind) DO NOTHING
                            RETURNING decision_ref
                            """,
                            (
                                org_id, space_id, info["source_id"], info["document_id"], info["version_id"],
                                info["roles"]["contract_revision"], info["roles"]["approver"], uuid4(), checked.log_ref,
                            ),
                        ).fetchone()
                        if inserted is not None:
                            replayed_deletions += 1

                # Count active source revocations in this space snapshot.
                replayed_revocations = len(source_snap.decisions)

                # Activate alternate approved model profile template & space release config, then rebuild lexical indexes
                # strictly for currently retained, non-stopped versions.
                tpl_reg_ctx = _rehearsal_request(
                    connection, org_id, space_id, owner_id,
                    "register_template_revision", "internal_sources", default_day,
                )
                alt_tpl_rev = templates.register_template_revision(
                    connection,
                    templates.TemplateWrite(org_id, owner_id, tpl_reg_ctx.request_id, tpl_reg_ctx.idempotency_key),
                    space_id,
                    templates.TemplateSpec(
                        "rebuilt-alt-model",
                        f"Rebuilt archive alternate profile: {alternate_model_profile.strip()}",
                        "synthetic-local",
                        8192, 1024, fallback_approver_id,
                    ),
                )
                tpl_adm_ctx = _rehearsal_request(
                    connection, org_id, space_id, fallback_approver_id,
                    "decide_template_admission", "internal_sources", default_day,
                )
                templates.decide_template_admission(
                    connection,
                    templates.TemplateWrite(org_id, fallback_approver_id, tpl_adm_ctx.request_id, tpl_adm_ctx.idempotency_key),
                    space_id, alt_tpl_rev, "approved", uuid4(), "approved_alternate_rebuild_profile",
                )
                rel_ctx = _rehearsal_request(
                    connection, org_id, space_id, owner_id,
                    release.SWITCH_SPACE_RELEASE, release.DESTINATION, default_day,
                )
                release.switch_space_release(
                    connection, rel_ctx, space_id,
                    action="trial_switch",
                    wiki_delivery_enabled=True,
                    lexical_index_mode=lexical_index_mode,
                    template_key="rebuilt-alt-model",
                    template_revision_ref=alt_tpl_rev,
                    rollback_trigger_summary="隔离重建切换替代模型配置，发现漏检或越权立即回退",
                    reason_code="rebuild_alternate_profile",
                    basis_ref=uuid4(),
                )

                indexed_versions: list[UUID] = []
                for vref, info in sorted(version_info_by_ref.items(), key=lambda pair: str(pair[0])):
                    if vref in stopped_version_refs or info["media_type"] != "text/markdown":
                        continue
                    lexical.build_index(
                        connection, store, permit.space_ref, vref, info["run_ref"], allow_rehearsal=True,
                    )
                    indexed_versions.append(vref)

                # Pre-open old-reference & current-permission verification against live source revocation snapshot!
                live_read_check = _authority_from_snapshot(source_snap, principal_ref_by_id, purpose_kind="evidence")
                reference_results: list[dict] = []
                for ref_check in reference_checks:
                    actor_id = principal_id_by_ref.get(ref_check.principal_ref)
                    if actor_id is None:
                        raise ArchiveRejected(f"Reference check principal {ref_check.principal_ref} was not restored.")
                    if ref_check.kind == "passage":
                        req_id = uuid4()
                        start_request(connection, RequestStart(
                            org_id, req_id, actor_id, None, "rehearsal-ref-check",
                            "read_passage", "employee", ref_check.business_date, 1, space_id=space_id,
                        ))
                        ctx = delivery.DeliveryContext(
                            req_id, org_id, actor_id, "rehearsal-ref-check",
                            "read_passage", "employee_evidence", "employee",
                            datetime.now(UTC) + timedelta(seconds=30),
                        )
                        read_dec = travel.read_travel_passage(
                            connection, ctx, space_id, ref_check.passage_ref, ref_check.excerpt_revision, store,
                            region=ref_check.region, traveler_class=ref_check.traveler_class,
                            check_authority=live_read_check,
                        )
                        finish_request(connection, org_id, req_id, read_dec.status, 0)
                        actual = read_dec.status == "succeeded" and read_dec.payload is not None
                        search_matched: bool | None = None
                        if ref_check.query:
                            s_req = uuid4()
                            start_request(connection, RequestStart(
                                org_id, s_req, actor_id, None, "rehearsal-ref-check",
                                "search", "employee", ref_check.business_date, 1, space_id=space_id,
                            ))
                            s_ctx = delivery.DeliveryContext(
                                s_req, org_id, actor_id, "rehearsal-ref-check",
                                "search", "employee_evidence", "employee",
                                datetime.now(UTC) + timedelta(seconds=30),
                            )
                            s_dec = travel.search_travel(
                                connection, s_ctx, space_id, ref_check.query, store,
                                region=ref_check.region, traveler_class=ref_check.traveler_class,
                                check_authority=live_read_check, include_wiki=True,
                            )
                            if s_dec.status != "no_evidence":
                                finish_request(connection, org_id, s_req, s_dec.status, 0)
                            if s_dec.status == "succeeded" and s_dec.payload is not None:
                                s_payload = json.loads(s_dec.payload.decode("utf-8"))
                                search_matched = any(
                                    item["passage_id"] == str(ref_check.passage_ref)
                                    and (ref_check.version_ref is None or item["version_id"] == str(ref_check.version_ref))
                                    for item in s_payload.get("passages", [])
                                )
                            else:
                                search_matched = False
                            if ref_check.expected_accessible and not search_matched:
                                raise ArchiveRejected(
                                    f"Old reference '{ref_check.label}' could not be located via rebuilt search."
                                )
                            if not ref_check.expected_accessible and search_matched:
                                raise ArchiveRejected(
                                    f"Restricted reference '{ref_check.label}' leaked into rebuilt search."
                                )
                        if actual != ref_check.expected_accessible:
                            raise ArchiveRejected(
                                f"Old reference '{ref_check.label}' accessibility mismatch "
                                f"(expected={ref_check.expected_accessible}, actual={actual}, status={read_dec.status})."
                            )
                        reference_results.append({
                            "label": ref_check.label,
                            "kind": "passage",
                            "passage_id": str(ref_check.passage_ref),
                            "version_id": str(ref_check.version_ref) if ref_check.version_ref else None,
                            "expected_accessible": ref_check.expected_accessible,
                            "actual_accessible": actual,
                            "status": read_dec.status,
                            "search_matched": search_matched,
                        })
                    else:
                        w_req = uuid4()
                        start_request(connection, RequestStart(
                            org_id, w_req, actor_id, None, "rehearsal-ref-check",
                            policy.WIKI_READ_ACCESS[0], policy.WIKI_READ_ACCESS[2], ref_check.business_date, 1, space_id=space_id,
                        ))
                        w_ctx = delivery.DeliveryContext(
                            w_req, org_id, actor_id, "rehearsal-ref-check",
                            *policy.WIKI_READ_ACCESS, datetime.now(UTC) + timedelta(seconds=30),
                        )
                        w_dec = publication.read_current_revision(
                            connection, w_ctx, space_id, ref_check.topic_key,
                            region=ref_check.region, traveler_class=ref_check.traveler_class,
                            check_authority=live_read_check,
                        )
                        finish_request(connection, org_id, w_req, w_dec.status, 0)
                        actual = w_dec.status == "succeeded" and w_dec.payload is not None
                        if actual != ref_check.expected_accessible:
                            raise ArchiveRejected(
                                f"Wiki reference '{ref_check.label}' accessibility mismatch "
                                f"(expected={ref_check.expected_accessible}, actual={actual}, status={w_dec.status})."
                            )
                        reference_results.append({
                            "label": ref_check.label,
                            "kind": "wiki",
                            "topic_key": ref_check.topic_key,
                            "expected_accessible": ref_check.expected_accessible,
                            "actual_accessible": actual,
                            "status": w_dec.status,
                        })

                duration_ms = max(0, int(round((monotonic() - started) * 1000.0)))
                scratch_bytes = _dir_size_bytes(store.root)
                verified_count = sum(1 for item in reference_results if item["actual_accessible"])
                blocked_count = sum(1 for item in reference_results if not item["actual_accessible"])

                with connection.transaction():
                    rebuild_ref, = connection.execute(
                        """
                        INSERT INTO thalion.space_archive_rebuild (
                            org_id, space_id, origin_org_id, origin_space_id, origin_space_ref,
                            export_ref, format_version, archive_digest, recovery_watermark,
                            rule_authority_ref, rule_log_ref, rule_stream_ref, rule_generation,
                            source_authority_ref, source_stream_ref, source_generation,
                            alternate_model_profile, lexical_index_mode,
                            rebuilt_sources, rebuilt_versions, rebuilt_wikis,
                            replayed_stops, replayed_deletions, replayed_revocations,
                            verified_references, blocked_references,
                            duration_ms, scratch_bytes, affected_services
                        ) VALUES (
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s,
                            %s, %s, %s,
                            %s, %s, %s,
                            %s, %s,
                            %s, %s, %s
                        ) RETURNING rebuild_ref
                        """,
                        (
                            org_id, space_id, permit.org_id, permit.space_id, permit.space_ref,
                            permit.export_ref, SPACE_ARCHIVE_FORMAT, permit.digest,
                            Jsonb(decoded.verified.recovery_watermark),
                            authority_ref, checked.log_ref, checked.stream_ref, len(checked.entries),
                            source_snap.authority_ref, source_snap.stream_ref, source_snap.generation,
                            alternate_model_profile.strip(), lexical_index_mode,
                            len(source_scope_by_ref), len(version_info_by_ref), rebuilt_wiki_count,
                            replayed_stops, replayed_deletions, replayed_revocations,
                            verified_count, blocked_count,
                            duration_ms, scratch_bytes, list(AFFECTED_SERVICES),
                        ),
                    ).fetchone()
                    append_event(connection, org_id, "lifecycle.space_archive.rebuilt", permit.space_ref, space_id=space_id)

                cleanup_dir = False
                return SpaceRebuildReport(
                    rebuild_ref=rebuild_ref,
                    org_id=org_id,
                    space_id=space_id,
                    space_ref=permit.space_ref,
                    export_ref=permit.export_ref,
                    format_version=SPACE_ARCHIVE_FORMAT,
                    archive_sha256=permit.digest.hex(),
                    dataset_kind=REBUILD_DATASET_KIND,
                    recovery_watermark=decoded.verified.recovery_watermark,
                    rule_generation=len(checked.entries),
                    source_generation=source_snap.generation,
                    alternate_model_profile=alternate_model_profile.strip(),
                    lexical_index_mode=lexical_index_mode,
                    rebuilt_sources=len(source_scope_by_ref),
                    rebuilt_versions=len(version_info_by_ref),
                    rebuilt_wikis=rebuilt_wiki_count,
                    indexed_versions=tuple(indexed_versions),
                    replayed_stops=replayed_stops,
                    replayed_deletions=replayed_deletions,
                    replayed_revocations=replayed_revocations,
                    reference_results=tuple(reference_results),
                    duration_ms=duration_ms,
                    scratch_bytes=scratch_bytes,
                    affected_services=AFFECTED_SERVICES,
                    store=store,
                    principal_ids=principal_id_by_ref,
                )
            finally:
                if cleanup_dir:
                    staged_dir.cleanup()
    except ArchiveRejected:
        raise
    except (
        Error, BadZipFile, KeyError, TypeError, ValueError, AttributeError, OSError, RecursionError,
        NotImplementedError, OriginalIntegrityError, LeaseLost, processing.ProcessingNotAdmitted,
        processing.QualityConflict, DispositionConflict, DispositionInventoryUnavailable,
        policy.PolicyNotAdmitted, policy.PolicyConflict, release.ReleaseNotAdmitted, release.ReleaseConflict,
        governance.GovernanceNotAdmitted, governance.GovernanceConflict, restriction_log._LogConflict,
    ) as exc:
        raise ArchiveRejected(f"The multi-source space archive could not be reconstructed: {exc}") from None


def _require_space_archive_participant(
    connection: Connection,
    call: OperationsCall,
    operation: str,
) -> tuple[bool, bool]:
    owner_id = require_scope(connection, call, operation, destination=DESTINATION)
    is_space_owner = owner_id == call.principal_id
    approver_row = connection.execute(
        """
        SELECT 1
        FROM thalion.source AS src
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (src.org_id, src.space_id, src.source_id, src.contract_revision)
        WHERE (src.org_id, src.space_id) = (%s, %s)
          AND contract.approver_id = %s
        LIMIT 1
        """,
        (call.org_id, call.space_id, call.principal_id),
    ).fetchone()
    is_source_approver = approver_row is not None
    if not (is_space_owner or is_source_approver):
        raise OperationsNotAdmitted("Space archive management requires the space owner or a source approver.")
    return is_space_owner, is_source_approver


def list_space_archives(connection: Connection, call: OperationsCall) -> dict:
    is_space_owner, is_source_approver = _require_space_archive_participant(connection, call, LIST)
    observed_at, = connection.execute("SELECT statement_timestamp()").fetchone()

    source_id_to_ref: dict[int, str] = {}
    available_sources: list[dict] = []
    for row in connection.execute(
        """
        SELECT src.source_id, sid.public_id, src.source_key, src.lifecycle,
               src.owner_principal_id = %s AS owned_by_caller,
               contract.approver_id = %s AS approved_by_caller
        FROM thalion.source AS src
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (src.org_id, src.space_id, 'source', src.source_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision)
           = (src.org_id, src.space_id, src.source_id, src.contract_revision)
        WHERE (src.org_id, src.space_id) = (%s, %s)
        ORDER BY src.source_id ASC
        """,
        (call.principal_id, call.principal_id, call.org_id, call.space_id),
    ).fetchall():
        source_id_to_ref[row[0]] = str(row[1])
        available_sources.append({
            "source_id": str(row[1]),
            "source_key": row[2],
            "lifecycle": row[3],
            "owned_by_caller": bool(row[4]),
            "approved_by_caller": bool(row[5]),
        })

    version_id_to_ref: dict[int, str] = {}
    available_versions: list[dict] = []
    for row in connection.execute(
        """
        SELECT ver.version_id, vid.public_id, sid.public_id, doc.display_name, ver.version_label, asset.media_type,
               EXISTS (
                   SELECT 1
                   FROM thalion.processing_run AS run
                   JOIN thalion.quality_decision AS q
                     ON q.run_ref = run.run_ref AND q.outcome = 'approved'
                   WHERE (run.org_id, run.space_id, run.version_id) = (ver.org_id, ver.space_id, ver.version_id)
                     AND NOT EXISTS (
                         SELECT 1 FROM thalion.quality_decision AS q2
                         WHERE q2.run_ref = run.run_ref AND q2.outcome = 'quarantined'
                     )
               )
               AND asset.media_type IN ('text/markdown', %s, %s) AS archive_eligible
        FROM thalion.document_version AS ver
        JOIN thalion.object_identity AS vid
          ON (vid.org_id, vid.space_id, vid.object_type, vid.object_id)
           = (ver.org_id, ver.space_id, 'document_version', ver.version_id)
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (ver.org_id, ver.space_id, 'source', ver.source_id)
        JOIN thalion.document AS doc
          ON (doc.org_id, doc.space_id, doc.source_id, doc.document_id)
           = (ver.org_id, ver.space_id, ver.source_id, ver.document_id)
        JOIN thalion.asset AS asset
          ON (asset.org_id, asset.space_id, asset.source_id, asset.document_id, asset.asset_id)
           = (ver.org_id, ver.space_id, ver.source_id, ver.document_id, ver.asset_id)
        WHERE (ver.org_id, ver.space_id) = (%s, %s)
        ORDER BY ver.version_id DESC
        LIMIT 200
        """,
        (PDF_MEDIA_TYPE, DOCX_MEDIA_TYPE, call.org_id, call.space_id),
    ).fetchall():
        version_id_to_ref[row[0]] = str(row[1])
        available_versions.append({
            "version_id": str(row[1]),
            "source_id": str(row[2]),
            "display_name": row[3],
            "version_label": row[4],
            "media_type": row[5],
            "archive_eligible": bool(row[6]),
        })

    available_wikis = [
        {
            "publication_id": str(row[0]),
            "revision_id": str(row[1]),
            "topic_key": row[2],
            "published_at": row[3].astimezone(UTC).isoformat(),
        }
        for row in connection.execute(
            """
            SELECT publication_ref, revision_ref, topic_key, recorded_at
            FROM thalion.available_wiki_publication
            WHERE (org_id, space_id) = (%s, %s)
            ORDER BY recorded_at DESC
            LIMIT 100
            """,
            (call.org_id, call.space_id),
        ).fetchall()
    ]

    rows = connection.execute(
        """
        SELECT req.export_ref, req.source_ids, req.version_ids, req.wiki_publication_refs,
               req.requested_at, req.requester_id = %s AS requested_by_caller,
               app.approval_ref, app.approved_at, app.expires_at, app.approver_id = %s AS approved_by_caller,
               pkg.package_ref, pkg.format_version, pkg.archive_digest, octet_length(pkg.archive_bytes),
               pkg.recovery_watermark, pkg.sealed_at
        FROM thalion.space_archive_request AS req
        LEFT JOIN thalion.space_archive_approval AS app
          ON (app.org_id, app.space_id, app.export_ref) = (req.org_id, req.space_id, req.export_ref)
        LEFT JOIN thalion.space_archive_package AS pkg
          ON (pkg.org_id, pkg.space_id, pkg.export_ref) = (req.org_id, req.space_id, req.export_ref)
        WHERE (req.org_id, req.space_id) = (%s, %s)
        ORDER BY req.requested_at DESC
        LIMIT 100
        """,
        (call.principal_id, call.principal_id, call.org_id, call.space_id),
    ).fetchall()

    archives = []
    for row in rows:
        if row[10] is not None:
            state = "sealed"
        elif row[6] is not None:
            state = "approved" if row[8] > observed_at else "approval_expired"
        else:
            state = "requested"
        archives.append({
            "export_id": str(row[0]),
            "state": state,
            "source_ids": [source_id_to_ref.get(sid, str(sid)) for sid in row[1]],
            "version_ids": [version_id_to_ref.get(vid, str(vid)) for vid in row[2]],
            "wiki_publication_ids": [str(w) for w in row[3]],
            "requested_at": row[4].astimezone(UTC).isoformat(),
            "requested_by_caller": bool(row[5]),
            "approval_id": str(row[6]) if row[6] is not None else None,
            "approved_at": row[7].astimezone(UTC).isoformat() if row[7] is not None else None,
            "approval_expires_at": row[8].astimezone(UTC).isoformat() if row[8] is not None else None,
            "approved_by_caller": bool(row[9]) if row[9] is not None else False,
            "package_id": str(row[10]) if row[10] is not None else None,
            "format_version": row[11],
            "archive_sha256": bytes(row[12]).hex() if row[12] is not None else None,
            "archive_bytes_length": row[13],
            "recovery_watermark": row[14],
            "sealed_at": row[15].astimezone(UTC).isoformat() if row[15] is not None else None,
        })

    return {
        "observed_at": observed_at.astimezone(UTC).isoformat(),
        "caller_roles": {
            "is_space_owner": is_space_owner,
            "is_source_approver": is_source_approver,
        },
        "available_sources": available_sources,
        "available_versions": available_versions,
        "available_wikis": available_wikis,
        "archives": archives,
    }


def verify_sealed_space_archive(connection: Connection, call: OperationsCall, export_id: UUID) -> dict:
    _require_space_archive_participant(connection, call, VERIFY)
    row = connection.execute(
        """
        SELECT pkg.package_ref, pkg.archive_bytes, pkg.archive_digest, pkg.sealed_at,
               sid.public_id, current_database(), statement_timestamp()
        FROM thalion.space_archive_package AS pkg
        JOIN thalion.object_identity AS sid
          ON (sid.org_id, sid.space_id, sid.object_type, sid.object_id)
           = (pkg.org_id, pkg.space_id, 'space', pkg.space_id)
        WHERE (pkg.org_id, pkg.space_id, pkg.export_ref) = (%s, %s, %s)
        """,
        (call.org_id, call.space_id, export_id),
    ).fetchone()
    if row is None:
        raise DispositionConflict("No sealed space archive package found for this export_id.")

    package_ref, archive_bytes, archive_digest, sealed_at, space_ref, db_name, verified_at = row
    permit = SpaceArchivePermit(
        org_id=call.org_id,
        space_id=call.space_id,
        space_ref=space_ref,
        export_ref=export_id,
        digest=bytes(archive_digest),
        database=db_name,
    )
    verified = verify_space_archive(permit, bytes(archive_bytes))
    return {
        "export_id": str(export_id),
        "package_id": str(package_ref),
        "space_id": str(verified.space_ref),
        "verified": True,
        "format_version": verified.format_version,
        "archive_sha256": bytes(archive_digest).hex(),
        "source_ids": [str(ref) for ref in verified.source_refs],
        "version_ids": [str(ref) for ref in verified.version_refs],
        "wiki_revision_ids": [str(ref) for ref in verified.wiki_revision_refs],
        "recovery_watermark": verified.recovery_watermark,
        "authorization_rules_keys": sorted(verified.authorization_rules.keys()),
        "safety_decisions_keys": sorted(verified.safety_decisions.keys()),
        "sealed_at": sealed_at.astimezone(UTC).isoformat(),
        "verified_at": verified_at.astimezone(UTC).isoformat(),
    }
