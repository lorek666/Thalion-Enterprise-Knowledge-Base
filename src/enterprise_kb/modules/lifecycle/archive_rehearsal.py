from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, replace
from datetime import timedelta
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4
from zipfile import ZIP_STORED, BadZipFile, ZipFile

from psycopg import Connection, Error, OperationalError
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from enterprise_kb.database import rehearsal_marker
from enterprise_kb.modules.access.delivery import AuthorizationUnavailable
from enterprise_kb.modules.evidence.docx_evidence import MEDIA_TYPE as DOCX_MEDIA_TYPE
from enterprise_kb.modules.evidence.markdown import LOCATOR_REVISION, MarkdownCandidate, parse_markdown
from enterprise_kb.modules.evidence.pdf_evidence import MEDIA_TYPE as PDF_MEDIA_TYPE
from enterprise_kb.modules.evidence.processing import (
    ProcessingNotAdmitted, QualityConflict, _prepare_original, _record_markdown_candidate,
)
from enterprise_kb.modules.evidence.quality_restrictions import PdfProcessingQuarantine, check_pinned_history
from enterprise_kb.modules.lifecycle.archives import MAX_ARCHIVE_BYTES, ORIGINAL_MEMBERS, _metadata_digest, archive_files
from enterprise_kb.modules.lifecycle.disposition import DispositionConflict, DispositionInventoryUnavailable
from enterprise_kb.modules.lifecycle.rebuild_format import (
    DOCX_REBUILD_FORMAT, DOCX_REPAIR_REBUILD_FORMAT, PDF_REBUILD_FORMAT, PDF_REPAIR_REBUILD_FORMAT,
    REBUILD_FORMAT, REBUILD_SCOPE, REPAIR_REBUILD_FORMAT, rebuild_metadata,
)
from enterprise_kb.modules.lifecycle.transcripts import MAX_TRANSCRIPT_PASSAGES, current_transcript
from enterprise_kb.modules.lifecycle.wiki_rebuild import (
    MAX_WIKI_INPUTS, WIKI_REBUILD_FORMAT, WIKI_REBUILD_SCOPE, canonical_ref, exact_refs, verify_manifest_graph,
    wiki_rebuild_material,
)
from enterprise_kb.modules.sources.restriction_log import pinned_replay_input
from enterprise_kb.modules.sources.originals import (
    MAX_SYNTHETIC_BYTES, OriginalAsset, OriginalIntegrityError, SyntheticOriginalStore, verify_payload,
)
from enterprise_kb.modules.sources.registry import (
    SYNTHETIC_ISSUER, _digest, _rebuild_document, _rebuild_original, _rebuild_source, _register_identity, _validate_keys,
)
from enterprise_kb.modules.sources.source_revocations import SourceRevocationAuthority
from enterprise_kb.runtime.events import append_event
from enterprise_kb.runtime.jobs import JobSpec, LeaseLost, claim_job, enqueue_job


class ArchiveRejected(Exception):
    pass


@dataclass(frozen=True)
class ArchivePin:
    org_id: int
    space_id: int
    package_ref: UUID
    digest: bytes = field(repr=False)


@dataclass(frozen=True)
class RebuildPermit:
    """Approved on the operator side, independently of the archive bytes."""

    org_id: int
    space_id: int
    export_ref: UUID
    version_ref: UUID
    digest: bytes = field(repr=False)
    database: str


@dataclass(frozen=True)
class WikiArchivePermit:
    org_id: int
    space_id: int
    export_ref: UUID
    version_ref: UUID
    revision_ref: UUID
    digest: bytes = field(repr=False)


@dataclass(frozen=True)
class WikiRebuildPermit:
    pin: WikiArchivePermit
    database: str


@dataclass(frozen=True)
class VerifiedWikiArchive:
    revision_ref: UUID
    version_refs: tuple[UUID, ...]
    manifest_refs: tuple[UUID, ...]


@dataclass(frozen=True)
class RebuiltWikiArchive:
    revision_ref: UUID
    store: SyntheticOriginalStore = field(repr=False)
    originals: tuple[tuple[UUID, OriginalAsset], ...] = field(repr=False)


@dataclass(frozen=True)
class _VersionMaterial:
    metadata: dict = field(repr=False)
    original: bytes = field(repr=False)
    digest: bytes
    candidate: MarkdownCandidate = field(repr=False)
    passage_refs: tuple[UUID, ...]
    run_ref: UUID


@dataclass(frozen=True)
class _RegisteredVersionMaterial:
    metadata: dict = field(repr=False)
    original: bytes = field(repr=False)
    digest: bytes
    run_ref: UUID
    passage_refs: frozenset[UUID]
    history: dict | None = field(default=None, repr=False)
    transcription: dict | None = field(default=None, repr=False)
    page_transcripts: tuple[bytes | None, ...] = field(default=(), repr=False)
    docx_transcripts: tuple[bytes, ...] = field(default=(), repr=False)
    media_type: str = "text/markdown"


@dataclass(frozen=True)
class _WikiMaterial:
    verified: VerifiedWikiArchive
    topic_key: str
    content: bytes = field(repr=False)
    dependencies: dict = field(repr=False)
    graph: dict = field(repr=False)
    versions: dict[UUID, _VersionMaterial | _RegisteredVersionMaterial] = field(repr=False)


@dataclass(frozen=True)
class StagedArchive:
    version_ref: UUID
    scope: str
    store: SyntheticOriginalStore = field(repr=False)
    asset: OriginalAsset = field(repr=False)


def _registered_target(connection, pin):
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute("""
            SELECT target.*, request.transcript_run_ref, request.wiki_publication_ref, request.repair_history_digest
            FROM thalion.synthetic_export_package AS package
            JOIN thalion.synthetic_export_request AS request USING (org_id, space_id, export_ref, requester_id)
            JOIN thalion.synthetic_original_export_target AS target USING (org_id, space_id, version_id)
            WHERE (package.org_id, package.space_id, package.package_ref, package.archive_digest) = (%s, %s, %s, %s)
              AND request.rebuild_metadata_digest IS NULL AND request.wiki_rebuild_digest IS NULL
              AND NOT target.blocked AND target.snapshot = request.snapshot
            """, (pin.org_id, pin.space_id, pin.package_ref, pin.digest)).fetchone()


def _read_member(archive, entry, expected_length):
    if (
        entry.compress_type != ZIP_STORED or entry.flag_bits != 0
        or entry.file_size != expected_length or entry.compress_size != expected_length
    ):
        raise ArchiveRejected("An archive member has unsupported encoding or length.")
    return archive.read(entry)


def _check_package(payload, digest):
    if (
        not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ARCHIVE_BYTES
        or sha256(payload).digest() != digest
    ):
        raise ArchiveRejected("Archive bytes do not match the bounded package pin.")


def _check_input(connection, payload, digest):
    _check_package(payload, digest)
    if (
        connection.closed or not connection.autocommit or connection.info.hostaddr not in {"127.0.0.1", "::1"}
        or connection.info.transaction_status != TransactionStatus.IDLE
    ):
        raise ArchiveRejected("Archive staging requires an idle local rehearsal database.")


def _check_archive(connection: Connection, pin: ArchivePin, payload: bytes):
    _check_input(connection, payload, pin.digest)
    try:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            if rehearsal_marker(connection) != connection.info.dbname:
                raise ArchiveRejected("Archive staging requires a database fenced for rehearsal.")
            target = _registered_target(connection, pin)
            if target is None or not 0 < target["byte_length"] <= MAX_SYNTHETIC_BYTES:
                raise ArchiveRejected("The exact archived version or sealed package is unavailable in the snapshot.")
            original_name = ORIGINAL_MEMBERS[target["media_type"]]
            with ZipFile(BytesIO(payload)) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_TRANSCRIPT_PASSAGES + 3 + (target["repair_history_digest"] is not None):
                    raise ArchiveRejected("The archive exceeds the bounded member count.")
                by_name = {entry.filename: entry for entry in entries}
                if len(by_name) != len(entries) or original_name not in by_name:
                    raise ArchiveRejected("Archive membership is ambiguous or incomplete.")
                original = _read_member(archive, by_name[original_name], target["byte_length"])
                verify_payload(original, target["content_digest"])
                expected, _, scope = archive_files(connection, pin.org_id, pin.space_id, target, original)
                if by_name.keys() != expected.keys() or any(
                    _read_member(archive, by_name[name], len(content)) != content
                    for name, content in expected.items() if name != original_name
                ):
                    raise ArchiveRejected("The package does not match the exact registered archive members.")
            return target, original, scope
    except (
        Error, BadZipFile, UnicodeError, NotImplementedError,
        DispositionConflict, DispositionInventoryUnavailable, OriginalIntegrityError,
    ):
        raise ArchiveRejected("The archived bytes or registered dependencies could not be verified.") from None


@contextmanager
def stage_original(connection: Connection, pin: ArchivePin, payload: bytes, scratch_root: Path):
    """Materialize only an already registered original in a fresh private rehearsal directory."""
    target, original, scope = _check_archive(connection, pin, payload)
    try:
        parent = SyntheticOriginalStore(scratch_root).root
    except (OSError, ValueError):
        raise ArchiveRejected("The archive rehearsal directory is not private and available.") from None
    with TemporaryDirectory(dir=parent, prefix="archive-rehearsal-") as activated:
        try:
            store = SyntheticOriginalStore(Path(activated))
            asset = store.stage(target["storage_key"], target["content_digest"], original)
        except (OSError, ValueError, OriginalIntegrityError):
            raise ArchiveRejected("The verified original could not be staged privately.") from None
        yield StagedArchive(target["version_ref"], scope, store, asset)


def _json_object(archive, entry, *, max_bytes, ensure_ascii):
    if not 0 < entry.file_size <= max_bytes:
        raise ArchiveRejected("The archive manifest exceeds its size limit.")
    raw = _read_member(archive, entry, entry.file_size)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=ensure_ascii, allow_nan=False,
    ).encode() != raw:
        raise ArchiveRejected("The archive manifest is not a canonical object.")
    return value, raw


def _decode_rebuild(permit, payload):
    with ZipFile(BytesIO(payload)) as archive:
        entries = archive.infolist()
        members = {entry.filename: entry for entry in entries}
        if not 4 <= len(entries) <= MAX_TRANSCRIPT_PASSAGES + 3 or len(members) != len(entries):
            raise ArchiveRejected("Unexpected archive members.")
        manifest, _ = _json_object(archive, members["manifest.json"], max_bytes=16_384, ensure_ascii=True)
        if (
            set(manifest) != {"format", "scope", "restorable", "version_id", "original_sha256", "byte_length",
                              "format_media_type", "safety_snapshot", "transcription_sha256", "org_id", "space_id",
                              "export_id", "rebuild"}
            or (manifest["format"], manifest["scope"], manifest["format_media_type"])
               != (REBUILD_FORMAT, REBUILD_SCOPE, "text/markdown")
            or manifest["restorable"] is not False
            or any(type(manifest[key]) is not int for key in ("org_id", "space_id"))
            or (manifest["org_id"], manifest["space_id"], manifest["export_id"], manifest["version_id"])
               != (permit.org_id, permit.space_id, str(permit.export_ref), str(permit.version_ref))
            or not isinstance(manifest["safety_snapshot"], list) or len(manifest["safety_snapshot"]) != 6
            or any(type(item) is not int or item < 0 for item in manifest["safety_snapshot"])
            or type(manifest["byte_length"]) is not int or not 0 < manifest["byte_length"] <= MAX_SYNTHETIC_BYTES
        ):
            raise ArchiveRejected("The rebuild archive does not match the approved format and scope.")
        original = _read_member(archive, members["original.md"], manifest["byte_length"])
        digest = sha256(original).digest()
        if digest.hex() != manifest["original_sha256"]:
            raise ArchiveRejected("The original does not match its manifest.")
        transcript, raw = _json_object(archive, members["transcription.json"], max_bytes=3_145_728, ensure_ascii=False)
        candidate = parse_markdown(original)
        if (
            set(transcript) != {"run_id", "manifest_sha256", "configuration_revision", "passages"}
            or type(transcript["configuration_revision"]) is not int or transcript["configuration_revision"] != 1
            or sha256(raw).hexdigest() != manifest["transcription_sha256"]
            or candidate.outcome != "pending_review" or not isinstance(transcript["passages"], list)
            or len(transcript["passages"]) != len(candidate.passages)
        ):
            raise ArchiveRejected("The archived run cannot be reconstructed by the admitted parser.")
        run_manifest = _digest(
            "markdown_manifest.v1", str(permit.version_ref), digest.hex(), 1, candidate.outcome, candidate.reason,
            [(part.heading_path, part.paragraph, part.kind, part.byte_start, part.byte_end, part.digest.hex())
             for part in candidate.passages],
        )
        if transcript["manifest_sha256"] != run_manifest.hex():
            raise ArchiveRejected("The archive has a different processing manifest.")
        run_ref = canonical_ref(transcript["run_id"])
        refs = []
        expected_members = {"manifest.json", "original.md", "transcription.json"}
        for entry, part in zip(transcript["passages"], candidate.passages, strict=True):
            ref = UUID(entry["passage_id"])
            member = f"transcript/{ref}.md"
            if entry != {
                "passage_id": str(ref), "excerpt_revision": 1, "locator_revision": LOCATOR_REVISION,
                "heading_path": list(part.heading_path), "paragraph": part.paragraph, "kind": part.kind,
                "byte_start": part.byte_start, "byte_end": part.byte_end, "sha256": part.digest.hex(), "member": member,
            } or any(type(entry[key]) is not int for key in (
                "excerpt_revision", "locator_revision", "paragraph", "byte_start", "byte_end",
            )) or _read_member(archive, members[member], part.byte_end - part.byte_start) != original[part.byte_start:part.byte_end]:
                raise ArchiveRejected("An archived passage does not match its exact revision and original bytes.")
            refs.append(ref)
            expected_members.add(member)
        if set(members) != expected_members or len(refs) != len(set(refs)):
            raise ArchiveRejected("The archive membership does not match its exact passages.")
    metadata = manifest["rebuild"]
    if not isinstance(metadata, dict) or set(metadata) != {
        "source_id", "document_id", "source_key", "object_namespace", "object_key", "incarnation",
        "display_name", "version_key", "version_label", "registration_sequence",
    }:
        raise ArchiveRejected("The archive has incomplete reconstruction metadata.")
    _validate_keys(*(metadata[key] for key in ("source_key", "object_namespace", "object_key", "incarnation", "version_key")))
    if (
        type(metadata["registration_sequence"]) is not int or not 0 < metadata["registration_sequence"] < 2**63
        or any(not isinstance(metadata[key], str) or not 0 < len(metadata[key].strip()) <= limit or "\0" in metadata[key]
               for key, limit in (("display_name", 300), ("version_label", 128)))
    ):
        raise ArchiveRejected("The archive contains invalid document metadata.")
    identities = {key: canonical_ref(metadata[key]) for key in ("source_id", "document_id")}
    if len(set(identities.values()) | {permit.version_ref, run_ref, *refs}) != len(refs) + 4:
        raise ArchiveRejected("The archive repeats a stable public identity.")
    return _VersionMaterial(metadata | identities, original, digest, candidate, tuple(refs), run_ref)


def _wiki_archive_header(archive, members, permit):
    header, _ = _json_object(archive, members["manifest.json"], max_bytes=16_384, ensure_ascii=True)
    if (
        set(header) != {"format", "scope", "restorable", "org_id", "space_id", "export_id", "version_id",
                        "topic_key", "manifest_graph_sha256", "wiki_dependencies_sha256", "versions"}
        or (header["format"], header["scope"]) != (WIKI_REBUILD_FORMAT, WIKI_REBUILD_SCOPE)
        or header["restorable"] is not False
        or any(type(header[key]) is not int for key in ("org_id", "space_id"))
        or (header["org_id"], header["space_id"], header["export_id"], header["version_id"]) != (
            permit.org_id, permit.space_id, str(permit.export_ref), str(permit.version_ref),
        )
        or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", header["topic_key"])
        or not isinstance(header["versions"], list) or not 1 <= len(header["versions"]) <= MAX_WIKI_INPUTS
    ):
        raise ArchiveRejected("The Wiki rebuild archive does not match the approved scope.")
    return header


def _wiki_archive_graph(archive, members, header, permit):
    dependencies, dependency_bytes = _json_object(
        archive, members["wiki/dependencies.json"], max_bytes=32_768, ensure_ascii=True,
    )
    graph, graph_bytes = _json_object(archive, members["wiki/manifests.json"], max_bytes=131_072, ensure_ascii=True)
    if (
        sha256(dependency_bytes).hexdigest() != header["wiki_dependencies_sha256"]
        or sha256(graph_bytes).hexdigest() != header["manifest_graph_sha256"]
        or set(graph) != {"manifests"}
        or set(dependencies) != {"revision_id", "publication_id", "content_sha256", "manifest_id", "manifest_format_revision",
                                 "input_sha256", "direct_count", "parent_manifest_ids", "inputs"}
        or dependencies["revision_id"] != str(permit.revision_ref)
        or type(dependencies["manifest_format_revision"]) is not int or dependencies["manifest_format_revision"] != 1
        or type(dependencies["direct_count"]) is not int
    ):
        raise ArchiveRejected("The Wiki revision and its manifests could not be verified.")
    canonical_ref(dependencies["publication_id"])
    root_ref = canonical_ref(dependencies["manifest_id"])
    manifest_refs, expanded = verify_manifest_graph(root_ref, graph["manifests"])
    root = next(node for node in graph["manifests"] if node["manifest_id"] == str(root_ref))
    if any(root[key] != dependencies[key] for key in ("direct_count", "parent_manifest_ids")) or (
        root["expanded_sha256"] != dependencies["input_sha256"]
    ):
        raise ArchiveRejected("The Wiki dependencies differ from their root manifest.")
    return dependencies, graph, manifest_refs, expanded


def _verify_statement_support(statements, citations):
    if not isinstance(statements, list) or not 1 <= len(statements) <= 20:
        raise ArchiveRejected("The Wiki statements are not in the supported format.")
    for statement in statements:
        if (
            not isinstance(statement, dict) or set(statement) != {"text", "support_groups"}
            or not isinstance(statement["text"], str) or not statement["text"].strip()
            or len(statement["text"]) > 2000 or "\0" in statement["text"]
            or not isinstance(statement["support_groups"], list) or not 1 <= len(statement["support_groups"]) <= 20
            or any(not exact_refs(group).items() <= citations.items() for group in statement["support_groups"])
        ):
            raise ArchiveRejected("The Wiki statement does not have exact cited support.")


def _wiki_revision_bytes(archive, members, dependencies, expanded):
    entry = members["wiki/revision.json"]
    if not 1 <= entry.file_size <= 131_072:
        raise ArchiveRejected("The Wiki revision exceeds its size limit.")
    raw = _read_member(archive, entry, entry.file_size)
    revision = json.loads(raw)
    if (
        sha256(raw).hexdigest() != dependencies["content_sha256"]
        or not isinstance(revision, dict) or set(revision) not in (
            {"title", "markdown", "citations"}, {"title", "markdown", "citations", "statements"},
        )
        or not isinstance(revision["title"], str) or not revision["title"].strip() or len(revision["title"]) > 256
        or not isinstance(revision["markdown"], str) or not revision["markdown"].strip()
        or "\0" in revision["title"] or "\0" in revision["markdown"]
        or json.dumps(revision, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() != raw
    ):
        raise ArchiveRejected("The Wiki revision differs from its recorded bytes.")
    markdown = revision["markdown"].encode()
    citations = exact_refs(revision["citations"])
    if _read_member(archive, members["wiki/content.md"], len(markdown)) != markdown or not citations.items() <= expanded.items():
        raise ArchiveRejected("The Wiki Markdown or citations do not match their exact inputs.")
    if "statements" in revision:
        _verify_statement_support(revision["statements"], citations)
    return raw


def _docx_parts(transcription):
    return transcription["paragraphs"] + [
        cell for table in transcription["tables"] for row in table["rows"] for cell in row["cells"]
    ]


def _wiki_version_archives(archive, members, header, permit, load_registered):
    versions, passages = {}, {}
    expected = {"manifest.json", "wiki/dependencies.json", "wiki/manifests.json", "wiki/revision.json", "wiki/content.md"}
    for item in header["versions"]:
        if not isinstance(item, dict) or set(item) != {"version_id", "sha256"}:
            raise ArchiveRejected("Invalid archived Wiki version declaration.")
        version_ref = canonical_ref(item["version_id"])
        name = f"versions/{version_ref}.zip"
        if version_ref in versions:
            raise ArchiveRejected("The Wiki archive repeats a source version.")
        entry = members[name]
        packed = _read_member(archive, entry, entry.file_size)
        digest = sha256(packed).digest()
        if digest.hex() != item["sha256"]:
            raise ArchiveRejected("An embedded source version differs from its archive digest.")
        nested = replace(permit, version_ref=version_ref, digest=digest)
        with ZipFile(BytesIO(packed)) as embedded:
            registered = any(ORIGINAL_MEMBERS[media] in embedded.namelist() for media in (PDF_MEDIA_TYPE, DOCX_MEDIA_TYPE))
        if registered:
            if load_registered is None:
                raise ArchiveRejected("PDF or DOCX Wiki reconstruction requires the independent checkpoint.")
            material = load_registered(nested, packed)
            parts = (
                material.transcription["pages"] if material.media_type == PDF_MEDIA_TYPE
                else _docx_parts(material.transcription)
            )
            exact = (
                (UUID(part["passage_id"]), part["excerpt_revision"], part["sha256"])
                for part in parts if "passage_id" in part
            )
        else:
            material = _decode_rebuild(nested, packed)
            exact = (
                (ref, 1, part.digest.hex())
                for ref, part in zip(material.passage_refs, material.candidate.passages, strict=True)
            )
        versions[version_ref] = material
        expected.add(name)
        for ref, revision, excerpt_digest in exact:
            if ref in passages:
                raise ArchiveRejected("An embedded passage belongs to more than one version.")
            passages[ref] = (version_ref, material.run_ref, revision, excerpt_digest)
        if len(passages) > MAX_TRANSCRIPT_PASSAGES:
            raise ArchiveRejected("The complete Wiki transcript scope exceeds the archive limit.")
    if members.keys() != expected or permit.version_ref not in versions:
        raise ArchiveRejected("Unexpected members in the Wiki rebuild archive.")
    return versions, passages


def verify_wiki_rebuild(permit: WikiArchivePermit, payload: bytes) -> VerifiedWikiArchive:
    """Verify the portable Wiki inputs offline, without importing or granting access."""
    return _decode_wiki_rebuild(permit, payload).verified


def _verify_version_relationships(versions, reserved):
    sources, documents, object_keys, version_keys, sequences = set(), {}, {}, set(), set()
    used = set(reserved)
    if len(used) != len(reserved):
        raise ArchiveRejected("The Wiki archive repeats a stable identity.")
    for version_ref, material in versions.items():
        meta = material.metadata
        source_ref, document_ref = meta["source_id"], meta["document_id"]
        sources.add((source_ref, meta["source_key"], meta["object_namespace"]))
        object_key = meta["object_key"], meta["incarnation"]
        descriptor = (*object_key, meta["display_name"])
        version_key = document_ref, meta["version_key"]
        sequence = document_ref, meta["registration_sequence"]
        if (
            documents.setdefault(document_ref, descriptor) != descriptor
            or object_keys.setdefault(object_key, document_ref) != document_ref
            or version_key in version_keys or sequence in sequences
        ):
            raise ArchiveRejected("Embedded Wiki versions disagree on their document relationships.")
        version_keys.add(version_key)
        sequences.add(sequence)
        identities = (version_ref, material.run_ref, *material.passage_refs)
        if len(set(identities)) != len(identities) or used.intersection(identities):
            raise ArchiveRejected("The Wiki archive repeats a stable identity.")
        used.update(identities)
    if len(sources) != 1:
        raise ArchiveRejected("Embedded Wiki versions require one consistent source.")
    source_ref, _, _ = next(iter(sources))
    if source_ref in documents or used.intersection({source_ref, *documents}):
        raise ArchiveRejected("The Wiki archive repeats a stable identity.")


def _decode_wiki_rebuild(permit, payload, *, load_registered=None):
    _check_package(payload, permit.digest)
    try:
        with ZipFile(BytesIO(payload)) as archive:
            entries = archive.infolist()
            members = {item.filename: item for item in entries}
            if not 6 <= len(entries) <= MAX_WIKI_INPUTS + 5 or len(entries) != len(members):
                raise ArchiveRejected("Unexpected Wiki archive members.")
            header = _wiki_archive_header(archive, members, permit)
            dependencies, graph, manifest_refs, expanded = _wiki_archive_graph(archive, members, header, permit)
            content = _wiki_revision_bytes(archive, members, dependencies, expanded)
            versions, passages = _wiki_version_archives(archive, members, header, permit, load_registered)
            _verify_version_relationships(
                versions, (permit.export_ref, permit.revision_ref, canonical_ref(dependencies["publication_id"]), *manifest_refs),
            )
            inputs = dependencies["inputs"]
            if not isinstance(inputs, list) or len(inputs) != len(expanded):
                raise ArchiveRejected("The Wiki archive does not cover every expanded input.")
            referenced = set()
            for position, ((ref, revision), item) in enumerate(zip(expanded.items(), inputs, strict=True), 1):
                version_ref, run_ref, archived_revision, digest = passages[ref]
                if revision != archived_revision or not isinstance(item, dict) or any(
                    type(item.get(key)) is not int for key in ("position", "excerpt_revision")
                ) or item != {
                    "position": position, "version_id": str(version_ref), "passage_id": str(ref),
                    "excerpt_revision": revision, "run_id": str(run_ref), "excerpt_sha256": digest,
                }:
                    raise ArchiveRejected("The Wiki input does not match its archived passage revision.")
                referenced.add(version_ref)
            if referenced != versions.keys():
                raise ArchiveRejected("The Wiki archive includes unrelated source versions.")
        verified = VerifiedWikiArchive(permit.revision_ref, tuple(sorted(versions)), manifest_refs)
        return _WikiMaterial(verified, header["topic_key"], content, dependencies, graph, versions)
    except (BadZipFile, KeyError, TypeError, ValueError, AttributeError, OSError, RecursionError, NotImplementedError):
        raise ArchiveRejected("The complete Wiki rebuild archive could not be verified.") from None


def _rebuild_scope(connection):
    org_id, = connection.execute("""
        INSERT INTO thalion.organization (name, business_timezone)
        VALUES ('Archive rehearsal', 'UTC') RETURNING org_id
        """).fetchone()
    principals = []
    for role in ("employee", "service"):
        principal_id, = connection.execute("""
            INSERT INTO thalion.principal (org_id, principal_type, authority_issuer, authority_subject_key)
            VALUES (%s, %s, %s, %s) RETURNING principal_id
            """, (org_id, role, SYNTHETIC_ISSUER, str(uuid4()))).fetchone()
        _register_identity(connection, org_id, None, "principal", principal_id)
        principals.append(principal_id)
    owner, worker = principals
    space_id, = connection.execute("""
        INSERT INTO thalion.space (org_id, name, classification, owner_principal_id)
        VALUES (%s, 'Archive rehearsal', 'internal', %s) RETURNING space_id
        """, (org_id, owner)).fetchone()
    _register_identity(connection, org_id, space_id, "space", space_id)
    return org_id, space_id, owner, worker


def _current_registered_target(authority, permit, version_id):
    version_scope = (permit.org_id, permit.space_id, version_id)
    authority.execute("SELECT thalion.lock_synthetic_export_target(%s, %s, %s)", version_scope)
    with authority.cursor(row_factory=dict_row) as cursor:
        return cursor.execute("""
            SELECT target.*, request.export_ref, request.transcript_run_ref, request.wiki_publication_ref,
                   request.repair_history_digest, request.rebuild_metadata_digest
            FROM thalion.synthetic_export_request AS request
            JOIN thalion.synthetic_original_export_target AS target USING (org_id, space_id, version_id)
            JOIN thalion.organization AS organization USING (org_id)
            JOIN thalion.space AS space USING (org_id, space_id)
            JOIN thalion.principal AS requester ON (requester.org_id, requester.principal_id) =
                (request.org_id, request.requester_id)
            WHERE (request.org_id, request.space_id, request.version_id, request.export_ref) = (%s, %s, %s, %s)
              AND NOT target.blocked AND target.snapshot = request.snapshot
              AND request.requester_id = target.owner_id AND request.requester_id = target.space_owner_id
              AND requester.principal_type = 'employee' AND requester.authority_issuer = %s AND NOT requester.disabled
            FOR SHARE OF organization, space, requester
            """, (*version_scope, permit.export_ref, SYNTHETIC_ISSUER)).fetchone()


def _registered_version_material(authority, permit, version_id, payload, *, media_type):
    version_scope = (permit.org_id, permit.space_id, version_id)
    target = _current_registered_target(authority, permit, version_id)
    if target is None or target["media_type"] != media_type or not 0 < target["byte_length"] <= MAX_SYNTHETIC_BYTES:
        raise ArchiveRejected("The sealed reconstruction archive is no longer current or admitted.")
    transcript = current_transcript(authority, *version_scope, target["transcript_run_ref"])
    repaired = target["repair_history_digest"] is not None
    metadata = rebuild_metadata(authority, *version_scope, transcript[1], repaired=repaired, media_type=media_type)
    if _metadata_digest(metadata) != target["rebuild_metadata_digest"]:
        raise ArchiveRejected("The registered reconstruction metadata changed.")
    return _verify_registered_members(authority, permit, payload, target, metadata)


def _verify_registered_members(authority, permit, payload, target, metadata):
    pdf = target["media_type"] == PDF_MEDIA_TYPE
    repaired = target.get("repair_history_digest") is not None
    original_name = ORIGINAL_MEMBERS[target["media_type"]]
    with ZipFile(BytesIO(payload)) as archive:
        entries = archive.infolist()
        members = {entry.filename: entry for entry in entries}
        if len(entries) > MAX_TRANSCRIPT_PASSAGES + 3 + repaired or len(members) != len(entries):
            raise ArchiveRejected("Unexpected members in the reconstruction archive.")
        original = _read_member(archive, members[original_name], target["byte_length"])
        verify_payload(original, target["content_digest"])
        expected, _, _ = archive_files(authority, permit.org_id, permit.space_id, target, original, metadata)
        if members.keys() != expected.keys() or any(
            _read_member(archive, members[name], len(content)) != content
            for name, content in expected.items() if name != original_name
        ):
            raise ArchiveRejected("The package does not match the registered reconstruction members.")
    metadata |= {key: canonical_ref(metadata[key]) for key in ("source_id", "document_id")}
    history = json.loads(expected["repair-history.json"]) if repaired else None
    docx = target["media_type"] == DOCX_MEDIA_TYPE
    locations = "pages" if pdf else "locations" if docx else "passages"
    run_ref = target["transcript_run_ref"]
    refs = {
        UUID(part["passage_id"]) for run in history["runs"] for part in run[locations] if "passage_id" in part
    } if history is not None else set()
    if pdf:
        transcription = json.loads(expected["transcription.json"])
        entries = transcription["pages"]
        refs.update(UUID(page["passage_id"]) for page in entries if "passage_id" in page)
        texts = tuple(expected[page["member"]] if "member" in page else None for page in entries)
        return _RegisteredVersionMaterial(
            metadata, original, target["content_digest"], run_ref, frozenset(refs),
            history=history, transcription=transcription, page_transcripts=texts, media_type=PDF_MEDIA_TYPE,
        )
    if docx:
        transcription = json.loads(expected["transcription.json"])
        parts = _docx_parts(transcription)
        refs.update(UUID(part["passage_id"]) for part in parts)
        if history is not None:
            original_headers = {
                (table["table_number"], column): sha256(header.encode("utf-8")).hexdigest()
                for table in transcription["tables"] for column, header in enumerate(table["headers"], start=1)
            }
            if any(
                original_headers.get((part["table"], part["column"])) != part["header_sha256"]
                for run in history["runs"] for part in run["locations"] if "table" in part
            ):
                raise ArchiveRejected("The historical DOCX table headers cannot be attested by the registered original.")
        texts = tuple(expected[f"transcript/{part['passage_id']}.txt"] for part in parts)
        return _RegisteredVersionMaterial(
            metadata, original, target["content_digest"], run_ref, frozenset(refs),
            history=history, transcription=transcription, docx_transcripts=texts, media_type=DOCX_MEDIA_TYPE,
        )
    return _RegisteredVersionMaterial(
        metadata, original, target["content_digest"], run_ref, frozenset(refs), history=history,
    )


def _checkpoint_wiki_material(authority, permit, payload, version_id, publication_ref, wiki_digest):
    registered_versions = None

    def load_registered(nested, packed):
        nonlocal registered_versions
        if registered_versions is None:
            if _current_registered_target(authority, permit, version_id) is None:
                raise ArchiveRejected("The sealed Wiki reconstruction archive is no longer current or admitted.")
            digest, _, _, versions = wiki_rebuild_material(authority, permit.org_id, permit.space_id, publication_ref)
            if digest != wiki_digest:
                raise ArchiveRejected("The registered Wiki reconstruction metadata changed.")
            registered_versions = {
                item["version_ref"]: item for item in versions if item["media_type"] in (PDF_MEDIA_TYPE, DOCX_MEDIA_TYPE)
            }
        target = registered_versions.get(nested.version_ref)
        if target is None or not 0 < target["byte_length"] <= MAX_SYNTHETIC_BYTES:
            raise ArchiveRejected("The embedded version does not match a registered Wiki input.")
        return _verify_registered_members(authority, nested, packed, target | {"export_ref": permit.export_ref}, target["metadata"])

    return _decode_wiki_rebuild(permit, payload, load_registered=load_registered)


def _verify_repair_quality(quality, repair, space_ref, version_ref, *, media_type):
    runs = {run["run_id"]: run for run in repair.history["runs"]}
    pdf = media_type == PDF_MEDIA_TYPE
    quarantine = {}
    replacements = set()
    for run_id, run in runs.items():
        decisions = {item["outcome"]: item for item in run["decisions"]}
        binding = (run["configuration_revision"], run["manifest_sha256"])
        if "quarantined" in decisions:
            decision = decisions["quarantined"]
            quarantine[run_id] = (*binding, "manual", decision["decision_id"], decision["basis_id"])
        elif pdf and run["outcome"] == "quarantined":
            quarantine[run_id] = (*binding, "processing", run_id, run["reason"], len(run["pages"]))
        if run["replaces_run_id"] is not None:
            approved = decisions.get("approved")
            if pdf:
                if approved is None or not approved.get("proof_sha256") or [
                    page["page"] for page in approved.get("pages", ())
                ] != [page["page"] for page in run["pages"]]:
                    raise ArchiveRejected("A sealed PDF repair has no whole-batch approval evidence.")
            else:
                docx_table = media_type == DOCX_MEDIA_TYPE and any("table" in part for part in run["locations"])
                digest_key = "batch_sha256" if docx_table else "difference_sha256"
                if approved is None or not approved.get("preview_id") or not approved.get(digest_key):
                    raise ArchiveRejected("A sealed repair has no matching approval evidence.")
            replacements.add(run["replaces_run_id"])
    logged = {}
    for item in quality.quarantines:
        if item.version_ref == version_ref:
            run_id = str(item.run_ref)
            if item.space_ref != space_ref or run_id in logged:
                raise ArchiveRejected("The independent quarantine scope differs from the repair archive.")
            binding = (item.configuration_revision, item.manifest_digest.hex())
            logged[run_id] = (*binding, *(
                ("processing", str(item.decision_ref), item.reason, item.page_count)
                if isinstance(item, PdfProcessingQuarantine) else ("manual", str(item.decision_ref), str(item.basis_ref))
            ))
    if not replacements or replacements != quarantine.keys() or quarantine != logged:
        raise ArchiveRejected("A current or unaccounted quarantine blocks the repair reconstruction.")


@contextmanager
def _rule_checkpoint(permit, sources, versions, *, wiki_payload=None, archive_payload=None, media_type="text/markdown", repaired=False):
    if sources is None:
        yield None, _decode_wiki_rebuild(permit, wiki_payload) if wiki_payload is not None else None
        return
    authority, log, authority_ref, log_ref, source_authority = sources
    if source_authority is None or source_authority.authority_ref in {authority_ref, log_ref}:
        raise ArchiveRejected("The independent source revocations require their own pinned authority.")
    with pinned_replay_input(authority, log, permit.org_id, authority_ref=authority_ref, log_ref=log_ref) as checked:
        if checked.status != "verified":
            raise ArchiveRejected("The current independent rule history could not be verified.")
        registered = authority.execute("""
            SELECT request.wiki_publication_ref, space.public_id, requester.public_id, request.version_id,
                   request.wiki_rebuild_digest
            FROM thalion.synthetic_export_package AS package
            JOIN thalion.synthetic_export_request AS request USING (org_id, space_id, export_ref, requester_id)
            JOIN thalion.object_identity AS version
              ON (version.org_id, version.space_id, version.object_type, version.object_id) =
                 (request.org_id, request.space_id, 'document_version', request.version_id)
            JOIN thalion.object_identity AS space
              ON (space.org_id, space.object_type, space.object_id) =
                 (request.org_id, 'space', request.space_id)
            JOIN thalion.object_identity AS requester
              ON (requester.org_id, requester.object_type, requester.object_id) =
                 (request.org_id, 'principal', request.requester_id)
            WHERE (request.org_id, request.space_id, request.export_ref, version.public_id, package.archive_digest) =
                  (%s, %s, %s, %s, %s)
              AND CASE WHEN %s THEN request.wiki_rebuild_digest IS NOT NULL
                       ELSE request.rebuild_metadata_digest IS NOT NULL
                            AND (request.repair_history_digest IS NOT NULL) = %s END
            """, (permit.org_id, permit.space_id, permit.export_ref, permit.version_ref, permit.digest,
                  wiki_payload is not None, repaired)).fetchone()
        if registered is None:
            raise ArchiveRejected("The current authority cannot attest the exact sealed archive.")
        publication_ref, space_ref, requester_ref, version_id, wiki_digest = registered
        version_refs = {permit.version_ref} if archive_payload is not None else set(versions)
        if wiki_payload is not None:
            registered_versions = authority.execute("""
                SELECT input.version_ref, input.version_id
                FROM thalion.wiki_archive_input AS input
                JOIN thalion.wiki_publication_event AS publication USING (org_id, space_id, publication_ref)
                JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
                WHERE (input.org_id, input.space_id, input.publication_ref, publication.revision_ref) = (%s, %s, %s, %s)
                ORDER BY document.document_id
                FOR SHARE OF document
                """, (permit.org_id, permit.space_id, publication_ref, permit.revision_ref)).fetchall()
            version_refs = {ref for ref, _ in registered_versions}
            if permit.version_ref not in version_refs:
                raise ArchiveRejected("The current authority cannot attest all archived Wiki versions.")
            if authority.execute("""
                SELECT 1 FROM thalion.current_version_hold
                WHERE (org_id, space_id) = (%s, %s) AND version_id = ANY(%s) AND action = 'establish'
                LIMIT 1
                """, (permit.org_id, permit.space_id, sorted({version for _, version in registered_versions}))).fetchone():
                raise ArchiveRejected("A current hold blocks an archived Wiki version.")
        if any(entry.version_ref in version_refs for entry in checked.entries):
            raise ArchiveRejected("Current rule history blocks an archived version.")
        material = None
        if archive_payload is not None:
            material = _registered_version_material(authority, permit, version_id, archive_payload, media_type=media_type)
        quality = check_pinned_history(authority, log, permit.org_id, authority_ref)
        if quality is None:
            raise ArchiveRejected("The current independent quality history could not be verified.")
        if material is not None and material.history is not None:
            _verify_repair_quality(quality, material, space_ref, permit.version_ref, media_type=media_type)
        elif version_refs & quality.blocked_versions:
            raise ArchiveRejected("Current quality history blocks an archived version.")
        if wiki_payload is not None:
            wiki = _checkpoint_wiki_material(authority, permit, wiki_payload, version_id, publication_ref, wiki_digest)
            if str(publication_ref) != wiki.dependencies["publication_id"] or version_refs != wiki.versions.keys():
                raise ArchiveRejected("The current authority cannot attest all archived Wiki versions.")
            versions, material = wiki.versions, wiki
        archive_refs = version_refs.union(ref for version in versions.values() for ref in version.passage_refs)
        if archive_payload is not None:
            archive_refs.update(material.passage_refs)
        if wiki_payload is not None:
            archive_refs.add(permit.revision_ref)
        with ExitStack() as stack:
            try:
                snapshot = stack.enter_context(source_authority.pinned_snapshot(space_ref))
            except AuthorizationUnavailable:
                raise ArchiveRejected("The current independent source revocations could not be verified.") from None
            if archive_refs & snapshot.denied_objects(requester_ref, "archive"):
                raise ArchiveRejected("Current source revocation blocks part of the sealed archive.")
            yield ((
                authority_ref, checked.log_ref, checked.stream_ref, len(checked.entries), quality.stream_ref,
                quality.generation, snapshot.authority_ref, snapshot.space_ref, snapshot.stream_ref,
                snapshot.generation, requester_ref,
            ), material)


def _begin_empty_rebuild(connection, database, store):
    connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
    connection.execute("SET LOCAL synchronous_commit = on")
    if rehearsal_marker(connection) != database:
        raise ArchiveRejected("Archive reconstruction requires a database fenced for rehearsal.")
    connection.execute("LOCK TABLE thalion.organization IN SHARE ROW EXCLUSIVE MODE")
    if connection.execute("SELECT 1 FROM thalion.organization LIMIT 1").fetchone() or any(store.root.iterdir()):
        raise ArchiveRejected("Archive reconstruction requires an empty database and private original directory.")


def _materialize_version(connection, scope, doc_scope, version_ref, material, *, restored_run_ref=None):
    org_id, space_id, _, worker = scope
    asset = _register_rebuilt_original(connection, doc_scope, version_ref, material, REBUILD_FORMAT, "text/markdown")
    job_id = enqueue_job(connection, JobSpec(org_id, space_id, version_ref, "parse", material.digest, 1))
    lease = claim_job(connection, org_id, "parse", worker, timedelta(minutes=1))
    if lease is None or lease.job_id != job_id:
        raise ArchiveRejected("The reconstructed original has no current processing lease.")
    prepared = _prepare_original(connection, lease)
    _record_markdown_candidate(
        connection, lease, prepared, material.candidate, passage_refs=material.passage_refs, restored_run_ref=restored_run_ref,
    )
    return asset


def _register_rebuilt_original(connection, document, ref, material, profile, media_type):
    key = _digest(profile, str(ref), material.digest.hex()).hex()
    asset = OriginalAsset(key, material.digest, len(material.original))
    _rebuild_original(connection, document, ref, material.metadata, asset, media_type=media_type)
    return asset


def _write_rebuilt_pdf(connection, record, material):
    connection.execute("""
        INSERT INTO thalion.archive_pdf_rebuild
            (version_ref, org_id, space_id, run_ref, transcription, page_transcripts, repair_history)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (*record, Jsonb(material.transcription), list(material.page_transcripts),
              Jsonb(material.history) if material.history is not None else None))


def _write_rebuilt_docx(connection, record, material):
    connection.execute("""
        INSERT INTO thalion.archive_docx_rebuild
            (version_ref, org_id, space_id, run_ref, amount_columns, transcription, transcript_bytes, repair_history)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (*record, material.metadata["docx_amount_columns"],
              Jsonb(material.transcription), list(material.docx_transcripts),
              Jsonb(material.history) if material.history is not None else None))


def _archive_scope(connection, org_id, space_id):
    connection.execute(
        "UPDATE thalion.space SET lifecycle = 'archived' WHERE (org_id, space_id) = (%s, %s)",
        (org_id, space_id),
    )


def _record_rule_checkpoints(connection, permit, version_refs, checkpoint):
    if checkpoint is not None:
        with connection.cursor() as cursor:
            cursor.executemany("""
                INSERT INTO thalion.archive_rebuild_rule_check (
                    version_ref, archive_digest, origin_org_id, origin_space_id, export_ref,
                    authority_ref, log_ref, stream_ref, generation, quality_stream_ref, quality_generation,
                    source_authority_ref, source_space_ref, source_stream_ref, source_generation, source_requester_ref
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, [(ref, permit.digest, permit.org_id, permit.space_id, permit.export_ref, *checkpoint)
                      for ref in version_refs])


def rebuild_version(connection: Connection, permit: RebuildPermit, payload: bytes, scratch_root: Path) -> StagedArchive:
    """Reconstruct offline for verification only, without claiming a current rule checkpoint."""
    return _rebuild(connection, permit, payload, scratch_root)


def rebuild_with_rule_checkpoint(
    connection: Connection, permit: RebuildPermit, payload: bytes, scratch_root: Path, *,
    authority: Connection, log: Connection, authority_ref: UUID, log_ref: UUID, source_authority: SourceRevocationAuthority,
) -> StagedArchive:
    """Check current rule, quality, and source archive restrictions before isolated reconstruction."""
    return _rebuild(connection, permit, payload, scratch_root, sources=(authority, log, authority_ref, log_ref, source_authority))


def _rebuild(connection, permit, payload, scratch_root, *, sources=None):
    _check_input(connection, payload, permit.digest)
    if permit.database != connection.info.dbname:
        raise ArchiveRejected("The permit is not for this rehearsal database.")
    try:
        if sources is not None:
            with ZipFile(BytesIO(payload)) as archive:
                names = archive.namelist()
            repaired = "repair-history.json" in names
            media_type = next((kind for kind in (PDF_MEDIA_TYPE, DOCX_MEDIA_TYPE) if ORIGINAL_MEMBERS[kind] in names), "text/markdown")
            if media_type != "text/markdown" or repaired:
                return _rebuild_registered(connection, permit, payload, scratch_root, sources, media_type=media_type, repaired=repaired)
        material = _decode_rebuild(permit, payload)
        store = SyntheticOriginalStore(scratch_root)
        with _rule_checkpoint(permit, sources, {permit.version_ref: material}) as (checkpoint, _), connection.transaction():
            _begin_empty_rebuild(connection, permit.database, store)
            scope = _rebuild_scope(connection)
            source = _rebuild_source(connection, scope, material.metadata)
            document = _rebuild_document(connection, source, material.metadata)
            asset = _materialize_version(connection, scope, document, permit.version_ref, material)
            org_id, space_id, *_ = scope
            _archive_scope(connection, org_id, space_id)
            append_event(connection, org_id, "lifecycle.synthetic_archive.rebuilt", permit.version_ref, space_id=space_id)
            _record_rule_checkpoints(connection, permit, (permit.version_ref,), checkpoint)
            connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
            store.stage(asset.key, asset.digest, material.original)
        return StagedArchive(permit.version_ref, REBUILD_SCOPE, store, asset)
    except (Error, BadZipFile, KeyError, TypeError, ValueError, AttributeError, OSError, RecursionError,
            NotImplementedError, OriginalIntegrityError, LeaseLost, ProcessingNotAdmitted, QualityConflict,
            DispositionConflict, DispositionInventoryUnavailable):
        raise ArchiveRejected("The archive could not be reconstructed in the fenced rehearsal.") from None


def _rebuild_registered(connection, permit, payload, scratch_root, sources, *, media_type, repaired):
    parent = SyntheticOriginalStore(scratch_root)
    if media_type == DOCX_MEDIA_TYPE:
        profile, kind = (DOCX_REPAIR_REBUILD_FORMAT if repaired else DOCX_REBUILD_FORMAT), "docx"
    elif media_type == PDF_MEDIA_TYPE:
        profile, kind = (PDF_REPAIR_REBUILD_FORMAT if repaired else PDF_REBUILD_FORMAT), "pdf"
    else:
        profile, kind = REPAIR_REBUILD_FORMAT, "repair"
    with ExitStack() as cleanup, _rule_checkpoint(
        permit, sources, {}, archive_payload=payload, media_type=media_type, repaired=repaired,
    ) as (checkpoint, material):
        staged = False
        try:
            with connection.transaction():
                _begin_empty_rebuild(connection, permit.database, parent)
                directory = TemporaryDirectory(dir=parent.root, prefix=f"{kind}-rehearsal-", delete=False)
                cleanup.callback(directory.cleanup)
                store = SyntheticOriginalStore(Path(directory.name))
                scope = _rebuild_scope(connection)
                source = _rebuild_source(connection, scope, material.metadata)
                document = _rebuild_document(connection, source, material.metadata)
                asset = _register_rebuilt_original(connection, document, permit.version_ref, material, profile, media_type)
                org_id, space_id, *_ = scope
                _archive_scope(connection, org_id, space_id)
                _record_rule_checkpoints(connection, permit, (permit.version_ref,), checkpoint)
                record = (permit.version_ref, org_id, space_id, material.run_ref)
                if media_type == PDF_MEDIA_TYPE:
                    _write_rebuilt_pdf(connection, record, material)
                elif media_type == DOCX_MEDIA_TYPE:
                    _write_rebuilt_docx(connection, record, material)
                else:
                    connection.execute("""
                        INSERT INTO thalion.archive_repair_rebuild (version_ref, org_id, space_id, run_ref, history)
                        VALUES (%s, %s, %s, %s, %s)
                        """, (*record, Jsonb(material.history)))
                event = f"lifecycle.synthetic_{kind}_archive.rebuilt"
                append_event(connection, org_id, event, permit.version_ref, space_id=space_id)
                connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
                store.stage(asset.key, asset.digest, material.original)
                staged = True
        except OperationalError:
            if staged and (connection.closed or connection.info.transaction_status == TransactionStatus.UNKNOWN):
                cleanup.pop_all()
            raise
        cleanup.pop_all()
    return StagedArchive(permit.version_ref, REBUILD_SCOPE, store, asset)


def rebuild_wiki(
    connection: Connection, permit: WikiRebuildPermit, payload: bytes, scratch_root: Path,
) -> RebuiltWikiArchive:
    """Reconstruct an offline Wiki snapshot; this neither attests current safety nor republishes it."""
    return _rebuild_wiki(connection, permit, payload, scratch_root)


def rebuild_wiki_with_rule_checkpoint(
    connection: Connection, permit: WikiRebuildPermit, payload: bytes, scratch_root: Path, *,
    authority: Connection, log: Connection, authority_ref: UUID, log_ref: UUID, source_authority: SourceRevocationAuthority,
) -> RebuiltWikiArchive:
    """Check current rule, quality, and source restrictions over the complete Wiki archive."""
    return _rebuild_wiki(connection, permit, payload, scratch_root, sources=(authority, log, authority_ref, log_ref, source_authority))


def _write_rebuilt_wiki(connection, pin, wiki, checkpoint):
    scope = _rebuild_scope(connection)
    source = _rebuild_source(connection, scope, wiki.versions[pin.version_ref].metadata)
    documents, originals = {}, []
    for ref, material in wiki.versions.items():
        doc_ref = material.metadata["document_id"]
        if doc_ref not in documents:
            documents[doc_ref] = _rebuild_document(connection, source, material.metadata)
        if isinstance(material, _RegisteredVersionMaterial):
            profile = DOCX_REBUILD_FORMAT if material.media_type == DOCX_MEDIA_TYPE else PDF_REBUILD_FORMAT
            asset = _register_rebuilt_original(connection, documents[doc_ref], ref, material, profile, material.media_type)
        else:
            asset = _materialize_version(connection, scope, documents[doc_ref], ref, material, restored_run_ref=material.run_ref)
        originals.append((ref, asset))
    org_id, space_id, *_ = scope
    _archive_scope(connection, org_id, space_id)
    connection.execute("""
        INSERT INTO thalion.archive_wiki_rebuild (
            revision_ref, org_id, space_id, origin_org_id, origin_space_id, export_ref,
            archive_digest, anchor_ref, topic_key, content, manifest_graph, dependencies
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (pin.revision_ref, org_id, space_id, pin.org_id, pin.space_id, pin.export_ref,
              pin.digest, pin.version_ref, wiki.topic_key, wiki.content, Jsonb(wiki.graph), Jsonb(wiki.dependencies)))
    _record_rule_checkpoints(connection, pin, wiki.versions, checkpoint)
    for ref, material in wiki.versions.items():
        if isinstance(material, _RegisteredVersionMaterial):
            record = (ref, org_id, space_id, material.run_ref)
            if material.media_type == DOCX_MEDIA_TYPE:
                _write_rebuilt_docx(connection, record, material)
            else:
                _write_rebuilt_pdf(connection, record, material)
    append_event(connection, org_id, "lifecycle.synthetic_wiki_archive.rebuilt", pin.version_ref, space_id=space_id)
    connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
    return tuple(originals)


def _rebuild_wiki(connection, permit, payload, scratch_root, *, sources=None):
    pin = permit.pin
    _check_input(connection, payload, pin.digest)
    if permit.database != connection.info.dbname:
        raise ArchiveRejected("The permit is not for this rehearsal database.")
    try:
        parent = SyntheticOriginalStore(scratch_root)
        with ExitStack() as cleanup, _rule_checkpoint(pin, sources, {}, wiki_payload=payload) as (checkpoint, wiki):
            staged = False
            try:
                with connection.transaction():
                    _begin_empty_rebuild(connection, permit.database, parent)
                    directory = TemporaryDirectory(dir=parent.root, prefix="wiki-rehearsal-", delete=False)
                    cleanup.callback(directory.cleanup)
                    store = SyntheticOriginalStore(Path(directory.name))
                    originals = _write_rebuilt_wiki(connection, pin, wiki, checkpoint)
                    for ref, asset in originals:
                        store.stage(asset.key, asset.digest, wiki.versions[ref].original)
                    staged = True
            except OperationalError:
                if staged and (connection.closed or connection.info.transaction_status == TransactionStatus.UNKNOWN):
                    cleanup.pop_all()
                raise
            cleanup.pop_all()
        return RebuiltWikiArchive(pin.revision_ref, store, originals)
    except (Error, OSError, ValueError, OriginalIntegrityError, LeaseLost, ProcessingNotAdmitted, QualityConflict,
            DispositionConflict, DispositionInventoryUnavailable):
        raise ArchiveRejected("The Wiki archive could not be reconstructed in the fenced rehearsal.") from None
