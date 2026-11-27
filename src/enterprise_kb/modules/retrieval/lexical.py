from hashlib import sha256
import json
from unicodedata import normalize, unidata_version
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from enterprise_kb.database import rehearsal_marker
from enterprise_kb.modules.evidence.docx_evidence import MEDIA_TYPE as DOCX_MEDIA_TYPE
from enterprise_kb.modules.evidence.multiformat_evidence import STRUCTURED_MEDIA_TYPES
from enterprise_kb.modules.evidence.pdf_evidence import MEDIA_TYPE as PDF_MEDIA_TYPE
from enterprise_kb.modules.evidence.processing import (
    list_approved_docx_paragraphs,
    list_approved_passages,
    list_approved_pdf_pages,
    list_approved_structured_passages,
    resolve_docx_paragraphs,
    resolve_structured_excerpts,
    resolve_pdf_transcripts,
)
from enterprise_kb.modules.sources.originals import (
    ObjectStorageOriginalStore, OriginalAsset, OriginalIntegrityError, SyntheticOriginalStore,
)
from enterprise_kb.modules.sources.registry import (
    SYNTHETIC_ADMISSION, has_source_delete_isolation, sql_storage_matches_admission, store_admission,
)


PROFILE = f"nfkc_casefold_v1:{unidata_version}"
MAX_PASSAGES = 512
MAX_INDEX_BYTES = 8 * 1024 * 1024


class LexicalIndexUnavailable(Exception):
    pass


def normalize_text(text: str) -> str:
    return normalize("NFKC", text).casefold()


def _target(connection, space_ref, version_ref, *, expected_admission: str):
    return connection.execute(f"""
        SELECT version.org_id, version.space_id, version.version_id, asset.media_type,
               asset.storage_key, asset.content_digest, asset.byte_length
        FROM thalion.document_version AS version
        JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
        JOIN thalion.asset AS asset USING (org_id, space_id, source_id, document_id, asset_id)
        JOIN thalion.source AS source USING (org_id, space_id, source_id)
        JOIN thalion.space AS space USING (org_id, space_id)
        JOIN thalion.source_contract_revision AS contract
          ON (contract.org_id, contract.space_id, contract.source_id, contract.revision) =
             (source.org_id, source.space_id, source.source_id, source.contract_revision)
        JOIN thalion.object_identity AS version_identity
          ON (version_identity.org_id, version_identity.space_id, version_identity.object_type, version_identity.object_id) =
             (version.org_id, version.space_id, 'document_version', version.version_id)
        JOIN thalion.object_identity AS space_identity
          ON (space_identity.org_id, space_identity.space_id, space_identity.object_type, space_identity.object_id) =
             (version.org_id, version.space_id, 'space', version.space_id)
        WHERE (space_identity.public_id, version_identity.public_id) = (%s, %s)
          AND space.lifecycle = 'active' AND source.lifecycle = 'active'
          AND contract.admission = %s
          AND {sql_storage_matches_admission('asset.storage_kind', 'contract.admission')}
          AND asset.media_type = ANY(%s)
        FOR SHARE OF source, space FOR UPDATE OF document
        """, (space_ref, version_ref, expected_admission, ["text/markdown", "application/pdf", DOCX_MEDIA_TYPE, *sorted(STRUCTURED_MEDIA_TYPES)])).fetchone()


def build_index(
    connection: Connection,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
    space_ref: UUID,
    version_ref: UUID,
    run_ref: UUID,
    *,
    allow_rehearsal: bool = False,
) -> UUID:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise ValueError("Index construction requires its own transaction.")
    expected_admission = store_admission(store)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        if expected_admission == SYNTHETIC_ADMISSION and connection.info.hostaddr not in {"127.0.0.1", "::1"}:
            raise LexicalIndexUnavailable("Index construction requires an isolated local development database.")
        marker = rehearsal_marker(connection)
        if allow_rehearsal:
            if marker != connection.info.dbname:
                raise LexicalIndexUnavailable("Rehearsal index construction requires a fenced restore_rehearsal database.")
        elif marker is not None:
            raise LexicalIndexUnavailable("Index construction requires an isolated local development database.")
        target = _target(connection, space_ref, version_ref, expected_admission=expected_admission)
        if target is None:
            raise LexicalIndexUnavailable("The synthetic version is not admitted in this space.")
        org_id, space_id, version_id, media_type, *asset = target
        scope = (org_id, space_id, version_id)
        run = connection.execute("""
            SELECT run_ref, passage_count FROM thalion.processing_run
            WHERE (org_id, space_id, version_id) = (%s, %s, %s)
            ORDER BY configuration_revision DESC LIMIT 1
            """, scope).fetchone()
        if run is None or run[0] != run_ref or not 1 <= run[1] <= MAX_PASSAGES:
            raise LexicalIndexUnavailable("The requested run is not the current bounded processing run.")
        delete_clause = (
            "OR thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
            if has_source_delete_isolation(connection)
            else ""
        )
        if connection.execute(f"""
            SELECT 1 FROM thalion.document_version AS version
            WHERE (version.org_id, version.space_id, version.version_id) = (%s, %s, %s)
              AND (
                  EXISTS (
                      SELECT 1 FROM thalion.current_version_hold AS hold
                      WHERE (hold.org_id, hold.space_id, hold.version_id, hold.action)
                          = (version.org_id, version.space_id, version.version_id, 'establish')
                  )
                  OR EXISTS (SELECT 1 FROM thalion.rule_use_stop WHERE version_id = version.version_id)
                  {delete_clause}
              )
            """, scope).fetchone():
            raise LexicalIndexUnavailable("A held, stopped, or source-deleted version cannot be indexed.")
        pdf = media_type == PDF_MEDIA_TYPE
        docx = media_type == DOCX_MEDIA_TYPE
        structured = media_type in STRUCTURED_MEDIA_TYPES
        if pdf:
            passages = list_approved_pdf_pages(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        elif docx:
            passages = list_approved_docx_paragraphs(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        elif structured:
            passages = list_approved_structured_passages(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        else:
            passages = list_approved_passages(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        if len(passages) != run[1] or (pdf and any(page.run_ref != run_ref for page in passages)):
            raise LexicalIndexUnavailable("The exact run is not fully approved for indexing.")
        payload = store.read(OriginalAsset(*asset))
        transcripts = resolve_pdf_transcripts(connection, passages) if pdf else {}
        docx_excerpts = resolve_docx_paragraphs(payload, passages) if docx else {}
        structured_excerpts = resolve_structured_excerpts(payload, media_type, passages) if structured else {}
        entries = {}
        for passage in passages:
            if pdf:
                excerpt = transcripts[passage]
            elif docx:
                excerpt = docx_excerpts[passage]
                if sha256(excerpt).digest() != passage.digest:
                    raise OriginalIntegrityError("An indexed DOCX excerpt does not match its original.")
            elif structured:
                excerpt = structured_excerpts[passage]
                if sha256(excerpt).digest() != passage.digest:
                    raise OriginalIntegrityError("An indexed structured excerpt does not match its original.")
            else:
                excerpt = payload[passage.byte_start:passage.byte_end]
                if len(excerpt) != passage.byte_end - passage.byte_start or sha256(excerpt).digest() != passage.digest:
                    raise OriginalIntegrityError("An indexed excerpt does not match its original.")
            entries[str(passage.passage_ref)] = [passage.revision, passage.digest.hex(), normalize_text(excerpt.decode("utf-8"))]
        encoded = json.dumps(entries, ensure_ascii=False)
        if len(encoded.encode("utf-8")) > MAX_INDEX_BYTES:
            raise LexicalIndexUnavailable("The lexical projection exceeds its storage limit.")
        material = Jsonb(entries)
        inserted = connection.execute("""
            INSERT INTO thalion.synthetic_lexical_index (org_id, space_id, version_id, run_ref, profile, entries, content_digest)
            VALUES (%s, %s, %s, %s, %s, %s, sha256(convert_to(%s::jsonb::text, 'UTF8')))
            ON CONFLICT (run_ref, profile) DO NOTHING RETURNING index_ref
            """, (*scope, run_ref, PROFILE, material, material)).fetchone()
        if inserted is None:
            inserted = connection.execute("""
                SELECT index_ref FROM thalion.synthetic_lexical_index
                WHERE (org_id, space_id, version_id, run_ref, profile) = (%s, %s, %s, %s, %s) AND entries = %s
                """, (*scope, run_ref, PROFILE, material)).fetchone()
        if inserted is None:
            raise OriginalIntegrityError("The exact run already has inconsistent lexical material.")
        return inserted[0]


def score_indexed_passages(connection, org_id, space_id, passages, terms):
    if not passages:
        return {}
    rows = connection.execute("""
        SELECT wanted.ref, projection.index_ref,
               CASE WHEN jsonb_typeof(part.entry) = 'array'
                          AND part.entry -> 0 = to_jsonb(wanted.revision)
                          AND part.entry ->> 1 = encode(excerpt.content_digest, 'hex')
                          AND jsonb_typeof(part.entry -> 2) = 'string'
                    THEN (SELECT count(*) FROM unnest(%s::text[]) AS query(term)
                          WHERE strpos((part.entry ->> 2) COLLATE "C", query.term) > 0)
               END
        FROM unnest(%s::uuid[], %s::bigint[], %s::bytea[]) AS wanted(ref, revision, digest)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.public_id) = (%s, %s, 'passage', wanted.ref)
        JOIN thalion.passage_excerpt AS excerpt
          ON (excerpt.org_id, excerpt.space_id, excerpt.passage_id, excerpt.excerpt_revision, excerpt.content_digest) =
             (identity.org_id, identity.space_id, identity.object_id, wanted.revision, wanted.digest)
        LEFT JOIN thalion.synthetic_lexical_index AS projection
          ON (projection.org_id, projection.space_id, projection.version_id, projection.run_ref, projection.profile) =
             (excerpt.org_id, excerpt.space_id, excerpt.version_id, excerpt.run_ref, %s)
        CROSS JOIN LATERAL (SELECT projection.entries -> wanted.ref::text AS entry) AS part
        """, (sorted(terms), [part.passage_ref for part in passages], [part.revision for part in passages],
              [part.digest for part in passages], org_id, space_id, PROFILE)).fetchall()
    if len(rows) != len(passages) or any(index is not None and score is None for _, index, score in rows):
        raise OriginalIntegrityError("An exact lexical index does not match its admitted passage revision.")
    return {ref: score for ref, index, score in rows if index is not None}
