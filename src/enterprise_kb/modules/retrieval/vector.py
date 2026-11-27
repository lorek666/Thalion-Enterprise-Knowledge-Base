from collections.abc import Sequence
from hashlib import sha256
import json
import math
import re
from typing import Literal
from uuid import UUID

from psycopg import Connection
from psycopg.pq import TransactionStatus

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
from enterprise_kb.modules.sources.originals import ObjectStorageOriginalStore, OriginalAsset, OriginalIntegrityError, SyntheticOriginalStore
from enterprise_kb.modules.sources.registry import SYNTHETIC_ADMISSION, has_source_delete_isolation, sql_storage_matches_admission, store_admission
from enterprise_kb.ports.contracts import AdmissionMode, EmbeddingPortUnavailable, EmbeddingProviderPort

from . import lexical


DEFAULT_MODEL_ID = "synthetic-hash-synonym-v1"
ALTERNATIVE_MODEL_ID = "synthetic-alt-embed-v2"
ALLOWED_SYNTHETIC_MODELS = frozenset({DEFAULT_MODEL_ID, ALTERNATIVE_MODEL_ID})
VECTOR_DIMENSION = 64
MIN_VECTOR_DIMENSION = 1
MAX_VECTOR_DIMENSION = 4096
DISTANCE_METRIC: Literal["cosine"] = "cosine"
DEFAULT_MIN_SIMILARITY = 0.25
MAX_PASSAGES = 512
MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$")
TOKEN_PATTERN = re.compile(r"[^\W_]+")


def is_valid_model_id(model_id: object) -> bool:
    return (
        isinstance(model_id, str)
        and bool(MODEL_ID_PATTERN.fullmatch(model_id))
        and ".." not in model_id
    )


def _validated_provider_dimension(provider: EmbeddingProviderPort) -> int | None:
    dimension = provider.dimension
    if (
        type(dimension) is not int
        or not MIN_VECTOR_DIMENSION <= dimension <= MAX_VECTOR_DIMENSION
        or provider.distance_metric != DISTANCE_METRIC
        or not is_valid_model_id(provider.model_id)
    ):
        return None
    return dimension

SYNONYM_CONCEPTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("concept:lodging", ("住宿", "酒店", "宾馆", "旅馆", "房费", "住房", "hotel", "lodging")),
    ("concept:limit", ("上限", "限额", "标准", "能报", "报销", "额度", "cap", "allowance")),
    ("concept:approval", ("审批", "批准", "核准", "签批", "书面", "approval")),
    ("concept:over_limit", ("超标", "超出", "超过", "超额")),
    ("concept:travel", ("差旅", "出差", "差标", "travel")),
    ("concept:city_shanghai", ("上海", "沪", "shanghai")),
    ("concept:city_beijing", ("北京", "京", "beijing")),
    ("concept:city_qingdao", ("青岛", "qingdao")),
    ("concept:meal", ("餐补", "伙食", "餐饮", "饭补", "meal")),
    ("concept:flight", ("机票", "航班", "舱位", "航空", "flight")),
    ("concept:dept_head", ("部门负责人", "负责人", "主管", "经理")),
)


class VectorIndexUnavailable(Exception):
    pass


def _validate_vector(values: Sequence[float], dimension: int) -> tuple[float, ...]:
    if len(values) != dimension:
        raise EmbeddingPortUnavailable("Embedding provider returned an unexpected vector dimension.")
    floats = tuple(float(item) for item in values)
    if any(not math.isfinite(item) for item in floats):
        raise EmbeddingPortUnavailable("Embedding provider returned non-finite coordinates.")
    norm = math.sqrt(sum(item * item for item in floats))
    if norm <= 1e-12:
        raise EmbeddingPortUnavailable("Embedding provider returned a zero-norm vector.")
    return tuple(round(item / norm, 6) for item in floats)


def _vector_literal(values: Sequence[float]) -> str:
    return "[" + ",".join(f"{item:.6f}" for item in values) + "]"


def _extract_features(text: str) -> list[tuple[str, float]]:
    normalized = lexical.normalize_text(text)
    features: list[tuple[str, float]] = []
    for concept, triggers in SYNONYM_CONCEPTS:
        if any(trigger in normalized for trigger in triggers):
            features.append((concept, 3.0))
    for token in TOKEN_PATTERN.findall(normalized):
        features.append((f"tok:{token}", 1.5))
        if len(token) >= 2:
            for index in range(len(token) - 1):
                features.append((f"bg:{token[index:index + 2]}", 0.6))
    if not features:
        features.append((f"raw:{normalized}", 1.0))
    return features


class SyntheticLocalEmbeddingProvider:
    admission: AdmissionMode = "synthetic_local"
    dimension: int = VECTOR_DIMENSION
    distance_metric: Literal["cosine"] = DISTANCE_METRIC

    def __init__(self, model_id: str = DEFAULT_MODEL_ID):
        if not isinstance(model_id, str) or model_id not in ALLOWED_SYNTHETIC_MODELS:
            raise ValueError(f"Unsupported synthetic embedding model: {model_id}")
        self.model_id = model_id

    def _encode_one(self, text: str) -> tuple[float, ...]:
        if not isinstance(text, str) or not text.strip():
            raise EmbeddingPortUnavailable("Embedding input text must be non-empty.")
        buckets = [0.0] * self.dimension
        for feature, weight in _extract_features(text):
            digest = sha256(f"{self.model_id}\0{feature}".encode("utf-8")).digest()
            first_bucket = digest[0] % self.dimension
            second_bucket = digest[1] % self.dimension
            first_sign = 1.0 if (digest[2] & 1) == 0 else -1.0
            second_sign = 1.0 if (digest[3] & 1) == 0 else -1.0
            buckets[first_bucket] += first_sign * weight
            buckets[second_bucket] += second_sign * weight * 0.5
        return _validate_vector(buckets, self.dimension)

    def embed_passages(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        return tuple(self._encode_one(item) for item in texts)

    def embed_query(self, text: str) -> tuple[float, ...]:
        return self._encode_one(text)


def resolve_synthetic_embedding_provider(model_id: str | None) -> SyntheticLocalEmbeddingProvider:
    if model_id is None or model_id not in ALLOWED_SYNTHETIC_MODELS:
        raise EmbeddingPortUnavailable("Configured synthetic embedding model is unavailable.")
    return SyntheticLocalEmbeddingProvider(model_id=model_id)


def _target(connection: Connection, space_ref: UUID, version_ref: UUID, *, expected_admission: str):
    return connection.execute(
        f"""
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
        """,
        (space_ref, version_ref, expected_admission, ["text/markdown", "application/pdf", DOCX_MEDIA_TYPE, *sorted(STRUCTURED_MEDIA_TYPES)]),
    ).fetchone()


def build_vector_index(
    connection: Connection,
    store: SyntheticOriginalStore | ObjectStorageOriginalStore,
    space_ref: UUID,
    version_ref: UUID,
    run_ref: UUID,
    provider: EmbeddingProviderPort,
    *,
    allow_rehearsal: bool = False,
) -> UUID:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise ValueError("Vector index construction requires its own transaction.")
    dimension = _validated_provider_dimension(provider)
    if dimension is None:
        raise VectorIndexUnavailable("Unsupported embedding provider specification.")
    expected_admission = store_admission(store)
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL synchronous_commit = on")
        if expected_admission == SYNTHETIC_ADMISSION and connection.info.hostaddr not in {"127.0.0.1", "::1"}:
            raise VectorIndexUnavailable("Vector index construction requires an isolated local development database.")
        marker = rehearsal_marker(connection)
        if allow_rehearsal:
            if marker != connection.info.dbname:
                raise VectorIndexUnavailable("Rehearsal vector index requires a fenced restore_rehearsal database.")
        elif marker is not None:
            raise VectorIndexUnavailable("Vector index construction requires an isolated local development database.")
        target = _target(connection, space_ref, version_ref, expected_admission=expected_admission)
        if target is None:
            raise VectorIndexUnavailable("The synthetic version is not admitted in this space.")
        org_id, space_id, version_id, media_type, *asset = target
        scope = (org_id, space_id, version_id)
        run = connection.execute(
            """
            SELECT run_ref, passage_count FROM thalion.processing_run
            WHERE (org_id, space_id, version_id) = (%s, %s, %s)
            ORDER BY configuration_revision DESC LIMIT 1
            """,
            scope,
        ).fetchone()
        if run is None or run[0] != run_ref or not 1 <= run[1] <= MAX_PASSAGES:
            raise VectorIndexUnavailable("The requested run is not the current bounded processing run.")
        delete_clause = (
            "OR thalion.document_source_deleted(version.org_id, version.space_id, version.source_id, version.document_id)"
            if has_source_delete_isolation(connection)
            else ""
        )
        if connection.execute(
            f"""
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
            """,
            scope,
        ).fetchone():
            raise VectorIndexUnavailable("A held, stopped, or source-deleted version cannot be vector indexed.")
        is_pdf = media_type == PDF_MEDIA_TYPE
        is_docx = media_type == DOCX_MEDIA_TYPE
        is_structured = media_type in STRUCTURED_MEDIA_TYPES
        if is_pdf:
            passages = list_approved_pdf_pages(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        elif is_docx:
            passages = list_approved_docx_paragraphs(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        elif is_structured:
            passages = list_approved_structured_passages(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        else:
            passages = list_approved_passages(connection, org_id, space_id, version_ref, limit=MAX_PASSAGES + 1)
        if len(passages) != run[1] or (is_pdf and any(item.run_ref != run_ref for item in passages)):
            raise VectorIndexUnavailable("The exact run is not fully approved for vector indexing.")
        payload = store.read(OriginalAsset(*asset))
        transcripts = resolve_pdf_transcripts(connection, passages) if is_pdf else {}
        docx_excerpts = resolve_docx_paragraphs(payload, passages) if is_docx else {}
        structured_excerpts = resolve_structured_excerpts(payload, media_type, passages) if is_structured else {}
        texts: list[str] = []
        for passage in passages:
            if is_pdf:
                excerpt = transcripts[passage]
            elif is_docx:
                excerpt = docx_excerpts[passage]
                if sha256(excerpt).digest() != passage.digest:
                    raise OriginalIntegrityError("An indexed DOCX excerpt does not match its original.")
            elif is_structured:
                excerpt = structured_excerpts[passage]
                if sha256(excerpt).digest() != passage.digest:
                    raise OriginalIntegrityError("An indexed structured excerpt does not match its original.")
            else:
                excerpt = payload[passage.byte_start:passage.byte_end]
                if len(excerpt) != passage.byte_end - passage.byte_start or sha256(excerpt).digest() != passage.digest:
                    raise OriginalIntegrityError("An indexed excerpt does not match its original.")
            texts.append(excerpt.decode("utf-8"))
        raw_embeddings = provider.embed_passages(texts)
        if len(raw_embeddings) != len(passages):
            raise EmbeddingPortUnavailable("Embedding count does not match passage count.")
        embeddings = tuple(_validate_vector(item, dimension) for item in raw_embeddings)
        canonical_rows = sorted(
            (str(passage.passage_ref), passage.revision, passage.digest.hex(), list(vector_values))
            for passage, vector_values in zip(passages, embeddings, strict=True)
        )
        content_digest = sha256(
            json.dumps(
                {
                    "model_id": provider.model_id,
                    "dimension": dimension,
                    "distance_metric": DISTANCE_METRIC,
                    "entries": canonical_rows,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).digest()
        existing = connection.execute(
            """
            SELECT index_ref, content_digest FROM thalion.synthetic_vector_index
            WHERE (run_ref, model_id) = (%s, %s)
            """,
            (run_ref, provider.model_id),
        ).fetchone()
        if existing is not None:
            if bytes(existing[1]) != content_digest:
                raise OriginalIntegrityError("The exact run already has inconsistent vector material.")
            return existing[0]
        next_generation = 1 + connection.execute(
            """
            SELECT coalesce(max(generation), 0) FROM thalion.synthetic_vector_index
            WHERE (org_id, space_id, version_id, run_ref) = (%s, %s, %s, %s)
            """,
            (*scope, run_ref),
        ).fetchone()[0]
        index_ref, = connection.execute(
            """
            INSERT INTO thalion.synthetic_vector_index (
                org_id, space_id, version_id, run_ref, model_id, dimension, distance_metric,
                generation, entry_count, content_digest
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING index_ref
            """,
            (*scope, run_ref, provider.model_id, dimension, DISTANCE_METRIC,
             next_generation, len(passages), content_digest),
        ).fetchone()
        passage_ids = dict(
            connection.execute(
                """
                SELECT public_id, object_id FROM thalion.object_identity
                WHERE (org_id, space_id, object_type) = (%s, %s, 'passage')
                  AND public_id = ANY(%s::uuid[])
                """,
                (org_id, space_id, [item.passage_ref for item in passages]),
            ).fetchall()
        )
        if len(passage_ids) != len(passages):
            raise OriginalIntegrityError("Approved passage identities could not be resolved for vector indexing.")
        for passage, vector_values in zip(passages, embeddings, strict=True):
            connection.execute(
                """
                INSERT INTO thalion.synthetic_vector_entry (
                    index_ref, org_id, space_id, version_id, run_ref, passage_id,
                    excerpt_revision, content_digest, embedding
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::vector)
                """,
                (
                    index_ref, org_id, space_id, version_id, run_ref, passage_ids[passage.passage_ref],
                    passage.revision, passage.digest, _vector_literal(vector_values),
                ),
            )
        return index_ref


def score_vector_passages(
    connection: Connection,
    org_id: int,
    space_id: int,
    passages,
    query_text: str,
    provider: EmbeddingProviderPort,
    *,
    min_similarity: float = DEFAULT_MIN_SIMILARITY,
) -> dict[UUID, float]:
    if not passages:
        return {}
    dimension = _validated_provider_dimension(provider)
    if dimension is None:
        raise EmbeddingPortUnavailable("Unsupported embedding provider specification.")
    query_vector = _validate_vector(provider.embed_query(query_text), dimension)
    rows = connection.execute(
        """
        SELECT wanted.ref, idx.index_ref, entry.passage_id,
               CASE WHEN entry.passage_id IS NOT NULL
                     AND entry.content_digest = excerpt.content_digest
                    THEN (1.0 - (entry.embedding <=> %s::vector))::double precision
               END AS similarity
        FROM unnest(%s::uuid[], %s::bigint[], %s::bytea[]) AS wanted(ref, revision, digest)
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.public_id)
           = (%s, %s, 'passage', wanted.ref)
        JOIN thalion.passage_excerpt AS excerpt
          ON (excerpt.org_id, excerpt.space_id, excerpt.passage_id, excerpt.excerpt_revision, excerpt.content_digest)
           = (identity.org_id, identity.space_id, identity.object_id, wanted.revision, wanted.digest)
        LEFT JOIN thalion.synthetic_vector_index AS idx
          ON (idx.org_id, idx.space_id, idx.version_id, idx.run_ref, idx.model_id, idx.dimension)
           = (excerpt.org_id, excerpt.space_id, excerpt.version_id, excerpt.run_ref, %s, %s)
        LEFT JOIN thalion.synthetic_vector_entry AS entry
          ON (entry.index_ref, entry.org_id, entry.space_id, entry.passage_id, entry.excerpt_revision)
           = (idx.index_ref, excerpt.org_id, excerpt.space_id, excerpt.passage_id, excerpt.excerpt_revision)
        """,
        (
            _vector_literal(query_vector),
            [part.passage_ref for part in passages],
            [part.revision for part in passages],
            [part.digest for part in passages],
            org_id,
            space_id,
            provider.model_id,
            provider.dimension,
        ),
    ).fetchall()
    if len(rows) != len(passages) or any(index_ref is not None and similarity is None for _, index_ref, _, similarity in rows):
        raise OriginalIntegrityError("An exact vector index does not match its admitted passage revision.")
    return {
        ref: float(similarity)
        for ref, index_ref, _, similarity in rows
        if index_ref is not None and similarity is not None and float(similarity) >= min_similarity
    }
