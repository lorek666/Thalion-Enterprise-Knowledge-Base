from dataclasses import replace
import json
import os
import subprocess
import sys
from uuid import UUID, uuid4

from psycopg import errors
import pytest

from docx_fixture import docx_package
from test_disposition import plan
from test_disposition_cases import candidate, submit
from test_docx_processing import docx_locators, register_docx
from test_effectivity import record as effectivity_record
from test_evidence import claim, evidence_db, review
from test_evidence_transport import evidence_transport, transport
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_travel_search import BEFORE, SEARCH_FIELDS, corpus, search


def _space_owner_write_context(connection, tenant, operation):
    from enterprise_kb.modules.sources.registry import SourceWrite
    from enterprise_kb.runtime.audit import RequestStart, start_request

    request_id = uuid4()
    start_request(
        connection,
        RequestStart(
            tenant.org_id,
            request_id,
            tenant.actor_id,
            None,
            "synthetic-release-test",
            operation,
            "internal_release",
            BEFORE,
            1,
            space_id=tenant.space_id,
            ingress="internal",
        ),
    )
    return SourceWrite(tenant.org_id, tenant.actor_id, request_id, str(uuid4()))


def test_pgvector_hybrid_retrieval_recalls_synonyms_with_strict_permission_isolation(corpus, monkeypatch):
    from enterprise_kb.modules.operations import release
    from enterprise_kb.modules.retrieval import lexical, vector
    from enterprise_kb.ports.contracts import EmbeddingPortUnavailable

    db, version, first, second, *_ = corpus
    connection, tenant, _, _, store = db
    run_ref, = connection.execute(
        """
        SELECT processing.run_ref FROM thalion.processing_run AS processing
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (processing.org_id, processing.space_id, 'document_version', processing.version_id)
        WHERE identity.public_id = %s
        """,
        (version.version_ref,),
    ).fetchone()

    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))

    # Pure lexical search misses synonym query ("酒店能报多少" vs "上海住宿标准 500 元")
    lexical_only = search(db, "酒店能报多少", top_k=5)
    assert lexical_only.status == "no_evidence"

    provider = vector.SyntheticLocalEmbeddingProvider()
    assert provider.admission == "synthetic_local"
    vec_index = vector.build_vector_index(
        connection, store, tenant.space_ref, version.version_ref, run_ref, provider,
    )
    assert vector.build_vector_index(
        connection, store, tenant.space_ref, version.version_ref, run_ref, provider,
    ) == vec_index
    lexical.build_index(connection, store, tenant.space_ref, version.version_ref, run_ref)

    # Immutability enforced at DB level
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.synthetic_vector_index SET entry_count = 0")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("DELETE FROM thalion.synthetic_vector_entry")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("TRUNCATE thalion.synthetic_vector_index, thalion.synthetic_vector_entry")

    # Switch space release config to hybrid_vector with synthetic-hash-synonym-v1
    ctx = _space_owner_write_context(connection, tenant, release.SWITCH_SPACE_RELEASE)
    switched = release.switch_space_release(
        connection,
        ctx,
        tenant.space_id,
        action="trial_switch",
        wiki_delivery_enabled=True,
        lexical_index_mode="hybrid_vector",
        vector_model_id=provider.model_id,
        rollback_trigger_summary="hybrid vector recall trial",
        reason_code="hybrid_trial",
        basis_ref=uuid4(),
    )
    assert switched["lexical_index_mode"] == "hybrid_vector"
    assert switched["vector_model_id"] == provider.model_id

    # Hybrid search recalls synonym query via pgvector cosine distance
    hybrid = search(db, "酒店能报多少", top_k=5)
    assert hybrid.status == "succeeded"
    hybrid_passages = json.loads(hybrid.payload)["passages"]
    assert any(item["passage_id"] == str(first.passage_ref) for item in hybrid_passages)

    # Unrelated query stays below similarity threshold -> no_evidence
    unrelated = search(db, "青岛餐补", top_k=5)
    assert unrelated.status == "no_evidence"

    # Permission filtering happens BEFORE vector scoring: unauthorized passage is never scored or returned
    observed_passages = []
    real_score = vector.score_vector_passages

    def spy_score(conn, org_id, space_id, passages, query_text, emb_provider, **kwargs):
        observed_passages.clear()
        observed_passages.extend(item.passage_ref for item in passages)
        return real_score(conn, org_id, space_id, passages, query_text, emb_provider, **kwargs)

    monkeypatch.setattr(vector, "score_vector_passages", spy_score)
    set_rules(db, replace(binding(tenant.actor_id, passage_ref=second.passage_ref), fields=SEARCH_FIELDS), expected=2)
    restricted = search(db, "酒店能报多少", top_k=5)
    assert observed_passages == [second.passage_ref]
    assert first.passage_ref not in observed_passages
    if restricted.payload is not None:
        assert str(first.passage_ref) not in restricted.payload.decode("utf-8")

    # Alternative model generation: no cross-model mixing
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS), expected=3)
    alt_provider = vector.SyntheticLocalEmbeddingProvider(model_id=vector.ALTERNATIVE_MODEL_ID)
    ctx_alt = _space_owner_write_context(connection, tenant, release.SWITCH_SPACE_RELEASE)
    release.switch_space_release(
        connection,
        ctx_alt,
        tenant.space_id,
        action="trial_switch",
        wiki_delivery_enabled=True,
        lexical_index_mode="hybrid_vector",
        vector_model_id=alt_provider.model_id,
        rollback_trigger_summary="switch to alt embedding before build",
        reason_code="alt_model_switch",
        basis_ref=uuid4(),
    )
    # Before alt model index is built, v1 vectors must NOT be mixed into alt model query
    before_alt_build = search(db, "酒店能报多少", top_k=5)
    assert before_alt_build.status == "no_evidence"

    alt_index = vector.build_vector_index(
        connection, store, tenant.space_ref, version.version_ref, run_ref, alt_provider,
    )
    assert alt_index != vec_index
    after_alt_build = search(db, "酒店能报多少", top_k=5)
    assert after_alt_build.status == "succeeded"
    assert any(item["passage_id"] == str(first.passage_ref) for item in json.loads(after_alt_build.payload)["passages"])

    # Roll back to earlier release config cleanly
    ctx_rb = _space_owner_write_context(connection, tenant, release.SWITCH_SPACE_RELEASE)
    rolled = release.switch_space_release(
        connection,
        ctx_rb,
        tenant.space_id,
        action="rollback",
        target_release_ref=UUID(switched["release_id"]),
        rollback_trigger_summary="rollback to v1 hybrid model",
        reason_code="rollback_v1",
        basis_ref=uuid4(),
    )
    assert rolled["vector_model_id"] == provider.model_id

    # Embedding provider fault fails closed -> dependency_unavailable
    def broken_resolve(model_id):
        raise EmbeddingPortUnavailable("simulated embedding outage")

    monkeypatch.setattr(vector, "resolve_synthetic_embedding_provider", broken_resolve)
    fault = search(db, "酒店能报多少", top_k=5)
    assert fault.status == "dependency_unavailable"


def test_vector_index_updates_disposition_inventory(candidate):
    from enterprise_kb.modules.retrieval import vector

    (client, db, (owner, _), _, _, *_), before, (version, passage, run) = candidate
    connection, tenant, _, _, store = db
    provider = vector.SyntheticLocalEmbeddingProvider()
    index_ref = vector.build_vector_index(
        connection, store, tenant.space_ref, version.version_ref, run.run_ref, provider,
    )
    after = plan(client, owner, version.version_ref).json()
    assert after["inventory_snapshot"] != before["inventory_snapshot"]
    assert [item["kind"] for item in after["copies"]].count("index") == 1
    assert str(index_ref) not in str(after)
    assert submit(client, owner, before).status_code == 409
    assert submit(client, owner, after).status_code == 200


def test_docx_paragraphs_support_lexical_and_vector_indexing(evidence_db):
    from enterprise_kb.modules.evidence import processing
    from enterprise_kb.modules.retrieval import lexical, vector

    connection, tenant, _, _, store = evidence_db
    docx_xml = """<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
  <w:p><w:pPr><w:outlineLvl w:val="0"/></w:pPr><w:r><w:t>差旅规定</w:t></w:r></w:p>
  <w:p><w:r><w:t>上海地区住宿上限为600元每晚。</w:t></w:r></w:p>
  <w:p><w:r><w:t>超标需部门负责人书面批准。</w:t></w:r></w:p>
  <w:sectPr/>
</w:body>
</w:document>"""
    version = register_docx(evidence_db, docx_package(docx_xml))
    run = processing.process_evidence_job(connection, claim(evidence_db), store)
    review(evidence_db, run)

    lex_ref = lexical.build_index(connection, store, tenant.space_ref, version.version_ref, run.run_ref)
    assert lex_ref is not None
    provider = vector.SyntheticLocalEmbeddingProvider()
    vec_ref = vector.build_vector_index(
        connection, store, tenant.space_ref, version.version_ref, run.run_ref, provider,
    )
    assert vec_ref is not None
    passages = docx_locators(evidence_db, version)
    assert len(passages) == 2
    lex_scores = lexical.score_indexed_passages(connection, tenant.org_id, tenant.space_id, passages, {"住宿上限"})
    assert lex_scores[passages[0].passage_ref] == 1
    assert lex_scores[passages[1].passage_ref] == 0
    vec_scores = vector.score_vector_passages(
        connection, tenant.org_id, tenant.space_id, passages, "酒店房费标准", provider,
    )
    assert passages[0].passage_ref in vec_scores


def test_vector_index_blocks_stopped_versions_and_supports_cli(corpus):
    from enterprise_kb.modules.retrieval import vector
    from enterprise_kb.modules.sources import effectivity

    db, version, first, _, *_ = corpus
    connection, tenant, database_url, _, store = db
    run_ref, = connection.execute(
        """
        SELECT processing.run_ref FROM thalion.processing_run AS processing
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (processing.org_id, processing.space_id, 'document_version', processing.version_id)
        WHERE identity.public_id = %s
        """,
        (version.version_ref,),
    ).fetchone()

    result = subprocess.run(
        [
            sys.executable, "-I", "-m", "enterprise_kb.index_build",
            "--mode", "vector",
            "--model-id", vector.DEFAULT_MODEL_ID,
            "--originals", str(store.root),
            "--space-id", str(tenant.space_ref),
            "--version-id", str(version.version_ref),
            "--run-id", str(run_ref),
        ],
        capture_output=True,
        text=True,
        env=os.environ | {"THALION_DATABASE_URL": database_url},
        check=False,
    )
    assert result.returncode == 0
    built_ref = UUID(result.stdout.strip())
    assert str(store.root) not in result.stdout

    stop_ctx = effectivity_record(connection, tenant, "stop_rule_use", "withdraw-for-vector-guard")
    effectivity.stop_synthetic_rule(
        connection,
        stop_ctx,
        tenant.space_id,
        version.version_ref,
        "withdrawn",
        uuid4(),
    )
    alt_provider = vector.SyntheticLocalEmbeddingProvider(model_id=vector.ALTERNATIVE_MODEL_ID)
    with pytest.raises(vector.VectorIndexUnavailable, match="stopped"):
        vector.build_vector_index(
            connection, store, tenant.space_ref, version.version_ref, run_ref, alt_provider,
        )
    assert built_ref is not None


def test_high_dimension_openai_compatible_vector_model_and_db_dimension_guard(corpus, monkeypatch):
    import httpx2

    from enterprise_kb.modules.operations import release
    from enterprise_kb.modules.retrieval import lexical, vector
    from enterprise_kb.ports.adapters import OpenAiCompatibleEmbeddingProviderAdapter
    from enterprise_kb.runtime.config import AuthenticatedEndpointConfig

    db, version, first, second, *_ = corpus
    connection, tenant, _, _, store = db
    run_ref, = connection.execute(
        """
        SELECT processing.run_ref FROM thalion.processing_run AS processing
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (processing.org_id, processing.space_id, 'document_version', processing.version_id)
        WHERE identity.public_id = %s
        """,
        (version.version_ref,),
    ).fetchone()

    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    monkeypatch.setenv("THALION_TEST_NVIDIA_EMB_KEY", "test-embed-token")

    dim = 1024
    model_id = "nvidia/nemotron-3.5-embed-8b"
    seen_input_types: list[str | None] = []

    def make_vec(hot_idx: int) -> list[float]:
        vec = [0.0] * dim
        vec[hot_idx] = 1.0
        return vec

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == model_id
        assert body["dimensions"] == dim
        seen_input_types.append(body.get("input_type"))
        data = []
        for idx, text in enumerate(body["input"]):
            if "住宿" in text or "酒店" in text:
                data.append({"index": idx, "embedding": make_vec(0)})
            else:
                data.append({"index": idx, "embedding": make_vec(1)})
        return httpx2.Response(200, json={"model": model_id, "data": data})

    provider = OpenAiCompatibleEmbeddingProviderAdapter(
        AuthenticatedEndpointConfig("https://emb.corp.example/v1", "env:THALION_TEST_NVIDIA_EMB_KEY"),
        model_id=model_id,
        dimension=dim,
        request_dimensions=True,
        passage_input_type="passage",
        query_input_type="query",
        transport=httpx2.MockTransport(handler),
    )

    vec_index = vector.build_vector_index(
        connection, store, tenant.space_ref, version.version_ref, run_ref, provider,
    )
    lexical.build_index(connection, store, tenant.space_ref, version.version_ref, run_ref)

    stored_model, stored_dim = connection.execute(
        "SELECT model_id, dimension FROM thalion.synthetic_vector_index WHERE index_ref = %s",
        (vec_index,),
    ).fetchone()
    assert (stored_model, stored_dim) == (model_id, dim)

    ctx = _space_owner_write_context(connection, tenant, release.SWITCH_SPACE_RELEASE)
    switched = release.switch_space_release(
        connection,
        ctx,
        tenant.space_id,
        action="trial_switch",
        wiki_delivery_enabled=True,
        lexical_index_mode="hybrid_vector",
        vector_model_id=model_id,
        rollback_trigger_summary="high-dim openai-compatible vector trial",
        reason_code="high_dim_trial",
        basis_ref=uuid4(),
    )
    assert switched["vector_model_id"] == model_id

    hybrid = search(db, "酒店能报多少", top_k=5, embedding_provider=provider)
    assert hybrid.status == "succeeded"
    payload = json.loads(hybrid.payload)
    assert payload["status"] == "hits"
    assert payload["passages"][0]["passage_id"] == str(first.passage_ref)
    assert "passage" in seen_input_types and "query" in seen_input_types

    # Path-traversal-like model_id with ".." is rejected before DB
    bad_ctx = _space_owner_write_context(connection, tenant, release.SWITCH_SPACE_RELEASE)
    with pytest.raises(ValueError, match="Invalid vector_model_id"):
        release.switch_space_release(
            connection,
            bad_ctx,
            tenant.space_id,
            action="trial_switch",
            wiki_delivery_enabled=True,
            lexical_index_mode="hybrid_vector",
            vector_model_id="nvidia/..bad",
            rollback_trigger_summary="reject invalid model id",
            reason_code="invalid_model_id",
            basis_ref=uuid4(),
        )

    # DB trigger enforces that entry vector_dims matches index dimension
    sample_row = connection.execute(
        """
        SELECT org_id, space_id, version_id, run_ref, passage_id, excerpt_revision, content_digest
        FROM thalion.synthetic_vector_entry
        WHERE index_ref = %s
        LIMIT 1
        """,
        (vec_index,),
    ).fetchone()
    assert sample_row is not None
    wrong_dim_literal = "[" + ",".join(["0.1"] * 64) + "]"
    with pytest.raises(errors.CheckViolation):
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO thalion.synthetic_vector_entry (
                    index_ref, org_id, space_id, version_id, run_ref, passage_id,
                    excerpt_revision, content_digest, embedding
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::vector)
                """,
                (vec_index, *sample_row, wrong_dim_literal),
            )
