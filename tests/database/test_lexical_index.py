from dataclasses import replace
import json
import os
import subprocess
import sys
from uuid import UUID, uuid4

from psycopg import errors
import pytest

from test_disposition import plan
from test_disposition_cases import candidate, submit
from test_disposition_verification import original as original_file
from test_evidence import evidence_db, review
from test_evidence_transport import evidence_transport, transport
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_travel_search import SEARCH_FIELDS, corpus, search


def build(db, version, run):
    from enterprise_kb.modules.retrieval.lexical import build_index

    connection, tenant, _, _, store = db
    return build_index(connection, store, tenant.space_ref, version.version_ref, run.run_ref)


def test_built_index_is_exact_and_changes_disposition_inventory(candidate):
    (client, db, (owner, _), _, _, *_), before, (version, passage, run) = candidate
    connection, *_ = db
    index = build(db, version, run)
    assert build(db, version, run) == index
    stored = connection.execute("""
        SELECT run_ref, entries -> %s FROM thalion.synthetic_lexical_index WHERE index_ref = %s
        """, (str(passage.passage_ref), index)).fetchone()
    assert stored == (run.run_ref, [passage.revision, passage.digest.hex(), "synthetic plan.\n"])
    after = plan(client, owner, version.version_ref).json()
    assert after["inventory_snapshot"] != before["inventory_snapshot"]
    assert [item["kind"] for item in after["copies"]].count("index") == 1
    assert str(index) not in str(after) and "synthetic plan" not in str(after)
    assert "cache" in after["unverified_copy_kinds"]
    assert submit(client, owner, before).status_code == 409
    assert submit(client, owner, after).status_code == 200
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("UPDATE thalion.synthetic_lexical_index SET entries = '{}'::jsonb")
    with pytest.raises(errors.ObjectNotInPrerequisiteState):
        connection.execute("TRUNCATE thalion.synthetic_lexical_index")


def test_indexed_matching_preserves_ranking_and_filters_before_reading_index(corpus, monkeypatch):
    from enterprise_kb.modules.retrieval import lexical

    db, version, first, second, *_ = corpus
    connection, tenant, *_ = db
    run_ref, = connection.execute("""
        SELECT processing.run_ref FROM thalion.processing_run AS processing
        JOIN thalion.object_identity AS identity
          ON (identity.org_id, identity.space_id, identity.object_type, identity.object_id) =
             (processing.org_id, processing.space_id, 'document_version', processing.version_id)
        WHERE identity.public_id = %s
        """, (version.version_ref,)).fetchone()
    set_rules(db, replace(binding(tenant.actor_id), fields=SEARCH_FIELDS))
    original = json.loads(search(db, "上海住宿 审批", top_k=2).payload)["passages"]
    lexical.build_index(connection, db[4], tenant.space_ref, version.version_ref, run_ref)
    assert json.loads(search(db, "上海住宿 审批", top_k=2).payload)["passages"] == original
    score = lexical.score_indexed_passages
    evaluated = {}

    def track(connection, org_id, space_id, passages, terms):
        assert list(passages) == [first]
        result = score(connection, org_id, space_id, passages, terms)
        evaluated.update(result)
        return result

    monkeypatch.setattr(lexical, "score_indexed_passages", track)
    set_rules(db, replace(binding(tenant.actor_id, passage_ref=first.passage_ref), fields=SEARCH_FIELDS), expected=2)
    result = json.loads(search(db, "上海住宿 审批", top_k=2).payload)
    assert evaluated == {first.passage_ref: 1}
    assert [item["passage_id"] for item in result["passages"]] == [str(first.passage_ref)]
    assert str(second.passage_ref) not in str(result)
    file = original_file(db, version)
    moved = file.with_suffix(".unavailable")
    file.rename(moved)
    try:
        assert search(db, "审批").status == "dependency_unavailable"
        assert evaluated == {first.passage_ref: 0}
    finally:
        moved.rename(file)


def test_index_build_requires_exact_current_approved_run_and_space(candidate):
    from enterprise_kb.modules.retrieval.lexical import LexicalIndexUnavailable, build_index

    (_, db, *_), _, (version, _, run) = candidate
    connection, tenant, _, _, store = db
    for space, requested in ((uuid4(), run.run_ref), (tenant.space_ref, uuid4())):
        with pytest.raises(LexicalIndexUnavailable):
            build_index(connection, store, space, version.version_ref, requested)
    index = build(db, version, run)
    review(db, run, decision="quarantined")
    with pytest.raises(LexicalIndexUnavailable):
        build(db, version, run)
    assert connection.execute("SELECT index_ref FROM thalion.synthetic_lexical_index").fetchall() == [(index,)]


def test_cli_builds_explicit_scope_without_printing_paths_or_content(candidate):
    (_, db, *_), _, (version, _, run) = candidate
    connection, tenant, url, _, store = db
    command = [
        sys.executable, "-I", "-m", "enterprise_kb.index_build",
        "--originals", str(store.root), "--version-id", str(version.version_ref),
        "--run-id", str(run.run_ref), "--space-id",
    ]
    environment = os.environ | {"THALION_DATABASE_URL": url}
    refused = subprocess.run([*command, str(uuid4())], env=environment, capture_output=True, text=True, check=False)
    assert refused.returncode == 1 and not refused.stdout
    assert str(store.root) not in refused.stderr and url not in refused.stderr
    assert connection.execute("SELECT count(*) FROM thalion.synthetic_lexical_index").fetchone() == (0,)
    built = subprocess.run([*command, str(tenant.space_ref)], env=environment, capture_output=True, text=True, check=False)
    assert built.returncode == 0, built.stderr
    index = UUID(built.stdout.strip())
    assert connection.execute("SELECT index_ref FROM thalion.synthetic_lexical_index").fetchall() == [(index,)]
