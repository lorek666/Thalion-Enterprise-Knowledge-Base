import json
import os
import subprocess
import sys

from psycopg import sql
import pytest

from enterprise_kb.database import upgrade
from test_runtime import open_database, runtime_db


def test_synthetic_e2e_benchmark_measures_http_mcp_hybrid_and_wiki_honestly(database_url, tmp_path):
    from enterprise_kb.benchmark import run_synthetic_e2e_benchmark

    upgrade(database_url)
    originals = tmp_path / "originals"
    originals.mkdir(mode=0o700)
    originals.chmod(0o700)

    report = run_synthetic_e2e_benchmark(
        database_url,
        originals_dir=originals,
        iterations=2,
        transport="asgi",
    )

    assert report["dataset_kind"] == "synthetic_local"
    assert report["replaces_frozen_blind_eval"] is False
    assert report["qa_answer_latency_status"] == "unmeasured_no_approved_agent"
    assert "合成" in report["disclaimer"]
    assert "不替代" in report["disclaimer"]
    assert report["sample_insufficient"] is True

    env = report["environment"]
    assert env["transport"] == "asgi"
    assert env["iterations"] == 2
    assert env["postgres_version"]
    assert env["pgvector_version"]
    assert env["python_version"]
    assert env["cpu_count"] >= 1

    expected_arms = (
        "indexed__rag_only",
        "indexed__rag_plus_wiki",
        "hybrid_vector__rag_only",
        "hybrid_vector__rag_plus_wiki",
    )
    assert tuple(report["arms"].keys()) == expected_arms

    for arm_name in expected_arms:
        arm = report["arms"][arm_name]
        http_res = arm["entrances"]["http"]
        mcp_res = arm["entrances"]["mcp"]
        for res in (http_res, mcp_res):
            assert res["unauthorized_disclosures"] == 0
            assert res["normal_requests"]["total"] > 0
            assert res["normal_requests"]["error_or_fault_count"] == 0
            assert res["dependency_fault_requests"]["total"] > 0
            assert res["dependency_fault_requests"]["accuracy"]["rate"] == 1.0
            assert res["correct_abstention_rate"]["rate"] == 1.0
            assert res["authority_revoked_zero_leak_rate"]["rate"] == 1.0
            assert res["historical_date_hit_rate"]["rate"] == 1.0
            assert res["first_search_cross_doc_complete_rate"]["rate"] == 1.0
            lat = res["normal_requests"]["all_normal_latency_ms"]
            assert 0 < lat["p50"] <= lat["p95"] <= lat["p99"] <= lat["max"]

        # HTTP 与 MCP 两条入口业务结果完全等价
        for metric_key in (
            "first_search_top5_hit_rate",
            "first_search_cross_doc_complete_rate",
            "semantic_synonym_hit_rate",
            "correct_abstention_rate",
            "authority_revoked_zero_leak_rate",
            "wiki_delivery_count",
            "wiki_citation_support_rate",
            "unauthorized_disclosures",
        ):
            assert http_res[metric_key] == mcp_res[metric_key]

        if arm_name.startswith("indexed__"):
            assert http_res["semantic_synonym_hit_rate"]["rate"] == 0.0
            assert http_res["first_search_top5_hit_rate"]["numerator"] == 8
            assert http_res["first_search_top5_hit_rate"]["denominator"] == 12
        else:
            assert http_res["semantic_synonym_hit_rate"]["rate"] == 1.0
            assert http_res["first_search_top5_hit_rate"]["rate"] == 1.0

        if arm_name.endswith("__rag_only"):
            assert http_res["wiki_delivery_count"] == 0
            assert http_res["wiki_citation_support_rate"]["status"] == "unmeasured"
        else:
            assert http_res["wiki_delivery_count"] > 0
            assert http_res["wiki_citation_support_rate"]["status"] == "measured"
            assert http_res["wiki_citation_support_rate"]["rate"] == 1.0

    # 核对共享请求账本中真实记录了 HTTP 与 MCP 请求
    with open_database(database_url) as connection:
        counts = dict(
            connection.execute(
                "SELECT ingress, count(*) FROM thalion.request_record WHERE operation = 'search' GROUP BY ingress"
            ).fetchall()
        )
    assert counts.get("http", 0) > 0
    assert counts.get("mcp", 0) > 0


def test_synthetic_benchmark_cli_loopback_http_and_rehearsal_guard(database_url, tmp_path):
    upgrade(database_url)
    originals = tmp_path / "originals"
    originals.mkdir(mode=0o700)
    originals.chmod(0o700)

    result = subprocess.run(
        [
            sys.executable, "-I", "-m", "enterprise_kb.benchmark",
            "--originals", str(originals),
            "--iterations", "1",
            "--transport", "loopback_http",
        ],
        capture_output=True,
        text=True,
        env=os.environ | {"THALION_DATABASE_URL": database_url},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["dataset_kind"] == "synthetic_local"
    assert payload["environment"]["transport"] == "loopback_http"
    assert payload["arms"]["hybrid_vector__rag_plus_wiki"]["entrances"]["http"]["semantic_synonym_hit_rate"]["rate"] == 1.0
    assert payload["arms"]["hybrid_vector__rag_plus_wiki"]["entrances"]["mcp"]["wiki_delivery_count"] > 0

    # 恢复演练围栏库必须拒绝执行基准
    with open_database(database_url) as connection:
        dbname, = connection.execute("SELECT current_database()").fetchone()
        connection.execute(
            sql.SQL("ALTER DATABASE {} SET thalion.restore_rehearsal = {}").format(
                sql.Identifier(dbname),
                sql.Literal(dbname),
            )
        )

    blocked = subprocess.run(
        [
            sys.executable, "-I", "-m", "enterprise_kb.benchmark",
            "--originals", str(originals),
            "--iterations", "1",
        ],
        capture_output=True,
        text=True,
        env=os.environ | {"THALION_DATABASE_URL": database_url},
        check=False,
    )
    assert blocked.returncode != 0
