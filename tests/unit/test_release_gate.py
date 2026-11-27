import json
from hashlib import sha256

import pytest

from enterprise_kb.modules.operations import release_gate


ARTIFACT = sha256(b"candidate artifact").hexdigest()
CASE_KINDS = ("retrieval", "no_evidence", "revocation", "historical", "wiki")


def encode(document):
    return json.dumps(document).encode("utf-8")


@pytest.fixture
def release_inputs():
    suite = {
        "schema": 1,
        "dataset_kind": "approved_blind",
        "query_set_sha256": sha256(b"private query set").hexdigest(),
        "corpus_sha256": sha256(b"private policy corpus").hexdigest(),
        "thresholds": {
            "top_k_hit_rate": 0.95,
            "historical_hit_rate": 0.95,
            "correct_abstention_rate": 1,
            "citation_support_rate": 0.95,
            "generation_support_rate": 0.95,
            "p95_ms": 1000,
        },
        "cases": [{"id": kind, "kind": kind} for kind in CASE_KINDS],
    }
    observations = {
        "schema": 1,
        "suite_sha256": sha256(encode(suite)).hexdigest(),
        "artifact_sha256": ARTIFACT,
        "query_set_sha256": suite["query_set_sha256"],
        "corpus_sha256": suite["corpus_sha256"],
        "results": [
            {
                "id": kind, "entrance": entrance, "elapsed_ms": 500, "disclosures": 0,
                "status": "no_evidence" if kind in {"no_evidence", "revocation"} else "hits",
                **({"hit": True} if kind in {"retrieval", "historical"} else {}),
                **({"claims": 2, "citation_supported": 2, "factually_supported": 2,
                    "reviewers": ["reviewer-a", "reviewer-b"]} if kind == "wiki" else {}),
            }
            for entrance in ("http", "mcp") for kind in CASE_KINDS
        ],
    }
    return suite, observations


def evaluate(suite, observations, *, expected_suite=None, expected_artifact=ARTIFACT):
    frozen_bytes = encode(suite)
    return release_gate.evaluate(
        frozen_bytes, encode(observations),
        expected_suite_sha256=expected_suite or sha256(frozen_bytes).hexdigest(),
        expected_artifact_sha256=expected_artifact,
    )


def test_matching_reviewed_evidence_passes_for_each_entrance(release_inputs):
    report = evaluate(*release_inputs)
    assert report["passed"] is True
    assert report["artifact_sha256"] == ARTIFACT
    assert report["entrances"]["http"]["citation_support_rate"] == {
        "numerator": 2, "denominator": 2, "rate": 1.0, "status": "measured",
    }
    assert report["entrances"]["mcp"]["revocation_zero_disclosure_rate"]["rate"] == 1.0
    assert "results" not in report and "reviewers" not in encode(report).decode()


def test_one_entrance_cannot_hide_a_disclosure_or_unsupported_claim(release_inputs):
    suite, observations = release_inputs
    observations["results"][7]["disclosures"] = 1
    observations["results"][9]["factually_supported"] = 1
    report = evaluate(suite, observations)
    assert report["passed"] is False
    assert report["entrances"]["http"]["failures"] == []
    assert set(report["entrances"]["mcp"]["failures"]) == {
        "generation_support_rate", "revocation_zero_disclosure_rate", "unauthorized_disclosures",
    }


def test_revocation_outage_cannot_count_as_a_successful_denial(release_inputs):
    suite, observations = release_inputs
    observations["results"][2]["status"] = "dependency_unavailable"
    report = evaluate(suite, observations)
    assert report["passed"] is False
    assert report["entrances"]["http"]["revocation_zero_disclosure_rate"]["rate"] == 0
    assert "unexpected_statuses" in report["entrances"]["http"]["failures"]


@pytest.mark.parametrize("defect", ["missing", "duplicate", "foreign", "no_review", "bad_count", "wrong_date_scope"])
def test_incomplete_or_untrusted_observation_is_invalid(release_inputs, defect):
    suite, observations = release_inputs
    if defect == "missing":
        observations["results"].pop()
    elif defect == "duplicate":
        observations["results"][-1] = observations["results"][0]
    elif defect == "foreign":
        observations["results"][0]["id"] = "not-in-suite"
    elif defect == "no_review":
        observations["results"][4]["reviewers"] = ["reviewer-a", "reviewer-a"]
    elif defect == "bad_count":
        observations["results"][4]["citation_supported"] = 3
    elif defect == "wrong_date_scope":
        observations["query_set_sha256"] = "a" * 64
    with pytest.raises(ValueError):
        evaluate(suite, observations)


def test_rejects_changed_suite_reused_artifact_and_synthetic_labels(release_inputs):
    suite, observations = release_inputs
    original_suite = observations["suite_sha256"]
    with pytest.raises(ValueError, match="artifact"):
        evaluate(suite, observations, expected_artifact="b" * 64)
    suite["thresholds"]["generation_support_rate"] = 0.1
    with pytest.raises(ValueError, match="suite"):
        evaluate(suite, observations, expected_suite=original_suite)
    suite["dataset_kind"] = "synthetic_local"
    observations["suite_sha256"] = sha256(encode(suite)).hexdigest()
    with pytest.raises(ValueError, match="approved_blind"):
        evaluate(suite, observations)


def test_missing_wiki_measurement_fails_closed(release_inputs):
    suite, observations = release_inputs
    observations["results"][4].update(claims=0, citation_supported=0, factually_supported=0)
    report = evaluate(suite, observations)
    assert report["passed"] is False
    assert report["entrances"]["http"]["generation_support_rate"]["status"] == "unmeasured"


def test_cli_returns_distinct_status_for_failed_and_invalid_evidence(release_inputs, tmp_path, capsys):
    suite, observations = release_inputs
    suite_path, observations_path = tmp_path / "suite.json", tmp_path / "observations.json"
    suite_path.write_bytes(encode(suite))
    observations_path.write_bytes(encode(observations))
    args = [str(suite_path), str(observations_path), "--suite-sha256", observations["suite_sha256"],
            "--artifact-sha256", ARTIFACT]
    assert release_gate.main(args) == 0
    assert json.loads(capsys.readouterr().out)["passed"] is True
    observations["results"][0]["elapsed_ms"] = 5000
    observations_path.write_bytes(encode(observations))
    assert release_gate.main(args) == 1
    assert json.loads(capsys.readouterr().out)["passed"] is False
    observations_path.write_text('{"schema":1,"schema":1,"private":"not-for-logs"}', encoding="utf-8")
    assert release_gate.main(args) == 2
    output = capsys.readouterr()
    assert not output.out
    assert "not-for-logs" not in output.err
