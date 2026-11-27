import argparse
import json
import math
import re
import sys
from hashlib import sha256
from pathlib import Path

from .evaluation import _percentile, _rate


_ENTRANCES = ("http", "mcp")
_CASE_KINDS = frozenset({"retrieval", "historical", "no_evidence", "revocation", "wiki"})
_RATE_THRESHOLDS = frozenset({
    "top_k_hit_rate", "historical_hit_rate", "correct_abstention_rate",
    "citation_support_rate", "generation_support_rate",
})
_DIGEST = re.compile(r"[0-9a-f]{64}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_CASES = 10_000


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def _document(raw: bytes) -> dict:
    if len(raw) > _MAX_INPUT_BYTES:
        raise ValueError("Release gate input is too large.")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("Unsupported release gate schema.")
    return value


def _fields(value, expected):
    if not isinstance(value, dict) or value.keys() != expected:
        raise ValueError("Unexpected release gate fields.")


def _label(value) -> str:
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError("Invalid release gate identifier.")
    return value


def _digest(value) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("Invalid SHA-256 digest.")
    return value


def _in_range(value, minimum, maximum):
    return type(value) in {int, float} and minimum <= value <= maximum


def _parse_cases(suite):
    cases = suite["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= _MAX_CASES:
        raise ValueError("Invalid frozen case list.")
    by_id = {}
    for case in cases:
        _fields(case, {"id", "kind"})
        case_id, kind = _label(case["id"]), _label(case["kind"])
        if case_id in by_id or kind not in _CASE_KINDS:
            raise ValueError("Duplicate or invalid frozen case.")
        by_id[case_id] = kind
    if set(by_id.values()) != _CASE_KINDS:
        raise ValueError("The frozen suite does not cover every required case kind.")
    return by_id


def _validate_result(result, kind):
    expected = {"id", "entrance", "elapsed_ms", "disclosures", "status"}
    if kind in {"retrieval", "historical"}:
        expected.add("hit")
    elif kind == "wiki":
        expected.update({"claims", "citation_supported", "factually_supported", "reviewers"})
    _fields(result, expected)
    status = _label(result["status"])
    if not _in_range(result["elapsed_ms"], 0, 3_600_000):
        raise ValueError("Invalid observed latency.")
    if type(result["disclosures"]) is not int or not 0 <= result["disclosures"] <= 10_000:
        raise ValueError("Invalid disclosure count.")
    if kind in {"retrieval", "historical"}:
        if type(result["hit"]) is not bool or (result["hit"] and status != "hits"):
            raise ValueError("Inconsistent retrieval observation.")
    elif kind == "wiki":
        claims, reviewers = result["claims"], result["reviewers"]
        counts = (claims, result["citation_supported"], result["factually_supported"])
        if (
            not all(type(count) is int for count in counts)
            or not 0 <= counts[2] <= counts[1] <= claims <= 10_000
            or (claims and status != "hits")
            or not isinstance(reviewers, list) or len(reviewers) != 2
            or _label(reviewers[0]) == _label(reviewers[1])
        ):
            raise ValueError("Wiki observation requires consistent counts and two distinct reviewer identifiers.")


def _entrance_report(results, thresholds):
    report = {}
    for metric, kind in (("top_k_hit_rate", "retrieval"), ("historical_hit_rate", "historical")):
        entries = results[kind]
        report[metric] = _rate(sum(entry["hit"] for entry in entries), len(entries))
    entries = results["no_evidence"]
    report["correct_abstention_rate"] = _rate(sum(entry["status"] == "no_evidence" for entry in entries), len(entries))
    entries = results["revocation"]
    denied_statuses = {"no_evidence", "rejected"}
    report["revocation_zero_disclosure_rate"] = _rate(sum(
        entry["status"] in denied_statuses and entry["disclosures"] == 0 for entry in entries
    ), len(entries))
    entries = results["wiki"]
    claims = sum(entry["claims"] for entry in entries)
    report["citation_support_rate"] = _rate(sum(entry["citation_supported"] for entry in entries), claims)
    report["generation_support_rate"] = _rate(sum(entry["factually_supported"] for entry in entries), claims)
    failures = []
    for metric in sorted(_RATE_THRESHOLDS | {"revocation_zero_disclosure_rate"}):
        counts = report[metric]
        if not counts["denominator"] or counts["numerator"] / counts["denominator"] < thresholds.get(metric, 1):
            failures.append(metric)
    allowed_statuses = {
        "retrieval": {"hits", "no_evidence"}, "historical": {"hits", "no_evidence"},
        "no_evidence": {"hits", "no_evidence"}, "revocation": denied_statuses | {"hits"}, "wiki": {"hits"},
    }
    report["unexpected_statuses"] = sum(
        entry["status"] not in allowed_statuses[kind] for kind, entries in results.items() for entry in entries
    )
    report["unmeasured_wiki_cases"] = sum(not entry["claims"] for entry in results["wiki"])
    all_results = [entry for entries in results.values() for entry in entries]
    report["case_count"] = len(all_results)
    report["unauthorized_disclosures"] = sum(entry["disclosures"] for entry in all_results)
    latencies = sorted(entry["elapsed_ms"] for entry in all_results)
    report["p95_ms"] = _percentile(latencies, 0.95)
    if latencies[math.ceil(len(latencies) * 0.95) - 1] > thresholds["p95_ms"]:
        failures.append("p95_ms")
    failures.extend(metric for metric in ("unexpected_statuses", "unmeasured_wiki_cases", "unauthorized_disclosures") if report[metric])
    report["failures"] = failures
    return report


def evaluate(
    frozen_suite: bytes, observations: bytes, *, expected_suite_sha256: str, expected_artifact_sha256: str,
) -> dict:
    if sha256(frozen_suite).hexdigest() != _digest(expected_suite_sha256):
        raise ValueError("The frozen suite does not match its approved digest.")
    _digest(expected_artifact_sha256)
    suite = _document(frozen_suite)
    _fields(suite, {"schema", "dataset_kind", "query_set_sha256", "corpus_sha256", "thresholds", "cases"})
    if suite["dataset_kind"] != "approved_blind":
        raise ValueError("Release evaluation requires an approved_blind suite.")
    thresholds = suite["thresholds"]
    _fields(thresholds, _RATE_THRESHOLDS | {"p95_ms"})
    if not all(_in_range(thresholds[metric], 0, 1) and thresholds[metric] > 0 for metric in _RATE_THRESHOLDS):
        raise ValueError("Invalid rate thresholds.")
    if not _in_range(thresholds["p95_ms"], 1, 3_600_000):
        raise ValueError("Invalid latency threshold.")
    case_kinds = _parse_cases(suite)

    recorded = _document(observations)
    _fields(recorded, {"schema", "suite_sha256", "artifact_sha256", "query_set_sha256", "corpus_sha256", "results"})
    if recorded["artifact_sha256"] != expected_artifact_sha256:
        raise ValueError("The observations do not match the candidate artifact.")
    if recorded["suite_sha256"] != expected_suite_sha256 or any(
        recorded[field] != _digest(suite[field]) for field in ("query_set_sha256", "corpus_sha256")
    ):
        raise ValueError("The observations do not match the frozen suite inputs.")
    results = recorded["results"]
    if not isinstance(results, list) or len(results) != len(case_kinds) * len(_ENTRANCES):
        raise ValueError("Every case must be observed once at each entrance.")
    collected = {entrance: {kind: [] for kind in _CASE_KINDS} for entrance in _ENTRANCES}
    seen = set()
    for entry in results:
        if not isinstance(entry, dict):
            raise ValueError("Invalid observation.")
        entrance, case_id = _label(entry.get("entrance")), _label(entry.get("id"))
        if entrance not in collected or case_id not in case_kinds or (entrance, case_id) in seen:
            raise ValueError("Duplicate or unknown result scope.")
        kind = case_kinds[case_id]
        _validate_result(entry, kind)
        collected[entrance][kind].append(entry)
        seen.add((entrance, case_id))
    entrances = {entrance: _entrance_report(results, thresholds) for entrance, results in collected.items()}
    return {
        "schema": 1, "suite_sha256": expected_suite_sha256, "artifact_sha256": expected_artifact_sha256,
        "entrances": entrances, "passed": all(not report["failures"] for report in entrances.values()),
    }


def _read_input(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(_MAX_INPUT_BYTES + 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="离线核验正式发布的冻结盲测记录")
    parser.add_argument("suite", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("--suite-sha256", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        report = evaluate(
            _read_input(arguments.suite), _read_input(arguments.observations),
            expected_suite_sha256=arguments.suite_sha256, expected_artifact_sha256=arguments.artifact_sha256,
        )
    except (OSError, ValueError, RecursionError) as error:
        print(f"FAIL 盲测证据不可用（{type(error).__name__}）。", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
