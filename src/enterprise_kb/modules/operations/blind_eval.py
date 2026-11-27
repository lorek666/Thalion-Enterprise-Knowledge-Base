import argparse
from datetime import date
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
from time import monotonic
from urllib.parse import urlsplit
from uuid import UUID

import httpx2

from . import release_gate
from .search_probe import post_search


_ACTOR = re.compile(r"[A-Z][A-Z0-9_]{0,31}")
_COLLECTED_FIELDS = {"schema", "suite_sha256", "artifact_sha256", "query_set_sha256", "corpus_sha256", "results"}


def _encode(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _reference(value) -> str:
    if not isinstance(value, str) or len(value) != 36 or str(UUID(value)) != value:
        raise ValueError("Invalid evidence or request identifier.")
    return value


def _query_cases(raw: bytes, suite: dict, case_kinds: dict) -> list[dict]:
    if sha256(raw).hexdigest() != suite["query_set_sha256"]:
        raise ValueError("Query set does not match the frozen suite.")
    queries = release_gate._document(raw)
    release_gate._fields(queries, {"schema", "cases"})
    cases = queries["cases"]
    if not isinstance(cases, list) or len(cases) != len(case_kinds):
        raise ValueError("Query set does not cover the frozen suite.")
    seen = set()
    for case in cases:
        release_gate._fields(case, {
            "id", "actor", "query", "business_date", "top_k", "include_wiki", "expected_passage_ids",
            "forbidden_passage_ids", "forbidden_substrings",
        })
        case_id = release_gate._label(case["id"])
        if case_id in seen or case_id not in case_kinds:
            raise ValueError("Duplicate or unknown case.")
        seen.add(case_id)
        actor, query, business_day, top_k = (case[key] for key in ("actor", "query", "business_date", "top_k"))
        if (
            not isinstance(actor, str) or not _ACTOR.fullmatch(actor)
            or not isinstance(query, str) or not 0 < len(query) <= 1000 or not query.strip() or "\x00" in query
            or not isinstance(business_day, str) or date.fromisoformat(business_day).isoformat() != business_day
            or type(top_k) is not int or not 1 <= top_k <= 20 or type(case["include_wiki"]) is not bool
        ):
            raise ValueError("Invalid frozen search arguments.")
        expected, forbidden, markers = (case[key] for key in (
            "expected_passage_ids", "forbidden_passage_ids", "forbidden_substrings",
        ))
        if not all(isinstance(values, list) and len(values) <= 100 for values in (expected, forbidden, markers)):
            raise ValueError("Invalid frozen evidence criteria.")
        expected_ids, forbidden_ids = ({_reference(value) for value in values} for values in (expected, forbidden))
        if (
            expected_ids & forbidden_ids
            or any(not isinstance(marker, str) or not marker.strip() or len(marker) > 512 for marker in markers)
            or (case_kinds[case_id] in {"retrieval", "historical"} and not expected_ids)
            or (case_kinds[case_id] == "revocation" and not (forbidden_ids or markers))
            or (case_kinds[case_id] == "wiki" and not case["include_wiki"])
        ):
            raise ValueError("Invalid evidence scope for case kind.")
    return cases


def _origin(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
        or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or any(ord(char) <= 32 for char in base_url)
    ):
        raise ValueError("Blind evaluation requires a trusted HTTPS origin.")
    return base_url.rstrip("/")


def _disclosures(body: dict, case: dict) -> int:
    serialized = _encode(body).decode("utf-8")
    return sum(marker in serialized for marker in set(case["forbidden_passage_ids"])) + sum(
        json.dumps(marker, ensure_ascii=False)[1:-1] in serialized for marker in set(case["forbidden_substrings"])
    )


def _observe(client, entrance: str, token: str, case: dict, kind: str, rpc_id: int) -> dict:
    arguments = {key: case[key] for key in ("query", "business_date", "top_k", "include_wiki")}
    started = monotonic()
    response = post_search(client, entrance, token, arguments, rpc_id)
    elapsed_ms = round((monotonic() - started) * 1000, 3)
    disclosures = 0
    try:
        if len(response.content) > release_gate._MAX_INPUT_BYTES:
            raise ValueError("Search response is too large.")
        body = json.loads(response.content, object_pairs_hook=release_gate._unique_object)
        if not isinstance(body, dict):
            raise ValueError("Unexpected search response.")
        disclosures = _disclosures(body, case)
        payload = body
        if entrance == "mcp" and response.status_code == 200:
            if body.get("jsonrpc") != "2.0" or type(body.get("id")) is not int or body["id"] != rpc_id or "error" in body:
                raise ValueError("MCP response does not match the request.")
            tool_result = body["result"]
            if tool_result.get("isError", False) is not False:
                raise ValueError("MCP returned a tool error.")
            payload = tool_result["structuredContent"]
        if response.status_code != 200 or payload.get("business_date") != case["business_date"]:
            raise ValueError("Search failed or returned an unexpected business date.")
        request_id = _reference(payload["request_id"])
        status, passages, wiki = (payload[key] for key in ("status", "passages", "wiki"))
        if (
            status not in {"hits", "no_evidence"} or not isinstance(passages, list) or not isinstance(wiki, list)
            or len(passages) > case["top_k"] or (status == "no_evidence" and (passages or wiki))
            or (not case["include_wiki"] and wiki) or (status == "hits" and not (passages or wiki))
        ):
            raise ValueError("Search response has an inconsistent evidence scope.")
        visible = {_reference(item["passage_id"]) for item in passages}
        for item in wiki:
            _reference(item["revision_id"])
            if not isinstance(item["claims"], list) or any(
                not isinstance(claim["text"], str) or not claim["text"].strip()
                or not isinstance(claim["passage_ids"], list)
                for claim in item["claims"]
            ):
                raise ValueError("Invalid Wiki claim.")
        result = {"id": case["id"], "entrance": entrance, "elapsed_ms": elapsed_ms, "disclosures": disclosures,
                  "status": status, "request_id": request_id}
        if kind in {"retrieval", "historical"}:
            result["hit"] = bool(set(case["expected_passage_ids"]) & visible)
        elif kind == "wiki":
            result["wiki"] = wiki
        return result
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return {
            "id": case["id"], "entrance": entrance, "elapsed_ms": elapsed_ms, "disclosures": disclosures,
            "status": "invalid_response", "request_id": None,
        } | ({"hit": False} if kind in {"retrieval", "historical"} else {"wiki": []} if kind == "wiki" else {})


def collect(
    frozen_suite: bytes, query_set: bytes, *, suite_sha256: str, artifact_sha256: str, base_url: str, credentials,
) -> dict:
    suite, case_kinds = release_gate.load_suite(frozen_suite, suite_sha256)
    cases = _query_cases(query_set, suite, case_kinds)
    artifact_sha256 = release_gate._digest(artifact_sha256)
    origin = _origin(base_url)
    actors = {case["actor"] for case in cases}
    tokens = {actor: credentials(actor) for actor in actors}
    if any(not isinstance(token, str) or not 32 <= len(token) <= 16384 or not re.fullmatch(r"[A-Za-z0-9_.-]+", token)
           for token in tokens.values()) or len(set(tokens.values())) != len(actors):
        raise ValueError("Each actor needs its own valid bearer credential.")
    with httpx2.Client(base_url=origin, timeout=30, follow_redirects=False, trust_env=False) as client:
        results = [
            _observe(client, entrance, tokens[case["actor"]], case, case_kinds[case["id"]], rpc_id)
            for rpc_id, case in enumerate(cases, 1) for entrance in release_gate._ENTRANCES
        ]
    return {"schema": 1, "suite_sha256": suite_sha256, "artifact_sha256": artifact_sha256,
            "query_set_sha256": suite["query_set_sha256"], "corpus_sha256": suite["corpus_sha256"], "results": results}


def finalize(collected_raw: bytes, reviews_raw: bytes) -> dict:
    collected, reviewed = (release_gate._document(raw) for raw in (collected_raw, reviews_raw))
    release_gate._fields(collected, _COLLECTED_FIELDS)
    release_gate._fields(reviewed, {"schema", "collection_sha256", "reviews"})
    if (reviewed["collection_sha256"] != sha256(collected_raw).hexdigest()
            or not isinstance(reviewed["reviews"], list) or not isinstance(collected["results"], list)):
        raise ValueError("Reviews do not match the collected run.")
    reviews = {}
    for review in reviewed["reviews"]:
        release_gate._fields(review, {"id", "entrance", "citation_supported", "factually_supported", "reviewers"})
        key = (release_gate._label(review["id"]), release_gate._label(review["entrance"]))
        if key in reviews:
            raise ValueError("Duplicate review.")
        reviews[key] = review
    observations = []
    for result in collected["results"]:
        result = dict(result)
        result.pop("request_id")
        if "wiki" in result:
            wiki = result.pop("wiki")
            key = (result["id"], result["entrance"])
            if key not in reviews:
                raise ValueError("A Wiki observation is missing independent review.")
            review = reviews.pop(key)
            result |= {field: review[field] for field in ("citation_supported", "factually_supported", "reviewers")}
            result["claims"] = sum(len(item["claims"]) for item in wiki)
            release_gate._validate_result(result, "wiki")
        observations.append(result)
    if reviews:
        raise ValueError("The review set includes unknown cases.")
    return collected | {"results": observations}


def _write_private(path: Path, document: dict) -> None:
    data = _encode(document)
    if len(data) > release_gate._MAX_INPUT_BYTES:
        raise ValueError("Evaluation output exceeds evidence size limit.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="采集和判分私有 HTTP/MCP 冻结盲测")
    commands = parser.add_subparsers(dest="command", required=True)
    acquire = commands.add_parser("collect")
    acquire.add_argument("suite", type=Path)
    acquire.add_argument("query_set", type=Path)
    acquire.add_argument("--suite-sha256", required=True)
    acquire.add_argument("--artifact-sha256", required=True)
    acquire.add_argument("--base-url", required=True)
    finish = commands.add_parser("finalize")
    finish.add_argument("collection", type=Path)
    finish.add_argument("reviews", type=Path)
    for command in (acquire, finish):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            result = collect(
                release_gate._read_input(args.suite), release_gate._read_input(args.query_set),
                suite_sha256=args.suite_sha256, artifact_sha256=args.artifact_sha256, base_url=args.base_url,
                credentials=lambda actor: os.environ.get(f"THALION_BLIND_TOKEN_{actor}"),
            )
        else:
            result = finalize(release_gate._read_input(args.collection), release_gate._read_input(args.reviews))
        _write_private(args.output, result)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, httpx2.HTTPError) as error:
        print(f"FAIL 盲测操作失败（{type(error).__name__}）。", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
