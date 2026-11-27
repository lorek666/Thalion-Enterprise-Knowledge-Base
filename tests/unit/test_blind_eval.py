from hashlib import sha256
import json
from pathlib import Path
from uuid import UUID

import httpx2
import pytest

from enterprise_kb.modules.operations import blind_eval, release_gate
from enterprise_kb.modules.operations.search_probe import MCP_PROTOCOL_VERSION


PASSAGE, REVOKED, REQUEST, REVISION = (str(UUID(int=number)) for number in range(1, 5))
ARTIFACT = "a" * 64
DAY = "2026-10-06"
KINDS = ("retrieval", "historical", "no_evidence", "revocation", "wiki")


def encode(value):
    return json.dumps(value, ensure_ascii=False, indent=2).encode()


@pytest.fixture
def frozen():
    query_set = encode({"schema": 1, "cases": [
        {"id": kind, "actor": "REVOKED" if kind == "revocation" else "EMPLOYEE", "query": kind,
         "business_date": DAY, "top_k": 1, "include_wiki": kind == "wiki",
         "expected_passage_ids": [PASSAGE] if kind in {"retrieval", "historical"} else [],
         "forbidden_passage_ids": [REVOKED], "forbidden_substrings": ["仅供合成评估的标记"]}
        for kind in KINDS
    ]})
    suite = encode({"schema": 1, "dataset_kind": "approved_blind", "query_set_sha256": sha256(query_set).hexdigest(),
                    "corpus_sha256": "b" * 64, "cases": [{"id": kind, "kind": kind} for kind in KINDS],
                    "thresholds": dict.fromkeys(release_gate._RATE_THRESHOLDS, 1) | {"p95_ms": 1000}})
    return suite, query_set


def run(frozen, *, base_url="https://kb.example.test", credentials=None):
    suite, query_set = frozen
    return blind_eval.collect(suite, query_set, suite_sha256=sha256(suite).hexdigest(),
                              artifact_sha256=ARTIFACT, base_url=base_url,
                              credentials=credentials or (lambda actor: actor * 8))


def reviews(collection):
    return {"schema": 1, "collection_sha256": sha256(collection).hexdigest(), "reviews": [
        {"id": "wiki", "entrance": entrance, "citation_supported": 1, "factually_supported": 1,
         "reviewers": ["reviewer-a", "reviewer-b"]} for entrance in ("http", "mcp")
    ]}


@pytest.fixture
def transport(monkeypatch):
    client = httpx2.Client
    faults = {}
    calls = []

    def respond(request):
        arguments = json.loads(request.content)
        mcp = request.url.path == "/mcp"
        if mcp:
            assert request.headers["mcp-protocol-version"] == MCP_PROTOCOL_VERSION
            rpc_id = arguments["id"]
            arguments = arguments["params"]["arguments"]
        query = arguments["query"]
        calls.append(("mcp" if mcp else "http", query, request.headers["authorization"]))
        empty = query in {"no_evidence", "revocation"}
        payload = {"status": "no_evidence" if empty else "hits", "business_date": arguments["business_date"],
                   "request_id": REQUEST, "wiki": [], "passages": [] if empty else [{"passage_id": PASSAGE}]}
        if arguments["include_wiki"]:
            payload["wiki"] = [{"revision_id": REVISION, "claims": [{"text": "当前制度", "passage_ids": [PASSAGE]}]}]
        if mcp:
            payload = {"jsonrpc": "2.0", "id": rpc_id, "result": {"structuredContent": payload, "isError": False}}
        status = 200
        if fault := faults.get((mcp, query)):
            status, payload = fault(payload)
        return httpx2.Response(status, json=payload)

    monkeypatch.setattr(blind_eval.httpx2, "Client", lambda **kwargs: client(**kwargs, transport=httpx2.MockTransport(respond)))
    return calls, faults


def test_collected_evidence_round_trips_to_gate(frozen, transport):
    collected = encode(run(frozen))
    assert len(transport[0]) == 10
    assert {token for _, kind, token in transport[0] if kind == "revocation"} == {f"Bearer {'REVOKED' * 8}"}
    assert b"Bearer" not in collected
    observations = encode(blind_eval.finalize(collected, encode(reviews(collected))))
    assert "当前制度".encode() not in observations and b"request_id" not in observations
    report = release_gate.evaluate(frozen[0], observations, expected_suite_sha256=sha256(frozen[0]).hexdigest(),
                                   expected_artifact_sha256=ARTIFACT)
    assert report["passed"] is True


@pytest.mark.parametrize("defect", ["digest", "duplicate", "missing"])
def test_reviews_cannot_be_reused_or_incomplete(frozen, transport, defect):
    collected = encode(run(frozen))
    review = reviews(collected)
    if defect == "digest":
        review["collection_sha256"] = "b" * 64
    if defect == "duplicate":
        review["reviews"].append(review["reviews"][0])
    if defect == "missing":
        review["reviews"].pop()
    with pytest.raises(ValueError):
        blind_eval.finalize(collected, encode(review))


def test_revoked_errors_with_disclosures_and_wrong_historical_date_fail(frozen, transport):
    _, faults = transport
    faults[True, "revocation"] = lambda _: (503, {"error": {"code": "dependency_unavailable", "message": REVOKED}})
    faults[False, "historical"] = lambda payload: (200, payload | {"business_date": "2026-10-07"})
    collected = encode(run(frozen))
    result = json.loads(collected)["results"]
    assert result[2]["status"] == "invalid_response"
    assert result[7]["status"] == "invalid_response" and result[7]["disclosures"] == 1
    observations = encode(blind_eval.finalize(collected, encode(reviews(collected))))
    report = release_gate.evaluate(frozen[0], observations, expected_suite_sha256=sha256(frozen[0]).hexdigest(),
                                   expected_artifact_sha256=ARTIFACT)
    assert not report["passed"]


def test_rejects_unfrozen_queries_cleartext_and_reused_credentials_before_network(frozen, transport):
    with pytest.raises(ValueError, match="Query set"):
        run((frozen[0], frozen[1] + b"\n"))
    with pytest.raises(ValueError, match="HTTPS"):
        run(frozen, base_url="http://kb.example.test")
    with pytest.raises(ValueError, match="credential"):
        run(frozen, credentials=lambda _: "same" * 10)
    assert not transport[0]


def test_private_collection_will_not_replace_existing_file(tmp_path: Path):
    filename = tmp_path / "collection.json"
    blind_eval._write_private(filename, {"private": True})
    assert filename.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        blind_eval._write_private(filename, {"private": False})
