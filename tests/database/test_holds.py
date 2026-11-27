from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from enterprise_kb.modules.sources import effectivity

from test_disposition import configure as retention, plan
from test_effectivity import AFTER, SWITCH, approve, record
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_findings import publish_topic
from test_gaps import command_headers, record_gap
from test_runtime import runtime_db
from test_travel_search import BEFORE, corpus, publish
from test_wiki_inputs import assemble
from test_wiki_invalidation import version_ref
from test_wiki_publication import configure as configure_wiki


PATH = "/internal/lifecycle/holds"
CAPABILITY = "decide_hold"


def decide(client, token, version, *, action="establish", generation=0, key=None, basis=None):
    return client.post(PATH, headers=command_headers(token, key), json={
        "version_id": str(version), "action": action, "expected_generation": generation, "basis_id": str(basis or uuid4()),
    })


def search(client, token, query, *, wiki=True, day=BEFORE):
    return client.post("/v1/search", headers=bearer(token), json={
        "query": query, "business_date": day.isoformat(), "include_wiki": wiki,
    })


def test_hold_of_uncited_input_pauses_original_wiki_and_gap_candidate_without_deletion(transport):
    client, db, (owner, custodian), credentials, _, first, second = transport
    connection, _, _, source, store = db
    configure_wiki(db, 2)
    publish_topic(db, "isolated-hold", "合成补充限额按原文。", first, second)
    assert search(client, owner, "限额").json()["wiki"]
    target = version_ref(connection, second)
    original_files = {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()}
    admit(credentials, custodian, CAPABILITY)
    admit(credentials, owner, "plan_disposition", "register_retention_policy", "record_gap", "read_gap_queue")
    assert retention(client, owner, source).status_code == 200
    held = decide(client, custodian, target)
    assert held.status_code == 200 and held.headers["Cache-Control"] == "no-store"
    assert held.json() == {
        "request_id": held.json()["request_id"], "decision_id": held.json()["decision_id"],
        "generation": 1, "state": "held",
    }
    current = search(client, owner, "上海住宿").json()
    assert [item["passage_id"] for item in current["passages"]] == [str(first.passage_ref)] and current["wiki"] == []
    assert assemble(db, (first, second)).status == "rejected"
    denied = client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner))
    assert denied.status_code == 404 and "hold" not in denied.text
    mcp = rpc(client, owner, "tools/call", name="read_passage", arguments={"id": str(second.passage_ref)})
    assert mcp.json()["result"]["structuredContent"]["error"] == denied.json()["error"]
    custodian_read = client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(custodian))
    assert custodian_read.status_code == 404
    gap = search(client, owner, "合成未命中").json()["request_id"]
    assert record_gap(client, owner, gap).status_code == 200
    assert client.get("/internal/feedback/gaps", headers=bearer(owner)).json()["items"] == []
    preview = plan(client, owner, target).json()
    assert preview["decision"] == "protected" and "custody_hold" in preview["protections"]
    assert connection.execute("SELECT reason FROM thalion.wiki_availability_event").fetchall() == [("custody_hold",)]
    assert {file.name: file.read_bytes() for file in store.root.iterdir() if file.is_file()} == original_files


def test_hold_release_rechecks_other_restrictions_and_never_revives_old_wiki(transport):
    client, db, (owner, custodian), credentials, _, first, second = transport
    connection, tenant, *_ = db
    configure_wiki(db, 2)
    publish_topic(db, "no-revival", "合成补充限额按原文。", first, second)
    target = version_ref(connection, second)
    admit(credentials, custodian, CAPABILITY)
    assert decide(client, custodian, target).status_code == 200
    before_release = client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner))
    assert before_release.status_code == 404
    released = decide(client, custodian, target, action="release", generation=1)
    assert released.status_code == 200 and released.json()["state"] == "released"
    assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner)).status_code == 200
    assert search(client, owner, "限额").json()["wiki"] == []
    effectivity.stop_synthetic_rule(connection, record(connection, tenant, "stop_rule_use", str(uuid4())),
                                   tenant.space_id, target, "withdrawn", uuid4())
    assert decide(client, custodian, target, generation=2).status_code == 200
    assert decide(client, custodian, target, action="release", generation=3).status_code == 200
    assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner)).status_code == 404


def test_hold_requires_current_independent_custodian_and_generation(transport):
    client, db, (owner, custodian), credentials, _, _, second = transport
    connection, *_ = db
    target = version_ref(connection, second)
    assert decide(client, custodian, target).status_code == 403
    admit(credentials, owner, CAPABILITY)
    assert decide(client, owner, target).status_code == 403
    admit(credentials, custodian, CAPABILITY)
    assert decide(client, custodian, uuid4()).status_code == 403
    assert decide(client, custodian, target, action="release").status_code == 409
    key, basis = str(uuid4()), uuid4()
    first = decide(client, custodian, target, key=key, basis=basis)
    assert first.status_code == 200
    assert decide(client, custodian, target, key=key, basis=basis).json()["decision_id"] == first.json()["decision_id"]
    assert decide(client, custodian, target, key=key, basis=uuid4()).status_code == 409
    assert decide(client, custodian, target, generation=1).status_code == 409
    with ThreadPoolExecutor(max_workers=2) as workers:
        attempts = [workers.submit(decide, client, custodian, target, action="release", generation=1) for _ in range(2)]
        assert sorted(attempt.result(timeout=10).status_code for attempt in attempts) == [200, 409]
    assert connection.execute("SELECT generation FROM thalion.version_hold_decision ORDER BY generation").fetchall() == [(1,), (2,)]


def test_hold_rollback_and_final_delivery_recheck(evidence_transport, transport, monkeypatch):
    service, *_ = evidence_transport
    client, db, (owner, custodian), credentials, _, _, second = transport
    connection, *_ = db
    target = version_ref(connection, second)
    admit(credentials, custodian, CAPABILITY)
    connection.execute("""
        ALTER TABLE thalion.outbox_event ADD CONSTRAINT test_hold_event
        CHECK (event_type <> 'lifecycle.version_hold.established') NOT VALID
    """)
    assert decide(client, custodian, target).status_code == 503
    assert connection.execute("SELECT count(*) FROM thalion.version_hold_decision").fetchone() == (0,)
    assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner)).status_code == 200
    connection.execute("ALTER TABLE thalion.outbox_event DROP CONSTRAINT test_hold_event")
    authority = service.check_source
    changes = []

    def hold_during_check(credential, probe):
        if not changes:
            changes.append(decide(client, custodian, target).status_code)
        return authority(credential, probe)

    monkeypatch.setattr(service, "check_source", hold_during_check)
    denied = client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(owner))
    assert changes == [200] and denied.status_code == 404
    assert connection.execute(
        "SELECT 1 FROM thalion.delivery_record WHERE request_id = %s", (denied.json()["request_id"],),
    ).fetchone() is None


def test_holding_active_replacement_never_falls_back_to_prior_version(transport, corpus):
    client, db, (owner, custodian), credentials, _, first, _ = transport
    connection, tenant, *_ = db
    _, _, _, _, _, prior_approval = corpus
    replacement, part, _ = publish(db, "allowance", "新版合成限额", "# 差旅\n\n新版合成限额。\n".encode(),
                                    source_version_key="hold-version-b", version_label="B")
    approve(connection, tenant, replacement, SWITCH, replaces=prior_approval)
    admit(credentials, custodian, CAPABILITY)
    assert search(client, owner, "限额", day=AFTER, wiki=False).json()["passages"][0]["passage_id"] == str(part.passage_ref)
    assert decide(client, custodian, replacement.version_ref).status_code == 200
    assert search(client, owner, "限额", day=AFTER, wiki=False).json()["status"] == "no_evidence"
    history = search(client, owner, "限额", day=BEFORE, wiki=False).json()
    assert [item["passage_id"] for item in history["passages"]] == [str(first.passage_ref)]


def test_release_removes_only_hold_and_recomputes_current_retention_policy(transport):
    client, db, (owner, custodian), credentials, _, *_ = transport
    _, _, _, source, _ = db
    admitted = ("plan_disposition", "register_retention_policy")
    admit(credentials, owner, *admitted)
    admit(credentials, custodian, CAPABILITY)
    version, _, _ = publish(db, "disposition-contrast", "合成办理对照", b"# Local\n\nNo publication.\n")
    assert retention(client, owner, source).status_code == 200
    prior = plan(client, owner, version.version_ref).json()
    assert prior["decision"] == "review_required"
    assert decide(client, custodian, version.version_ref).status_code == 200
    assert plan(client, owner, version.version_ref).json()["protections"] == ["custody_hold"]
    assert decide(client, custodian, version.version_ref, generation=1, action="release").status_code == 200
    released = plan(client, owner, version.version_ref).json()
    assert released["copies"] == prior["copies"] and released["decision"] == "review_required"
    assert released["inventory_snapshot"] != prior["inventory_snapshot"]
    assert decide(client, custodian, version.version_ref, generation=2).status_code == 200
    assert retention(client, owner, source, expected=1, days=30).status_code == 200
    assert decide(client, custodian, version.version_ref, generation=3, action="release").status_code == 200
    updated = plan(client, owner, version.version_ref).json()
    assert (updated["policy_revision"], updated["decision"], updated["protections"], updated["executable"]) == (
        2, "retention_active", [], False,
    )
