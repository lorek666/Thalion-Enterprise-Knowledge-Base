from datetime import UTC, datetime, timedelta
from uuid import uuid4

from enterprise_kb.modules.access import policy

from test_employee_portal import browser, loopback_page
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_feedback_work import admit
from test_gaps import command_headers
from test_persisted_access import binding, set_rules
from test_runtime import runtime_db
from test_travel_search import corpus


def policy_path(source):
    return f"/internal/sources/{source}/access-policy"


def replace_policy(client, owner, source, body, key=None):
    return client.post(policy_path(source), headers=command_headers(owner, key), json=body)


def test_owner_records_reader_rules_in_the_same_policy_used_at_delivery(transport):
    client, db, (owner, reader), credentials, live, first, second = transport
    connection, tenant, _, source, _ = db
    assert client.get(policy_path(source), headers=bearer(owner)).status_code == 403
    admit(credentials, owner, "read_local_policy", "replace_local_policy")
    snapshot = client.get(policy_path(source), headers=bearer(owner))
    assert snapshot.status_code == 200 and snapshot.headers["Cache-Control"] == "no-store"
    body = snapshot.json()
    assert set(body) == {"request_id", "safety_epoch", "policy_revision", "rules"}
    assert (body["safety_epoch"], body["policy_revision"]) == (2, 2)
    assert {rule["subject_id"] for rule in body["rules"]} == {
        str(credentials[owner].employee_ref), str(credentials[reader].employee_ref),
    }
    rule = next(rule for rule in body["rules"] if rule["subject_id"] == str(credentials[reader].employee_ref))
    assert rule["passage_id"] == str(first.passage_ref)
    command = {"expected_epoch": body["safety_epoch"], "basis_id": str(uuid4()), "rules": [rule]}
    key = str(uuid4())
    changed = replace_policy(client, owner, source, command, key)
    assert changed.status_code == 200 and changed.headers["Cache-Control"] == "no-store"
    assert changed.json() == {"request_id": changed.json()["request_id"], "policy_revision": 3}
    assert replace_policy(client, owner, source, command, key).json()["policy_revision"] == 3
    assert replace_policy(client, owner, source, command, str(uuid4())).status_code == 409
    conflicting = replace_policy(client, owner, source, command | {"rules": []}, key)
    assert conflicting.status_code == 409 and conflicting.json()["error"]["code"] == "local_policy_conflict"
    current = client.get(policy_path(source), headers=bearer(owner)).json()
    assert (current["safety_epoch"], current["policy_revision"], current["rules"]) == (3, 3, [rule])
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(owner)).status_code == 404
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(reader)).status_code == 200
    assert client.get(f"/v1/passages/{second.passage_ref}", headers=bearer(reader)).status_code == 404
    results = rpc(client, reader, "tools/call", name="read_passage", arguments={"id": str(first.passage_ref)}).json()
    assert not results["result"]["isError"]
    live.remove(tenant.other_actor_id)
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(reader)).status_code == 404
    live.add(tenant.other_actor_id)
    revoked = replace_policy(client, owner, source, command | {"expected_epoch": 3, "rules": []})
    assert revoked.status_code == 200 and revoked.json()["policy_revision"] == 4
    assert replace_policy(client, owner, source, command, key).json()["policy_revision"] == 3
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(reader)).status_code == 404
    assert connection.execute("SELECT local_policy_revision FROM thalion.source").fetchone() == (4,)
    assert connection.execute("""
        SELECT operation, destination, scope_space_id, outcome FROM thalion.request_record WHERE request_id = %s
    """, (changed.json()["request_id"],)).fetchone() == (
        "replace_local_policy", "internal_access", tenant.space_id, "succeeded",
    )


def test_policy_endpoint_does_not_allow_external_destinations_or_unknown_subjects(transport):
    client, db, (owner, other), credentials, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "read_local_policy", "replace_local_policy")
    admit(credentials, other, "read_local_policy", "replace_local_policy")
    body = client.get(policy_path(source), headers=bearer(owner)).json()
    rule = body["rules"][0]
    command = {"expected_epoch": body["safety_epoch"], "basis_id": str(uuid4()), "rules": [rule]}
    denied = client.get(policy_path(source), headers=bearer(other))
    unknown = client.get(policy_path(uuid4()), headers=bearer(owner))
    assert denied.status_code == unknown.status_code == 403
    assert denied.json()["error"] == unknown.json()["error"]
    assert replace_policy(client, other, source, command).status_code == 403
    assert replace_policy(client, owner, source, command | {"rules": [rule | {"subject_id": str(uuid4())}]}).status_code == 403
    assert replace_policy(client, owner, source, command | {
        "rules": [rule | {"purpose": "model_answer", "destination": "remote_gateway"}],
    }).status_code == 400
    assert replace_policy(client, owner, source, command | {
        "rules": [rule | {"valid_from": "2026-11-23T00:00:00"}],
    }).status_code == 400
    assert replace_policy(client, owner, source, command | {"expected_epoch": True}).status_code == 400
    assert connection.execute("SELECT safety_epoch, local_policy_revision FROM thalion.source").fetchone() == (2, 2)
    assert connection.execute("SELECT count(*) FROM thalion.policy_revision").fetchone() == (1,)


def test_full_local_policy_can_be_read_and_replaced_without_truncation(transport):
    client, db, (owner, _), credentials, *_ = transport
    _, _, _, source, _ = db
    admit(credentials, owner, "read_local_policy", "replace_local_policy")
    body = client.get(policy_path(source), headers=bearer(owner)).json()
    rule = body["rules"][0]
    starts = datetime.fromisoformat(rule["valid_from"])
    rules = [rule | {"valid_from": (starts + timedelta(seconds=index)).isoformat()} for index in range(500)]
    command = {"expected_epoch": body["safety_epoch"], "basis_id": str(uuid4()), "rules": rules}
    changed = replace_policy(client, owner, source, command)
    assert changed.status_code == 200
    current = client.get(policy_path(source), headers=bearer(owner)).json()
    assert current["rules"] == rules
    assert replace_policy(client, owner, source, command | {"rules": rules + [rule]}).status_code == 400
    headers = command_headers(owner) | {"Content-Type": "application/json"}
    oversized = client.post(policy_path(source), headers=headers, content=b" " * (512 * 1024 + 1))
    assert oversized.status_code == 413


def load_policy_page(page, token, source):
    page.get_by_label("管理测试凭据").fill(token)
    page.get_by_role("button", name="载入管理凭据").click()
    page.get_by_label("来源编号").fill(str(source))
    page.get_by_role("button", name="读取当前规则").click()


def test_policy_management_edits_reader_rules_without_changing_workspace_policy(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, reader), credentials, _, first, _ = transport
    _, tenant, _, source, _ = db
    operation, purpose, destination = policy.WIKI_INPUT_ACCESS
    workspace = policy.LocalRule(
        tenant.actor_id, operation, "allow", purpose, destination, frozenset({"excerpt"}),
        datetime.now(UTC) - timedelta(days=1), passage_ref=first.passage_ref,
    )
    set_rules(db, binding(tenant.actor_id, passage_ref=first.passage_ref), workspace, expected=2)
    admit(credentials, owner, "read_local_policy", "replace_local_policy")
    before = client.get(policy_path(source), headers=bearer(owner)).json()["rules"]
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_role("link", name="读者规则").click()
        expect(page).to_have_url("/manage/readers")
        load_policy_page(page, owner, source)
        expect(page.get_by_text("保留 1 条本地工作区规则。", exact=True)).to_be_visible()
        page.get_by_role("button", name="新增读者规则").click()
        rule = page.get_by_role("group", name="读者规则 2")
        rule.get_by_label("主体编号").fill(str(credentials[reader].employee_ref))
        rule.get_by_label("片段编号").fill(str(first.passage_ref))
        rule.get_by_label("有效起始").fill("2026-11-01T00:00:00+08:00")
        for field in ("摘录", "引用", "标题", "定位", "版本"):
            rule.get_by_label(field, exact=True).check()
        page.get_by_label("变更依据编号").fill(str(uuid4()))
        save = page.get_by_role("button", name="保存来源规则")
        expect(save).to_be_disabled()
        page.get_by_label("确认替换该来源的全部读者规则").check()
        save.click()
        expect(page.get_by_text("已登记规则修订 4。", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="保存来源规则")).to_be_hidden()
    current = client.get(policy_path(source), headers=bearer(owner)).json()["rules"]
    assert [rule for rule in before if rule["operation"] != "read_passage"] == [
        rule for rule in current if rule["operation"] != "read_passage"
    ]
    assert client.get(f"/v1/passages/{first.passage_ref}", headers=bearer(reader)).status_code == 200


def test_policy_management_drops_a_late_snapshot_after_credential_change(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, other), credentials, *_ = evidence_transport
    admit(credentials, owner, "read_local_policy")
    with loopback_page(browser, service, "/manage/readers") as (page, _, response):
        assert response.status == 200 and response.headers["cache-control"] == "no-store"
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                window.fetch = realFetch;
                const response = await realFetch(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestSnapshot = resolve;
                    document.body.dataset.testSnapshotReady = 'true';
                });
                return response;
            };
        }""")
        load_policy_page(page, owner, db[3])
        expect(page.locator("body")).to_have_attribute("data-test-snapshot-ready", "true")
        page.get_by_role("button", name="更换凭据").click()
        load_policy_page(page, other, db[3])
        expect(page.get_by_text("当前凭据不能管理该来源的规则。", exact=True)).to_be_visible()
        page.evaluate("async () => { window.releaseTestSnapshot(); await new Promise(requestAnimationFrame); }")
        expect(page.get_by_role("group", name="读者规则 1")).to_have_count(0)
        expect(page.get_by_role("button", name="保存来源规则")).to_be_hidden()


def test_policy_management_does_not_overwrite_a_concurrent_change(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, _), credentials, *_ = evidence_transport
    connection, tenant, _, source, _ = db
    admit(credentials, owner, "read_local_policy", "replace_local_policy")
    with loopback_page(browser, service, "/manage/readers") as (page, _, _):
        load_policy_page(page, owner, source)
        expect(page.get_by_text("当前规则修订 2。", exact=True)).to_be_visible()
        set_rules(db, binding(tenant.actor_id, effect="deny"), expected=2)
        page.get_by_label("变更依据编号").fill(str(uuid4()))
        page.get_by_label("确认替换该来源的全部读者规则").check()
        save = page.get_by_role("button", name="保存来源规则")
        save.click()
        expect(page.get_by_text("规则已变化或提交冲突，请读取当前规则后重新核对。", exact=True)).to_be_visible()
        expect(save).to_be_hidden()
        page.get_by_role("button", name="读取当前规则").click()
        expect(page.get_by_text("当前规则修订 3。", exact=True)).to_be_visible()
        expect(page.get_by_label("规则结果")).to_have_value("deny")
        expect(save).to_be_disabled()
    assert connection.execute("SELECT count(*) FROM thalion.policy_revision").fetchone() == (2,)
