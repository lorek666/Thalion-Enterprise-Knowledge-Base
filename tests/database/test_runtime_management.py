from dataclasses import replace
from datetime import UTC, datetime, timedelta
import pytest

from enterprise_kb.runtime.jobs import claim_job, complete_job, enqueue_job, retry_job
from enterprise_kb.transport import api

from test_employee_portal import browser, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import bearer, evidence_transport, rpc, transport
from test_external_calls import dispatch, expire
from test_identity import space
from test_runtime import LEASE_FOR, register_tenant, runtime_db, spec_for
from test_runtime_backlog_estimate import seed_estimate_history
from test_runtime_report import backlog_states, external_reservation, seed_job
from test_travel_search import corpus


PATH = "/internal/runtime/backlog"
OPERATION = "read_runtime_backlog"


def stage_backlog(db):
    connection, tenant, *_ = db
    enqueue_job(connection, spec_for(tenant))
    lease = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
    retry_job(connection, lease, delay=timedelta(hours=1))
    next_retry, = connection.execute(
        "SELECT available_at FROM thalion.job WHERE job_id = %s", (lease.job_id,),
    ).fetchone()
    waiting, call_id = external_reservation(connection, tenant, "synthetic_model_excerpts")
    assert dispatch(connection, waiting, call_id)
    expire(connection, waiting)
    assert claim_job(connection, tenant.org_id, waiting.spec.stage, tenant.worker_id, LEASE_FOR) is None
    return next_retry, lease.job_id, waiting.job_id


def test_backlog_requires_own_grant_and_only_returns_flat_scoped_metadata(transport):
    client, db, (owner, employee), credentials, live, *_ = transport
    connection, tenant, *_ = db
    next_retry, retry_ref, waiting_ref = stage_backlog(db)
    private_stages = ("private-work-apple", "private-work-peach")
    for stage in private_stages:
        enqueue_job(connection, spec_for(tenant, stage))
    with connection.transaction():
        other_space, other_ref = space(connection, tenant.org_id, tenant.actor_id)
    enqueue_job(connection, spec_for(replace(tenant, space_id=other_space, space_ref=other_ref)))
    enqueue_job(connection, spec_for(register_tenant(connection, "Other backlog tenant")))
    assert client.get(PATH).status_code == 401
    assert client.get(PATH, headers=bearer(owner)).status_code == 403
    credentials[employee] = replace(credentials[employee], operations={OPERATION})
    assert client.get(PATH, headers=bearer(employee)).status_code == 403
    credentials[owner] = replace(credentials[owner], operations={OPERATION})
    assert client.get(PATH, params={"space_id": str(other_ref)}, headers=bearer(owner)).status_code == 400
    live.clear()
    response = client.get(PATH, headers=bearer(owner))
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    result = response.json()
    assert set(result) == {"request_id", "observed_at", "job_backlog_by_stage", "job_throughput_by_stage"}
    assert datetime.fromisoformat(result["observed_at"]).utcoffset() == timedelta(0)
    assert all(row["estimated_clear_minutes"] is None for row in result["job_backlog_by_stage"])
    assert result["job_throughput_by_stage"] == [
        {"stage": "other", "enqueued": 2, "succeeded": 0},
        {"stage": "parse", "enqueued": 3, "succeeded": 2},
        {"stage": "synthetic_model_excerpts", "enqueued": 1, "succeeded": 0},
    ]
    assert backlog_states(result) == [
        {"stage": "other", "unfinished": 2, "states": {"ready": 2}, "next_retry_at": None},
        {"stage": "parse", "unfinished": 1, "states": {"retry_delayed": 1}, "next_retry_at": next_retry.isoformat()},
        {"stage": "synthetic_model_excerpts", "unfinished": 1, "states": {"awaiting_external": 1}, "next_retry_at": None},
    ]
    assert all(text not in response.text for text in (
        str(retry_ref), str(waiting_ref), str(other_ref), *private_stages, "上海住宿",
    ))
    assert rpc(client, owner, "tools/list").json()["result"]["tools"] == []
    assert connection.execute("""
        SELECT ingress, operation, destination, outcome FROM thalion.request_record WHERE request_id = %s
    """, (result["request_id"],)).fetchone() == ("http", OPERATION, "internal_management", "succeeded")
    assert connection.execute("""
        SELECT 1 FROM thalion.delivery_record WHERE request_id = %s
    """, (result["request_id"],)).fetchone() is None


@pytest.mark.parametrize(("change", "status", "outcome"), [
    ("owner", 403, "rejected"), ("credential", 401, "rejected"), ("deadline", 503, "dependency_unavailable"),
])
def test_backlog_checks_current_authority_before_dispatch(evidence_transport, transport, monkeypatch, change, status, outcome):
    service, db, (owner, _), credentials, *_ = evidence_transport
    client = transport[0]
    connection, tenant, *_ = db
    credentials[owner] = replace(credentials[owner], operations={OPERATION})
    stage_backlog(db)
    execute = service.execute_internal

    def change_after_projection(*args, **kwargs):
        reply = execute(*args, **kwargs)
        assert reply.status_code == 200
        if change == "owner":
            connection.execute("UPDATE thalion.space SET owner_principal_id = %s WHERE space_id = %s",
                               (tenant.other_actor_id, tenant.space_id))
        elif change == "credential":
            del credentials[owner]
        else:
            monkeypatch.setattr(api, "release_time", lambda: datetime.now(UTC) + timedelta(minutes=1))
        return reply

    monkeypatch.setattr(service, "execute_internal", change_after_projection)
    response = client.get(PATH, headers=bearer(owner))
    assert response.status_code == status
    assert "job_backlog_by_stage" not in response.json()
    assert "job_throughput_by_stage" not in response.json()
    assert connection.execute("SELECT outcome FROM thalion.request_record WHERE request_id = %s",
                              (response.json()["request_id"],)).fetchone() == (outcome,)


def test_runtime_portal_displays_paused_reasons_and_clears_session(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, _), credentials, *_ = portal
    stage_backlog(db)
    connection, tenant, *_ = db
    older, = connection.execute("SELECT clock_timestamp() - interval '2 hours'").fetchone()
    seed_job(connection, replace(spec_for(tenant, "synthetic_model_excerpts"), configuration_revision=2), older)
    enqueue_job(connection, spec_for(tenant, "completed-only"))
    lease = claim_job(connection, tenant.org_id, "completed-only", tenant.worker_id, LEASE_FOR)
    complete_job(connection, lease, lambda tx: tenant.space_ref)
    credentials[owner] = replace(credentials[owner], operations={OPERATION})
    page.set_viewport_size({"width": 390, "height": 820})
    response = page.goto("/manage/runtime")
    assert response.status == 200 and response.headers["cache-control"] == "no-store"
    assert owner not in response.text() and "等待外部回执" not in response.text()
    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="查看任务积压").click()
    expect(page.get_by_text("等待外部回执", exact=True)).to_be_visible()
    expect(page.get_by_text("延时重试", exact=True)).to_be_visible()
    expect(page.get_by_text("最早计划重试", exact=True)).to_be_visible()
    model = page.get_by_role("listitem").filter(has=page.get_by_role("heading", name="合成模型任务"))
    expect(model.get_by_text("最长已知队龄", exact=True)).to_be_visible()
    expect(model.get_by_text("存在已入队一小时以上的任务，近一小时无成功完成。", exact=True)).to_be_visible()
    other = page.get_by_role("listitem").filter(has=page.get_by_role("heading", name="其他任务"))
    expect(other.get_by_text("近一小时成功完成", exact=True)).to_be_visible()
    expect(other.get_by_text("未完成 0", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "runtime-management-mobile.png")
    page.set_viewport_size({"width": 1280, "height": 850})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "runtime-management-desktop.png")
    page.evaluate("""() => {
        const fetchReal = window.fetch;
        window.fetch = async (url, options) => {
            const response = await fetchReal(url, {...options, signal: undefined});
            await new Promise(resolve => {
                window.releaseBacklog = resolve;
                document.documentElement.dataset.backlogResponse = "held";
            });
            return response;
        };
    }""")
    page.get_by_role("button", name="刷新积压").click()
    expect(page.locator("html")).to_have_attribute("data-backlog-response", "held")
    page.get_by_role("button", name="退出管理").click()
    page.evaluate("async () => { window.releaseBacklog(); await new Promise(requestAnimationFrame); }")
    expect(page.get_by_text("等待外部回执", exact=True)).to_have_count(0)
    expect(page.get_by_text("近一小时成功完成", exact=True)).to_have_count(0)
    expect(page.get_by_text("已退出，凭据与快照已清除。", exact=True)).to_be_visible()
    expect(page.get_by_label("管理测试凭据")).to_have_value("")
    assert page.evaluate("sessionStorage.length + localStorage.length") == 0


def test_runtime_portal_shows_estimate_only_while_observed_conditions_hold(portal):
    from playwright.sync_api import expect

    page, _, db, (owner, _), credentials, *_ = portal
    connection, tenant, *_ = db
    observed, = connection.execute("SELECT statement_timestamp() + interval '1 minute'").fetchone()
    seed_estimate_history(connection, tenant, observed)
    credentials[owner] = replace(credentials[owner], operations={OPERATION})
    page.set_viewport_size({"width": 390, "height": 820})
    page.goto("/manage/runtime")
    page.get_by_label("管理测试凭据").fill(owner)
    page.get_by_role("button", name="查看任务积压").click()
    estimate = page.get_by_text("预计清空：约 20 分钟（按近一小时速率）", exact=True)
    expect(estimate).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "runtime-estimate-mobile.png")
    page.set_viewport_size({"width": 1280, "height": 850})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    screenshot(page, "runtime-estimate-desktop.png")

    lease = claim_job(connection, tenant.org_id, "parse", tenant.worker_id, LEASE_FOR)
    retry_job(connection, lease, delay=timedelta(hours=1))
    page.get_by_role("button", name="刷新积压").click()
    expect(page.get_by_text("延时重试", exact=True)).to_be_visible()
    expect(estimate).to_have_count(0)
    expect(page.get_by_text("预计清空：暂无可靠估计", exact=True)).to_be_visible()
