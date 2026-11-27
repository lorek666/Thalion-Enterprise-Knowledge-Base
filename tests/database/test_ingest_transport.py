from base64 import b64encode
from uuid import UUID, uuid4

import psycopg
from docx_fixture import docx_package
from fastapi.testclient import TestClient

from enterprise_kb.modules.evidence import processing
from enterprise_kb.modules.sources import effectivity, ingest, registry
from enterprise_kb.runtime.jobs import JobSpec, enqueue_job
from enterprise_kb.transport import api
from test_evidence import claim, evidence_db, review
from test_evidence_transport import bearer, evidence_transport, transport
from test_employee_portal import browser, loopback_page
from test_feedback_work import admit
from test_gaps import command_headers
from test_pdf_processing import pdf_document, text_page
from test_runtime import runtime_db
from test_sources import request_for
from test_travel_search import corpus


MARKDOWN = b"# Synthetic travel rules\n\nBook rail tickets in advance.\n"
PDF = pdf_document(text_page(b"Travel allowance 600 CNY"))
DOCX = docx_package()


def upload(client, token, source, files, key=None):
    return client.post(
        f"/internal/sources/{source}/ingest-batches",
        headers=command_headers(token, key),
        json={"files": files},
    )


def file(name, title, version, identifier, content, *, confirm=False):
    return {
        "name": name, "title": title, "version": version, "identifier": identifier,
        "content": b64encode(content).decode(), "confirm_new_version": confirm,
    }


def test_mixed_upload_returns_each_file_status_and_records_the_batch(transport):
    client, db, (owner, _), credentials, *_ = transport
    connection, tenant, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    before = connection.execute("SELECT count(*) FROM thalion.document_version").fetchone()[0]
    jobs = connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone()[0]
    response = upload(client, owner, source, [
        file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN),
        file("travel.pdf", "Travel PDF", "A", "travel-pdf", PDF),
        file("travel.docx", "Travel DOCX", "A", "travel-docx", DOCX),
    ])
    assert response.status_code == 200, response.text
    body = response.json()
    assert [item["status"] for item in body["files"]] == ["registered"] * 3
    assert [item["media_type"] for item in body["files"]] == [
        "text/markdown", "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (before + 3,)
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_batch").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_item").fetchone() == (3,)
    assert connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone() == (jobs + 3,)
    assert connection.execute("""
        SELECT operation, destination, outcome, ingress FROM thalion.request_record
        WHERE request_id IN (%s, %s) ORDER BY operation
    """, (body["request_id"], body["ingestion_request_id"])).fetchall() == [
        ("register_version", "internal_sources", "succeeded", "internal"),
        ("upload_source_batch", "internal_sources", "succeeded", "http"),
    ]


def test_same_batch_key_with_changed_files_is_a_conflict(transport):
    client, db, (owner, _), credentials, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    key = "batch-1"
    before = connection.execute("SELECT count(*) FROM thalion.document_version").fetchone()[0]
    first = upload(client, owner, source, [file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN)], key)
    assert first.status_code == 200
    changed = upload(client, owner, source, [
        file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN + b"Changed.\n"),
    ], key)
    assert changed.status_code == 409 and changed.json()["error"]["code"] == "ingest_conflict"
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (before + 1,)


def test_partial_failure_keeps_successful_files_and_exposes_the_reason(transport):
    client, _, (owner, _), credentials, *_ = transport
    admit(credentials, owner, "upload_source_batch")
    response = upload(client, owner, transport[1][3], [
        file("broken.docx", "Broken", "A", "broken", b"not a docx"),
        file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN),
        file("notes.txt", "Wrong suffix", "A", "wrong-suffix", MARKDOWN),
        file("empty.md", "Empty", "A", "empty", b""),
    ])
    assert response.status_code == 200
    assert [(item["status"], item["reason"]) for item in response.json()["files"]] == [
        ("rejected", "unsupported_media"),
        ("registered", None),
        ("rejected", "unsupported_media"),
        ("rejected", "empty"),
    ]


def test_empty_file_batch_records_rejection_without_a_version(transport):
    client, db, (owner, _), credentials, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    before = connection.execute("SELECT count(*) FROM thalion.document_version").fetchone()
    response = upload(client, owner, source, [file("empty.md", "Empty", "A", "empty", b"")])
    assert response.status_code == 200
    assert response.json()["files"][0]["reason"] == "empty"
    assert connection.execute("SELECT total_bytes FROM thalion.source_ingest_batch").fetchall() == [(0,)]
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == before


def test_upload_requires_the_operation_and_source_ownership(transport):
    client, _, (owner, other), credentials, *_ = transport
    admit(credentials, owner, "upload_source_batch")
    admit(credentials, other, "upload_source_batch")
    source = transport[1][3]
    assert upload(client, owner, source, [file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN)]).status_code == 200
    denied = upload(client, other, source, [file("other.md", "Other", "A", "other", MARKDOWN)])
    assert denied.status_code == 403 and "files" not in denied.json()
    credentials[owner] = credentials[owner].__class__(
        credentials[owner].employee_ref, credentials[owner].space_ref, credentials[owner].client_id,
        credentials[owner].region, credentials[owner].traveler_class, frozenset({"search"}),
        credentials[owner].expires_at,
    )
    assert upload(client, owner, source, [file("travel2.md", "Travel 2", "A", "travel-2", MARKDOWN)]).status_code == 403


def test_upload_rejects_invalid_envelope_and_oversize_content(transport):
    client, _, (owner, _), credentials, *_ = transport
    admit(credentials, owner, "upload_source_batch")
    source = transport[1][3]
    assert client.post(
        f"/internal/sources/{source}/ingest-batches", headers=command_headers(owner), json={"entries": []},
    ).status_code == 400
    too_large = file("big.md", "Big", "A", "big", b"x" * (17 * 1024 * 1024))
    assert upload(client, owner, source, [too_large]).status_code == 413


def test_upload_reports_a_database_dependency_failure_without_partial_success(evidence_transport, monkeypatch):
    service, db, (owner, _), credentials, *_ = evidence_transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")

    def unavailable():
        raise psycopg.OperationalError("synthetic database outage")

    monkeypatch.setattr(service, "connect", unavailable)
    with TestClient(api.create_app(service), base_url="http://127.0.0.1") as client:
        response = upload(client, owner, source, [file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN)])
    assert response.status_code == 503 and response.json()["error"]["code"] == "dependency_unavailable"
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_batch").fetchone() == (0,)


def processing_status(client, token, version, *, query=""):
    return client.get(f"/internal/sources/versions/{version}/processing-status{query}", headers=bearer(token))


def ledger(client, token, source, *, query=""):
    return client.get(f"/internal/sources/{source}/ingest-batches{query}", headers=bearer(token))


def test_ingest_ledger_lists_durable_mixed_outcomes_once_after_replay(transport):
    client, db, (owner, _), credentials, *_ = transport
    connection, tenant, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    files = [
        file("travel.md", "Travel ledger title", "A", "travel-ledger", MARKDOWN),
        file("broken.docx", "Unrecognized format", "A", "broken-ledger", b"not a docx"),
    ]
    first = upload(client, owner, source, files, "mixed-ledger")
    replay = upload(client, owner, source, files, "mixed-ledger")
    assert first.status_code == replay.status_code == 200
    assert first.json()["ingestion_request_id"] != replay.json()["ingestion_request_id"]
    assert ledger(client, owner, source).status_code == 403
    admit(credentials, owner, "list_source_ingest_batches")
    response = ledger(client, owner, source)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store", response.text
    body = response.json()
    assert set(body) == {"request_id", "source_id", "batches", "next_cursor"}
    assert body["source_id"] == str(source) and body["next_cursor"] is None
    batch, = body["batches"]
    persisted_ref, = connection.execute("SELECT batch_ref FROM thalion.source_ingest_batch").fetchone()
    assert batch["batch_id"] == str(persisted_ref)
    assert batch["item_count"] == 2 and batch["completed_at"]
    assert [(item["title"], item["status"], item["reason"]) for item in batch["files"]] == [
        ("Travel ledger title", "registered", None),
        ("Unrecognized format", "rejected", "unsupported_media"),
    ]
    assert batch["files"][0]["version_id"] == first.json()["files"][0]["version_id"]
    assert batch["files"][1]["version_id"] is None
    assert all(set(item) == {
        "position", "title", "status", "media_type", "document_id", "version_id", "reason",
    } for item in batch["files"])
    assert "Book rail tickets" not in response.text
    assert not set(batch) & {"actor_id", "digest", "request_id", "total_bytes", "key_digest"}
    assert connection.execute("""
        SELECT principal_id, scope_space_id, operation, destination, outcome FROM thalion.request_record
        WHERE request_id = %s
    """, (body["request_id"],)).fetchone() == (
        tenant.actor_id, tenant.space_id, "list_source_ingest_batches", "internal_sources", "succeeded",
    )
    version = batch["files"][0]["version_id"]
    assert processing_status(client, owner, version).status_code == 403
    assert client.get(f"/employee/originals/{version}", headers=bearer(owner)).status_code == 403


def test_ingest_ledger_keeps_partial_batch_incomplete_until_replay(transport, monkeypatch):
    client, db, (owner, _), credentials, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch", "list_source_ingest_batches")
    files = [
        file("travel.md", "Partial ledger title", "A", "partial-ledger", MARKDOWN),
        file("second.md", "Resumed ledger title", "A", "resumed-ledger", MARKDOWN),
    ]
    versions_before, = connection.execute("SELECT count(*) FROM thalion.document_version").fetchone()
    jobs_before, = connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone()
    record_item = ingest._record_item

    def interrupt_after_first_item(connection, org_id, space_id, batch_ref, outcome):
        if outcome.position == 1:
            raise psycopg.OperationalError("synthetic ledger persistence interruption")
        record_item(connection, org_id, space_id, batch_ref, outcome)

    with monkeypatch.context() as outage:
        outage.setattr(ingest, "_record_item", interrupt_after_first_item)
        assert upload(client, owner, source, files, "partial-ledger").status_code == 503
    response = ledger(client, owner, source)
    assert response.status_code == 200, response.text
    batch, = response.json()["batches"]
    assert batch["completed_at"] is None and batch["item_count"] == 2
    assert [item["status"] for item in batch["files"]] == ["registered"]
    versions_during, = connection.execute("SELECT count(*) FROM thalion.document_version").fetchone()
    jobs_during, = connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone()
    replay = upload(client, owner, source, files, "partial-ledger")
    assert replay.status_code == 200
    assert [item["status"] for item in replay.json()["files"]] == ["registered", "registered"]
    completed, = ledger(client, owner, source).json()["batches"]
    assert completed["batch_id"] == batch["batch_id"] and completed["completed_at"]
    assert completed["files"][0] == batch["files"][0]
    assert completed["files"][1]["status"] == "registered"
    assert completed["files"][1]["version_id"] == replay.json()["files"][1]["version_id"]
    assert (versions_during, jobs_during) == (versions_before + 1, jobs_before + 1)
    assert connection.execute("SELECT count(*) FROM thalion.document_version").fetchone() == (versions_before + 2,)
    assert connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone() == (jobs_before + 2,)


def test_ingest_ledger_pages_newest_first_within_current_source_and_owner(transport):
    client, db, (owner, other), credentials, *_ = transport
    connection, tenant, _, source, _ = db
    admit(credentials, owner, "upload_source_batch", "list_source_ingest_batches")
    admit(credentials, other, "list_source_ingest_batches")
    second_source = registry.register_synthetic_source(
        connection, request_for(connection, tenant, tenant.actor_id, "ledger-second-source", "register_source_contract"),
        tenant.space_id, registry.SyntheticSource("ledger-second", "ledger-archive", tenant.worker_id),
    )
    empty = ledger(client, owner, source)
    assert empty.status_code == 200, empty.text
    assert empty.json()["batches"] == [] and empty.json()["next_cursor"] is None
    for index in range(21):
        response = upload(client, owner, source, [file("empty.md", f"Batch {index}", "A", "empty-ledger", b"")])
        assert response.status_code == 200, response.text
    assert upload(client, owner, second_source, [
        file("empty.md", "Second source", "A", "empty-ledger", b""),
    ]).status_code == 200
    first = ledger(client, owner, source).json()
    assert [batch["files"][0]["title"] for batch in first["batches"]] == [
        f"Batch {index}" for index in range(20, 0, -1)
    ]
    cursor = first["next_cursor"]
    assert cursor and cursor == first["batches"][-1]["batch_id"]
    assert upload(client, owner, source, [
        file("empty.md", "Inserted later", "A", "empty-ledger", b""),
    ]).status_code == 200
    last = ledger(client, owner, source, query=f"?after={cursor}").json()
    assert [batch["files"][0]["title"] for batch in last["batches"]] == ["Batch 0"]
    assert last["next_cursor"] is None
    assert ledger(client, owner, second_source, query=f"?after={cursor}").status_code == 400
    assert ledger(client, owner, source, query="?limit=1000").status_code == 400
    assert ledger(client, owner, source, query=f"?after={cursor}&after={cursor}").status_code == 400
    assert ledger(client, other, source, query=f"?after={cursor}").status_code == 403
    assert ledger(client, owner, uuid4()).status_code == 403
    connection.execute("UPDATE thalion.space SET owner_principal_id = %s", (tenant.other_actor_id,))
    revoked = ledger(client, owner, source, query=f"?after={cursor}")
    assert revoked.status_code == 403 and "batches" not in revoked.json()


def test_ingest_ledger_page_recovers_history_and_checks_current_processing(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, _), credentials, *_ = transport
    admit(credentials, owner, "upload_source_batch", "list_source_ingest_batches", "read_source_processing_status")
    received = upload(client, owner, db[3], [
        file("travel.md", "Historical travel title", "A", "history-ledger", MARKDOWN),
        file("empty.md", "Historical empty title", "A", "empty-ledger", b""),
    ])
    assert received.status_code == 200
    version = received.json()["files"][0]["version_id"]
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.set_viewport_size({"width": 390, "height": 844})
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        source = page.get_by_label("来源编号")
        source.fill(str(db[3]))
        history = page.get_by_role("region", name="入库台账")
        history.get_by_role("button", name="查询台账").click()
        history.locator("summary").click()
        travel = history.get_by_role("heading", name="1. Historical travel title", exact=True)
        expect(travel).to_be_visible()
        expect(history.get_by_text("Historical empty title", exact=False)).to_be_visible()
        expect(history.get_by_text("文件为空", exact=False)).to_be_visible()
        history.get_by_role("button", name="查看处理状态：Historical travel title").click()
        processing_region = page.get_by_role("region", name="查看版本处理状态")
        expect(processing_region.get_by_label("资料版本编号")).to_have_value(version)
        expect(processing_region.get_by_text("等待解析", exact=True)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth") == 390
        source.fill(str(uuid4()))
        expect(travel).to_have_count(0)
        expect(processing_region.get_by_label("资料版本编号")).to_have_value("")
        expect(processing_region.get_by_text("等待解析", exact=True)).to_have_count(0)


def test_late_ingest_ledger_response_cannot_restore_a_changed_source_or_session(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, other), credentials, *_ = transport
    admit(credentials, owner, "upload_source_batch", "list_source_ingest_batches")
    assert upload(client, owner, db[3], [
        file("empty.md", "Old ledger title", "A", "empty-ledger", b""),
    ]).status_code == 200
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                const response = await realFetch(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestLedger = resolve;
                    document.body.dataset.testLedgerReady = 'true';
                });
                return response;
            };
        }""")
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        source = page.get_by_label("来源编号")
        history = page.get_by_role("region", name="入库台账")
        for change in ("source", "credential"):
            source.fill(str(db[3]))
            history.get_by_role("button", name="查询台账").click()
            expect(page.locator("body")).to_have_attribute("data-test-ledger-ready", "true")
            if change == "source":
                source.fill(str(uuid4()))
            else:
                page.get_by_role("button", name="更换凭据").click()
                page.get_by_label("管理测试凭据").fill(other)
                page.get_by_role("button", name="载入上传凭据").click()
                expect(source).to_have_value("")
            page.evaluate("""async () => {
                delete document.body.dataset.testLedgerReady;
                window.releaseTestLedger();
                await new Promise(requestAnimationFrame);
            }""")
            expect(history.get_by_text("Old ledger title", exact=False)).to_have_count(0)


def test_source_owner_can_read_the_exact_version_processing_status_without_evidence(transport):
    client, db, (owner, reviewer), credentials, *_ = transport
    connection, tenant, _, source, store = db
    admit(credentials, owner, "upload_source_batch")
    response = upload(client, owner, source, [file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN)])
    assert response.status_code == 200
    version = response.json()["files"][0]["version_id"]
    unadmitted = processing_status(client, owner, version)
    assert unadmitted.status_code == 403
    admit(credentials, owner, "read_source_processing_status")

    def check(expected):
        result = processing_status(client, owner, version)
        assert result.status_code == 200 and result.headers["Cache-Control"] == "no-store"
        assert result.json() == {"request_id": result.json()["request_id"], "version_id": version, "state": expected}
        assert connection.execute("""
            SELECT principal_id, scope_space_id, operation, destination, outcome FROM thalion.request_record
            WHERE request_id = %s
        """, (result.json()["request_id"],)).fetchone() == (
            tenant.actor_id, tenant.space_id, "read_source_processing_status", "internal_sources", "succeeded",
        )

    bindings = connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone()
    check("queued")
    lease = claim(db)
    assert str(lease.spec.target_ref) == version
    check("processing")
    run = processing.process_markdown_job(connection, lease, store)
    check("pending_review")
    review(db, run)
    check("quality_approved")
    review(db, run, decision="quarantined")
    check("quarantined")
    connection.execute("""
        INSERT INTO thalion.processing_config_revision
            (configuration_revision, parser_version, profile, locator_revision)
        SELECT 2, parser_version, profile, locator_revision FROM thalion.processing_config_revision
        WHERE configuration_revision = 1
    """)
    enqueue_job(connection, JobSpec(tenant.org_id, tenant.space_id, UUID(version), "parse", lease.spec.input_digest, 2))
    check("queued")
    replacement = processing.process_markdown_job(connection, claim(db), store)
    assert replacement.run_ref != run.run_ref
    check("pending_review")
    stop = request_for(connection, tenant, tenant.other_actor_id, "stop-upload", "stop_rule_use")
    effectivity.stop_synthetic_rule(connection, stop, tenant.space_id, UUID(version), "withdrawn", uuid4())
    check("blocked")
    assert connection.execute("SELECT count(*) FROM thalion.permission_binding").fetchone() == bindings


def test_processing_status_fails_closed_for_nonowners_unknown_versions_and_stopped_sources(transport):
    client, db, (owner, other), credentials, *_ = transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    admit(credentials, owner, "read_source_processing_status")
    admit(credentials, other, "read_source_processing_status")
    response = upload(client, owner, source, [file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN)])
    version = response.json()["files"][0]["version_id"]
    denied = processing_status(client, other, version)
    unknown = processing_status(client, owner, uuid4())
    assert denied.status_code == unknown.status_code == 403
    assert denied.json()["error"] == unknown.json()["error"]
    assert processing_status(client, owner, version, query="?scope=other").status_code == 400
    assert processing_status(client, owner, "not-a-uuid").status_code == 400
    connection.execute("UPDATE thalion.source SET lifecycle = 'suspended'")
    assert processing_status(client, owner, version).status_code == 403


def test_management_upload_page_reports_each_registered_file(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, _), credentials, *_ = evidence_transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        page.get_by_label("来源编号").fill(str(source))
        page.get_by_label("选择文件").set_input_files([{
            "name": "travel.md", "mimeType": "text/markdown", "buffer": MARKDOWN,
        }])
        expect(page.get_by_text("已选择 1 个文件。", exact=True)).to_be_visible()
        page.get_by_label("版本", exact=True).fill("A")
        page.get_by_role("button", name="登记本批文件").click()
        expect(page.get_by_text("已登记，待解析")).to_be_visible()
    assert connection.execute("SELECT count(*) FROM thalion.source_ingest_batch").fetchone() == (1,)


def test_management_upload_page_retries_only_the_replaced_file(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, _), credentials, *_ = evidence_transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    jobs_before = connection.execute("SELECT count(*) FROM thalion.job WHERE stage = 'parse'").fetchone()[0]
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.set_viewport_size({"width": 390, "height": 844})
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        page.get_by_label("来源编号").fill(str(source))
        page.get_by_label("选择文件").set_input_files([
            {"name": "travel.md", "mimeType": "text/markdown", "buffer": MARKDOWN},
            {"name": "broken.docx", "mimeType": "application/octet-stream", "buffer": b"not a docx"},
        ])
        for field in page.get_by_label("版本", exact=True).all():
            field.fill("A")
        path = f"**/internal/sources/{source}/ingest-batches"
        with page.expect_response(path) as uploaded:
            page.get_by_role("button", name="登记本批文件").click()
        original = uploaded.value.json()
        first = original["files"][0]["version_id"]
        expect(page.get_by_text(f"版本 {first}", exact=True)).to_be_visible()
        expect(page.get_by_text("格式不受支持或扩展名与内容不符", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="重试第 1 项")).to_have_count(0)
        replacement = page.get_by_label("第 2 项替换文件")
        expect(replacement).to_be_visible(timeout=2000)
        replacement.set_input_files({
            "name": "fixed.docx",
            "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "buffer": DOCX,
        })
        with page.expect_response(path) as submitted:
            page.get_by_role("button", name="重试第 2 项").click()
        resent = submitted.value.request.post_data_json["files"]
        assert [(item["name"], item["identifier"]) for item in resent] == [("fixed.docx", "broken")]
        retried = submitted.value.json()
        second = retried["files"][0]["version_id"]
        assert first != second
        expect(page.get_by_text(f"版本 {first}", exact=True)).to_be_visible()
        expect(page.get_by_text(f"版本 {second}", exact=True)).to_be_visible()
        expect(page.get_by_text(f"重试回执 {retried['ingestion_request_id']}", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="重试第 2 项")).to_have_count(0)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert connection.execute("""
        SELECT item_count FROM thalion.source_ingest_batch ORDER BY created_at
    """).fetchall() == [(2,), (1,)]
    assert connection.execute(
        "SELECT count(*) FROM thalion.job WHERE stage = 'parse'",
    ).fetchone() == (jobs_before + 2,)


def test_management_upload_page_checks_current_status_of_the_registered_version(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, _), credentials, *_ = evidence_transport
    connection, _, _, source, store = db
    admit(credentials, owner, "upload_source_batch", "read_source_processing_status")
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        page.get_by_label("来源编号").fill(str(source))
        page.get_by_label("选择文件").set_input_files([
            {"name": "travel.md", "mimeType": "text/markdown", "buffer": MARKDOWN},
            {"name": "empty.md", "mimeType": "text/markdown", "buffer": b""},
        ])
        for field in page.get_by_label("版本", exact=True).all():
            field.fill("A")
        page.get_by_role("button", name="登记本批文件").click()
        expect(page.get_by_text("已登记，待解析")).to_be_visible()
        expect(page.get_by_role("button", name="查看处理状态：第 2 项")).to_have_count(0)
        page.get_by_role("button", name="查看处理状态：第 1 项").click()
        status = page.get_by_role("region", name="查看版本处理状态")
        expect(status.get_by_text("等待解析", exact=True)).to_be_visible()
        lease = claim(db)
        expect(status.get_by_label("资料版本编号")).to_have_value(str(lease.spec.target_ref))
        check = status.get_by_role("button", name="查询处理状态")
        run = processing.process_markdown_job(connection, lease, store)
        check.click()
        expect(status.get_by_text("待质量审核", exact=True)).to_be_visible()
        review(db, run)
        check.click()
        expect(status.get_by_text("质量已批准", exact=True)).to_be_visible()
        assert "Book rail tickets" not in status.inner_text()
        connection.execute("UPDATE thalion.source SET lifecycle = 'suspended'")
        check.click()
        expect(status.get_by_text("该版本的处理状态不可查看。", exact=True)).to_be_visible()
        expect(status.get_by_text("质量已批准", exact=True)).to_have_count(0)


def test_late_processing_status_does_not_reappear_after_credential_change(browser, evidence_transport, transport):
    from playwright.sync_api import expect

    service, *_ = evidence_transport
    client, db, (owner, other), credentials, *_ = transport
    admit(credentials, owner, "upload_source_batch", "read_source_processing_status")
    uploaded = upload(client, owner, db[3], [file("travel.md", "Travel rules", "A", "travel-rules", MARKDOWN)])
    version = uploaded.json()["files"][0]["version_id"]
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                const response = await realFetch(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestStatus = resolve;
                    document.body.dataset.testStatusReady = 'true';
                });
                return response;
            };
        }""")
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        page.get_by_label("资料版本编号").fill(version)
        page.get_by_role("button", name="查询处理状态").click()
        expect(page.locator("body")).to_have_attribute("data-test-status-ready", "true")
        page.get_by_role("button", name="更换凭据").click()
        page.get_by_label("管理测试凭据").fill(other)
        page.get_by_role("button", name="载入上传凭据").click()
        page.evaluate("async () => { window.releaseTestStatus(); await new Promise(requestAnimationFrame); }")
        expect(page.get_by_label("资料版本编号")).to_have_value("")
        expect(page.locator("#ingest-processing-message")).to_be_empty()


def test_late_upload_response_cannot_repopulate_a_new_session(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, other), credentials, *_ = evidence_transport
    _, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.evaluate("""() => {
            const realFetch = window.fetch;
            window.fetch = async (url, options) => {
                const response = await realFetch(url, {...options, signal: undefined});
                await new Promise(resolve => {
                    window.releaseTestUpload = resolve;
                    document.body.dataset.testUploadReady = "true";
                });
                return response;
            };
        }""")
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        page.get_by_label("来源编号").fill(str(source))
        page.get_by_label("选择文件").set_input_files([{
            "name": "travel.md", "mimeType": "text/markdown", "buffer": MARKDOWN,
        }])
        page.get_by_label("版本", exact=True).fill("A")
        submit = page.get_by_role("button", name="登记本批文件")
        submit.click()
        expect(page.locator("body")).to_have_attribute("data-test-upload-ready", "true")
        page.locator("#ingest-logout").click()
        page.get_by_label("管理测试凭据").fill(other)
        page.get_by_role("button", name="载入上传凭据").click()
        page.evaluate("async () => { window.releaseTestUpload(); await new Promise(requestAnimationFrame); }")
        expect(page.get_by_text("已登记，待解析")).to_have_count(0)
        expect(submit).to_be_disabled()
        assert page.get_by_label("管理测试凭据").input_value() == ""


def test_management_upload_page_confirms_a_changed_version(browser, evidence_transport):
    from playwright.sync_api import expect

    service, db, (owner, _), credentials, *_ = evidence_transport
    connection, _, _, source, _ = db
    admit(credentials, owner, "upload_source_batch")
    with loopback_page(browser, service, "/manage/ingest") as (page, _, _):
        page.get_by_label("管理测试凭据").fill(owner)
        page.get_by_role("button", name="载入上传凭据").click()
        page.get_by_label("来源编号").fill(str(source))
        page.get_by_label("选择文件").set_input_files([{
            "name": "travel.md", "mimeType": "text/markdown", "buffer": MARKDOWN,
        }])
        page.get_by_label("版本", exact=True).fill("A")
        page.get_by_role("button", name="登记本批文件").click()
        expect(page.get_by_text("已登记，待解析")).to_be_visible()
        page.get_by_label("选择文件").set_input_files([
            {"name": "guide.md", "mimeType": "text/markdown", "buffer": MARKDOWN},
            {"name": "travel.md", "mimeType": "text/markdown", "buffer": MARKDOWN + b"Changed.\n"},
        ])
        for field in page.get_by_label("版本", exact=True).all():
            field.fill("A")
        path = f"**/internal/sources/{source}/ingest-batches"
        with page.expect_response(path) as uploaded:
            page.get_by_role("button", name="登记本批文件").click()
        guide = uploaded.value.json()["files"][0]["version_id"]
        expect(page.get_by_text("需确认新版本")).to_be_visible()
        retry = page.get_by_role("form", name="第 2 项单独重试")
        expect(retry).to_be_visible(timeout=2000)
        retry.get_by_label("第 2 项替换文件").set_input_files({
            "name": "revised-travel.md", "mimeType": "text/markdown", "buffer": MARKDOWN + b"Revised.\n",
        })
        version = retry.get_by_label("版本", exact=True)
        with page.expect_response(path) as still_pending:
            version.press("Enter")
        assert still_pending.value.json()["files"][0]["status"] == "needs_confirmation"
        expect(retry.get_by_text("重试文件：revised-travel.md", exact=True)).to_be_visible()
        retry.get_by_role("checkbox", name="内容有变，确认按新版本登记").check()
        version.fill("B")
        with page.expect_response(path) as retried:
            version.press("Enter")
        files = retried.value.request.post_data_json["files"]
        assert [(item["name"], item["version"]) for item in files] == [("revised-travel.md", "B")]
        revised = retried.value.json()["files"][0]["version_id"]
        expect(page.get_by_text(f"版本 {revised}", exact=True)).to_be_visible()
        expect(page.get_by_text(f"版本 {guide}", exact=True)).to_be_visible()
    assert connection.execute("""
        SELECT version.version_label FROM thalion.document_version AS version
        JOIN thalion.document AS document USING (org_id, space_id, source_id, document_id)
        WHERE document.source_object_key = 'travel'
        ORDER BY version.registration_sequence
    """).fetchall() == [("A",), ("B",)]
