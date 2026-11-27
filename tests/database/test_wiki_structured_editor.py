from dataclasses import replace

import pytest

from test_employee_portal import browser, portal, screenshot
from test_evidence import evidence_db
from test_evidence_transport import evidence_transport, transport
from test_runtime import runtime_db
from test_travel_search import BEFORE, corpus
from test_wiki_workflow_transport import AUTHOR_OPS, REVIEWER_OPS, _principal_ref, _setup_wiki_rules


@pytest.fixture
def wiki_editor(portal):
    page, _, db, (owner, reviewer), credentials, _, first, _ = portal
    connection, tenant, *_ = db
    _setup_wiki_rules(db)
    credentials[owner] = replace(credentials[owner], operations=AUTHOR_OPS)
    credentials[reviewer] = replace(credentials[reviewer], operations=REVIEWER_OPS)
    page.goto("/manage/wiki")
    sign_in(page, owner)
    return page, reviewer, _principal_ref(connection, tenant.other_actor_id), first


def sign_in(page, token):
    page.get_by_label("管理测试凭据").fill(token)
    page.get_by_role("button", name="查看发布台账").click()


def add_block(page, kind, fields):
    page.get_by_label("内容块类型").select_option(kind)
    page.get_by_role("button", name="添加内容块").click()
    for label, value in fields.items():
        page.get_by_label(label, exact=True).fill(value)
    page.get_by_role("button", name="应用到正文").click()


def test_structured_wiki_flows_through_candidate_preview_citation_and_review(wiki_editor):
    from playwright.sync_api import expect

    page, reviewer, reviewer_ref, first = wiki_editor
    direct = f"{first.passage_ref}:{first.revision}"
    page.get_by_label("办理业务日期").fill(BEFORE.isoformat())
    page.get_by_label("直接依据列表").fill(direct)
    page.get_by_role("button", name="组装并封存输入清单").click()
    expect(page.locator("#wiki-inputs-status")).to_contain_text("已封存输入清单")
    page.get_by_label("主题键").fill("wiki-structured-travel")
    page.get_by_label("草稿标题").fill("差旅结构化总结")
    page.get_by_label("独立审核人标识").fill(reviewer_ref)
    page.get_by_label("正文引用依据").fill(direct)
    page.get_by_label("可核对陈述").fill("上海住宿限额以原文核对为准。")

    page.get_by_role("button", name="结构化编辑", exact=True).click()
    add_block(page, "heading", {"标题文字": "住宿标准"})
    add_block(page, "list", {"列表项（每行一项）": "核对城市\n核对生效日期"})
    add_block(page, "table", {"第 1 列表头": "城市", "第 2 列表头": "备注", "第 1 行第 1 列": "上海", "第 1 行第 2 列": "以上限 | 为准"})
    add_block(page, "quote", {"引用文字": "以原文为准。"})
    add_block(page, "code", {"代码语言（选填）": "text", "代码内容": "city=SH\n```"})
    add_block(page, "link", {"链接文字": "参考页", "链接地址": "https://example.com/policy"})
    page.get_by_role("button", name="Markdown 源码", exact=True).click()
    markdown = page.get_by_label("Markdown 正文").input_value()
    assert markdown == (
        "## 住宿标准\n\n- 核对城市\n- 核对生效日期\n\n"
        "| 城市 | 备注 |\n| --- | --- |\n| 上海 | 以上限 \\| 为准 |\n\n"
        "> 以原文为准。\n\n````text\ncity=SH\n```\n````\n\n"
        "[参考页](<https://example.com/policy>)"
    )
    page.get_by_role("button", name="结构化编辑", exact=True).click()
    screenshot(page, "management-wiki-structured-editor.png")
    with page.expect_request(lambda req: req.url.endswith("/internal/wiki/revisions") and req.method == "POST") as candidate:
        page.get_by_role("button", name="提交候选草稿").click()
    assert candidate.value.post_data_json["markdown"] == markdown
    assert candidate.value.post_data_json["citations"] == [[str(first.passage_ref), first.revision]]
    expect(page.locator("#wiki-candidate-status")).to_contain_text("已提交候选修订")

    page.get_by_role("button", name="退出管理").click()
    assert page.get_by_label("Markdown 正文").input_value() == ""
    expect(page.locator("#wiki-draft-blocks li")).to_have_count(0)
    page.set_viewport_size({"width": 390, "height": 844})
    sign_in(page, reviewer)
    expect(page.get_by_role("button", name="结构化编辑", exact=True)).to_be_hidden()
    with page.expect_response(lambda resp: resp.url.endswith("/preview")) as loaded:
        page.get_by_role("button", name="载入预览").click()
    preview_material = loaded.value.json()
    preview = page.locator("#wiki-preview-markdown")
    expect(preview.get_by_role("heading", name="住宿标准")).to_be_visible()
    expect(preview.locator("ul li")).to_have_text(["核对城市", "核对生效日期"])
    expect(preview.get_by_role("cell", name="以上限 | 为准")).to_be_visible()
    expect(preview.locator("blockquote")).to_have_text("以原文为准。")
    expect(preview.locator("pre code")).to_have_text("city=SH\n```", use_inner_text=True)
    expect(preview.get_by_role("link", name="参考页")).to_have_attribute("href", "https://example.com/policy")
    page.get_by_text("查看 Markdown 源码", exact=True).click()
    assert page.locator("#wiki-preview-source").text_content() == markdown
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    with page.expect_request(f"**/v1/passages/{first.passage_ref}"):
        page.get_by_role("button", name="核对原文").click()
    expect(page.locator("#wiki-citation-text")).to_contain_text("上海住宿限额")
    with page.expect_request("**/review") as decision:
        page.get_by_role("button", name="批准该修订").click()
    for key in ("content_digest", "input_digest", "review_material_id"):
        assert decision.value.post_data_json[key] == preview_material[key]
    expect(page.locator("#wiki-review-status")).to_contain_text("已记录审核决定：approved")
    page.get_by_role("button", name="发布已批修订").click()
    expect(page.locator("#wiki-review-status")).to_contain_text("已发布主题修订")


def test_markdown_round_trip_preserves_existing_source_and_previews_inert_text(wiki_editor):
    from playwright.sync_api import expect

    page, *_ = wiki_editor
    page.set_viewport_size({"width": 390, "height": 844})
    source = (
        "\n# 标题\n\n3. 第一项\n4. 第二项\n\n"
        "| 城市 | 备注 |\n| :--- | ---: |\n| 上海 | 原说明 |\n\n"
        '<img alt="仅文字" src="/wiki-example.png">\n\n'
        "[不打开](javascript:void%280%29) 和 [相对路径](/policy) 与 `例子`\n\n"
        "[定义式链接][ref]\n\n[ref]: https://example.com '原始格式'\n"
    )
    raw = page.get_by_label("Markdown 正文")
    raw.fill(source)
    page.get_by_role("button", name="结构化编辑", exact=True).click()
    blocks = page.locator("#wiki-draft-blocks")
    expect(blocks.get_by_role("heading", name="标题")).to_be_visible()
    expect(blocks.locator("ol")).to_have_attribute("start", "3")
    expect(blocks.locator("img")).to_have_count(0)
    expect(blocks.get_by_text('<img alt="仅文字" src="/wiki-example.png">', exact=True)).to_be_visible()
    expect(blocks.get_by_role("link", name="不打开")).to_have_count(0)
    expect(blocks.get_by_role("link", name="相对路径")).to_have_attribute("href", "/policy")
    expect(blocks.get_by_text("例子", exact=True)).to_be_visible()
    page.get_by_role("button", name="Markdown 源码", exact=True).click()
    assert raw.input_value() == source

    page.get_by_role("button", name="结构化编辑", exact=True).click()
    table = blocks.locator(":scope > li").nth(2)
    table.get_by_role("button", name="编辑此块").click()
    page.get_by_label("第 1 行第 2 列", exact=True).fill("  核对后  ")
    expect(page.get_by_role("button", name="提交候选草稿")).to_be_disabled()
    page.get_by_role("button", name="应用到正文").click()
    expect(blocks.get_by_role("cell", name="核对后")).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.get_by_role("button", name="Markdown 源码", exact=True).click()
    assert raw.input_value() == source.replace("原说明", "核对后")
