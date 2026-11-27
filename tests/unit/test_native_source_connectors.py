from base64 import b64decode
from hashlib import sha256
import json
from uuid import uuid4

import httpx2
import pytest

from enterprise_kb.ports import source_connectors
from enterprise_kb.ports.contracts import ConnectorPortUnavailable
from enterprise_kb.runtime.config import AuthenticatedEndpointConfig


def test_feishu_wiki_uses_tenant_token_and_reads_docx_pages():
    requests = []
    payload = "差旅制度：住宿标准为每晚 500 元。"

    def respond(request):
        requests.append(request)
        if request.url.path.endswith("/tenant_access_token/internal"):
            assert request.method == "POST"
            assert json.loads(request.content) == {"app_id": "cli_test", "app_secret": "app-secret"}
            return httpx2.Response(200, json={"code": 0, "tenant_access_token": "tenant-token", "expire": 7200})
        if request.url.path.endswith("/wiki/v2/spaces/space-1/nodes"):
            assert request.headers["Authorization"] == "Bearer tenant-token"
            return httpx2.Response(200, json={
                "code": 0,
                "data": {
                    "items": [{"node_token": "wikcn123", "obj_token": "doxcn123", "obj_type": "docx", "title": "差旅制度"}],
                    "has_more": False,
                    "page_token": "",
                },
            })
        if request.url.path.endswith("/docx/v1/documents/doxcn123/raw_content"):
            return httpx2.Response(200, json={"code": 0, "data": {"content": payload}})
        raise AssertionError(request.url)

    connector = source_connectors.FeishuWikiConnector(
        AuthenticatedEndpointConfig("https://open.feishu.cn", "vault:feishu/app-secret"),
        app_id="cli_test",
        space_id="space-1",
        transport=httpx2.MockTransport(respond),
        secret_resolver=lambda _: "app-secret",
    )
    page = connector.fetch_delta_page(uuid4(), None)
    item = page.items[0]
    assert page.through_cursor and not page.has_more
    assert item["object_key"] == "feishu:wikcn123"
    assert item["display_name"] == "差旅制度"
    assert b64decode(item["content_base64"]).decode() == payload
    assert item["content_sha256"] == sha256(payload.encode()).hexdigest()
    assert sum(request.url.path.endswith("/tenant_access_token/internal") for request in requests) == 1


def test_feishu_rejects_unsupported_wiki_objects_without_advancing():
    def respond(request):
        if request.url.path.endswith("/tenant_access_token/internal"):
            return httpx2.Response(200, json={"code": 0, "tenant_access_token": "tenant-token", "expire": 7200})
        return httpx2.Response(200, json={
            "code": 0,
            "data": {"items": [{"node_token": "bitable", "obj_token": "bitable", "obj_type": "bitable", "title": "表格"}], "has_more": False},
        })

    connector = source_connectors.FeishuWikiConnector(
        AuthenticatedEndpointConfig("https://open.feishu.cn", "vault:feishu/app-secret"),
        app_id="cli_test",
        space_id="space-1",
        transport=httpx2.MockTransport(respond),
        secret_resolver=lambda _: "app-secret",
    )
    with pytest.raises(ConnectorPortUnavailable):
        connector.fetch_delta_page(uuid4(), None)


def test_feishu_resumes_nested_pages_and_starts_a_new_sweep():
    source_ref = uuid4()
    pages = {
        (None, None): ([('travel', True)], 'root-next'),
        ('travel', None): ([('hotels', True)], 'travel-next'),
        ('hotels', None): ([('limits', False)], None),
        ('travel', 'travel-next'): ([('flights', False)], None),
        (None, 'root-next'): ([('expenses', False)], None),
    }

    def respond(request):
        if request.url.path.endswith('/tenant_access_token/internal'):
            return httpx2.Response(200, json={"code": 0, "tenant_access_token": "tenant-token", "expire": 7200})
        if request.url.path.endswith('/nodes'):
            rows, next_token = pages[(request.url.params.get('parent_node_token'), request.url.params.get('page_token'))]
            return httpx2.Response(200, json={
                "code": 0, "data": {"items": [
                    {"node_token": name, "obj_token": name, "obj_type": "docx", "title": name, "has_child": children}
                    for name, children in rows
                ], "has_more": next_token is not None, "page_token": next_token},
            })
        if request.url.path.endswith('/raw_content'):
            return httpx2.Response(200, json={"code": 0, "data": {"content": request.url.path}})
        raise AssertionError(request.url)

    def connector():
        return source_connectors.FeishuWikiConnector(
            AuthenticatedEndpointConfig("https://open.feishu.cn", "vault:feishu/app-secret"),
            app_id="cli_test", space_id="space-1", transport=httpx2.MockTransport(respond),
            secret_resolver=lambda _: "app-secret",
        )

    cursor = None
    expected = ["travel", "hotels", "limits", "flights", "expenses"]
    checkpoints = set()
    for index, name in enumerate(expected):
        page = connector().fetch_delta_page(source_ref, cursor)
        assert [item["object_key"] for item in page.items] == [f"feishu:{name}"]
        assert page.has_more == (index < len(expected) - 1)
        assert page.previous_cursor == cursor and page.through_cursor not in checkpoints
        cursor = page.through_cursor
        checkpoints.add(cursor)

    inventory = connector().fetch_full_inventory(source_ref)
    assert inventory.complete and inventory.stable_object_keys == {f"feishu:{name}" for name in expected}
    next_sweep = connector().fetch_delta_page(source_ref, cursor)
    assert next_sweep.through_cursor not in checkpoints
    assert [item["object_key"] for item in next_sweep.items] == ["feishu:travel"]


def test_feishu_skips_directory_nodes_but_continues_into_their_children():
    source_ref = uuid4()
    calls = []

    def respond(request):
        if request.url.path.endswith('/tenant_access_token/internal'):
            return httpx2.Response(200, json={"code": 0, "tenant_access_token": "tenant-token", "expire": 7200})
        if request.url.path.endswith('/nodes'):
            parent = request.url.params.get("parent_node_token")
            calls.append(parent)
            if parent is None:
                rows = [{"node_token": "folder", "obj_token": "", "obj_type": "folder", "title": "制度目录", "has_child": True}]
            else:
                rows = [{"node_token": "leaf", "obj_token": "doxcn123", "obj_type": "docx", "title": "住宿制度", "has_child": False}]
            return httpx2.Response(200, json={"code": 0, "data": {"items": rows, "has_more": False, "page_token": ""}})
        if request.url.path.endswith('/raw_content'):
            return httpx2.Response(200, json={"code": 0, "data": {"content": "酒店标准"}})
        raise AssertionError(request.url)

    connector = source_connectors.FeishuWikiConnector(
        AuthenticatedEndpointConfig("https://open.feishu.cn", "vault:feishu/app-secret"),
        app_id="cli_test", space_id="space-1", transport=httpx2.MockTransport(respond),
        secret_resolver=lambda _: "app-secret",
    )
    page = connector.fetch_delta_page(source_ref, None)
    assert page.items == () and page.has_more
    page = connector.fetch_delta_page(source_ref, page.through_cursor)
    assert [item["object_key"] for item in page.items] == ["feishu:leaf"]
    assert calls == [None, "folder"]


def test_sharepoint_graph_reads_delta_content_and_inventory():
    source_ref = uuid4()
    content = b"Travel policy\nHotel limit: 500"
    requests = []

    def respond(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer graph-token"
        if request.url.path.endswith("/drives/drive-1/root/delta"):
            assert request.url.params["$top"] == "5"
            return httpx2.Response(200, json={
                "value": [{
                    "id": "item-1", "name": "travel.md", "eTag": "etag-1",
                    "file": {"mimeType": "text/markdown"},
                }],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/drive-1/root/delta?$deltatoken=next",
            })
        if request.url.path.endswith("/drives/drive-1/items/item-1/content"):
            return httpx2.Response(200, content=content)
        raise AssertionError(request.url)

    connector = source_connectors.SharePointGraphConnector(
        AuthenticatedEndpointConfig("https://graph.microsoft.com/v1.0", "vault:graph/token"),
        drive_id="drive-1",
        transport=httpx2.MockTransport(respond),
        secret_resolver=lambda _: "graph-token",
    )
    page = connector.fetch_delta_page(source_ref, None)
    assert page.through_cursor and not page.has_more
    item = page.items[0]
    assert item["object_key"] == "sharepoint:item-1"
    assert b64decode(item["content_base64"]) == content
    assert item["content_sha256"] == sha256(content).hexdigest()
    inventory = connector.fetch_full_inventory(source_ref)
    assert inventory.complete and inventory.stable_object_keys == {"sharepoint:item-1"}
    assert sum(request.url.path.endswith("/content") for request in requests) == 2


def test_sharepoint_graph_refreshes_oauth_client_credentials_for_unattended_sync():
    source_ref = uuid4()
    token_requests = []
    graph_requests = []

    def respond(request):
        if request.url.host == "login.microsoftonline.com":
            token_requests.append(request)
            assert request.method == "POST"
            assert request.content.decode() == (
                "grant_type=client_credentials&client_id=client-id&client_secret=client-secret&"
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"
            )
            return httpx2.Response(200, json={"access_token": "oauth-token", "expires_in": 3600})
        graph_requests.append(request)
        assert request.headers["Authorization"] == "Bearer oauth-token"
        if request.url.path.endswith("/drives/drive-1/root/delta"):
            return httpx2.Response(200, json={
                "value": [],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/drive-1/root/delta?$deltatoken=stable",
            })
        raise AssertionError(request.url)

    connector = source_connectors.SharePointGraphConnector(
        AuthenticatedEndpointConfig(
            "https://graph.microsoft.com/v1.0", "vault:graph/client-secret",
        ),
        drive_id="drive-1",
        token_endpoint="https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        client_id="client-id",
        transport=httpx2.MockTransport(respond),
        secret_resolver=lambda _: "client-secret",
    )
    connector.fetch_delta_page(source_ref, None)
    connector.fetch_delta_page(source_ref, None)
    assert len(token_requests) == 1
    assert len(graph_requests) == 2


def test_sharepoint_resumes_bounded_chunks_from_a_legacy_cursor():
    source_ref = uuid4()
    resource = "https://graph.microsoft.com/v1.0/drives/drive-1/root/delta"
    legacy_link, delta_link = f"{resource}?$skiptoken=legacy", f"{resource}?$deltatoken=stable"
    rows = [{"id": "folder-1", "name": "Policies", "folder": {"childCount": 23}}] + [
        {"id": f"item-{number}", "name": f"file-{number}.md", "eTag": "etag-1", "file": {"mimeType": "text/markdown"}}
        for number in range(23)
    ]
    downloads = []

    def respond(request):
        if str(request.url) in {legacy_link, resource}:
            return httpx2.Response(200, json={"value": rows, "@odata.deltaLink": delta_link})
        if str(request.url) == delta_link:
            return httpx2.Response(200, json={"value": [], "@odata.deltaLink": delta_link})
        if request.url.path.endswith('/content'):
            downloads.append(request.url.path.split('/')[-2])
            return httpx2.Response(200, content=b"policy text")
        raise AssertionError(request.url)

    def connector():
        return source_connectors.SharePointGraphConnector(
            AuthenticatedEndpointConfig("https://graph.microsoft.com/v1.0", "vault:graph/token"),
            drive_id="drive-1", transport=httpx2.MockTransport(respond), secret_resolver=lambda _: "graph-token",
        )

    cursor = json.dumps({"scope": connector()._scope(source_ref), "url": legacy_link}, separators=(",", ":"))
    expected = [f"item-{number}" for number in range(23)]
    for index, limit in enumerate((5, 10, 15, 20, 23)):
        page = connector().fetch_delta_page(source_ref, cursor)
        assert [item["object_key"] for item in page.items] == [f"sharepoint:{key}" for key in expected[index * 5:limit]]
        assert downloads == expected[:limit]
        assert page.has_more == (limit < len(expected))
        assert page.previous_cursor == cursor and page.through_cursor != cursor
        cursor = page.through_cursor
        if index == 0:
            rows[1], rows[2] = rows[2], rows[1]
            with pytest.raises(ConnectorPortUnavailable):
                connector().fetch_delta_page(source_ref, cursor)
            rows[1], rows[2] = rows[2], rows[1]

    unchanged = connector().fetch_delta_page(source_ref, cursor)
    assert not unchanged.items and not unchanged.has_more and unchanged.through_cursor == cursor


def test_sharepoint_rejects_delta_links_outside_graph():
    def respond(request):
        return httpx2.Response(200, json={
            "value": [],
            "@odata.nextLink": "https://evil.example/delta?token=1",
        })

    connector = source_connectors.SharePointGraphConnector(
        AuthenticatedEndpointConfig("https://graph.microsoft.com/v1.0", "vault:graph/token"),
        drive_id="drive-1",
        transport=httpx2.MockTransport(respond),
        secret_resolver=lambda _: "graph-token",
    )
    with pytest.raises(ConnectorPortUnavailable):
        connector.fetch_delta_page(uuid4(), None)


def test_sharepoint_does_not_follow_content_redirect_to_an_untrusted_host():
    calls = []

    def respond(request):
        calls.append(request)
        if request.url.path.endswith("/content"):
            return httpx2.Response(302, headers={"Location": "https://evil.example/download"})
        raise AssertionError(request.url)

    connector = source_connectors.SharePointGraphConnector(
        AuthenticatedEndpointConfig("https://graph.microsoft.com/v1.0", "vault:graph/token"),
        drive_id="drive-1",
        transport=httpx2.MockTransport(respond),
        secret_resolver=lambda _: "graph-token",
    )
    with pytest.raises(ConnectorPortUnavailable):
        connector._read_content("item-1")
    assert len(calls) == 1


def test_connector_map_accepts_native_feishu_and_sharepoint_types():
    feishu_ref, sharepoint_ref = uuid4(), uuid4()
    mapping = {
        str(feishu_ref): {
            "type": "feishu_wiki", "endpoint": "https://open.feishu.cn", "credential_ref": "vault:feishu/app-secret",
            "app_id": "cli_test", "space_id": "space-1",
        },
        str(sharepoint_ref): {
            "type": "sharepoint_graph", "endpoint": "https://graph.microsoft.com/v1.0", "credential_ref": "vault:graph/token",
            "drive_id": "drive-1",
        },
        str(uuid4()): {
            "type": "sharepoint_graph", "endpoint": "https://graph.microsoft.com/v1.0",
            "credential_ref": "vault:graph/client-secret", "drive_id": "drive-2",
            "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "client_id": "client-id",
        },
    }
    router = source_connectors.load_source_connector_map(
        "vault:test/connectors", secret_resolver=lambda _: json.dumps(mapping),
    )
    assert source_connectors.connector_for_source(router, feishu_ref).source_system == "feishu_wiki"
    assert source_connectors.connector_for_source(router, sharepoint_ref).source_system == "sharepoint_graph"
