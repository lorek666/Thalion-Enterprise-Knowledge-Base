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


def test_sharepoint_graph_reads_delta_content_and_inventory():
    source_ref = uuid4()
    content = b"Travel policy\nHotel limit: 500"
    requests = []

    def respond(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer graph-token"
        if request.url.path.endswith("/drives/drive-1/root/delta"):
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
    }
    router = source_connectors.load_source_connector_map(
        "vault:test/connectors", secret_resolver=lambda _: json.dumps(mapping),
    )
    assert source_connectors.connector_for_source(router, feishu_ref).source_system == "feishu_wiki"
    assert source_connectors.connector_for_source(router, sharepoint_ref).source_system == "sharepoint_graph"
