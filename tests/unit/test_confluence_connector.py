from hashlib import sha256
import json
from uuid import uuid4

import httpx2
import pytest

from enterprise_kb.ports import source_connectors
from enterprise_kb.ports.contracts import ConnectorPortUnavailable
from enterprise_kb.runtime.config import AuthenticatedEndpointConfig


ENDPOINT = "https://test-team.atlassian.net/wiki"
RESOURCE = "/wiki/api/v2/spaces/123/pages"


def build(transport):
    return source_connectors.ConfluenceCloudConnector(
        AuthenticatedEndpointConfig(ENDPOINT, "vault:example/token"),
        account="sync@example.test", space_id="123", transport=httpx2.MockTransport(transport),
        secret_resolver=lambda _: "test-only-confluence-token",
    )


def page(identifier):
    return {
        "id": identifier, "spaceId": "123", "status": "current", "title": "出差手册",
        "version": {"number": 3}, "body": {"storage": {"value": "<h1>出差手册</h1><p>住宿费每晚 500 元。</p>"}},
    }


def test_confluence_reads_and_resumes_pages_and_builds_inventory():
    received = []

    def respond(request):
        assert request.url.host == "test-team.atlassian.net" and request.url.path == RESOURCE
        assert request.headers["Authorization"].startswith("Basic ")
        assert request.url.params["body-format"] == "storage"
        assert request.url.params["status"] == "current"
        cursor = request.url.params.get("cursor")
        received.append(cursor)
        if cursor is not None:
            assert cursor == "A+/=12"
            return httpx2.Response(200, json={"results": [page("456")]})
        return httpx2.Response(200, json={"results": [page("321")], "_links": {"next": f"{RESOURCE}?cursor=A%2B%2F%3D12"}})

    source_ref = uuid4()
    first = build(respond).fetch_delta_page(source_ref, None)
    assert first.has_more and first.items[0]["object_key"] == "confluence:321"
    connector = build(respond)
    second = connector.fetch_delta_page(source_ref, first.through_cursor)
    assert not second.has_more and second.items[0]["source_version_key"] == "version:3"
    assert second.items[0]["content_sha256"] == sha256(page("456")["body"]["storage"]["value"].encode()).hexdigest()
    new_sweep = connector.fetch_delta_page(source_ref, second.through_cursor)
    assert new_sweep.has_more and new_sweep.through_cursor != first.through_cursor
    inventory = connector.fetch_full_inventory(source_ref)
    assert inventory.complete and inventory.stable_object_keys == {"confluence:321", "confluence:456"}
    assert received == [None, "A+/=12", None, None, "A+/=12"]


@pytest.mark.parametrize("next_uri", [
    "https://outside.example/wiki/api/v2/spaces/123/pages?cursor=bad",
    "/wiki/api/v2/spaces/456/pages?cursor=bad",
    f"{RESOURCE}?cursor=one&cursor=two",
])
def test_confluence_rejects_foreign_or_ambiguous_pagination_without_following_it(next_uri):
    calls = []

    def respond(request):
        calls.append(request.url)
        return httpx2.Response(200, json={"results": [page("321")], "_links": {"next": next_uri}})

    with pytest.raises(ConnectorPortUnavailable):
        build(respond).fetch_delta_page(uuid4(), None)
    assert len(calls) == 1


def test_connector_configuration_binds_credentials_and_provider_to_each_local_source():
    confluence_ref, gateway_ref = uuid4(), uuid4()
    connector_map = {
        str(confluence_ref): {"type": "confluence_cloud", "endpoint": ENDPOINT, "credential_ref": "vault:test/cloud",
                              "account": "sync@example.test", "space_id": "123"},
        str(gateway_ref): {"type": "http", "endpoint": "https://gateway.example.test", "credential_ref": "vault:test/gateway",
                           "source_system": "company-oa"},
    }
    router = source_connectors.load_source_connector_map("vault:test/connectors", secret_resolver=lambda _: json.dumps(connector_map))
    assert source_connectors.connector_for_source(router, confluence_ref).source_system == "confluence_cloud"
    assert source_connectors.connector_for_source(router, gateway_ref).source_system == "company-oa"
    assert source_connectors.connector_for_source(router, uuid4()) is None
    with pytest.raises(ConnectorPortUnavailable):
        router.fetch_full_inventory(uuid4())
