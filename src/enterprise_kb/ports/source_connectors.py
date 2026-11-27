from base64 import b64encode
from datetime import UTC, datetime
from hashlib import sha256
import json
import re
from urllib.parse import parse_qs, urljoin, urlsplit
from uuid import UUID, uuid4

import httpx2

from enterprise_kb.runtime.config import AuthenticatedEndpointConfig, ConfigValidationError

from .adapters import HttpSourceConnectorAdapter, _BaseHttpAdapter, _parse_json_strict, resolve_secret_ref
from .contracts import ConnectorDeltaPage, ConnectorInventory, ConnectorPortUnavailable, PortUnavailable, SourceConnectorPort


_PAGE_SIZE = 5
_MAX_PAGE_BYTES = 16 * 1024 * 1024
_MAX_BODY_BYTES = 2 * 1024 * 1024
_MAX_SWEEP_PAGES = 400
_MAX_CURSOR_LENGTH = 2048
_PAGE_ID = re.compile(r"[0-9]{1,32}")


class ConfluenceCloudConnector(_BaseHttpAdapter):
    admission = "production_approved"
    source_system = "confluence_cloud"

    def __init__(self, config: AuthenticatedEndpointConfig, *, account: str, space_id: str, **options):
        super().__init__(config.endpoint, config.credential_ref, timeout_seconds=8, **options)
        endpoint = urlsplit(self._endpoint)
        is_site = re.fullmatch(r"[a-z0-9][a-z0-9-]*\.atlassian\.net", endpoint.netloc) and endpoint.path == "/wiki"
        is_cloud_api = endpoint.netloc == "api.atlassian.com" and re.fullmatch(
            r"/ex/confluence/[a-f0-9-]{36}/wiki", endpoint.path,
        )
        if not (is_site or is_cloud_api) or "?" in self._endpoint or "#" in self._endpoint:
            raise ConfigValidationError("Confluence endpoint must be an Atlassian Cloud wiki origin or cloud API URL.")
        if not isinstance(account, str) or not re.fullmatch(r"[^\s:@]{1,160}@[^\s:@]{1,160}", account):
            raise ConfigValidationError("Confluence requires the API token owner's email address.")
        if not isinstance(space_id, str) or not _PAGE_ID.fullmatch(space_id):
            raise ConfigValidationError("Confluence requires a numeric space ID.")
        self._account = account
        self._space_id = space_id
        self._resource = f"{self._endpoint}/api/v2/spaces/{space_id}/pages"

    @staticmethod
    def _remote_cursor(value) -> bool:
        return isinstance(value, str) and 0 < len(value) <= _MAX_CURSOR_LENGTH and value.isascii() and value.isprintable()

    def _next_cursor(self, link: str | None, current: str | None) -> str | None:
        if link is None:
            return None
        if not isinstance(link, str) or not 0 < len(link) <= 4096 or not link.isprintable() or "\\" in link:
            raise ValueError("Invalid pagination link.")
        redirect = urlsplit(urljoin(self._resource, link))
        root = urlsplit(self._resource)
        paths = {root.path}
        if root.netloc == "api.atlassian.com":
            paths.add(root.path[root.path.index("/wiki/"):])
        if redirect.scheme != root.scheme or redirect.netloc != root.netloc or redirect.path not in paths or redirect.fragment:
            raise ValueError("Pagination link is outside the configured source.")
        cursors = parse_qs(redirect.query, max_num_fields=20).get("cursor", ())
        if len(cursors) != 1 or not self._remote_cursor(cursors[0]) or cursors[0] == current:
            raise ValueError("Invalid or stalled pagination cursor.")
        return cursors[0]

    def _item(self, row: dict) -> dict:
        identifier, title = row["id"], row["title"]
        version, body = row["version"]["number"], row["body"]["storage"]["value"]
        if (
            row["spaceId"] != self._space_id or row["status"] != "current"
            or not isinstance(identifier, str) or not _PAGE_ID.fullmatch(identifier)
            or not isinstance(title, str) or not 1 <= len(title.strip()) <= 300 or not title.isprintable()
            or type(version) is not int or not 1 <= version <= 2_147_483_647 or not isinstance(body, str)
        ):
            raise ValueError("Invalid Confluence page metadata.")
        payload = body.encode("utf-8")
        if not 0 < len(payload) <= _MAX_BODY_BYTES:
            raise ValueError("Confluence page is empty or exceeds the size limit.")
        return {
            "object_key": f"confluence:{identifier}", "source_version_key": f"version:{version}",
            "display_name": title.strip(), "version_label": f"v{version}", "media_type": "text/html",
            "content_sha256": sha256(payload).hexdigest(), "content_base64": b64encode(payload).decode("ascii"),
        }

    def _read_page(self, cursor: str | None) -> tuple[tuple[dict, ...], str | None]:
        try:
            token = resolve_secret_ref(self._credential_ref, external_resolver=self._secret_resolver)
            credential = b64encode(f"{self._account}:{token}".encode()).decode("ascii")
            params = {"status": "current", "body-format": "storage", "sort": "id", "limit": str(_PAGE_SIZE)}
            if cursor is not None:
                params["cursor"] = cursor
            with self._client() as client:
                with client.stream("GET", self._resource, params=params, headers={
                    "Authorization": f"Basic {credential}", "Accept": "application/json", "Accept-Encoding": "identity",
                }) as response:
                    if response.status_code != 200:
                        raise ConnectorPortUnavailable(f"Confluence page listing returned HTTP {response.status_code}.")
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise ValueError("Unexpected content encoding.")
                    payload = bytearray()
                    for chunk in response.iter_bytes():
                        if len(payload) + len(chunk) > _MAX_PAGE_BYTES:
                            raise ValueError("Confluence page listing is too large.")
                        payload.extend(chunk)
                    page = _parse_json_strict(bytes(payload))
                    rows = page["results"]
                    if not isinstance(rows, list) or len(rows) > _PAGE_SIZE:
                        raise ValueError("Invalid Confluence page listing.")
                    next_link = page.get("_links", {}).get("next") or response.links.get("next", {}).get("url")
            items = tuple(self._item(row) for row in rows)
            if len({item["object_key"] for item in items}) != len(items):
                raise ValueError("Confluence returned a duplicate page.")
            return items, self._next_cursor(next_link, cursor)
        except ConnectorPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise ConnectorPortUnavailable("Could not read the configured Confluence Cloud space.") from None

    def fetch_delta_page(self, source_ref: UUID, cursor: str | None) -> ConnectorDeltaPage:
        scope = sha256(f"{source_ref}:{self._resource}".encode()).hexdigest()[:24]
        sweep, page, after = 1, 1, None
        if cursor is not None:
            try:
                cursor_scope, previous_sweep, previous_page, after = json.loads(cursor)
                if (cursor_scope != scope or type(previous_sweep) is not int or type(previous_page) is not int
                    or not 1 <= previous_sweep < 2**53 or not 1 <= previous_page <= _MAX_SWEEP_PAGES
                    or (after is not None and not self._remote_cursor(after))):
                    raise ValueError("Invalid cursor scope or position.")
                sweep, page = (previous_sweep + 1, 1) if after is None else (previous_sweep, previous_page + 1)
            except (TypeError, ValueError, RecursionError):
                raise ConnectorPortUnavailable("Confluence cursor is invalid for this source contract.") from None
        if page > _MAX_SWEEP_PAGES:
            raise ConnectorPortUnavailable("Confluence space exceeds the page limit for one sync.")
        items, next_cursor = self._read_page(after)
        checkpoint = json.dumps([scope, sweep, page, next_cursor], separators=(",", ":"))
        return ConnectorDeltaPage(cursor, checkpoint, items, next_cursor is not None)

    def fetch_full_inventory(self, source_ref: UUID) -> ConnectorInventory:
        entries = {}
        cursor = None
        seen_cursors = set()
        for _ in range(_MAX_SWEEP_PAGES):
            items, cursor = self._read_page(cursor)
            for item in items:
                key = item["object_key"]
                if key in entries:
                    raise ConnectorPortUnavailable("Confluence inventory changed during enumeration.")
                entries[key] = {field: item[field] for field in ("object_key", "source_version_key", "content_sha256")}
            if cursor is None:
                return ConnectorInventory(str(uuid4()), datetime.now(UTC), frozenset(entries), True, tuple(entries.values()))
            if cursor in seen_cursors:
                break
            seen_cursors.add(cursor)
        raise ConnectorPortUnavailable("Confluence inventory pagination did not finish.")


class ConfiguredSourceConnectors:
    admission = "production_approved"
    source_system = "configured_sources"

    def __init__(self, by_source: dict[UUID, SourceConnectorPort]):
        self._by_source = dict(by_source)

    def for_source(self, source_ref: UUID) -> SourceConnectorPort | None:
        return self._by_source.get(source_ref)

    def _require_source(self, source_ref: UUID) -> SourceConnectorPort:
        connector = self.for_source(source_ref)
        if connector is None:
            raise ConnectorPortUnavailable("No connector is configured for this source.")
        return connector

    def fetch_delta_page(self, source_ref: UUID, cursor: str | None) -> ConnectorDeltaPage:
        return self._require_source(source_ref).fetch_delta_page(source_ref, cursor)

    def fetch_full_inventory(self, source_ref: UUID) -> ConnectorInventory:
        return self._require_source(source_ref).fetch_full_inventory(source_ref)

    def fetch_document_bytes(self, source_ref: UUID, download_ref: str, digest: bytes) -> bytes:
        fetch = getattr(self._require_source(source_ref), "fetch_document_bytes", None)
        if fetch is None:
            raise ConnectorPortUnavailable("This connector cannot fetch external document references.")
        return fetch(source_ref, download_ref, digest)


def connector_for_source(connector: SourceConnectorPort | None, source_ref: UUID) -> SourceConnectorPort | None:
    return connector.for_source(source_ref) if isinstance(connector, ConfiguredSourceConnectors) else connector


def load_source_connector_map(reference: str, *, secret_resolver=None) -> ConfiguredSourceConnectors:
    try:
        mapping = _parse_json_strict(resolve_secret_ref(reference, external_resolver=secret_resolver).encode())
        if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 100:
            raise ValueError("A connector map requires between 1 and 100 sources.")
        connectors = {}
        for key, entry in mapping.items():
            source_ref = UUID(key)
            if str(source_ref) != key or not isinstance(entry, dict):
                raise ValueError("Connector map requires canonical source UUIDs and configuration objects.")
            endpoint = AuthenticatedEndpointConfig(entry["endpoint"], entry["credential_ref"])
            common = {"type", "endpoint", "credential_ref"}
            if entry["type"] == "confluence_cloud" and set(entry) == common | {"account", "space_id"}:
                connector = ConfluenceCloudConnector(endpoint, account=entry["account"], space_id=entry["space_id"], secret_resolver=secret_resolver)
            elif entry["type"] == "http" and set(entry) == common | {"source_system"}:
                connector = HttpSourceConnectorAdapter(endpoint, source_system=entry["source_system"], secret_resolver=secret_resolver)
            else:
                raise ValueError("Unsupported connector type or configuration.")
            connectors[source_ref] = connector
    except (PortUnavailable, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ConfigValidationError("The private source connector map could not be loaded.") from None
    return ConfiguredSourceConnectors(connectors)
