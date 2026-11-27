from base64 import b64encode
from datetime import UTC, datetime
from hashlib import sha256
import json
import re
from threading import Lock
from time import monotonic
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


class FeishuWikiConnector(_BaseHttpAdapter):
    admission = "production_approved"
    source_system = "feishu_wiki"

    def __init__(self, config: AuthenticatedEndpointConfig, *, app_id: str, space_id: str, **options):
        super().__init__(config.endpoint, config.credential_ref, timeout_seconds=12, **options)
        endpoint = urlsplit(self._endpoint)
        if endpoint.netloc not in {"open.feishu.cn", "open.larksuite.com"} or endpoint.path not in {"", "/"}:
            raise ConfigValidationError("Feishu endpoint must be open.feishu.cn or open.larksuite.com.")
        if not isinstance(app_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", app_id):
            raise ConfigValidationError("Feishu app_id is invalid.")
        if not isinstance(space_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", space_id):
            raise ConfigValidationError("Feishu wiki space_id is invalid.")
        self._app_id = app_id
        self._space_id = space_id
        self._token_lock = Lock()
        self._tenant_token: str | None = None
        self._tenant_token_deadline = 0.0
        self._resource = f"{self._endpoint}/open-apis/wiki/v2/spaces/{space_id}/nodes"

    @staticmethod
    def _remote_cursor(value: object) -> bool:
        return isinstance(value, str) and 0 < len(value) <= _MAX_CURSOR_LENGTH and value.isascii() and value.isprintable()

    def _access_token(self) -> str:
        now = monotonic()
        with self._token_lock:
            if self._tenant_token is not None and now < self._tenant_token_deadline:
                return self._tenant_token
            try:
                app_secret = resolve_secret_ref(self._credential_ref, external_resolver=self._secret_resolver)
                with self._client() as client:
                    response = client.post(
                        f"{self._endpoint}/open-apis/auth/v3/tenant_access_token/internal",
                        headers={"Accept": "application/json", "Content-Type": "application/json"},
                        json={"app_id": self._app_id, "app_secret": app_secret},
                    )
                if response.status_code != 200:
                    raise ConnectorPortUnavailable(f"Feishu token endpoint returned HTTP {response.status_code}.")
                body = _parse_json_strict(response.content)
                token = body.get("tenant_access_token") if isinstance(body, dict) else None
                expire = body.get("expire") if isinstance(body, dict) else None
                if not isinstance(body, dict) or body.get("code") != 0 or not isinstance(token, str) or not 1 <= len(token) <= 4096:
                    raise ValueError("Invalid Feishu tenant access token response.")
                if type(expire) is not int or not 60 <= expire <= 86_400:
                    raise ValueError("Invalid Feishu tenant access token lifetime.")
            except ConnectorPortUnavailable:
                raise
            except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError, KeyError):
                raise ConnectorPortUnavailable("Could not obtain the Feishu tenant access token.") from None
            self._tenant_token = token
            self._tenant_token_deadline = now + max(30, expire - 60)
            return token

    def _json_get(self, url: str, *, params: dict[str, str] | None = None) -> dict:
        try:
            with self._client() as client:
                response = client.get(
                    url,
                    headers={"Authorization": f"Bearer {self._access_token()}", "Accept": "application/json"},
                    params=params,
                )
            if response.status_code != 200:
                raise ConnectorPortUnavailable(f"Feishu API returned HTTP {response.status_code}.")
            if len(response.content) > _MAX_PAGE_BYTES:
                raise ValueError("Feishu API response is too large.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict) or body.get("code") != 0:
                raise ValueError("Feishu API returned an error payload.")
            return body
        except ConnectorPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError, KeyError):
            raise ConnectorPortUnavailable("Could not read the configured Feishu wiki.") from None

    def _read_document(self, obj_token: str, obj_type: str) -> bytes:
        if obj_type == "docx":
            url = f"{self._endpoint}/open-apis/docx/v1/documents/{obj_token}/raw_content"
        elif obj_type == "doc":
            url = f"{self._endpoint}/open-apis/doc/v2/{obj_token}/raw_content"
        else:
            raise ConnectorPortUnavailable("Feishu wiki contains an unsupported document type.")
        body = self._json_get(url)
        data = body.get("data")
        content = data.get("content") if isinstance(data, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Feishu document content is empty or malformed.")
        payload = content.encode("utf-8")
        if len(payload) > _MAX_BODY_BYTES:
            raise ValueError("Feishu document exceeds the size limit.")
        return payload

    def _read_nodes(self, page_token: str | None) -> tuple[tuple[dict, ...], str | None]:
        params = {"page_size": str(_PAGE_SIZE)}
        if page_token is not None:
            params["page_token"] = page_token
        body = self._json_get(self._resource, params=params)
        data = body.get("data")
        rows = data.get("items") if isinstance(data, dict) else None
        has_more = data.get("has_more") if isinstance(data, dict) else None
        next_token = data.get("page_token") if isinstance(data, dict) else None
        if (
            not isinstance(rows, list) or len(rows) > _PAGE_SIZE or type(has_more) is not bool
            or (has_more and not self._remote_cursor(next_token))
            or (not has_more and next_token not in (None, ""))
        ):
            raise ConnectorPortUnavailable("Feishu wiki pagination payload is malformed.")
        items = []
        for row in rows:
            if not isinstance(row, dict):
                raise ConnectorPortUnavailable("Feishu wiki returned an invalid node.")
            node_token, obj_token, obj_type, title = (
                row.get("node_token"), row.get("obj_token"), row.get("obj_type"), row.get("title")
            )
            if (
                not isinstance(node_token, str) or not self._remote_cursor(node_token)
                or not isinstance(obj_token, str) or not self._remote_cursor(obj_token)
                or obj_type not in {"docx", "doc"}
                or not isinstance(title, str) or not 1 <= len(title.strip()) <= 300 or not title.isprintable()
            ):
                raise ConnectorPortUnavailable("Feishu wiki returned an unsupported or invalid node.")
            try:
                payload = self._read_document(obj_token, obj_type)
            except ConnectorPortUnavailable:
                raise
            except (ValueError, TypeError):
                raise ConnectorPortUnavailable("Could not read a Feishu wiki document.") from None
            digest = sha256(payload).hexdigest()
            items.append({
                "object_key": f"feishu:{node_token}",
                "source_version_key": f"content:{digest}",
                "display_name": title.strip(),
                "version_label": digest[:16],
                "media_type": "text/plain",
                "content_sha256": digest,
                "content_base64": b64encode(payload).decode("ascii"),
            })
        if len({item["object_key"] for item in items}) != len(items):
            raise ConnectorPortUnavailable("Feishu wiki returned duplicate nodes.")
        return tuple(items), (next_token or None)

    def _scope(self, source_ref: UUID) -> str:
        return sha256(f"{source_ref}:{self._resource}".encode()).hexdigest()[:24]

    def fetch_delta_page(self, source_ref: UUID, cursor: str | None) -> ConnectorDeltaPage:
        scope, page, page_token = self._scope(source_ref), 1, None
        if cursor is not None:
            try:
                raw = json.loads(cursor)
                if (
                    not isinstance(raw, list) or len(raw) != 3 or raw[0] != scope or type(raw[1]) is not int
                    or not 1 <= raw[1] <= _MAX_SWEEP_PAGES or (raw[2] is not None and not self._remote_cursor(raw[2]))
                ):
                    raise ValueError
                page, page_token = raw[1] + 1, raw[2]
            except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
                raise ConnectorPortUnavailable("Feishu wiki cursor is invalid for this source contract.") from None
        if page > _MAX_SWEEP_PAGES:
            raise ConnectorPortUnavailable("Feishu wiki exceeds the page limit for one sync.")
        items, next_token = self._read_nodes(page_token)
        through_cursor = json.dumps([scope, page, next_token], separators=(",", ":"))
        return ConnectorDeltaPage(cursor, through_cursor, items, next_token is not None)

    def fetch_full_inventory(self, source_ref: UUID) -> ConnectorInventory:
        entries = {}
        page_token = None
        seen = set()
        for _ in range(_MAX_SWEEP_PAGES):
            items, page_token = self._read_nodes(page_token)
            for item in items:
                key = item["object_key"]
                if key in entries:
                    raise ConnectorPortUnavailable("Feishu wiki inventory changed during enumeration.")
                entries[key] = {field: item[field] for field in ("object_key", "source_version_key", "content_sha256")}
            if page_token is None:
                return ConnectorInventory(str(uuid4()), datetime.now(UTC), frozenset(entries), True, tuple(entries.values()))
            if page_token in seen:
                break
            seen.add(page_token)
        raise ConnectorPortUnavailable("Feishu wiki inventory pagination did not finish.")


class SharePointGraphConnector(_BaseHttpAdapter):
    admission = "production_approved"
    source_system = "sharepoint_graph"
    _DOWNLOAD_HOST_SUFFIXES = (".sharepoint.com", ".sharepoint-df.com", ".1drv.com", ".blob.core.windows.net")

    def __init__(self, config: AuthenticatedEndpointConfig, *, drive_id: str, root_item_id: str = "root", **options):
        super().__init__(config.endpoint, config.credential_ref, timeout_seconds=20, **options)
        endpoint = urlsplit(self._endpoint)
        if endpoint.netloc != "graph.microsoft.com" or endpoint.path not in {"/v1.0", "/beta"}:
            raise ConfigValidationError("SharePoint endpoint must be graph.microsoft.com/v1.0 or /beta.")
        if not isinstance(drive_id, str) or not re.fullmatch(r"[A-Za-z0-9!._-]{1,255}", drive_id):
            raise ConfigValidationError("SharePoint drive_id is invalid.")
        if not isinstance(root_item_id, str) or not re.fullmatch(r"[A-Za-z0-9!._-]{1,255}", root_item_id):
            raise ConfigValidationError("SharePoint root_item_id is invalid.")
        self._drive_id = drive_id
        self._root_item_id = root_item_id
        self._resource = (
            f"{self._endpoint}/drives/{drive_id}/root/delta"
            if root_item_id == "root" else f"{self._endpoint}/drives/{drive_id}/items/{root_item_id}/delta"
        )

    def _validate_graph_url(self, raw_url: str) -> str:
        if not isinstance(raw_url, str) or not 0 < len(raw_url) <= 4096 or not raw_url.isprintable() or "\\" in raw_url:
            raise ValueError("Invalid SharePoint pagination link.")
        parsed = urlsplit(urljoin(self._resource, raw_url))
        root = urlsplit(self._endpoint)
        if parsed.scheme != root.scheme or parsed.netloc != root.netloc or parsed.fragment:
            raise ValueError("SharePoint pagination link is outside Microsoft Graph.")
        if not parsed.path.startswith(root.path + "/"):
            raise ValueError("SharePoint pagination link is outside the configured Graph API.")
        return parsed.geturl()

    def _json_get(self, url: str, *, params: dict[str, str] | None = None) -> dict:
        try:
            with self._client() as client:
                response = client.get(url, headers=self._auth_headers(), params=params)
            if response.status_code != 200:
                raise ConnectorPortUnavailable(f"Microsoft Graph returned HTTP {response.status_code}.")
            if len(response.content) > _MAX_PAGE_BYTES:
                raise ValueError("Microsoft Graph response is too large.")
            body = _parse_json_strict(response.content)
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise ValueError("Microsoft Graph response is malformed.")
            return body
        except ConnectorPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError, KeyError):
            raise ConnectorPortUnavailable("Could not read the configured SharePoint drive.") from None

    def _read_content(self, item_id: str) -> bytes:
        url = f"{self._endpoint}/drives/{self._drive_id}/items/{item_id}/content"
        try:
            with httpx2.Client(
                timeout=self._timeout_seconds, transport=self._transport, follow_redirects=True, trust_env=False,
            ) as client:
                response = client.get(url, headers=self._auth_headers())
            final = urlsplit(str(response.url))
            if final.netloc != "graph.microsoft.com" and not final.netloc.endswith(self._DOWNLOAD_HOST_SUFFIXES):
                raise ValueError("SharePoint content redirect is outside an approved host.")
            if response.status_code != 200:
                raise ConnectorPortUnavailable(f"SharePoint content returned HTTP {response.status_code}.")
            payload = response.content
            if not 0 < len(payload) <= _MAX_BODY_BYTES:
                raise ValueError("SharePoint document is empty or exceeds the size limit.")
            return payload
        except ConnectorPortUnavailable:
            raise
        except (PortUnavailable, httpx2.HTTPError, ValueError, TypeError):
            raise ConnectorPortUnavailable("Could not download the SharePoint document.") from None

    def _items(self, rows: list[object]) -> tuple[dict, ...]:
        items = []
        for row in rows:
            if not isinstance(row, dict):
                raise ConnectorPortUnavailable("Microsoft Graph returned an invalid drive item.")
            if "deleted" in row:
                continue
            identifier, title, file_info = row.get("id"), row.get("name"), row.get("file")
            if (
                not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9!._-]{1,255}", identifier)
                or not isinstance(title, str) or not 1 <= len(title.strip()) <= 300 or not title.isprintable()
                or not isinstance(file_info, dict)
            ):
                raise ConnectorPortUnavailable("Microsoft Graph returned an unsupported drive item.")
            payload = self._read_content(identifier)
            digest = sha256(payload).hexdigest()
            media_type = file_info.get("mimeType", "application/octet-stream")
            if not isinstance(media_type, str) or not 1 <= len(media_type) <= 200 or not media_type.isprintable():
                media_type = "application/octet-stream"
            version = row.get("eTag") or row.get("cTag") or row.get("lastModifiedDateTime")
            if not isinstance(version, str) or not 1 <= len(version) <= 512 or not version.isprintable():
                raise ConnectorPortUnavailable("Microsoft Graph drive item has no stable version.")
            items.append({
                "object_key": f"sharepoint:{identifier}", "source_version_key": f"version:{version}",
                "display_name": title.strip(), "version_label": version, "media_type": media_type,
                "content_sha256": digest, "content_base64": b64encode(payload).decode("ascii"),
            })
        if len({item["object_key"] for item in items}) != len(items):
            raise ConnectorPortUnavailable("Microsoft Graph returned duplicate drive items.")
        return tuple(items)

    def _read_delta(self, url: str, *, initial: bool) -> tuple[tuple[dict, ...], str, bool]:
        body = self._json_get(url, params={"$top": "200"} if initial else None)
        next_url = body.get("@odata.nextLink")
        delta_url = body.get("@odata.deltaLink")
        if next_url is not None and not isinstance(next_url, str):
            raise ConnectorPortUnavailable("Microsoft Graph returned an invalid nextLink.")
        if delta_url is not None and not isinstance(delta_url, str):
            raise ConnectorPortUnavailable("Microsoft Graph returned an invalid deltaLink.")
        continuation = next_url or delta_url
        if continuation is None:
            raise ConnectorPortUnavailable("Microsoft Graph returned no continuation link.")
        try:
            continuation = self._validate_graph_url(continuation)
        except ValueError:
            raise ConnectorPortUnavailable("Microsoft Graph returned a pagination link outside the configured API.") from None
        if continuation == url:
            raise ConnectorPortUnavailable("Microsoft Graph pagination stalled.")
        return self._items(body["value"]), continuation, next_url is not None

    def _scope(self, source_ref: UUID) -> str:
        return sha256(f"{source_ref}:{self._resource}".encode()).hexdigest()[:24]

    def fetch_delta_page(self, source_ref: UUID, cursor: str | None) -> ConnectorDeltaPage:
        scope = self._scope(source_ref)
        url, initial = self._resource, True
        if cursor is not None:
            try:
                raw = json.loads(cursor)
                if not isinstance(raw, dict) or raw.get("scope") != scope or not isinstance(raw.get("url"), str):
                    raise ValueError
                url, initial = self._validate_graph_url(raw["url"]), False
            except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
                raise ConnectorPortUnavailable("SharePoint cursor is invalid for this source contract.") from None
        items, continuation, has_more = self._read_delta(url, initial=initial)
        through_cursor = json.dumps({"scope": scope, "url": continuation}, separators=(",", ":"))
        return ConnectorDeltaPage(cursor, through_cursor, items, has_more)

    def fetch_full_inventory(self, source_ref: UUID) -> ConnectorInventory:
        entries = {}
        url, initial = self._resource, True
        seen = set()
        for _ in range(_MAX_SWEEP_PAGES):
            items, continuation, has_more = self._read_delta(url, initial=initial)
            for item in items:
                key = item["object_key"]
                if key in entries:
                    raise ConnectorPortUnavailable("SharePoint inventory changed during enumeration.")
                entries[key] = {field: item[field] for field in ("object_key", "source_version_key", "content_sha256")}
            if not has_more:
                return ConnectorInventory(str(uuid4()), datetime.now(UTC), frozenset(entries), True, tuple(entries.values()))
            if continuation in seen:
                break
            seen.add(continuation)
            url, initial = continuation, False
        raise ConnectorPortUnavailable("SharePoint inventory pagination did not finish.")

    def fetch_document_bytes(self, source_ref: UUID, download_ref: str, digest: bytes) -> bytes:
        if not isinstance(download_ref, str) or not re.fullmatch(r"[A-Za-z0-9!._-]{1,255}", download_ref):
            raise ConnectorPortUnavailable("SharePoint document reference is invalid.")
        payload = self._read_content(download_ref)
        if sha256(payload).digest() != digest:
            raise ConnectorPortUnavailable("SharePoint document bytes failed SHA-256 verification.")
        return payload


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
            elif entry["type"] == "feishu_wiki" and set(entry) == common | {"app_id", "space_id"}:
                connector = FeishuWikiConnector(endpoint, app_id=entry["app_id"], space_id=entry["space_id"], secret_resolver=secret_resolver)
            elif entry["type"] == "sharepoint_graph" and set(entry) in (
                common | {"drive_id"}, common | {"drive_id", "root_item_id"},
            ):
                connector = SharePointGraphConnector(
                    endpoint,
                    drive_id=entry["drive_id"],
                    root_item_id=entry.get("root_item_id", "root"),
                    secret_resolver=secret_resolver,
                )
            elif entry["type"] == "http" and set(entry) == common | {"source_system"}:
                connector = HttpSourceConnectorAdapter(endpoint, source_system=entry["source_system"], secret_resolver=secret_resolver)
            else:
                raise ValueError("Unsupported connector type or configuration.")
            connectors[source_ref] = connector
    except (PortUnavailable, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ConfigValidationError("The private source connector map could not be loaded.") from None
    return ConfiguredSourceConnectors(connectors)
