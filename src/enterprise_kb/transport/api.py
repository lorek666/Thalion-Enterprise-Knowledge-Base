from collections.abc import Sequence
from contextlib import ExitStack, asynccontextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
import json
import re

from anyio import CancelScope, fail_after
from fastapi import FastAPI, Request, Response
from mcp import MCPError, types
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from enterprise_kb.modules.access import policy
from enterprise_kb.modules.evidence import docx_review, pdf_review, processing, repair_review
from enterprise_kb.modules.lifecycle import (
    archives, backup_expiry, backup_inventory, disposition, holds, receipts, space_archive, verification,
)
from enterprise_kb.modules.operations import (
    feedback, findings, gaps, handoffs, runtime_backlog, source_audit, source_sync_status,
)
from enterprise_kb.modules.sources import effectivity, ingest, responsibility

from . import ingest as ingest_transport
from .oidc_sso import EXCHANGE_COOKIE, TX_COOKIE, OidcSsoError, OidcSsoManager
from .evidence import (
    IDEMPOTENCY_PATTERN, INTERNAL_PAGES, INTERNAL_WRITES, OPERATIONS, SOURCE_PAGES, EvidenceReply, EvidenceService,
    GuardedMetadataReply, ServiceRefusal, encode, error_reply, parse_ref,
)
from .portal import (
    register_archives_management_portal, register_catalog_management_portal,
    register_effectivity_management_portal, register_employee_portal, register_feedback_management_portal,
    register_glossary_management_portal, register_governance_management_portal,
    register_ingest_management_portal, register_lifecycle_management_portal, register_policy_management_portals,
    register_repair_management_portal,
    register_responsibility_management_portal, register_runtime_management_portal, register_sources_management_portal,
    register_wiki_management_portal,
)


MAX_BODY = 64 * 1024
MAX_POLICY_BODY = 512 * 1024
MAX_UPLOAD_BODY = 48 * 1024 * 1024
TOKEN = re.compile(r"Bearer ([A-Za-z0-9_.-]{32,16384})", re.IGNORECASE | re.ASCII)
HOST = re.compile(r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?", re.IGNORECASE | re.ASCII)
NO_STORE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
WIKI_STATUS_PATH = "/internal/wiki/status"
WIKI_BASE_PATH = "/internal/wiki"
WIKI_INPUTS_PATH = f"{WIKI_BASE_PATH}/inputs"
WIKI_REVISIONS_PATH = f"{WIKI_BASE_PATH}/revisions"
RUNTIME_BACKLOG_PATH = "/internal/runtime/backlog"
EMPLOYEE_SOURCE_OPTIONS_PATH = "/employee/source-options"
EMPLOYEE_DEPARTMENT_OPTIONS_PATH = "/employee/department-options"
GLOSSARY_PATH = "/internal/glossary"
EMPLOYEE_SUGGESTIONS_PATH = "/employee/search-suggestions"
EMPLOYEE_ORIGINALS_PATH = "/employee/originals"
REPAIR_PATH = "/internal/evidence/repairs"
EVIDENCE_RULES_PATH = "/internal/evidence/rules"
GOVERNANCE_PATH = "/internal/governance"
RELEASE_PATH = "/internal/release"
PDF_CORRECTION_PATH = "/internal/evidence/pdf-corrections"
FEEDBACK_PATH = "/internal/feedback"
GAPS_PATH = f"{FEEDBACK_PATH}/gaps"
HANDOFFS_PATH = f"{FEEDBACK_PATH}/handoffs"
DISPOSITION_PATH = "/internal/lifecycle/disposition-preview"
DISPOSITION_CASES_PATH = "/internal/lifecycle/disposition-cases"
BACKUP_COPIES_PATH = "/internal/lifecycle/backup-copies"
ORIGINAL_EXPORTS_PATH = "/internal/lifecycle/original-exports"
SPACE_ARCHIVES_PATH = "/internal/lifecycle/space-archives"
SOURCE_INGEST_PATH = "/internal/sources"
RETENTION_PATH = "/internal/lifecycle/retention-policy"
HOLD_PATH = "/internal/lifecycle/holds"
SEARCH_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["query"],
    "properties": {
        "query": {"type": "string", "minLength": 1, "maxLength": 1000},
        "business_date": {"type": "string", "format": "date"},
        "top_k": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
        "include_wiki": {"type": "boolean", "default": False},
        "include_source_facets": {"type": "boolean", "default": False},
        "include_department_facets": {"type": "boolean", "default": False},
        "departments": {"type": "array", "maxItems": 20, "items": {"type": "string", "minLength": 1, "maxLength": 64}},
        "space_ids": {"type": "array", "maxItems": 20, "items": {"type": "string", "format": "uuid"}},
        "source_ids": {"type": "array", "maxItems": 20, "items": {"type": "string", "format": "uuid"}},
    },
}
PASSAGE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["id"],
    "properties": {"id": {"type": "string", "format": "uuid"}},
}
TOOLS = (
    types.Tool(name="search", description="按业务日搜索当前可交付的证据。", input_schema=SEARCH_SCHEMA,
               annotations=types.ToolAnnotations(read_only_hint=True)),
    types.Tool(name="read_passage", description="按稳定引用复核并读取原文摘录。", input_schema=PASSAGE_SCHEMA,
               annotations=types.ToolAnnotations(read_only_hint=True)),
)


@dataclass(frozen=True)
class _McpReply:
    rpc_id: str | int | None
    reply: EvidenceReply


def release_time() -> datetime:
    return datetime.now(UTC)


def _http_reply(reply: EvidenceReply) -> Response:
    headers = dict(NO_STORE)
    if reply.attachment_name is not None:
        headers["Content-Disposition"] = f'attachment; filename="{reply.attachment_name}"'
        headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
        return Response(reply.body, status_code=reply.status_code, media_type="application/octet-stream", headers=headers)
    if reply.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return Response(reply.body, status_code=reply.status_code, media_type="application/json", headers=headers)


def _mcp_result(reply: EvidenceReply) -> types.CallToolResult:
    text = reply.body.decode("utf-8")
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)], structured_content=json.loads(text),
        is_error=reply.status_code != 200,
    )


def _expired_mcp(rpc_id, reply: EvidenceReply) -> Response:
    unavailable = error_reply("dependency_unavailable", reply.request_id)
    result = _mcp_result(unavailable).model_dump(mode="json", by_alias=True, exclude_none=True)
    return Response(encode({"jsonrpc": "2.0", "id": rpc_id, "result": result}), media_type="application/json", headers=NO_STORE)


def _compile_host_policy(allowed_hosts: Sequence[str] | None):
    if allowed_hosts is None:
        return (
            HOST,
            ("http",),
            ["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*"],
            ["http://127.0.0.1", "http://127.0.0.1:*", "http://localhost", "http://localhost:*"],
        )
    normalized = [host.strip().lower() for host in allowed_hosts if isinstance(host, str) and host.strip()]
    if not normalized:
        raise ValueError("allowed_hosts must contain at least one hostname.")
    patterns: list[str] = []
    mcp_hosts: list[str] = []
    mcp_origins: list[str] = []
    for host in normalized:
        escaped = re.escape(host)
        if ":" in host:
            patterns.append(escaped)
            mcp_hosts.append(host)
            mcp_origins.append(f"https://{host}")
        else:
            patterns.append(f"{escaped}(?::[0-9]{{1,5}})?")
            mcp_hosts.extend([host, f"{host}:*"])
            mcp_origins.extend([f"https://{host}", f"https://{host}:*"])
    return (
        re.compile(f"(?:{'|'.join(patterns)})", re.IGNORECASE | re.ASCII),
        ("https",),
        mcp_hosts,
        mcp_origins,
    )


def _valid_site(request: Request, host_pattern: re.Pattern[str], allowed_schemes: tuple[str, ...]) -> bool:
    hosts = request.headers.getlist("host")
    origins = request.headers.getlist("origin")
    if len(hosts) != 1 or host_pattern.fullmatch(hosts[0]) is None:
        return False
    if not origins:
        return True
    allowed_origins = {f"{scheme}://{hosts[0]}" for scheme in allowed_schemes}
    return len(origins) == 1 and origins[0] in allowed_origins


class _Ingress:
    def __init__(
        self,
        app,
        service: EvidenceService,
        *,
        host_pattern: re.Pattern[str] = HOST,
        allowed_schemes: tuple[str, ...] = ("http",),
    ):
        self.app = app
        self.service = service
        self.host_pattern = host_pattern
        self.allowed_schemes = allowed_schemes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        path = scope["path"]
        is_mcp = path == "/mcp"
        if not _valid_site(request, self.host_pattern, self.allowed_schemes):
            if is_mcp:
                denied = Response(
                    encode({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Host or Origin"}}),
                    status_code=403, media_type="application/json", headers=NO_STORE,
                )
            else:
                denied = _http_reply(error_reply("forbidden"))
            await denied(scope, receive, send)
            return
        if (
            is_mcp or path in {"/v1/search", EMPLOYEE_SOURCE_OPTIONS_PATH, EMPLOYEE_DEPARTMENT_OPTIONS_PATH, EMPLOYEE_SUGGESTIONS_PATH, WIKI_STATUS_PATH, GLOSSARY_PATH,
                               RUNTIME_BACKLOG_PATH, FEEDBACK_PATH, DISPOSITION_PATH, DISPOSITION_CASES_PATH, RETENTION_PATH, HOLD_PATH,
                               BACKUP_COPIES_PATH, ORIGINAL_EXPORTS_PATH, SPACE_ARCHIVES_PATH, EVIDENCE_RULES_PATH, GOVERNANCE_PATH}
            or path.startswith(("/v1/passages/", f"{FEEDBACK_PATH}/", f"{DISPOSITION_CASES_PATH}/", f"{ORIGINAL_EXPORTS_PATH}/",
                                f"{SPACE_ARCHIVES_PATH}/",
                                f"{BACKUP_COPIES_PATH}/", f"{REPAIR_PATH}/", f"{PDF_CORRECTION_PATH}/",
                                f"{SOURCE_INGEST_PATH}/", f"{EMPLOYEE_ORIGINALS_PATH}/", f"{WIKI_BASE_PATH}/",
                                f"{EVIDENCE_RULES_PATH}/", f"{GOVERNANCE_PATH}/", f"{RELEASE_PATH}/", f"{GLOSSARY_PATH}/"))
        ):
            headers = request.headers.getlist("authorization")
            match = TOKEN.fullmatch(headers[0]) if len(headers) == 1 else None
            try:
                if match is None:
                    raise ServiceRefusal("unauthenticated")
                caller = await run_in_threadpool(self.service.identify, match[1])
                request.state.employee = replace(caller, ingress="mcp" if is_mcp else "http")
            except ServiceRefusal as error:
                await _http_reply(error_reply(error.code))(scope, receive, send)
                return

        replaced = False

        async def release(message):
            nonlocal replaced
            if replaced:
                return
            pending = getattr(request.state, "evidence_reply", None)
            reply = pending.reply if isinstance(pending, _McpReply) else pending
            dispatch_at = release_time() if reply is not None and reply.valid_until is not None else None
            if message["type"] == "http.response.start" and isinstance(reply, GuardedMetadataReply):
                request.state.release_guard = ExitStack()
                checked = await run_in_threadpool(
                    self.service.release_guarded_metadata, request.state.employee, reply, request.state.release_guard, dispatch_at,
                )
                if checked.status_code != 200:
                    replaced = True
                    await _http_reply(checked)(scope, receive, send)
                    return
                dispatch_at = max(dispatch_at, datetime.now(UTC))
            remaining = (
                (reply.valid_until - dispatch_at).total_seconds() if dispatch_at is not None else None
            )
            expired = remaining is not None and remaining <= 0
            if message["type"] == "http.response.body" and expired:
                replaced = True
                return
            if message["type"] == "http.response.start":
                substitute = None
                if isinstance(pending, _McpReply) and reply.status_code in {401, 403}:
                    substitute = _http_reply(reply)
                elif expired:
                    substitute = _expired_mcp(pending.rpc_id, reply) if isinstance(pending, _McpReply) else _http_reply(
                        error_reply("dependency_unavailable", reply.request_id),
                    )
                if substitute is not None:
                    replaced = True
                    await substitute(scope, receive, send)
                    return
                headers = [(name, value) for name, value in message["headers"]
                           if name.lower() not in {b"cache-control", b"x-content-type-options"}]
                message = message | {"headers": headers + [(name.lower().encode(), value.encode()) for name, value in NO_STORE.items()]}
            if remaining is not None and (isinstance(reply, GuardedMetadataReply) or reply.attachment_name is not None):
                with fail_after(remaining):
                    await send(message)
            else:
                await send(message)

        try:
            await self.app(scope, receive, release)
        finally:
            release_guard = getattr(request.state, "release_guard", None)
            if release_guard is not None:
                with CancelScope(shield=True):
                    await run_in_threadpool(release_guard.close)


async def _json_arguments(request: Request, *, max_body: int = MAX_BODY):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise ServiceRefusal("invalid_arguments")
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > max_body:
                raise ServiceRefusal("request_too_large")
            body.extend(chunk)
        return json.loads(body)
    except (ValueError, RecursionError, ClientDisconnect):
        raise ServiceRefusal("invalid_arguments") from None


async def _upload_arguments(request: Request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise ServiceRefusal("invalid_arguments")
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_UPLOAD_BODY:
                raise ServiceRefusal("request_too_large")
            body.extend(chunk)
        return json.loads(body)
    except (ValueError, RecursionError, ClientDisconnect):
        raise ServiceRefusal("invalid_arguments") from None


def create_app(
    service: EvidenceService,
    *,
    allowed_hosts: Sequence[str] | None = None,
    oidc_sso: OidcSsoManager | None = None,
) -> FastAPI:
    host_pattern, allowed_schemes, mcp_hosts, mcp_origins = _compile_host_policy(allowed_hosts)

    async def list_tools(context, params):
        caller = context.request.state.employee
        return types.ListToolsResult(tools=[tool for tool in TOOLS if tool.name in caller.credential.operations])

    async def call_tool(context, params):
        if params.name not in OPERATIONS:
            raise MCPError(types.ErrorData(code=types.INVALID_PARAMS, message="Unknown tool"))
        request = context.request
        arguments = params.arguments if params.arguments is not None else {}
        reply = await run_in_threadpool(service.execute, request.state.employee, params.name, arguments)
        request.state.evidence_reply = _McpReply(context.request_id, reply)
        return _mcp_result(reply)

    mcp = Server("thalion-evidence", version="0.1.0", on_list_tools=list_tools, on_call_tool=call_tool)
    mcp_app = mcp.streamable_http_app(
        stateless_http=True, json_response=True, max_request_body_size=MAX_BODY,
        transport_security=TransportSecuritySettings(
            allowed_hosts=mcp_hosts,
            allowed_origins=mcp_origins,
        ),
    )

    @asynccontextmanager
    async def lifespan(app):
        async with mcp_app.router.lifespan_context(mcp_app):
            yield

    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None, lifespan=lifespan, redirect_slashes=False)
    app.add_middleware(_Ingress, service=service, host_pattern=host_pattern, allowed_schemes=allowed_schemes)

    @app.post("/v1/search")
    async def search(request: Request):
        try:
            arguments = await _json_arguments(request)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(service.execute, request.state.employee, "search", arguments)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get("/v1/passages/{citation}")
    async def read_passage(request: Request, citation: str):
        reply = await run_in_threadpool(service.execute, request.state.employee, "read_passage", {"id": citation})
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(EMPLOYEE_SOURCE_OPTIONS_PATH)
    async def employee_source_options(request: Request):
        arguments = request.query_params.multi_items()
        if arguments and (len(arguments) != 1 or arguments[0][0] != "business_date"):
            return _http_reply(error_reply("invalid_arguments"))
        day = arguments[0][1] if arguments else None
        reply = await run_in_threadpool(service.execute_source_options, request.state.employee, day)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(EMPLOYEE_DEPARTMENT_OPTIONS_PATH)
    async def employee_department_options(request: Request):
        arguments = request.query_params.multi_items()
        if arguments and (len(arguments) != 1 or arguments[0][0] != "business_date"):
            return _http_reply(error_reply("invalid_arguments"))
        day = arguments[0][1] if arguments else None
        reply = await run_in_threadpool(service.execute_department_options, request.state.employee, day)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(EMPLOYEE_SUGGESTIONS_PATH)
    async def employee_search_suggestions(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=4096)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(service.execute_search_suggestions, request.state.employee, arguments)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(f"{EMPLOYEE_ORIGINALS_PATH}/{{version}}")
    async def employee_original(request: Request, version: str):
        if request.query_params or request.headers.get("range") is not None:
            return _http_reply(error_reply("invalid_arguments"))
        request.state.release_guard = ExitStack()
        reply = await run_in_threadpool(service.execute_original_download, request.state.employee, version, request.state.release_guard)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(WIKI_STATUS_PATH)
    async def read_wiki_status(request: Request):
        arguments = request.query_params.multi_items()
        try:
            if arguments and (len(arguments) != 1 or arguments[0][0] != "after"):
                raise ValueError("Unexpected management query parameters.")
            after = parse_ref(arguments[0][1]) if arguments else None
        except ValueError:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_wiki_status, request.state.employee, after)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(WIKI_REVISIONS_PATH)
    async def list_wiki_revisions(request: Request):
        arguments = request.query_params.multi_items()
        try:
            if arguments and (len(arguments) != 1 or arguments[0][0] != "wiki_id"):
                raise ValueError("Unexpected wiki revision query parameters.")
            wiki_ref = parse_ref(arguments[0][1]) if arguments else None
        except ValueError:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_wiki_revisions, request.state.employee, wiki_ref)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(WIKI_INPUTS_PATH)
    async def assemble_wiki_inputs(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(service.execute_wiki_inputs, request.state.employee, arguments)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(WIKI_REVISIONS_PATH)
    async def create_wiki_revision(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_POLICY_BODY)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(service.execute_wiki_candidate, request.state.employee, arguments, keys[0])
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{WIKI_REVISIONS_PATH}/generate")
    async def generate_wiki_revision(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(service.execute_wiki_generate, request.state.employee, arguments, keys[0])
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{WIKI_REVISIONS_PATH}/{{revision_id}}/preview")
    async def preview_wiki_revision(request: Request, revision_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(service.execute_wiki_preview, request.state.employee, revision_id, arguments)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{WIKI_REVISIONS_PATH}/{{revision_id}}/review")
    async def review_wiki_revision(request: Request, revision_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(
            service.execute_wiki_review, request.state.employee, revision_id, arguments, keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{WIKI_REVISIONS_PATH}/{{revision_id}}/publish")
    async def publish_wiki_revision(request: Request, revision_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(
            service.execute_wiki_publish, request.state.employee, revision_id, arguments, keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    async def internal_response(
        request: Request, operation: str, resource_id: str | None = None, *, page_number: str | None = None,
    ):
        try:
            query = request.query_params.multi_items()
            allowed_after = operation in (INTERNAL_PAGES | SOURCE_PAGES) and len(query) == 1 and query[0][0] == "after"
            allowed_audit_request = operation == source_audit.READ and len(query) == 1 and query[0][0] == "request_id"
            allowed_docx_format = operation == docx_review.PREVIEW and query == [("format", docx_review.TABLE_BATCH_FORMAT)]
            if query and not (allowed_after or allowed_audit_request or allowed_docx_format):
                raise ValueError("Unexpected internal query parameters.")
            ref = parse_ref(resource_id) if resource_id is not None else None
            key = ""
            arguments = dict(query) if page_number is None else {"page_number": page_number}
            if operation in INTERNAL_WRITES:
                keys = request.headers.getlist("idempotency-key")
                if len(keys) != 1:
                    raise ValueError("Expected exactly one idempotency key.")
                key = keys[0]
            if operation in INTERNAL_WRITES or operation in {disposition.PLAN, effectivity.PREVIEW, effectivity.PREVIEW_STOP}:
                arguments = await _json_arguments(request, max_body=MAX_POLICY_BODY if operation in policy.WRITE_OPERATIONS else MAX_BODY)
                if page_number is not None:
                    if not isinstance(arguments, dict) or "page_number" in arguments:
                        raise ValueError("Physical page number must come from the route.")
                    arguments["page_number"] = page_number
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        except ValueError:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_internal, request.state.employee, operation, arguments, ref, key)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(FEEDBACK_PATH)
    async def record_feedback(request: Request):
        return await internal_response(request, feedback.RECORD)

    @app.get(f"{REPAIR_PATH}/{{run_id}}/preview")
    async def preview_repair(request: Request, run_id: str):
        return await internal_response(request, repair_review.PREVIEW, run_id)

    @app.get(f"{REPAIR_PATH}/{{run_id}}/docx-preview")
    async def preview_docx(request: Request, run_id: str):
        return await internal_response(request, docx_review.PREVIEW, run_id)

    @app.post(f"{REPAIR_PATH}/{{run_id}}/docx-decision")
    async def decide_docx(request: Request, run_id: str):
        return await internal_response(request, docx_review.DECIDE, run_id)

    @app.post(f"{SOURCE_INGEST_PATH}/{{source_id}}/ingest-batches")
    async def ingest_source_batch(request: Request, source_id: str):
        try:
            key = request.headers.get("idempotency-key", "")
            if IDEMPOTENCY_PATTERN.fullmatch(key) is None:
                raise ServiceRefusal("invalid_arguments")
            body = await _upload_arguments(request)
            reply = await run_in_threadpool(
                ingest_transport.execute, service, request.state.employee, parse_ref(source_id), body, key,
            )
        except ServiceRefusal as error:
            reply = error_reply(error.code)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(f"{SOURCE_INGEST_PATH}/{{source_id}}/ingest-batches")
    async def read_ingest_batches(request: Request, source_id: str):
        return await internal_response(request, ingest.LIST_BATCHES, source_id)

    @app.get(f"{SOURCE_INGEST_PATH}/{{source_id}}/audit")
    async def read_source_audit(request: Request, source_id: str):
        return await internal_response(request, source_audit.READ, source_id)

    @app.get(f"{SOURCE_INGEST_PATH}/catalog")
    async def read_source_catalog(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_source_catalog, request.state.employee)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{SOURCE_INGEST_PATH}/{{source_id}}/connector-sync")
    async def trigger_connector_sync(request: Request, source_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type:
            try:
                arguments = await _json_arguments(request, max_body=MAX_BODY)
            except ServiceRefusal as error:
                return _http_reply(error_reply(error.code))
        else:
            raw = await request.body()
            if raw:
                return _http_reply(error_reply("invalid_arguments"))
            arguments = {}
        reply = await run_in_threadpool(
            service.execute_connector_sync, request.state.employee, source_id,
            arguments=arguments, key=keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(f"{SOURCE_INGEST_PATH}/{{source_id}}/sync-status")
    async def read_source_sync_status(request: Request, source_id: str):
        return await internal_response(request, source_sync_status.READ, source_id)

    @app.get(RUNTIME_BACKLOG_PATH)
    async def read_runtime_backlog(request: Request):
        return await internal_response(request, runtime_backlog.READ)

    @app.post(f"{SOURCE_INGEST_PATH}/versions/{{version_id}}/effectivity")
    async def approve_effectivity(request: Request, version_id: str):
        return await internal_response(request, effectivity.APPROVE, version_id)

    @app.post(f"{SOURCE_INGEST_PATH}/versions/{{version_id}}/effectivity-preview")
    async def preview_effectivity(request: Request, version_id: str):
        return await internal_response(request, effectivity.PREVIEW, version_id)

    @app.post(f"{SOURCE_INGEST_PATH}/versions/{{version_id}}/stop-preview")
    async def preview_rule_stop(request: Request, version_id: str):
        return await internal_response(request, effectivity.PREVIEW_STOP, version_id)

    @app.post(f"{SOURCE_INGEST_PATH}/versions/{{version_id}}/stop")
    async def stop_rule_use(request: Request, version_id: str):
        return await internal_response(request, effectivity.STOP, version_id)

    @app.post(f"{SOURCE_INGEST_PATH}/versions/{{version_id}}/effectivity-conflicts")
    async def record_effectivity_conflict(request: Request, version_id: str):
        return await internal_response(request, effectivity.RECORD_CONFLICT, version_id)

    @app.get(f"{SOURCE_INGEST_PATH}/documents/{{document_id}}/effectivity-conflicts")
    async def list_effectivity_conflicts(request: Request, document_id: str):
        return await internal_response(request, effectivity.LIST_CONFLICTS, document_id)

    @app.post(f"{SOURCE_INGEST_PATH}/effectivity-conflicts/{{conflict_id}}/resolution")
    async def resolve_effectivity_conflict(request: Request, conflict_id: str):
        return await internal_response(request, effectivity.RESOLVE_CONFLICT, conflict_id)

    @app.get(f"{SOURCE_INGEST_PATH}/versions/{{version_id}}/processing-status")
    async def read_processing_status(request: Request, version_id: str):
        return await internal_response(request, processing.STATUS_OPERATION, version_id)

    @app.get(f"{SOURCE_INGEST_PATH}/{{source_id}}/access-policy")
    async def read_local_policy(request: Request, source_id: str):
        return await internal_response(request, policy.READ, source_id)

    @app.post(f"{SOURCE_INGEST_PATH}/{{source_id}}/access-policy")
    async def replace_local_policy(request: Request, source_id: str):
        return await internal_response(request, policy.REPLACE, source_id)

    @app.get(f"{SOURCE_INGEST_PATH}/{{source_id}}/model-egress-policy")
    async def read_model_policy(request: Request, source_id: str):
        return await internal_response(request, policy.READ_MODEL, source_id)

    @app.post(f"{SOURCE_INGEST_PATH}/{{source_id}}/model-egress-policy")
    async def replace_model_policy(request: Request, source_id: str):
        return await internal_response(request, policy.REPLACE_MODEL, source_id)

    @app.get(f"{SOURCE_INGEST_PATH}/documents/{{document_id}}/responsibility")
    async def read_document_responsibility(request: Request, document_id: str):
        return await internal_response(request, responsibility.READ, document_id)

    @app.post(f"{SOURCE_INGEST_PATH}/documents/{{document_id}}/responsibility")
    async def set_document_responsibility(request: Request, document_id: str):
        return await internal_response(request, responsibility.SET, document_id)

    @app.get(f"{SOURCE_INGEST_PATH}/documents/{{document_id}}/department")
    async def read_document_department(request: Request, document_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_document_department, request.state.employee, "read", document_id)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{SOURCE_INGEST_PATH}/documents/{{document_id}}/department")
    async def set_document_department(request: Request, document_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(
            service.execute_document_department, request.state.employee, "set", document_id,
            arguments=arguments, key=keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(GLOSSARY_PATH)
    async def list_glossary(request: Request):
        params = dict(request.query_params)
        if set(params) - {"include_inactive", "q"}:
            return _http_reply(error_reply("invalid_arguments"))
        raw_inc = params.get("include_inactive", "true").lower()
        if raw_inc not in {"true", "false"}:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(
            service.execute_glossary, request.state.employee, "list",
            include_inactive=(raw_inc == "true"), query=params.get("q"),
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(GLOSSARY_PATH)
    async def create_glossary(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(
            service.execute_glossary, request.state.employee, "create", arguments=arguments, key=keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{GLOSSARY_PATH}/{{entry_id}}")
    async def update_glossary(request: Request, entry_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(
            service.execute_glossary, request.state.employee, "update", entry_id=entry_id, arguments=arguments, key=keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{GLOSSARY_PATH}/{{entry_id}}/status")
    async def set_glossary_status(request: Request, entry_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request)
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        reply = await run_in_threadpool(
            service.execute_glossary, request.state.employee, "status", entry_id=entry_id, arguments=arguments, key=keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get("/auth/oidc/status")
    async def oidc_status():
        payload = oidc_sso.status_payload() if oidc_sso is not None else {"enabled": False, "issuer": None, "login_url": None}
        return Response(encode(payload), status_code=200, media_type="application/json", headers=NO_STORE)

    @app.get("/auth/oidc/login")
    async def oidc_login(request: Request):
        if oidc_sso is None:
            return Response(encode({"error": {"code": "oidc_disabled", "message": "当前环境未启用企业 OIDC SSO 登录。"}}), status_code=404, media_type="application/json", headers=NO_STORE)
        try:
            auth_url, tx_binding = oidc_sso.begin_login(request.query_params.get("return_to"))
        except OidcSsoError as error:
            return Response(encode({"error": {"code": error.code, "message": error.message}}), status_code=error.status_code, media_type="application/json", headers=NO_STORE)
        response = Response(status_code=302, headers={"Location": auth_url, **NO_STORE})
        response.set_cookie(
            TX_COOKIE, tx_binding, max_age=oidc_sso.config.state_ttl_seconds,
            path="/auth/oidc", httponly=True, samesite="lax", secure=oidc_sso.cookie_secure,
        )
        return response

    @app.get("/auth/oidc/callback")
    async def oidc_callback(request: Request):
        if oidc_sso is None:
            return Response(encode({"error": {"code": "oidc_disabled", "message": "当前环境未启用企业 OIDC SSO 登录。"}}), status_code=404, media_type="application/json", headers=NO_STORE)
        try:
            redirect_url, exchange_binding = await run_in_threadpool(
                oidc_sso.complete_callback,
                code=request.query_params.get("code"),
                state=request.query_params.get("state"),
                tx_cookie=request.cookies.get(TX_COOKIE),
                idp_error=request.query_params.get("error"),
            )
        except OidcSsoError as error:
            err_resp = Response(encode({"error": {"code": error.code, "message": error.message}}), status_code=error.status_code, media_type="application/json", headers=NO_STORE)
            err_resp.delete_cookie(TX_COOKIE, path="/auth/oidc")
            return err_resp
        response = Response(status_code=302, headers={"Location": redirect_url, **NO_STORE})
        response.delete_cookie(TX_COOKIE, path="/auth/oidc")
        response.set_cookie(
            EXCHANGE_COOKIE, exchange_binding, max_age=oidc_sso.config.ticket_ttl_seconds,
            path="/auth/oidc", httponly=True, samesite="lax", secure=oidc_sso.cookie_secure,
        )
        return response

    @app.post("/auth/oidc/exchange")
    async def oidc_exchange(request: Request):
        if oidc_sso is None:
            return Response(encode({"error": {"code": "oidc_disabled", "message": "当前环境未启用企业 OIDC SSO 登录。"}}), status_code=404, media_type="application/json", headers=NO_STORE)
        try:
            arguments = await _json_arguments(request, max_body=2048)
            ticket = arguments.get("ticket") if isinstance(arguments, dict) else None
            result = oidc_sso.exchange_ticket(ticket, request.cookies.get(EXCHANGE_COOKIE))
        except ServiceRefusal as error:
            return _http_reply(error_reply(error.code))
        except OidcSsoError as error:
            err_resp = Response(encode({"error": {"code": error.code, "message": error.message}}), status_code=error.status_code, media_type="application/json", headers=NO_STORE)
            err_resp.delete_cookie(EXCHANGE_COOKIE, path="/auth/oidc")
            return err_resp
        response = Response(encode(result), status_code=200, media_type="application/json", headers=NO_STORE)
        response.delete_cookie(EXCHANGE_COOKIE, path="/auth/oidc")
        return response

    @app.get(f"{REPAIR_PATH}/{{run_id}}/pdf-pages/{{page_number}}")
    async def preview_pdf_page(request: Request, run_id: str, page_number: str):
        return await internal_response(request, pdf_review.PREVIEW, run_id, page_number=page_number)

    @app.get(f"{REPAIR_PATH}/{{run_id}}/pdf-pages/{{page_number}}/review")
    async def preview_pdf_repair_page(request: Request, run_id: str, page_number: str):
        return await internal_response(request, pdf_review.PREVIEW_REPAIR, run_id, page_number=page_number)

    @app.post(f"{REPAIR_PATH}/{{run_id}}/pdf-approval")
    async def approve_pdf_repair(request: Request, run_id: str):
        return await internal_response(request, pdf_review.APPROVE_REPAIR, run_id)

    @app.post(f"{REPAIR_PATH}/{{run_id}}/pdf-pages/{{page_number}}/corrections")
    async def submit_pdf_correction(request: Request, run_id: str, page_number: str):
        return await internal_response(request, pdf_review.SUBMIT_CORRECTION, run_id, page_number=page_number)

    @app.get(f"{PDF_CORRECTION_PATH}/{{correction_id}}/preview")
    async def preview_pdf_correction(request: Request, correction_id: str):
        return await internal_response(request, pdf_review.PREVIEW_CORRECTION, correction_id)

    @app.post(f"{PDF_CORRECTION_PATH}/{{correction_id}}/decision")
    async def decide_pdf_correction(request: Request, correction_id: str):
        return await internal_response(request, pdf_review.DECIDE_CORRECTION, correction_id)

    @app.post(f"{REPAIR_PATH}/{{run_id}}/decision")
    async def decide_repair(request: Request, run_id: str):
        return await internal_response(request, repair_review.DECIDE, run_id)

    @app.get(EVIDENCE_RULES_PATH)
    async def list_evidence_rules(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_rule_revisions, request.state.employee)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(f"{EVIDENCE_RULES_PATH}/{{configuration_revision}}/impact")
    async def read_evidence_rule_impact(request: Request, configuration_revision: str):
        arguments = request.query_params.multi_items()
        try:
            if not configuration_revision.isascii() or not configuration_revision.isdigit():
                raise ValueError("Configuration revision must be positive digits.")
            cfg_rev = int(configuration_revision)
            if arguments and (len(arguments) != 1 or arguments[0][0] != "source_id"):
                raise ValueError("Unexpected impact query parameters.")
            source_ref = parse_ref(arguments[0][1]) if arguments else None
        except ValueError:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_rule_impact, request.state.employee, cfg_rev, source_ref)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{EVIDENCE_RULES_PATH}/{{configuration_revision}}/rollback")
    async def plan_evidence_rule_rollback(request: Request, configuration_revision: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            if not configuration_revision.isascii() or not configuration_revision.isdigit():
                raise ValueError("Configuration revision must be positive digits.")
            cfg_rev = int(configuration_revision)
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except (ValueError, ServiceRefusal) as error:
            code = error.code if isinstance(error, ServiceRefusal) else "invalid_arguments"
            return _http_reply(error_reply(code))
        reply = await run_in_threadpool(
            service.execute_rule_rollback, request.state.employee, cfg_rev, arguments, keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    async def governance_response(
        request: Request, action: str, *, raw_ref: str | None = None, raw_sub_ref: str | None = None, write: bool = False,
    ):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            ref = parse_ref(raw_ref) if raw_ref is not None else None
            sub_ref = parse_ref(raw_sub_ref) if raw_sub_ref is not None else None
        except ValueError:
            return _http_reply(error_reply("invalid_arguments"))
        arguments = None
        key = None
        if write:
            keys = request.headers.getlist("idempotency-key")
            if len(keys) != 1:
                return _http_reply(error_reply("invalid_arguments"))
            key = keys[0]
            try:
                arguments = await _json_arguments(request, max_body=MAX_BODY)
            except ServiceRefusal as refusal:
                return _http_reply(error_reply(refusal.code))
        reply = await run_in_threadpool(
            service.execute_governance, request.state.employee, action,
            ref=ref, sub_ref=sub_ref, arguments=arguments, key=key,
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.get(GOVERNANCE_PATH)
    async def read_space_governance(request: Request):
        return await governance_response(request, "overview")

    @app.post(f"{GOVERNANCE_PATH}/shared-groups")
    async def create_governance_shared_group(request: Request):
        return await governance_response(request, "create_shared_group", write=True)

    @app.post(f"{GOVERNANCE_PATH}/shared-groups/{{group_id}}/members")
    async def add_governance_shared_group_member(request: Request, group_id: str):
        return await governance_response(request, "add_shared_group_member", raw_ref=group_id, write=True)

    @app.post(f"{GOVERNANCE_PATH}/shared-groups/{{group_id}}/members/{{membership_id}}/revoke")
    async def revoke_governance_shared_group_member(request: Request, group_id: str, membership_id: str):
        return await governance_response(
            request, "revoke_shared_group_member", raw_ref=group_id, raw_sub_ref=membership_id, write=True,
        )

    @app.post(f"{GOVERNANCE_PATH}/shared-groups/{{group_id}}/revoke")
    async def revoke_governance_shared_group(request: Request, group_id: str):
        return await governance_response(request, "revoke_shared_group", raw_ref=group_id, write=True)

    @app.post(f"{GOVERNANCE_PATH}/delegations")
    async def create_governance_delegation(request: Request):
        return await governance_response(request, "create_delegation", write=True)

    @app.post(f"{GOVERNANCE_PATH}/delegations/{{delegation_id}}/revoke")
    async def revoke_governance_delegation(request: Request, delegation_id: str):
        return await governance_response(request, "revoke_delegation", raw_ref=delegation_id, write=True)

    @app.post(f"{GOVERNANCE_PATH}/spaces/archive")
    async def archive_governance_space(request: Request):
        return await governance_response(request, "archive_space", write=True)

    @app.get(f"{GOVERNANCE_PATH}/transitions/{{employee_id}}")
    async def inspect_governance_transition(request: Request, employee_id: str):
        return await governance_response(request, "inspect_transition", raw_ref=employee_id)

    @app.post(f"{GOVERNANCE_PATH}/transitions/{{employee_id}}/handoff")
    async def record_governance_transition_handoff(request: Request, employee_id: str):
        return await governance_response(request, "record_transition_handoff", raw_ref=employee_id, write=True)

    @app.get(f"{RELEASE_PATH}/spaces")
    async def read_space_release(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_space_release, request.state.employee, "overview")
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{RELEASE_PATH}/spaces/switch")
    async def switch_space_release(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except ServiceRefusal as refusal:
            return _http_reply(error_reply(refusal.code))
        reply = await run_in_threadpool(
            service.execute_space_release, request.state.employee, "switch", arguments=arguments, key=keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(f"{RELEASE_PATH}/wiki/{{wiki_id}}/rollback")
    async def rollback_wiki_topic(request: Request, wiki_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            return _http_reply(error_reply("invalid_arguments"))
        try:
            arguments = await _json_arguments(request, max_body=MAX_BODY)
        except ServiceRefusal as refusal:
            return _http_reply(error_reply(refusal.code))
        reply = await run_in_threadpool(
            service.execute_wiki_topic_rollback, request.state.employee, wiki_id, arguments, keys[0],
        )
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(DISPOSITION_PATH)
    async def plan_disposition(request: Request):
        return await internal_response(request, disposition.PLAN)

    @app.post(DISPOSITION_CASES_PATH)
    async def submit_disposition_case(request: Request):
        return await internal_response(request, disposition.SUBMIT)

    @app.post(f"{DISPOSITION_CASES_PATH}/{{case_id}}/rejection")
    async def reject_disposition_case(request: Request, case_id: str):
        return await internal_response(request, disposition.REJECT, case_id)

    @app.post(f"{DISPOSITION_CASES_PATH}/{{case_id}}/approval")
    async def approve_disposition_case(request: Request, case_id: str):
        return await internal_response(request, disposition.APPROVE, case_id)

    @app.post(f"{DISPOSITION_CASES_PATH}/{{case_id}}/original-verification")
    async def verify_disposition_original(request: Request, case_id: str):
        return await internal_response(request, verification.VERIFY_ORIGINAL, case_id)

    @app.post(f"{DISPOSITION_CASES_PATH}/{{case_id}}/deletion-tombstone")
    async def register_deletion_tombstone(request: Request, case_id: str):
        return await internal_response(request, disposition.REGISTER_TOMBSTONE, case_id)

    @app.post(f"{DISPOSITION_CASES_PATH}/{{case_id}}/copy-observations")
    async def observe_disposition_copies(request: Request, case_id: str):
        return await internal_response(request, receipts.OBSERVE, case_id)

    @app.post(BACKUP_COPIES_PATH)
    async def register_backup_copy(request: Request):
        return await internal_response(request, backup_inventory.REGISTER_BACKUP)

    @app.post(f"{BACKUP_COPIES_PATH}/{{backup_id}}/expiry-plan")
    async def schedule_backup_expiry(request: Request, backup_id: str):
        return await internal_response(request, backup_expiry.SCHEDULE, backup_id)

    @app.post(f"{BACKUP_COPIES_PATH}/{{backup_id}}/expiry-observation")
    async def observe_backup_expiry(request: Request, backup_id: str):
        return await internal_response(request, backup_expiry.OBSERVE, backup_id)

    @app.post(ORIGINAL_EXPORTS_PATH)
    async def request_original_export(request: Request):
        return await internal_response(request, archives.REQUEST)

    @app.post(f"{ORIGINAL_EXPORTS_PATH}/{{export_id}}/approval")
    async def approve_original_export(request: Request, export_id: str):
        return await internal_response(request, archives.APPROVE, export_id)

    @app.post(f"{ORIGINAL_EXPORTS_PATH}/{{export_id}}/seal")
    async def seal_original_export(request: Request, export_id: str):
        return await internal_response(request, archives.EXPORT, export_id)

    @app.get(SPACE_ARCHIVES_PATH)
    async def list_space_archives_route(request: Request):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_space_archive_list, request.state.employee)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(SPACE_ARCHIVES_PATH)
    async def request_space_archive(request: Request):
        return await internal_response(request, space_archive.REQUEST)

    @app.post(f"{SPACE_ARCHIVES_PATH}/{{export_id}}/approve")
    async def approve_space_archive(request: Request, export_id: str):
        return await internal_response(request, space_archive.APPROVE, export_id)

    @app.post(f"{SPACE_ARCHIVES_PATH}/{{export_id}}/seal")
    async def seal_space_archive(request: Request, export_id: str):
        return await internal_response(request, space_archive.EXPORT, export_id)

    @app.post(f"{SPACE_ARCHIVES_PATH}/{{export_id}}/verify")
    async def verify_space_archive_route(request: Request, export_id: str):
        if request.query_params:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute_space_archive_verify, request.state.employee, export_id)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    @app.post(RETENTION_PATH)
    async def register_retention_policy(request: Request):
        return await internal_response(request, disposition.REGISTER)

    @app.post(HOLD_PATH)
    async def decide_hold(request: Request):
        return await internal_response(request, holds.DECIDE)

    @app.get(FEEDBACK_PATH)
    async def read_feedback_queue(request: Request):
        return await internal_response(request, feedback.QUEUE)

    @app.get(f"{FEEDBACK_PATH}/notices")
    async def read_feedback_notices(request: Request):
        return await internal_response(request, feedback.NOTICES)

    @app.post(GAPS_PATH)
    async def record_gap(request: Request):
        return await internal_response(request, gaps.RECORD)

    @app.get(GAPS_PATH)
    async def read_gap_queue(request: Request):
        return await internal_response(request, gaps.QUEUE)

    @app.post(f"{GAPS_PATH}/{{gap_id}}/reclassify")
    async def reclassify_gap(request: Request, gap_id: str):
        return await internal_response(request, gaps.RECLASSIFY, gap_id)

    @app.post(f"{FEEDBACK_PATH}/findings")
    async def emit_finding(request: Request):
        return await internal_response(request, findings.EMIT)

    @app.post(HANDOFFS_PATH)
    async def authorize_feedback_handoff(request: Request):
        return await internal_response(request, handoffs.AUTHORIZE)

    @app.post(f"{HANDOFFS_PATH}/{{handoff_id}}/accept")
    async def accept_feedback_handoff(request: Request, handoff_id: str):
        return await internal_response(request, handoffs.ACCEPT, handoff_id)

    @app.post(f"{HANDOFFS_PATH}/{{handoff_id}}/revoke")
    async def revoke_feedback_handoff(request: Request, handoff_id: str):
        return await internal_response(request, handoffs.REVOKE, handoff_id)

    @app.get(f"{FEEDBACK_PATH}/{{feedback_id}}")
    async def read_feedback_status(request: Request, feedback_id: str):
        return await internal_response(request, feedback.STATUS, feedback_id)

    @app.post(f"{FEEDBACK_PATH}/{{feedback_id}}/transitions")
    async def transition_feedback(request: Request, feedback_id: str):
        return await internal_response(request, feedback.TRANSITION, feedback_id)

    @app.post(f"{FEEDBACK_PATH}/{{feedback_id}}/quarantine")
    async def quarantine_feedback_evidence(request: Request, feedback_id: str):
        return await internal_response(request, feedback.QUARANTINE, feedback_id)

    @app.get(f"{FEEDBACK_PATH}/{{feedback_id}}/evidence")
    async def read_feedback_evidence(request: Request, feedback_id: str):
        try:
            if request.query_params:
                raise ValueError("Feedback evidence cannot override the recorded reference.")
            ref = parse_ref(feedback_id)
        except ValueError:
            return _http_reply(error_reply("invalid_arguments"))
        reply = await run_in_threadpool(service.execute, request.state.employee, "read_passage", {}, feedback_ref=ref)
        request.state.evidence_reply = reply
        return _http_reply(reply)

    register_employee_portal(app)
    register_wiki_management_portal(app)
    register_runtime_management_portal(app)
    register_sources_management_portal(app)
    register_feedback_management_portal(app)
    register_repair_management_portal(app)
    register_ingest_management_portal(app)
    register_effectivity_management_portal(app)
    register_policy_management_portals(app)
    register_responsibility_management_portal(app)
    register_governance_management_portal(app)
    register_lifecycle_management_portal(app)
    register_catalog_management_portal(app)
    register_glossary_management_portal(app)
    register_archives_management_portal(app)
    app.mount("/", mcp_app)
    return app
