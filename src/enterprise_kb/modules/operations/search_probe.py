MCP_PROTOCOL_VERSION = "2026-07-28"


def post_search(client, entrance: str, token: str, arguments: dict, rpc_id: int = 0):
    headers = {"Authorization": f"Bearer {token}"}
    if entrance == "http":
        return client.post("/v1/search", headers=headers, json=arguments)
    if entrance != "mcp":
        raise ValueError("Unknown search entrance.")
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        },
        headers=headers | {
            "Accept": "application/json, text/event-stream",
            "Mcp-Protocol-Version": MCP_PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "search",
        },
    )
