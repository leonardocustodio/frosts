# @frosts/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
exposes the entire `@frosts` API surface to MCP-aware AI tools (Claude Code,
Cursor, Claude Desktop, Windsurf, …) so they can navigate the packages without
you pasting docs around.

It runs locally over **stdio** — no network endpoint, no account, nothing to
host. The server bundles a [TypeDoc](https://typedoc.org)-derived index of every
`@frosts` package, generated at publish time, and answers fast, read-only
lookups against it.

## Tools

| Tool | Purpose |
|------|---------|
| `list_packages` | Enumerate all `@frosts` packages with descriptions and symbol counts |
| `search_symbols` | Search exported symbols (functions, classes, types) globally or scoped to one package |
| `get_symbol` | Fetch full details (kind, doc comment, members, source link) for a specific symbol |
| `get_guide` | Read the README / hand-written guide for a package |
| `find_examples` | Find code examples whose doc comments match a query |

## Add it to your client

**Claude Code** — one command:

```bash
claude mcp add frosts -- npx -y @frosts/mcp
```

**Cursor / Windsurf** — add to `.cursor/mcp.json` (or the equivalent project config):

```json
{
  "mcpServers": {
    "frosts": {
      "command": "npx",
      "args": ["-y", "@frosts/mcp"]
    }
  }
}
```

**Claude Desktop** — `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "frosts": {
      "command": "npx",
      "args": ["-y", "@frosts/mcp"]
    }
  }
}
```

That's it — the next session can call `list_packages`, `search_symbols`,
`get_symbol`, `get_guide`, and `find_examples`.

## Run it directly

```bash
npx -y @frosts/mcp
```

The process speaks newline-delimited JSON-RPC 2.0 on stdin/stdout, e.g.:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_packages","arguments":{}}}' \
  | npx -y @frosts/mcp
```

## License

MIT
