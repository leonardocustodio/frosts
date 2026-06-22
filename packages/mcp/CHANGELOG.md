# @frosts/mcp

## 0.2.2-alpha.5

### Minor Changes

- Initial release. A stdio [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that exposes the `@frosts` API surface to MCP-aware AI tools (Claude Code, Cursor, Claude Desktop, Windsurf, …) through five tools: `list_packages`, `search_symbols`, `get_symbol`, `get_guide`, and `find_examples`. It bundles a TypeDoc-derived index of every `@frosts` package and answers read-only lookups over stdio — no hosted endpoint required. Add it with `claude mcp add frosts -- npx -y @frosts/mcp`.
