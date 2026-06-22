/**
 * MCP server for the @frosts docs — stateless JSON-RPC 2.0 dispatch.
 *
 * Transport-agnostic: `dispatch()` takes a parsed JSON-RPC request and returns
 * a response (or `undefined` for notifications). `src/index.ts` wires it to a
 * stdio loop. All five tools are fast, synchronous lookups over the bundled
 * data index (see `data.ts`).
 */

import {
  type PackageData,
  type SearchEntry,
  type SymbolData,
  loadGuide,
  loadIndex,
  loadPackage,
  loadSearch,
  serverVersion,
} from "./data.js";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "frosts-docs", version: serverVersion() };
const CODE_FENCE = "```";

export const TOOLS = [
  {
    name: "list_packages",
    description: "List all @frosts TypeScript packages with descriptions and symbol counts.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "search_symbols",
    description: "Search for exported symbols (functions, classes, types) across @frosts packages.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Substring to match against symbol names." },
        package: {
          type: "string",
          description: "Optional package name to scope the search (e.g. 'ed25519').",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "get_symbol",
    description:
      "Get full details (kind, doc comment, source link, members) for a specific symbol.",
    inputSchema: {
      type: "object",
      properties: {
        package: { type: "string", description: "Package name (e.g. 'ed25519')." },
        name: { type: "string", description: "Exported symbol name." },
      },
      required: ["package", "name"],
      additionalProperties: false,
    },
  },
  {
    name: "get_guide",
    description: "Get the README / hand-written guide for a package.",
    inputSchema: {
      type: "object",
      properties: { package: { type: "string" } },
      required: ["package"],
      additionalProperties: false,
    },
  },
  {
    name: "find_examples",
    description:
      "Find code examples whose summary or doc comment matches a query, across @frosts packages.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
      additionalProperties: false,
    },
  },
];

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

function listPackages(): string {
  const data = loadIndex();
  if (!data) return "MCP index not found.";
  const lines = data.packages.map(
    (p) =>
      `- **@frosts/${p.name}** (${String(p.symbolCount)} symbols) — ${p.description || "no description"}\n  ${p.url}`,
  );
  return `# @frosts packages (${String(data.packages.length)})\n\n${lines.join("\n")}`;
}

function searchSymbols(query: string, pkg?: string): string {
  const data = loadSearch();
  if (!data) return "MCP search index not found.";
  const q = query.toLowerCase();
  const matches = data.filter((s) => {
    if (pkg !== undefined && s.package !== pkg) return false;
    return s.name.toLowerCase().includes(q) || s.summary.toLowerCase().includes(q);
  });
  if (matches.length === 0) {
    return `No symbols matched "${query}"${pkg !== undefined ? ` in @frosts/${pkg}` : ""}.`;
  }
  const limited = matches.slice(0, 100);
  const lines = limited.map(
    (m) =>
      `- \`${m.kind} ${m.name}\` — @frosts/${m.package}\n  ${m.summary || "(no summary)"}\n  ${m.url}`,
  );
  const suffix =
    matches.length > limited.length
      ? `\n\n_${String(matches.length - limited.length)} more results truncated._`
      : "";
  const scope = pkg !== undefined ? ` in @frosts/${pkg}` : "";
  return `# ${String(matches.length)} match${matches.length === 1 ? "" : "es"} for "${query}"${scope}\n\n${lines.join("\n")}${suffix}`;
}

function getSymbol(pkg: string, name: string): string {
  const data = loadPackage(pkg);
  if (!data) return `Package not found: ${pkg}`;
  const sym: SymbolData | undefined = data.symbols[name];
  if (!sym) return `Symbol \`${name}\` not found in @frosts/${pkg}.`;
  const out: string[] = [];
  out.push(`# ${sym.kind} \`${sym.name}\` — @frosts/${pkg}`);
  out.push("");
  if (sym.summary) {
    out.push(`> ${sym.summary}`);
    out.push("");
  }
  if (sym.comment && sym.comment !== sym.summary) {
    out.push(sym.comment);
    out.push("");
  }
  if (sym.members && sym.members.length > 0) {
    out.push("## Members");
    out.push("");
    for (const m of sym.members) {
      out.push(`- \`${m.kind} ${m.name}\`${m.summary ? ` — ${m.summary}` : ""}`);
    }
    out.push("");
  }
  out.push(`HTML: ${sym.url}`);
  if (sym.source !== undefined) out.push(`Source: ${sym.source}`);
  return out.join("\n");
}

function getGuide(pkg: string): string {
  const md = loadGuide(pkg);
  if (md === undefined) return `No guide available for @frosts/${pkg}.`;
  return md;
}

function extractCodeBlocks(text: string): string[] {
  const blocks: string[] = [];
  const re = /```(?:ts|typescript|js|javascript)?\s*\n([\s\S]*?)\n```/g;
  let m: RegExpExecArray | null = re.exec(text);
  while (m !== null) {
    blocks.push((m[1] ?? "").trim());
    m = re.exec(text);
  }
  return blocks;
}

function findExamples(query: string): string {
  const search = loadSearch();
  if (!search) return "MCP search index not found.";
  const q = query.toLowerCase();
  const candidates = search.filter(
    (s) => s.summary.toLowerCase().includes(q) || s.name.toLowerCase().includes(q),
  );
  if (candidates.length === 0) return `No examples found for "${query}".`;

  // Group by package; load each package's full data to scan comments for code blocks.
  const byPkg = new Map<string, SearchEntry[]>();
  for (const c of candidates) {
    const list = byPkg.get(c.package) ?? [];
    list.push(c);
    byPkg.set(c.package, list);
  }
  const sections: string[] = [];
  let total = 0;
  for (const [pkg, syms] of byPkg) {
    if (total >= 20) break;
    const data: PackageData | undefined = loadPackage(pkg);
    if (!data) continue;
    for (const s of syms) {
      if (total >= 20) break;
      const full: SymbolData | undefined = data.symbols[s.name];
      if (full === undefined || full.comment === "") continue;
      const blocks = extractCodeBlocks(full.comment);
      const matchingBlocks = blocks.filter((b) => b.toLowerCase().includes(q));
      if (matchingBlocks.length === 0 && !full.comment.toLowerCase().includes(q)) continue;
      const block = matchingBlocks[0] ?? blocks[0];
      const body = block !== undefined ? `${CODE_FENCE}ts\n${block}\n${CODE_FENCE}` : full.summary;
      sections.push(`## @frosts/${pkg} · \`${full.kind} ${full.name}\`\n\n${body}\n\n${full.url}`);
      total++;
    }
  }
  if (sections.length === 0) return `No examples found for "${query}".`;
  return `# Examples matching "${query}"\n\n${sections.join("\n\n")}`;
}

// ---------------------------------------------------------------------------
// JSON-RPC dispatch
// ---------------------------------------------------------------------------

export interface RpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

interface RpcSuccess {
  jsonrpc: "2.0";
  id: number | string | null;
  result: unknown;
}

interface RpcErrorResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  error: { code: number; message: string; data?: unknown };
}

export type RpcResponse = RpcSuccess | RpcErrorResponse;

export function rpcError(
  id: number | string | null,
  code: number,
  message: string,
): RpcErrorResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

/** Read a string argument, defaulting to "" when absent or non-string. */
function strArg(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  return typeof value === "string" ? value : "";
}

/** Read an optional string argument, `undefined` when absent or non-string. */
function optStrArg(args: Record<string, unknown>, key: string): string | undefined {
  const value = args[key];
  return typeof value === "string" ? value : undefined;
}

function callTool(name: string, args: Record<string, unknown>): ToolResult {
  let text: string;
  try {
    switch (name) {
      case "list_packages":
        text = listPackages();
        break;
      case "search_symbols":
        text = searchSymbols(strArg(args, "query"), optStrArg(args, "package"));
        break;
      case "get_symbol":
        text = getSymbol(strArg(args, "package"), strArg(args, "name"));
        break;
      case "get_guide":
        text = getGuide(strArg(args, "package"));
        break;
      case "find_examples":
        text = findExamples(strArg(args, "query"));
        break;
      default:
        return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    }
  } catch (err) {
    return {
      content: [{ type: "text", text: `Tool error: ${(err as Error).message}` }],
      isError: true,
    };
  }
  return { content: [{ type: "text", text }] };
}

export function dispatch(req: RpcRequest): RpcResponse | undefined {
  // Notifications carry no `id` → no response.
  const isNotification = req.id === undefined;
  const id = req.id ?? null;

  if (req.method === "initialize") {
    if (isNotification) return undefined;
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        serverInfo: SERVER_INFO,
        capabilities: { tools: {} },
        instructions:
          "@frosts docs MCP. Use `list_packages` first, then `search_symbols`, `get_symbol`, `get_guide`, or `find_examples`.",
      },
    };
  }
  if (req.method === "notifications/initialized" || req.method === "initialized") {
    return undefined;
  }
  if (req.method === "tools/list") {
    if (isNotification) return undefined;
    return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
  }
  if (req.method === "tools/call") {
    if (isNotification) return undefined;
    const params = (req.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
    if (params.name === undefined) return rpcError(id, -32602, "Missing tool name");
    return { jsonrpc: "2.0", id, result: callTool(params.name, params.arguments ?? {}) };
  }
  if (req.method === "ping") {
    if (isNotification) return undefined;
    return { jsonrpc: "2.0", id, result: {} };
  }
  if (isNotification) return undefined;
  return rpcError(id, -32601, `Method not found: ${req.method}`);
}
