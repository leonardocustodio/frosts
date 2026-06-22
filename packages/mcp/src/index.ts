#!/usr/bin/env node
/**
 * `@frosts/mcp` — stdio entry point.
 *
 * Reads newline-delimited JSON-RPC 2.0 messages from stdin, dispatches them
 * against the docs server, and writes responses to stdout. This is the standard
 * MCP stdio transport, so any MCP-aware client can launch it via `npx`.
 */

import { type RpcRequest, type RpcResponse, dispatch, rpcError } from "./server.js";

function writeResponse(res: RpcResponse): void {
  process.stdout.write(`${JSON.stringify(res)}\n`);
}

function handleLine(line: string): void {
  const trimmed = line.trim();
  if (trimmed === "") return;

  let req: RpcRequest;
  try {
    req = JSON.parse(trimmed) as RpcRequest;
  } catch {
    writeResponse(rpcError(null, -32700, "Parse error"));
    return;
  }

  try {
    const res = dispatch(req);
    if (res) writeResponse(res);
  } catch (err) {
    writeResponse(rpcError(req.id ?? null, -32603, `Internal error: ${(err as Error).message}`));
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");

process.stdin.on("data", (chunk: string) => {
  buffer += chunk;
  let newline = buffer.indexOf("\n");
  while (newline !== -1) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    handleLine(line);
    newline = buffer.indexOf("\n");
  }
});

process.stdin.on("end", () => {
  if (buffer.trim() !== "") handleLine(buffer);
  process.exit(0);
});
