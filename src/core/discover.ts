import { readFile, stat } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { z } from "zod";

import { logger } from "../shared/logger.js";
import { VERSION } from "../shared/version.js";
import { checkHttpTransport } from "./httpChecks.js";
import { DEFAULT_LIMITS, enforceLimits, type Limits } from "./limits.js";
import type { ServerInventory, TargetSource, ToolInfo } from "./types.js";

export type Target =
  | { kind: "stdio"; command: string; args: string[]; env?: Record<string, string> }
  | { kind: "http"; url: string; headers?: Record<string, string> }
  | { kind: "json"; path: string };

/** A live connection kept open after discovery so --probe can reuse it. */
export interface Connection {
  inventory: ServerInventory;
  client?: Client;
  /** Canary injected into the server environment (stdio only). */
  canary?: string;
  /** Epoch ms when this server's time budget runs out (live targets only). */
  deadline?: number;
  close(): Promise<void>;
}

export class TargetError extends Error {}

export const CANARY_ENV = "MCP_GUARD_CANARY_TOKEN";

export function newClient(): Client {
  return new Client({ name: "mcp-guard", version: VERSION }, { capabilities: {} });
}

/**
 * Reads every list the server advertises, following pagination cursors up to
 * the item limit, then applies the size limits (see limits.ts).
 */
export async function inventoryFromClient(
  client: Client,
  source: TargetSource,
  fallbackName: string,
  limits: Limits = DEFAULT_LIMITS,
): Promise<ServerInventory> {
  const caps = client.getServerCapabilities() ?? {};
  const info = client.getServerVersion();
  const inv: ServerInventory = {
    name: (info?.name || fallbackName).slice(0, 128),
    source,
    ...(info ? { serverInfo: { name: info.name, version: info.version } } : {}),
    ...(client.getInstructions() ? { instructions: client.getInstructions() } : {}),
    tools: [],
    resources: [],
    resourceTemplates: [],
    prompts: [],
    truncated: [],
  };
  const list = <R extends { nextCursor?: string }, T>(
    what: string,
    fetchPage: (cursor?: string) => Promise<R>,
    pick: (r: R) => T[],
  ) =>
    paginate(fetchPage, pick, limits.maxItems, () =>
      inv.truncated!.push(`${what} beyond the first ${limits.maxItems}`),
    );
  if (caps.tools) {
    // The SDK types schemas loosely; the rules read them as plain JSON Schema.
    inv.tools = (await list(
      "tools",
      (cursor) => client.listTools({ cursor }),
      (r) => r.tools,
    )) as ToolInfo[];
  }
  if (caps.resources) {
    inv.resources = await list(
      "resources",
      (cursor) => client.listResources({ cursor }),
      (r) => r.resources,
    );
    inv.resourceTemplates = await list(
      "resource templates",
      (cursor) => client.listResourceTemplates({ cursor }),
      (r) => r.resourceTemplates,
    ).catch(() => []); // optional method; some servers answer MethodNotFound
  }
  if (caps.prompts) {
    inv.prompts = await list(
      "prompts",
      (cursor) => client.listPrompts({ cursor }),
      (r) => r.prompts,
    );
  }
  return enforceLimits(inv, limits);
}

const MAX_PAGES = 100;

async function paginate<R extends { nextCursor?: string }, T>(
  fetchPage: (cursor?: string) => Promise<R>,
  pick: (r: R) => T[],
  maxItems: number,
  onTruncate: () => void,
): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await fetchPage(cursor);
    out.push(...pick(page));
    cursor = page.nextCursor;
    if (out.length > maxItems || (cursor && out.length === maxItems)) {
      onTruncate();
      return out.slice(0, maxItems);
    }
    if (!cursor) return out;
  }
  onTruncate();
  return out;
}

export interface OpenOptions {
  timeoutMs: number;
  limits?: Limits;
}

/** Opens a target. A JSON export can hold several servers, hence the array. */
export async function openTarget(target: Target, opts: OpenOptions): Promise<Connection[]> {
  if (target.kind === "json") {
    return (await loadExports(target.path, opts.limits)).map((inventory) => ({
      inventory,
      close: async () => {},
    }));
  }
  return [await connect(target, opts)];
}

async function connect(
  target: Exclude<Target, { kind: "json" }>,
  opts: OpenOptions,
): Promise<Connection> {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const deadline = Date.now() + limits.serverTimeoutMs;
  const client = newClient();
  let transport: Transport;
  let source: TargetSource;
  let canary: string | undefined;
  let fallbackName: string;

  if (target.kind === "stdio") {
    canary = `mcpguard-canary-${crypto.randomUUID()}`;
    // The server gets the SDK's minimal environment (PATH, HOME...), not ours:
    // a scanned server should not see the CI runner's tokens.
    transport = new StdioClientTransport({
      command: target.command,
      args: target.args,
      env: { ...getDefaultEnvironment(), ...target.env, [CANARY_ENV]: canary },
      stderr: "pipe",
    });
    source = { kind: "stdio", command: target.command, args: target.args };
    fallbackName = [target.command, ...target.args].join(" ");
  } else {
    transport = new StreamableHTTPClientTransport(new URL(target.url), {
      requestInit: { headers: target.headers ?? {} },
    });
    source = { kind: "http", url: target.url };
    fallbackName = target.url;
  }

  // Each step gets the per-request timeout, and all of them together the server's budget.
  const left = (what: string) => {
    const ms = Math.min(opts.timeoutMs, deadline - Date.now());
    if (ms <= 0)
      throw new Error(`server time budget (${limits.serverTimeoutMs} ms) exhausted before ${what}`);
    return ms;
  };
  try {
    await withTimeout(
      client.connect(transport),
      left("connecting"),
      `connecting to ${fallbackName}`,
    );
    // Listing may take several pages, so it gets the whole remaining budget.
    const inventory = await withTimeout(
      inventoryFromClient(client, source, fallbackName, limits),
      Math.max(1, deadline - Date.now()),
      `listing ${fallbackName}`,
    );
    if (target.kind === "http") {
      inventory.transport = await checkHttpTransport(
        target.url,
        target.headers ?? {},
        left("transport checks"),
      );
    }
    logger.info({ server: inventory.name, tools: inventory.tools.length }, "inventory collected");
    return {
      inventory,
      client,
      deadline,
      ...(canary ? { canary } : {}),
      close: () => client.close(),
    };
  } catch (err) {
    await client.close().catch(() => {});
    throw new TargetError(`Could not scan ${fallbackName}: ${explain(err)}`);
  }
}

function explain(err: unknown): string {
  if (err instanceof StreamableHTTPError && (err.code === 401 || err.code === 403)) {
    return `the server requires credentials (HTTP ${err.code}); pass them with -H "Authorization: Bearer <token>"`;
  }
  if (err instanceof StreamableHTTPError && err.code) return `HTTP ${err.code} ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

async function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms ${what}`)), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------- JSON export

const ToolSchema = z.looseObject({
  name: z.string(),
  title: z.string().optional(),
  description: z.string().optional(),
  inputSchema: z.record(z.string(), z.unknown()).optional(),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
  annotations: z.record(z.string(), z.unknown()).optional(),
});

const ServerExport = z.object({
  name: z.string().optional(),
  instructions: z.string().optional(),
  tools: z.array(ToolSchema).default([]),
  resources: z
    .array(z.looseObject({ uri: z.string(), name: z.string(), description: z.string().optional() }))
    .default([]),
  resourceTemplates: z
    .array(
      z.looseObject({
        uriTemplate: z.string(),
        name: z.string(),
        description: z.string().optional(),
      }),
    )
    .default([]),
  prompts: z
    .array(
      z.looseObject({
        name: z.string(),
        description: z.string().optional(),
        arguments: z
          .array(
            z.object({
              name: z.string(),
              description: z.string().optional(),
              required: z.boolean().optional(),
            }),
          )
          .optional(),
      }),
    )
    .default([]),
});

/**
 * Accepts what people actually have on disk: a tools/list result
 * (`{ "tools": [...] }`), a bare array of tools, or several servers
 * (`{ "servers": [{ "name": ..., "tools": [...] }] }`) so cross-server rules
 * can run without starting anything.
 */
export async function loadExports(
  path: string,
  limits: Limits = DEFAULT_LIMITS,
): Promise<ServerInventory[]> {
  let raw: unknown;
  try {
    const { size } = await stat(path);
    if (size > limits.maxServerChars) {
      throw new Error(
        `${size} bytes is over the ${limits.maxServerChars}-byte limit (--max-server-mb)`,
      );
    }
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    throw new TargetError(
      `Could not read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseExport(raw, path, limits);
}

/**
 * Turns an already-parsed export into inventories. `path` names the source in
 * the report and gives the fallback server name; the MCP server passes a label.
 */
export function parseExport(
  raw: unknown,
  path: string,
  limits: Limits = DEFAULT_LIMITS,
): ServerInventory[] {
  const fallback = path
    .split("/")
    .pop()!
    .replace(/\.json$/, "");
  const entries: unknown[] = Array.isArray(raw)
    ? [{ tools: raw }]
    : raw && typeof raw === "object" && Array.isArray((raw as { servers?: unknown }).servers)
      ? (raw as { servers: unknown[] }).servers
      : [raw];

  return entries.map((entry, i) => {
    const parsed = ServerExport.safeParse(entry);
    if (!parsed.success) {
      throw new TargetError(`${path}: not a tools/list export (${z.prettifyError(parsed.error)})`);
    }
    const s = parsed.data;
    const truncated: string[] = [];
    const cap = <T>(what: string, items: unknown[]): T[] => {
      if (items.length > limits.maxItems)
        truncated.push(`${what} beyond the first ${limits.maxItems}`);
      return items.slice(0, limits.maxItems) as T[];
    };
    return enforceLimits(
      {
        name: (s.name ?? (entries.length > 1 ? `${fallback}#${i + 1}` : fallback)).slice(0, 128),
        source: { kind: "json", path },
        ...(s.instructions ? { instructions: s.instructions } : {}),
        tools: cap("tools", s.tools),
        resources: cap("resources", s.resources),
        resourceTemplates: cap("resource templates", s.resourceTemplates),
        prompts: cap("prompts", s.prompts),
        truncated,
      },
      limits,
    );
  });
}

/** Splits a command line on whitespace, honouring single and double quotes. */
export function splitCommand(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += ch;
    }
  }
  if (quote) throw new TargetError(`Unterminated quote in command: ${line}`);
  if (has || cur) out.push(cur);
  return out;
}
