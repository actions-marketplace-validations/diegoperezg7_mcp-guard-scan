import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

import { RULES } from "../rules/index.js";
import { printable } from "../text.js";
import type { ScanReport } from "../scan.js";
import type { Finding, ServerInventory, Severity } from "../types.js";
import { ruleDocUrl } from "./links.js";

/** GitHub code scanning maps security-severity to its own labels: >= 9 critical, >= 7 high, >= 4 medium. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/**
 * SARIF 2.1.0 as GitHub code scanning reads it. Findings are not lines of
 * code, so each result points at the file that defines the target (the JSON
 * export, or the script a stdio command runs) and carries the tool or
 * resource as a logical location.
 */
export function toSarif(report: ScanReport, cwd = process.cwd()): object {
  const servers = new Map(report.servers.map((s) => [s.name, s]));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-guard",
            semanticVersion: report.scanner.version,
            informationUri: "https://github.com/diegoperezg7/mcp-guard-scan",
            rules: RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.title },
              fullDescription: { text: r.description },
              helpUri: ruleDocUrl(r.id),
              help: {
                text: `${r.description}\n\nRemediation: ${r.remediation}`,
                markdown: [
                  r.description,
                  `**Remediation.** ${r.remediation}`,
                  `Bad:\n\n\`\`\`\n${r.bad}\n\`\`\``,
                  `Good:\n\n\`\`\`\n${r.good}\n\`\`\``,
                  r.references.map((ref) => `- [${ref.title}](${ref.url})`).join("\n"),
                ].join("\n\n"),
              },
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: {
                "security-severity": SECURITY_SEVERITY[r.severity],
                precision: r.severity === "low" ? "medium" : "high",
                tags: ["security", "mcp", r.category],
              },
            })),
          },
        },
        automationDetails: { id: "mcp-guard/" },
        results: withOccurrence(report.findings).map(({ f, occurrence }) =>
          result(f, occurrence, servers.get(f.location.server), cwd),
        ),
      },
    ],
  };
}

const findingKey = (f: Finding) =>
  [f.ruleId, f.location.server, f.location.kind, f.location.name, f.location.field ?? ""].join(
    "\u0000",
  );

/**
 * Numbers findings that share rule and location (two secrets in one field),
 * so each gets its own fingerprint. Findings are sorted, so the numbering is
 * stable from one run to the next.
 */
function withOccurrence(findings: Finding[]): { f: Finding; occurrence: number }[] {
  const seen = new Map<string, number>();
  return findings.map((f) => {
    const key = findingKey(f);
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    return { f, occurrence };
  });
}

function result(
  f: Finding,
  occurrence: number,
  server: ServerInventory | undefined,
  cwd: string,
): object {
  const l = f.location;
  const where = printable(`[${l.server}] ${l.kind} "${l.name}"${l.field ? ` (${l.field})` : ""}`);
  const text = [
    `${where}: ${printable(f.message)}`,
    f.evidence ? `Evidence: ${printable(f.evidence)}` : "",
    f.judge
      ? `LLM judge (${printable(f.judge.model)}, informational): ${f.judge.verdict}. ${printable(f.judge.reason)}`
      : "",
  ]
    .filter(Boolean)
    .join("\n");
  return {
    ruleId: f.ruleId,
    ruleIndex: RULES.findIndex((r) => r.id === f.ruleId),
    level: LEVEL[f.severity],
    message: { text },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactFor(server, cwd) },
          region: { startLine: 1 },
        },
        logicalLocations: [
          {
            name: printable(l.name),
            fullyQualifiedName: printable(
              `${l.server}/${l.kind}/${l.name}${l.field ? `#${l.field}` : ""}`,
            ),
            kind:
              l.kind === "tool"
                ? "function"
                : l.kind === "server" || l.kind === "transport"
                  ? "module"
                  : "resource",
          },
        ],
      },
    ],
    partialFingerprints: {
      "mcpGuardFinding/v1": createHash("sha256")
        .update(`${findingKey(f)}\u0000${occurrence}`)
        .digest("hex")
        .slice(0, 32),
    },
    properties: {
      severity: f.severity,
      server: printable(l.server),
      ...(f.judge ? { judge: f.judge } : {}),
    },
  };
}

/** The repository file that best represents the target, so GitHub can attach the alert to something. */
function artifactFor(server: ServerInventory | undefined, cwd: string): string {
  const src = server?.source;
  if (src?.kind === "json") return toUri(src.path, cwd);
  if (src?.kind === "stdio") {
    const script = src.args.find(
      (a) => !a.startsWith("-") && /\.(m?[jt]s|py|cjs)$/.test(a) && existsSync(resolve(cwd, a)),
    );
    if (script) return toUri(script, cwd);
  }
  return "mcp-guard.targets";
}

/** Repository-relative when the file is inside the working directory, otherwise an absolute file:// URI. */
function toUri(path: string, cwd: string): string {
  const abs = resolve(cwd, path);
  const rel = relative(cwd, abs);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return pathToFileURL(abs).href;
  return rel.split(sep).map(encodeURIComponent).join("/");
}
