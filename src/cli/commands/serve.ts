import { Command } from "commander";

import { ALLOW_PRIVATE_ENV, ALLOW_STDIO_ENV, startStdioServer } from "../../mcp/server.js";

export function buildServeCommand(): Command {
  return new Command("serve")
    .description("Run mcp-guard as an MCP server on stdio, for Claude, Cursor, VS Code and others.")
    .addHelpText(
      "after",
      `
Tools: scan_tools_export, scan_server, list_rules, explain_rule.
${ALLOW_STDIO_ENV}=1 adds scan_stdio_server, which starts commands.
${ALLOW_PRIVATE_ENV}=1 lets scan_server reach local and private addresses over http.`,
    )
    .action(async () => {
      await startStdioServer();
    });
}
