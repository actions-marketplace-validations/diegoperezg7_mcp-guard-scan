import { Command, CommanderError } from "commander";

import { printable } from "../core/text.js";
import { logger } from "../shared/logger.js";
import { VERSION } from "../shared/version.js";
import { buildRulesCommand } from "./commands/rules.js";
import { buildScanCommand, EXIT, UsageError } from "./commands/scan.js";
import { buildServeCommand } from "./commands/serve.js";

const program = new Command()
  .name("mcp-guard")
  .description(
    "Security scanner for MCP servers: tool poisoning, shadowing, permissions, secrets and transport.",
  )
  .version(VERSION);

program.addCommand(buildScanCommand());
program.addCommand(buildRulesCommand());
program.addCommand(buildServeCommand());

// Commander exits with 1 on usage errors, which CI would read as "findings".
// Throw instead, so every usage error maps to 2 as documented.
for (const cmd of [program, ...program.commands]) cmd.exitOverride();

program.parseAsync(process.argv).catch((err: unknown) => {
  if (err instanceof CommanderError) {
    // Commander has already printed the message, help text or version.
    process.exit(err.exitCode === 0 ? EXIT.pass : EXIT.error);
  }
  if (!(err instanceof UsageError)) logger.debug({ err }, "unexpected error");
  // Error messages can quote what a server sent; print them inert.
  process.stderr.write(`Error: ${printable(err instanceof Error ? err.message : String(err))}\n`);
  process.exit(EXIT.error);
});
