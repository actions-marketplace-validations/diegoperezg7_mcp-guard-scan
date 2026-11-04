# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.1] - 2026-11-04

### Changed

- README: Glama score badge, and the published package page now matches the repository.
- Releases publish to npm through trusted publishing (OIDC with provenance) instead of a token.

## [1.1.0] - 2026-11-04

### Added

- `mcp-guard serve`: an MCP server on stdio, so an agent can check a server before you install it.
  Tools: `scan_tools_export` (static, no network or processes), `scan_server` (public https
  endpoints only; hosts that resolve to loopback, private or link-local addresses are refused
  unless `MCP_GUARD_ALLOW_PRIVATE_NETWORK=1`), `list_rules` and `explain_rule`.
  `MCP_GUARD_ALLOW_STDIO=1` adds `scan_stdio_server`. In its default configuration the server
  passes its own rules; with stdio enabled it reports MCPG-022 on itself, as it should.
- Published to npm as `mcp-guard-scan` (the `mcp-guard` name belongs to another package), with
  `mcp-guard-scan` as a second command name so `npx mcp-guard-scan` works, and to the MCP
  Registry as `io.github.diegoperezg7/mcp-guard-scan`.

### Changed

- The repository is now `diegoperezg7/mcp-guard-scan`: workflows must use
  `uses: diegoperezg7/mcp-guard-scan@v1` (GitHub does not redirect actions after a rename).
- `parseExport` in the library API: scan an export that is already in memory.

### Unchanged

- `scan`, `rules` and the GitHub Action behave as in 1.0.1.

## [1.0.1] - 2026-10-28

### Fixed

- MCPG-003 no longer reports a warning against sharing secrets ("Do not include any API keys or
  passwords in your query") as an exfiltration request. Found in the [field study](docs/field-study.md).

## [1.0.0] - 2026-10-28

First public release.

### Added

- GitHub Action (`uses: diegoperezg7/mcp-guard@v1`): scans stdio, Streamable HTTP and exported
  JSON targets in-process from a committed bundle, writes SARIF and an optional HTML report,
  appends the Markdown report to the job summary, sets `findings`, `critical`, `high`, `medium`,
  `low`, `verdict`, `sarif-file` and `html-report` outputs and fails according to `fail-on`.
- `npm run build:action`, and a CI check that fails when `dist/action` is stale.
- `action-selftest` workflow that runs the action against the demo servers.
- CLI `mcp-guard scan` over stdio, Streamable HTTP and exported `tools/list` JSON, with 24 rules
  for tool poisoning, shadowing, excessive permissions, secrets, transport and runtime behaviour,
  plus a coverage notice when input limits cut something.
- Optional read-only probe (`--probe`, `--allow-unsafe`) with canary inputs, and an optional LLM
  judge that only annotates MCPG-005 findings.
- Reports: terminal table, JSON, Markdown, SARIF 2.1.0 and a self-contained HTML report, all
  hardened against hostile server-supplied text.
- Input limits per list, field, server inventory and time, reported as MCPG-090 when reached.

### Changed

- Licensed under the Apache License 2.0.

[Unreleased]: https://github.com/diegoperezg7/mcp-guard-scan/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/diegoperezg7/mcp-guard-scan/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/diegoperezg7/mcp-guard-scan/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/diegoperezg7/mcp-guard-scan/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/diegoperezg7/mcp-guard-scan/releases/tag/v1.0.0
