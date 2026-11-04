export const REPO_URL = "https://github.com/diegoperezg7/mcp-guard-scan";

export function ruleDocUrl(id: string): string {
  return `${REPO_URL}/blob/main/docs/rules.md#${id.toLowerCase()}`;
}
