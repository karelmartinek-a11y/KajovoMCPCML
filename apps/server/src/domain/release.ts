export const KCML_RELEASE = {
  applicationVersion: "2026.07.22",
  blueprintVersion: "2026.07.22",
  catalogVersion: "2026.07.22",
  manifestSchemaVersion: "2026.07.22",
  pulseEnvelopeVersion: "2026.07.22",
  policyBaseline: "2026-07-22",
  mcpProtocolVersion: "2025-11-25"
} as const;

export const KCML_MANAGED_SERVICE_IDS = [
  "KCML-AUTH-001",
  "KCML-CTL-002",
  "KCML-MON-003",
  "KCML-AUD-004",
  "KCML-SEC-005"
] as const;

export const KCML_AI_COMPONENTS = [
  ["AI-CLS-001", "AGENT_ROUTER"],
  ["AI-QRP-002", "AGENT_WORKER"],
  ["AI-LYL-003", "AGENT_WORKER"],
  ["AI-GRP-004", "AGENT_WORKER"],
  ["AI-BIZ-005", "AGENT_WORKER"],
  ["AI-IND-006", "AGENT_WORKER"],
  ["AI-HIS-007", "AGENT_CONTEXT"],
  ["AI-BRD-008", "AGENT_REVIEW"],
  ["AI-QA-009", "AGENT_QA"]
] as const;

export const KCML_MCP_COMPONENTS = [
  ["MCP-RX-WA-001", "EVENT_INGRESS"],
  ["MCP-RX-MS-002", "EVENT_INGRESS"],
  ["MCP-RX-EM-003", "EVENT_INGRESS"],
  ["MCP-RX-BC-004", "EVENT_INGRESS"],
  ["MCP-PMS-RO-005", "ISOLATED_HANDLER"],
  ["MCP-PMS-RW-006", "STATEFUL_HANDLER"],
  ["MCP-TX-WA-007", "ASYNC_EGRESS"],
  ["MCP-TX-MS-008", "ASYNC_EGRESS"],
  ["MCP-TX-EM-009", "ASYNC_EGRESS"],
  ["MCP-TX-BC-010", "ASYNC_EGRESS"],
  ["MCP-WFC-011", "STATEFUL_SERVICE"]
] as const;

export const KCML_BLUEPRINT_COMPONENT_IDS = [
  ...KCML_AI_COMPONENTS.map(([componentId]) => componentId),
  ...KCML_MCP_COMPONENTS.map(([componentId]) => componentId)
] as const;

function commitFromBuildId(buildId: string | undefined): string | undefined {
  const match = buildId?.match(/^([0-9a-f]{40})(?:[-_.]|$)/i);
  return match?.[1]?.toLowerCase();
}

export function buildMetadata(): { buildId: string; commitSha: string } {
  const buildId = process.env.KCML_BUILD_ID
    ?? process.env.GITHUB_RUN_ID
    ?? process.env.BUILD_ID;
  const commitSha = process.env.KCML_COMMIT_SHA
    ?? process.env.GITHUB_SHA
    ?? process.env.COMMIT_SHA
    ?? process.env.SOURCE_COMMIT
    ?? commitFromBuildId(buildId)
    ?? "unknown";
  return { buildId: buildId ?? commitSha, commitSha };
}
