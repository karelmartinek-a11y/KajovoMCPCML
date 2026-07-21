export const KCML_RELEASE = {
  normativeLabel: "2026.07.19-NR",
  auditedBaselineCommit: "e2589ca4dc0b4ecb442aa8ef36141609b3b4dd76",
  applicationVersion: "2026.07.24",
  blueprintVersion: "2026.07.24",
  catalogVersion: "2026.07.24",
  manifestSchemaVersion: "2026.07.24",
  pulseEnvelopeVersion: "2026.07.24",
  policyBaseline: "2026-07-24",
  mcpProtocolVersion: "2025-11-25"
} as const;

export const KCML_RELEASE_WAVE_KEY = "baseline-2026-07-24";
export const KCML_RELEASE_WAVE_LABEL = "Prvni release vlna 9 AI / 11 MCP / 5 managed";

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

export const KCML_MANAGED_COMPONENTS = [
  ["KCML-AUTH-001", "PLATFORM_AUTH"],
  ["KCML-CTL-002", "CONTROL_PLANE"],
  ["KCML-MON-003", "MONITORING"],
  ["KCML-AUD-004", "AUDIT_ARCHIVE"],
  ["KCML-SEC-005", "SECRET_MANAGER"]
] as const;

export type KcmlBlueprintComponentId =
  | (typeof KCML_AI_COMPONENTS)[number][0]
  | (typeof KCML_MCP_COMPONENTS)[number][0]
  | (typeof KCML_MANAGED_COMPONENTS)[number][0];

export const KCML_BLUEPRINT_COMPONENT_IDS = [
  ...KCML_AI_COMPONENTS.map(([componentId]) => componentId),
  ...KCML_MCP_COMPONENTS.map(([componentId]) => componentId),
  ...KCML_MANAGED_COMPONENTS.map(([componentId]) => componentId)
] as readonly KcmlBlueprintComponentId[];

export type KcmlGeneratedBlueprintComponentId =
  | (typeof KCML_AI_COMPONENTS)[number][0]
  | (typeof KCML_MCP_COMPONENTS)[number][0];

export const KCML_GENERATED_BLUEPRINT_COMPONENT_IDS = [
  ...KCML_AI_COMPONENTS.map(([componentId]) => componentId),
  ...KCML_MCP_COMPONENTS.map(([componentId]) => componentId)
] as readonly KcmlGeneratedBlueprintComponentId[];

export const KCML_PLATFORM_PREREQUISITE_COMPONENT_IDS = [
  ...KCML_MANAGED_COMPONENTS.map(([componentId]) => componentId)
] as readonly (typeof KCML_MANAGED_COMPONENTS)[number][0][];

export const KCML_BLUEPRINT_RELEASE_MAX_CHILD_JOBS = KCML_GENERATED_BLUEPRINT_COMPONENT_IDS.length;

export function isGeneratedBlueprintComponentId(componentId: string): componentId is KcmlGeneratedBlueprintComponentId {
  return (KCML_GENERATED_BLUEPRINT_COMPONENT_IDS as readonly string[]).includes(componentId);
}

export type BlueprintComponentContract = {
  componentId: KcmlBlueprintComponentId;
  category: "AI_AGENT" | "MCP_SERVER" | "PLATFORM_SERVICE";
  registrationType: "KCML_ACCESS_CLIENT" | "MCP_SERVER" | "MANAGED_PLATFORM_SERVICE";
  role: "AGENT" | "SERVICE" | "PLATFORM";
  releaseVersion: typeof KCML_RELEASE.catalogVersion;
  releaseWaveKey: typeof KCML_RELEASE_WAVE_KEY;
};

export const KCML_BLUEPRINT_COMPONENT_CONTRACTS: Record<KcmlBlueprintComponentId, BlueprintComponentContract> = Object.fromEntries([
  ...KCML_AI_COMPONENTS.map(([componentId]) => [componentId, {
    componentId,
    category: "AI_AGENT",
    registrationType: "KCML_ACCESS_CLIENT",
    role: "AGENT",
    releaseVersion: KCML_RELEASE.catalogVersion,
    releaseWaveKey: KCML_RELEASE_WAVE_KEY
  }]),
  ...KCML_MCP_COMPONENTS.map(([componentId]) => [componentId, {
    componentId,
    category: "MCP_SERVER",
    registrationType: "MCP_SERVER",
    role: "SERVICE",
    releaseVersion: KCML_RELEASE.catalogVersion,
    releaseWaveKey: KCML_RELEASE_WAVE_KEY
  }]),
  ...KCML_MANAGED_COMPONENTS.map(([componentId]) => [componentId, {
    componentId,
    category: "PLATFORM_SERVICE",
    registrationType: "MANAGED_PLATFORM_SERVICE",
    role: "PLATFORM",
    releaseVersion: KCML_RELEASE.catalogVersion,
    releaseWaveKey: KCML_RELEASE_WAVE_KEY
  }])
]) as Record<KcmlBlueprintComponentId, BlueprintComponentContract>;

export function blueprintComponentContract(componentId: string): BlueprintComponentContract | null {
  return KCML_BLUEPRINT_COMPONENT_CONTRACTS[componentId as KcmlBlueprintComponentId] ?? null;
}

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
