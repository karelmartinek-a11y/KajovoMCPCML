export const KCML_RELEASE = {
  normativeLabel: "2026.07.22-COMPLIANCE.1",
  applicationVersion: "2026.07.22-compliance.1",
  catalogVersion: "2026.07.22-compliance.1",
  manifestSchemaVersion: "2026.07.22-compliance.1",
  pulseEnvelopeVersion: "2026.07.22-compliance.1",
  policyBaseline: "2026-07-22",
  mcpProtocolVersion: "2025-11-25"
} as const;

function commitFromBuildId(buildId: string | undefined): string | undefined {
  const match = buildId?.match(/^([0-9a-f]{40})(?:[-_.]|$)/i);
  return match?.[1]?.toLowerCase();
}

export function buildMetadata(): { buildId: string; commitSha: string } {
  const buildId = process.env.KCML_BUILD_ID ?? process.env.GITHUB_RUN_ID ?? process.env.BUILD_ID;
  const commitSha = process.env.KCML_COMMIT_SHA
    ?? process.env.GITHUB_SHA
    ?? process.env.COMMIT_SHA
    ?? process.env.SOURCE_COMMIT
    ?? commitFromBuildId(buildId)
    ?? "unknown";
  return { buildId: buildId ?? commitSha, commitSha };
}
