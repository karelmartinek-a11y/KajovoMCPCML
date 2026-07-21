import { afterEach, describe, expect, it } from "vitest";
import {
  buildMetadata,
  isGeneratedBlueprintComponentId,
  KCML_AI_COMPONENTS,
  KCML_BLUEPRINT_COMPONENT_IDS,
  KCML_BLUEPRINT_RELEASE_MAX_CHILD_JOBS,
  KCML_GENERATED_BLUEPRINT_COMPONENT_IDS,
  KCML_MANAGED_SERVICE_IDS,
  KCML_MCP_COMPONENTS,
  KCML_PLATFORM_PREREQUISITE_COMPONENT_IDS,
  KCML_RELEASE
} from "./release.js";

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

describe("buildMetadata", () => {
  it("derives commitSha from deployment build id when no explicit commit env exists", () => {
    delete process.env.KCML_COMMIT_SHA;
    delete process.env.GITHUB_SHA;
    delete process.env.COMMIT_SHA;
    delete process.env.SOURCE_COMMIT;
    delete process.env.KCML_BUILD_ID;
    delete process.env.GITHUB_RUN_ID;
    process.env.BUILD_ID = "89f56ddd3b91ec50a5bc37b60e1239403807e1b8-29625860458-1";

    expect(buildMetadata()).toEqual({
      buildId: "89f56ddd3b91ec50a5bc37b60e1239403807e1b8-29625860458-1",
      commitSha: "89f56ddd3b91ec50a5bc37b60e1239403807e1b8"
    });
  });

  it("prefers explicit commit env over parsed build id", () => {
    process.env.BUILD_ID = "89f56ddd3b91ec50a5bc37b60e1239403807e1b8-29625860458-1";
    process.env.KCML_COMMIT_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    expect(buildMetadata().commitSha).toBe("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  });
});

describe("release descriptor", () => {
  it("separates normative label, technical catalog version and MCP protocol", () => {
    expect(KCML_RELEASE.normativeLabel).toBe("2026.07.19-NR");
    expect(KCML_RELEASE.catalogVersion).toBe("2026.07.24");
    expect(KCML_RELEASE.mcpProtocolVersion).toBe("2025-11-25");
    expect(KCML_RELEASE.auditedBaselineCommit).toMatch(/^[a-f0-9]{40}$/);
  });

  it("keeps blueprint release child jobs limited to generated AI and MCP components", () => {
    expect(KCML_AI_COMPONENTS).toHaveLength(9);
    expect(KCML_MCP_COMPONENTS).toHaveLength(11);
    expect(KCML_MANAGED_SERVICE_IDS).toHaveLength(5);
    expect(KCML_GENERATED_BLUEPRINT_COMPONENT_IDS).toHaveLength(20);
    expect(KCML_PLATFORM_PREREQUISITE_COMPONENT_IDS).toEqual([...KCML_MANAGED_SERVICE_IDS]);
    expect(KCML_BLUEPRINT_RELEASE_MAX_CHILD_JOBS).toBe(20);
    expect(KCML_GENERATED_BLUEPRINT_COMPONENT_IDS.every(isGeneratedBlueprintComponentId)).toBe(true);
    expect(KCML_MANAGED_SERVICE_IDS.some(isGeneratedBlueprintComponentId)).toBe(false);
    expect(new Set(KCML_BLUEPRINT_COMPONENT_IDS)).toEqual(new Set([...KCML_GENERATED_BLUEPRINT_COMPONENT_IDS, ...KCML_PLATFORM_PREREQUISITE_COMPONENT_IDS]));
  });
});
