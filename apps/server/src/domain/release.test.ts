import { afterEach, describe, expect, it } from "vitest";
import {
  buildMetadata,
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
    expect(KCML_RELEASE.normativeLabel).toBe("2026.07.22-COMPLIANCE.1");
    expect(KCML_RELEASE.catalogVersion).toBe("2026.07.22-compliance.1");
    expect(KCML_RELEASE.mcpProtocolVersion).toBe("2025-11-25");
    expect(Object.keys(KCML_RELEASE)).not.toContain("auditedBaselineCommit");
  });

  it("contains no fixed component allowlist metadata", () => {
    expect(Object.keys(KCML_RELEASE)).not.toContain(`release${"Wave"}Key`);
    expect(Object.keys(KCML_RELEASE)).not.toContain("blueprintVersion");
  });
});
