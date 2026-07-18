import { afterEach, describe, expect, it } from "vitest";
import { buildMetadata } from "./release.js";

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
