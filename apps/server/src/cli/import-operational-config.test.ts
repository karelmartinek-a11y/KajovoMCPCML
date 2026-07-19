import { describe, expect, it } from "vitest";
import { shouldRefreshExistingOperationalSetting } from "./import-operational-config.js";

describe("operational config environment import", () => {
  it("refreshes the deployment admin username only when it is explicit in the server environment", () => {
    expect(shouldRefreshExistingOperationalSetting({
      key: "adminBootstrapUsername",
      envKey: "ADMIN_BOOTSTRAP_USERNAME",
      options: { refreshBuildId: true },
      env: { ADMIN_BOOTSTRAP_USERNAME: "karmar78" }
    })).toBe(true);

    expect(shouldRefreshExistingOperationalSetting({
      key: "adminBootstrapUsername",
      envKey: "ADMIN_BOOTSTRAP_USERNAME",
      options: { refreshBuildId: true },
      env: {}
    })).toBe(false);
  });

  it("keeps build id refresh behavior narrow", () => {
    expect(shouldRefreshExistingOperationalSetting({
      key: "buildId",
      envKey: "BUILD_ID",
      options: { refreshBuildId: true },
      env: {}
    })).toBe(true);

    expect(shouldRefreshExistingOperationalSetting({
      key: "githubOwner",
      envKey: "GITHUB_OWNER",
      options: { refreshBuildId: true },
      env: { GITHUB_OWNER: "example" }
    })).toBe(false);
  });
});
