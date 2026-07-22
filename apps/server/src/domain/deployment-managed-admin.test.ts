import { describe, expect, it } from "vitest";
import { canonicalAdminPassword, requireDeploymentManagedAdminPassword } from "./deployment-managed-admin.js";

describe("deployment managed admin password handling", () => {
  it("removes only trailing CRLF characters", () => {
    expect(canonicalAdminPassword("secret\r\n")).toBe("secret");
    expect(canonicalAdminPassword("secret\n\r")).toBe("secret");
    expect(canonicalAdminPassword("se\ncret")).toBe("se\ncret");
  });

  it("rejects empty PASS after canonicalization", () => {
    expect(() => requireDeploymentManagedAdminPassword(undefined)).toThrow("PASS must not be empty");
    expect(() => requireDeploymentManagedAdminPassword("\r\n")).toThrow("PASS must not be empty after removing trailing line endings");
  });
});
