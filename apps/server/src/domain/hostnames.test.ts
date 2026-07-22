import { describe, expect, it } from "vitest";
import { canonicalKcmlHostnamePattern, controlPlaneHostnames, isKcmlHostname, kcmlHostnameForCode, normalizeBaseDomain } from "./hostnames.js";

describe("runtime hostname policy", () => {
  it("normalizes a configured domain and builds every hostname consistently", () => {
    expect(normalizeBaseDomain("Example.Test.")).toBe("example.test");
    expect(controlPlaneHostnames("example.test")).toEqual({
      adminHost: "admin.example.test",
      authHost: "auth.example.test",
      registerHost: "register.example.test"
    });
    expect(kcmlHostnameForCode("KCML0042")).toBe("kcml0042.kajovocml.hcasc.cz");
    expect(isKcmlHostname("kcml0042.kajovocml.hcasc.cz")).toBe(true);
    expect(canonicalKcmlHostnamePattern().test("kcml0042.kajovocml.hcasc.cz")).toBe(true);
  });

  it("escapes the configured domain and rejects malformed values", () => {
    expect(isKcmlHostname("kcml0042.hcasc.cz")).toBe(false);
    expect(canonicalKcmlHostnamePattern().test("kcml0042.hcasc.cz")).toBe(false);
    expect(() => normalizeBaseDomain("https://example.test/path")).toThrow("config_invalid_hostname");
    expect(() => kcmlHostnameForCode("not-kcml")).toThrow("invalid_kcml_code");
  });
});
