import { describe, expect, it } from "vitest";
import { canonicalJson, componentManifestDigest, MCP_REQUIRED_CAPABILITIES, validateComponentManifest } from "./component.js";
import { KCML_RELEASE } from "./release.js";

function manifest(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: KCML_RELEASE.catalogVersion,
    name: "Testovací komponenta",
    description: "Bezpečný obecný runtime pro kontraktní test.",
    category: "MANAGED_RUNTIME",
    registrationType: "GENERIC_COMPONENT",
    role: "RUNTIME",
    revision: "1.0.0",
    capabilities: ["component.discovery"],
    protocols: ["HTTPS"],
    transports: ["HTTPS"],
    owners: { service: "KCML" },
    contacts: { operations: "KCML" },
    monitoring: { enabled: true },
    audit: { enabled: true, replaySupported: true },
    authorization: { mode: "OAUTH2_CLIENT_CREDENTIALS" },
    endpoint: { public: true },
    technicalDisable: { supported: true },
    ...overrides
  };
}

describe(`component manifest ${KCML_RELEASE.catalogVersion}`, () => {
  it("normalizes unordered capability declarations and creates a stable canonical digest", () => {
    const parsed = validateComponentManifest(manifest({ capabilities: ["zeta", "component.discovery", "zeta", "alpha"] }));
    expect(parsed.capabilities).toEqual(["alpha", "component.discovery", "zeta"]);
    expect(componentManifestDigest(parsed)).toHaveLength(64);
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("requires the complete MCP module for MCP server profiles", () => {
    expect(() => validateComponentManifest(manifest({ category: "MCP_SERVER", registrationType: "MCP_SERVER" }))).toThrow("catalog_incompatible");
    expect(validateComponentManifest(manifest({
      category: "MCP_SERVER",
      registrationType: "MCP_SERVER",
      role: "SERVICE",
      capabilities: [...MCP_REQUIRED_CAPABILITIES]
    })).capabilities).toEqual([...MCP_REQUIRED_CAPABILITIES].sort());
  });

  it("rejects older schema versions for new component intake", () => {
    expect(() => validateComponentManifest(manifest({ schemaVersion: "2026.07.20" }))).toThrow("invalid_manifest");
  });
});
