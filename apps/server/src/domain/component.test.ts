import { describe, expect, it } from "vitest";
import { canonicalJson, componentManifestDigest, MCP_REQUIRED_CAPABILITIES, validateComponentManifest } from "./component.js";
import { KCML_RELEASE } from "./release.js";

function manifest(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: KCML_RELEASE.catalogVersion,
    blueprint: { componentId: "MCP-RX-WA-001", version: KCML_RELEASE.catalogVersion, releaseWaveKey: "baseline-2026-07-23" },
    name: "Testovací komponenta",
    description: "Bezpečný obecný runtime pro kontraktní test.",
    category: "MCP_SERVER",
    registrationType: "MCP_SERVER",
    role: "SERVICE",
    revision: "1.0.0",
    capabilities: [...MCP_REQUIRED_CAPABILITIES],
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
    const parsed = validateComponentManifest(manifest({ capabilities: ["zeta", ...MCP_REQUIRED_CAPABILITIES, "zeta", "alpha"] }));
    expect(parsed.capabilities).toEqual(["alpha", ...MCP_REQUIRED_CAPABILITIES, "zeta"].sort());
    expect(componentManifestDigest(parsed)).toHaveLength(64);
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("requires the complete MCP module for MCP server profiles", () => {
    expect(() => validateComponentManifest(manifest({ capabilities: ["mcp.initialize"] }))).toThrow("catalog_incompatible");
    expect(validateComponentManifest(manifest({
      capabilities: [...MCP_REQUIRED_CAPABILITIES]
    })).capabilities).toEqual([...MCP_REQUIRED_CAPABILITIES].sort());
  });

  it("rejects blueprint registration mismatches", () => {
    expect(() => validateComponentManifest(manifest({ registrationType: "KAJA_CLIENT" }))).toThrow("registration_type_mismatch");
  });

  it("rejects older schema versions for new component intake", () => {
    expect(() => validateComponentManifest(manifest({ schemaVersion: "2026.07.20" }))).toThrow("invalid_manifest");
  });
});
