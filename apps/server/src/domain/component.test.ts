import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalJson, componentManifestDigest, validateComponentManifest } from "./component.js";
import { KCML_RELEASE } from "./release.js";

const exampleManifest = JSON.parse(readFileSync(new URL("../../../../docs/onboarding-manifest-2026.07.23.example.json", import.meta.url), "utf8")) as Record<string, unknown>;

function manifest(overrides: Record<string, unknown> = {}) {
  return {
    ...structuredClone(exampleManifest),
    ...overrides
  };
}

describe(`component manifest ${KCML_RELEASE.catalogVersion}`, () => {
  it("validates the full catalog schema and creates a stable canonical digest", () => {
    const parsed = validateComponentManifest(manifest());
    expect(parsed.componentType).toBe("MCP_SERVER");
    expect(parsed.registrationType).toBe("MCP_SERVER");
    expect(componentManifestDigest(parsed)).toHaveLength(64);
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("rejects the former minimal runtime manifest", () => {
    expect(() => validateComponentManifest({
      schemaVersion: KCML_RELEASE.catalogVersion,
      blueprint: { componentId: "MCP-RX-WA-001", version: KCML_RELEASE.catalogVersion, releaseWaveKey: "baseline-2026-07-23" },
      name: "Minimal",
      category: "MCP_SERVER",
      registrationType: "MCP_SERVER",
      role: "SERVICE",
      revision: "1.0.0"
    })).toThrow("invalid_manifest");
  });

  it("rejects placeholder references even when the JSON schema shape is otherwise valid", () => {
    const invalid = manifest({
      documentationEvidence: [
        { ...(exampleManifest.documentationEvidence as Record<string, unknown>[])[0], evidenceRef: "evidence/todo.md" }
      ]
    });
    expect(() => validateComponentManifest(invalid)).toThrow("manifest_evidence_missing");
  });

  it("normalizes legacy KAJA_CLIENT only when it matches an AI access client contract", () => {
    const aiManifest = manifest({
      componentType: "AI_AGENT",
      registrationType: "KAJA_CLIENT",
      blueprint: { componentId: "AI-CLS-001", version: KCML_RELEASE.catalogVersion, releaseWaveKey: "baseline-2026-07-23" },
      agentKey: "classifier",
      agentVersion: "1.0.0",
      executionProfile: { mode: "isolated" },
      modelPolicy: { allowed: ["gpt-5"] },
      promptPolicy: { source: "repository" },
      toolScopesAllowlist: ["component.pulse"],
      memoryPolicy: { mode: "none" },
      fallbackPolicy: { mode: "fail-closed" },
      publicEndpoints: []
    });

    expect(validateComponentManifest(aiManifest).registrationType).toBe("KCML_ACCESS_CLIENT");
  });

  it("rejects older schema versions for new component intake", () => {
    expect(() => validateComponentManifest(manifest({ schemaVersion: "2026.07.20" }))).toThrow("invalid_manifest");
  });
});
