import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { digestCanonicalJson, reviewMetadataForManifest, validateManifest, validateOnboardingManifest, validateStoredOnboardingManifest } from "./registration.js";
import { KCML_RELEASE } from "./release.js";

const componentFixture = JSON.parse(
  readFileSync(new URL(`../../../../docs/onboarding-manifest-${KCML_RELEASE.manifestSchemaVersion}.example.json`, import.meta.url), "utf8")
) as Record<string, unknown>;

const legacy15Fixture = JSON.parse(
  readFileSync(new URL("../../../../docs/archive/pre-2026.07.20/onboarding-manifest-v1.5.example.json", import.meta.url), "utf8")
) as Record<string, unknown>;

function manifest(): Record<string, unknown> {
  return structuredClone(componentFixture);
}

describe(`component manifest ${KCML_RELEASE.manifestSchemaVersion}`, () => {
  it("accepts the published strict component example and normalizes the MCP runtime profile", () => {
    const accepted = validateOnboardingManifest(manifest());
    expect(accepted.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(accepted.manifest).toMatchObject({
      schemaVersion: KCML_RELEASE.manifestSchemaVersion,
      releaseVersion: KCML_RELEASE.applicationVersion,
      componentType: "MCP_SERVER",
      registrationType: "MCP_SERVER",
      pulseEnvelopeVersion: KCML_RELEASE.pulseEnvelopeVersion,
      protocol: { protocolVersion: KCML_RELEASE.mcpProtocolVersion },
      handlerKey: "whatsapp_ingress"
    });
  });

  it("uses the same strict contract for registration intake", () => {
    expect(validateManifest(manifest(), "hcasc.cz").manifest.schemaVersion).toBe(KCML_RELEASE.manifestSchemaVersion);
  });

  it("rejects platform-generated identity fields and old schema versions in new intake", () => {
    expect(() => validateOnboardingManifest({ ...manifest(), hostname: "kcml0001.hcasc.cz" })).toThrow("component_identity_forbidden");
    expect(() => validateOnboardingManifest(legacy15Fixture)).toThrow("old_manifest_schema_not_accepted");
  });

  it("binds the digest to the submitted component manifest", () => {
    const original = validateOnboardingManifest(manifest()).digest;
    const changed = manifest();
    changed.registrationRevision = "2026-07-20.2";
    expect(validateOnboardingManifest(changed).digest).not.toBe(original);
    const normalized = validateOnboardingManifest(changed).manifest;
    expect(digestCanonicalJson(normalized.tool.inputSchema)).toBe(normalized.contractDigests.inputSchema);
  });
});

describe("stored production manifest compatibility", () => {
  it("keeps normalized 2026.07.20 MCP manifests readable for monitoring and recertification", () => {
    const historic = structuredClone(validateOnboardingManifest(manifest()).manifest) as unknown as Record<string, unknown>;
    historic.schemaVersion = "2026.07.20";
    historic.releaseVersion = "2026.07.20";
    historic.pulseEnvelopeVersion = "2026.07.20";
    historic.blueprint = { ...(historic.blueprint as Record<string, unknown>), version: "2026.07.20" };
    const stored = validateStoredOnboardingManifest(historic);
    expect(stored.manifest.schemaVersion).toBe("2026.07.20");
    expect(reviewMetadataForManifest(stored.manifest)).toMatchObject({ intervalDays: 180 });
    expect(() => validateOnboardingManifest(historic)).toThrow("old_manifest_schema_not_accepted");
  });

  it("reads stored 1.5 manifests without accepting them as new intake", () => {
    const stored = validateStoredOnboardingManifest(legacy15Fixture);
    expect(stored.manifest.schemaVersion).toBe("1.5");
    expect(() => validateOnboardingManifest(legacy15Fixture)).toThrow("old_manifest_schema_not_accepted");
  });

  it("reads immutable historic 1.4 manifests for archival review only", () => {
    const legacy = {
      schemaVersion: "1.4",
      registrationRevision: "ha-device-catalog-2.0.16",
      environment: "production",
      handlerKey: "home_assistant_device_catalog",
      handlerVersion: "2.0.16",
      displayName: "Seznam zařízení Home Assistant",
      businessPurpose: "Poskytuje úplný aktuální katalog zařízení pro produkční agenty.",
      owners: { service: "Karel Martinek", technical: "Karel Martinek", security: "Karel Martinek", operations: "Karel Martinek" },
      source: { runtime: "nodejs22-typescript", entrypoint: "src/index.ts", testCommand: "pnpm test" },
      runtime: { memoryMb: 256, cpuCores: 0.5, pidsLimit: 64, egressAllowlist: ["ha-inventory.hcasc.cz:443"] },
      tool: {
        title: "Vyžádat kompletní seznam zařízení Home Assistant",
        description: "Vrátí aktuální katalog zařízení.",
        inputSchema: { type: "object", additionalProperties: false },
        outputSchema: { type: "object", additionalProperties: false },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false, taskSupport: "forbidden" }
      },
      behavior: {
        effectClass: "READ_ONLY", timeoutMs: 20_000, maxConcurrency: 2, requestMaxBytes: 1_024, responseMaxBytes: 1_048_576,
        rateLimit: { windowSeconds: 60, maxRequests: 10 }, shutdownPolicy: "COMPLETE_IN_FLIGHT",
        idempotencyPolicy: "Operace je pouze pro čtení a je bezpečně opakovatelná.", retryPolicy: { automaticRetry: false }
      },
      testContract: { safeInput: {}, expectedResult: {}, cleanupOrCompensation: "Není potřeba; operace je pouze pro čtení." },
      monitoringProfile: {
        sloTargets: { availabilityPercent: 99 }, probeIntervals: { syntheticSeconds: 300 },
        alertRules: [{ name: "catalog_probe_failure", severity: "critical", consecutiveFailures: 3 }],
        runbookRef: "mcp-handler/README.md", primaryAlertChannel: "KCML operations", backupAlertChannel: "Karel Martinek"
      },
      change: {
        rollbackRef: "Vrátit produkční handler na předchozí podepsaný OCI digest.",
        decommissionRef: "Deaktivovat MCP server a odstranit runtime.",
        reviewDueAt: "2027-01-13T00:00:00.000Z"
      }
    };
    const stored = validateStoredOnboardingManifest(legacy);
    expect(stored.manifest.schemaVersion).toBe("1.4");
    expect(reviewMetadataForManifest(stored.manifest)).toMatchObject({ reviewDueAt: "2027-01-13T00:00:00.000Z", intervalDays: 365 });
    expect(() => validateOnboardingManifest(legacy)).toThrow("old_manifest_schema_not_accepted");
  });
});
