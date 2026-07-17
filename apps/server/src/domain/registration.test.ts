import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { digestCanonicalJson, reviewMetadataForManifest, validateManifest, validateOnboardingManifest, validateStoredOnboardingManifest } from "./registration.js";

const manifestFixture = JSON.parse(
  readFileSync(new URL("../../../../docs/onboarding-manifest-v1.5.example.json", import.meta.url), "utf8")
) as Record<string, unknown>;

function manifest(): Record<string, unknown> {
  return structuredClone(manifestFixture);
}

describe("registration manifest 1.5", () => {
  it("accepts the published strict onboarding example", () => {
    expect(validateOnboardingManifest(manifest()).digest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("uses the same strict contract for registration intake", () => {
    expect(validateManifest(manifest(), "hcasc.cz").digest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("rejects unknown fields and automatic retry", () => {
    expect(() => validateOnboardingManifest({ ...manifest(), bypassActivation: true })).toThrow();
    const changed = manifest();
    changed.behavior = {
      ...(changed.behavior as Record<string, unknown>),
      retryPolicy: { automaticRetry: true }
    };
    expect(() => validateOnboardingManifest(changed)).toThrow();
  });

  it("rejects runtime expansion beyond the isolation contract", () => {
    const changed = manifest();
    changed.runtime = { ...(changed.runtime as Record<string, unknown>), memoryMb: 2_048 };
    expect(() => validateOnboardingManifest(changed)).toThrow();
  });

  it("binds the digest to nested contract values", () => {
    const original = validateOnboardingManifest(manifest()).digest;
    const changed = manifest();
    changed.behavior = { ...(changed.behavior as Record<string, unknown>), timeoutMs: 10_001 };
    expect(validateOnboardingManifest(changed).digest).not.toBe(original);
  });

  it("rejects schema digest drift before registration", () => {
    const changed = manifest();
    const tool = changed.tool as Record<string, unknown>;
    tool.inputSchema = {
      ...(tool.inputSchema as Record<string, unknown>),
      description: "An unapproved schema change"
    };
    expect(() => validateOnboardingManifest(changed)).toThrow("input_schema_digest_mismatch");
  });

  it("computes the published schema digest canonically", () => {
    const current = manifest();
    const tool = current.tool as Record<string, unknown>;
    const digests = current.contractDigests as Record<string, unknown>;
    expect(digestCanonicalJson(tool.inputSchema)).toBe(digests.inputSchema);
    expect(digestCanonicalJson(tool.outputSchema)).toBe(digests.outputSchema);
  });
});

describe("stored production manifest 1.5 compatibility", () => {
  it("normalizes the historic nodejs22 runtime label without weakening intake", () => {
    const stored = manifest();
    const source = stored.source as Record<string, unknown>;
    source.runtime = "nodejs22-typescript";

    expect(validateStoredOnboardingManifest(stored).manifest.source.runtime).toBe("nodejs24-typescript");
    expect(() => validateOnboardingManifest(stored)).toThrow();
  });
});

describe("stored production manifest 1.4 compatibility", () => {
  const legacy = {
    schemaVersion: "1.4",
    registrationRevision: "ha-device-catalog-2.0.16",
    environment: "production",
    handlerKey: "home_assistant_device_catalog",
    handlerVersion: "2.0.16",
    displayName: "Seznam zařízení Home Assistant",
    businessPurpose: "Poskytuje úplný aktuální katalog zařízení pro produkční agenty.",
    owners: { service: "Karel Martinek", technical: "Karel Martinek", security: "Karel Martinek", operations: "Karel Martinek" },
    source: { runtime: "nodejs24-typescript", entrypoint: "src/index.ts", testCommand: "pnpm test" },
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

  it("reads the immutable historic production shape without accepting it at intake", () => {
    const stored = validateStoredOnboardingManifest(legacy);
    expect(stored.manifest.schemaVersion).toBe("1.4");
    expect(reviewMetadataForManifest(stored.manifest)).toMatchObject({ reviewDueAt: "2027-01-13T00:00:00.000Z", intervalDays: 365 });
    expect(() => validateOnboardingManifest(legacy)).toThrow();
  });
});
