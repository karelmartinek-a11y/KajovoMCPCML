import { describe, expect, it } from "vitest";
import { validateManifest } from "./registration.js";

const validManifest = {
  schemaVersion: "1.3",
  registrationRevision: "rev-1",
  environment: "production",
  handlerKey: "example",
  handlerVersion: "1.0.0",
  displayName: "Example",
  businessPurpose: "A concrete production purpose.",
  owners: { service: "svc", technical: "tech", security: "sec", operations: "ops" },
  tool: {
    name: "example",
    title: "example",
    description: "Example tool",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    outputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false, taskSupport: "forbidden" }
  },
  behavior: {
    effectClass: "READ_ONLY",
    timeoutMs: 1000,
    maxConcurrency: 1,
    requestMaxBytes: 1024,
    responseMaxBytes: 1024,
    rateLimit: { windowSeconds: 60, maxRequests: 10 },
    shutdownPolicy: "COMPLETE_IN_FLIGHT",
    idempotencyPolicy: "read only",
    retryPolicy: { automaticRetry: false }
  },
  testContract: { safeInput: {}, expectedResult: {}, cleanupOrCompensation: "none required" },
  monitoringProfile: {
    sloTargets: {},
    probeIntervals: {},
    alertRules: [{ severity: "critical" }],
    runbookRef: "docs/runbooks/example.md",
    primaryAlertChannel: "primary",
    backupAlertChannel: "backup"
  },
  approvals: { architecture: "approved", security: "approved", operations: "approved" },
  artifact: {
    digest: `sha256:${"a".repeat(64)}`,
    sbomDigest: `sha256:${"b".repeat(64)}`
  },
  change: { rollbackRef: "rollback", decommissionRef: "decommission", reviewDueAt: "2027-01-01T00:00:00.000Z" }
};

describe("registration manifest", () => {
  it("accepts strict complete manifests", () => {
    expect(validateManifest(validManifest).digest).toMatch(/^sha256:/);
  });

  it("rejects unknown fields and automatic retry", () => {
    expect(() => validateManifest({ ...validManifest, extra: true })).toThrow();
    expect(() => validateManifest({ ...validManifest, behavior: { ...validManifest.behavior, retryPolicy: { automaticRetry: true } } })).toThrow();
  });

  it("binds the digest to nested contract values", () => {
    const original = validateManifest(validManifest).digest;
    const changed = validateManifest({
      ...validManifest,
      behavior: { ...validManifest.behavior, timeoutMs: validManifest.behavior.timeoutMs + 1 }
    }).digest;
    expect(changed).not.toBe(original);
  });
});
