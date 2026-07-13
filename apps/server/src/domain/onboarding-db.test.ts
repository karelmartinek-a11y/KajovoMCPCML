import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import {
  authenticateIntegrationToken,
  createIntegrationToken,
  createOnboardingJob,
  requestDigest,
  revokeIntegrationToken
} from "./onboarding.js";
import { validateOnboardingManifest } from "./registration.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

const manifestInput = {
  schemaVersion: "1.4",
  registrationRevision: "db-test-1",
  environment: "staging",
  handlerKey: "db-test",
  handlerVersion: "1.0.0",
  displayName: "Database test",
  businessPurpose: "Validate transactional automated onboarding.",
  owners: { service: "test", technical: "test", security: "test", operations: "test" },
  source: { runtime: "nodejs22-typescript", entrypoint: "src/index.ts", testCommand: "pnpm test" },
  runtime: { memoryMb: 64, cpuCores: 0.1, pidsLimit: 16, egressAllowlist: [] },
  tool: { title: "DB test", description: "Database contract test", inputSchema: { type: "object", additionalProperties: false }, outputSchema: { type: "object", additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false, taskSupport: "forbidden" } },
  behavior: { effectClass: "READ_ONLY", timeoutMs: 1000, maxConcurrency: 1, requestMaxBytes: 1024, responseMaxBytes: 1024, rateLimit: { windowSeconds: 60, maxRequests: 5 }, shutdownPolicy: "COMPLETE_IN_FLIGHT", idempotencyPolicy: "read only", retryPolicy: { automaticRetry: false } },
  testContract: { safeInput: {}, expectedResult: {}, cleanupOrCompensation: "none" },
  monitoringProfile: { sloTargets: {}, probeIntervals: {}, alertRules: [{ severity: "critical" }], runbookRef: "test", primaryAlertChannel: "test", backupAlertChannel: "test" },
  change: { rollbackRef: "test", decommissionRef: "test", reviewDueAt: "2027-01-01T00:00:00.000Z" }
};

describe.skipIf(!enabled)("onboarding PostgreSQL transactions", () => {
  let db: Db;
  let config: AppConfig;
  let adminId: string;

  beforeAll(async () => {
    config = loadConfig(process.env);
    db = createDb(config);
    const admin = await db.query("select id from admin_account where username='karmar78'");
    adminId = String(admin.rows[0].id);
  });

  beforeEach(async () => {
    await db.query("truncate table onboarding_gate,onboarding_event,onboarding_source_revision,egress_capability,onboarding_job,integration_token,registration_revision,function_statistics,mcp_server,audit_event restart identity cascade");
  });

  afterAll(async () => db.end());

  it("stores only the HMAC lookup digest and makes first registration idempotent under concurrency", async () => {
    const created = await createIntegrationToken(db, config, adminId, randomUUID(), "DB integration test");
    expect(created.token).toMatch(/^kci_/);
    const stored = await db.query("select lookup_digest,fingerprint from integration_token where id=$1", [created.id]);
    expect(Buffer.isBuffer(stored.rows[0].lookup_digest)).toBe(true);
    expect(JSON.stringify(stored.rows[0])).not.toContain(created.token);
    const principal = await authenticateIntegrationToken(db, created.token, config);
    const { manifest, digest: manifestDigest } = validateOnboardingManifest(manifestInput);
    const sourceDigest = `sha256:${"b".repeat(64)}`;
    const evidence = { archivePath: "/tmp/source.zip", sourceDigest, manifestDigest, requestDigest: requestDigest(manifestDigest, sourceDigest), validation: { fileCount: 5 } };
    const idempotencyKey = "db-test-idempotency-0001";
    const [first, retry] = await Promise.all([
      createOnboardingJob(db, config, principal, idempotencyKey, manifest, evidence, randomUUID()),
      createOnboardingJob(db, config, principal, idempotencyKey, manifest, evidence, randomUUID())
    ]);
    expect(retry.id).toBe(first.id);
    expect(first.code).toBe("KCML0001");
    expect(first.hostname).toBe("kcml0001.hcasc.cz");
    expect((await db.query("select count(*)::int as count from onboarding_job")).rows[0].count).toBe(1);
    await expect(createOnboardingJob(db, config, principal, "db-test-idempotency-other", manifest, evidence, randomUUID())).rejects.toThrow("integration_token_already_bound");
  });

  it("rejects a revoked token with the generic authentication error", async () => {
    const created = await createIntegrationToken(db, config, adminId, randomUUID(), "Revocation test");
    await revokeIntegrationToken(db, created.id, adminId, randomUUID());
    await expect(authenticateIntegrationToken(db, created.token, config)).rejects.toThrow("invalid_integration_token");
  });
});
