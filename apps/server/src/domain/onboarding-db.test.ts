import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import { registerDisabledServer, type ActivationJob } from "../onboarding/activation.js";
import {
  authenticateIntegrationToken,
  createIntegrationToken,
  createOnboardingJob,
  requestDigest,
  releaseQuarantinedOnboardingJob,
  revokeIntegrationToken,
  transitionJob
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
    const failed = await transitionJob(
      db,
      first.id,
      first.lockVersion,
      "FAILED",
      "pipeline.failed",
      { error: "regression test" },
      randomUUID(),
      { blocking_error_code: "regression_test", blocking_error_detail: "regression test" }
    );
    expect(failed.state).toBe("FAILED");
    await expect(createOnboardingJob(db, config, principal, "db-test-idempotency-other", manifest, evidence, randomUUID())).rejects.toThrow("integration_token_already_bound");
  });

  it("rejects a revoked token with the generic authentication error", async () => {
    const created = await createIntegrationToken(db, config, adminId, randomUUID(), "Revocation test");
    await revokeIntegrationToken(db, created.id, adminId, randomUUID());
    await expect(authenticateIntegrationToken(db, created.token, config)).rejects.toThrow("invalid_integration_token");
  });

  it("updates the registered server and preserves revision history on a repaired upload", async () => {
    const created = await createIntegrationToken(db, config, adminId, randomUUID(), "Revision update test");
    const principal = await authenticateIntegrationToken(db, created.token, config);
    const { manifest, digest: manifestDigest } = validateOnboardingManifest(manifestInput);
    const sourceDigest = `sha256:${"b".repeat(64)}`;
    const job = await createOnboardingJob(db, config, principal, "db-test-revision-update", manifest, {
      archivePath: "/tmp/source.zip",
      sourceDigest,
      manifestDigest,
      requestDigest: requestDigest(manifestDigest, sourceDigest),
      validation: { fileCount: 5 }
    }, randomUUID());
    await db.query("update onboarding_job set state='DEPLOYING' where id=$1", [job.id]);
    const first: ActivationJob = {
      id: job.id,
      code: String(job.code),
      hostname: String(job.hostname),
      toolName: String(job.toolName),
      manifestDigest,
      sourceDigest,
      imageReference: "ghcr.io/example/handler:first",
      imageDigest: `sha256:${"1".repeat(64)}`,
      sbomDigest: `sha256:${"2".repeat(64)}`,
      provenanceDigest: `sha256:${"3".repeat(64)}`,
      sourceCommit: "first-commit",
      buildId: "first-build",
      manifest
    };
    const serverId = await registerDisabledServer(db, first, "/run/kcml/first.sock", randomUUID());
    const revisedManifest = {
      ...manifest,
      registrationRevision: "db-test-2",
      handlerVersion: "2.0.0"
    };
    const second: ActivationJob = {
      ...first,
      manifest: revisedManifest,
      imageReference: "ghcr.io/example/handler:second",
      imageDigest: `sha256:${"4".repeat(64)}`,
      sourceCommit: "second-commit",
      buildId: "second-build"
    };
    const sameServerId = await registerDisabledServer(db, second, "/run/kcml/second.sock", randomUUID());
    expect(sameServerId).toBe(serverId);
    const registered = await db.query(
      "select handler_version,image_reference,image_digest,artifact_digest,runtime_socket,registration_state,enabled from mcp_server where id=$1",
      [serverId]
    );
    expect(registered.rows[0]).toMatchObject({
      handler_version: "2.0.0",
      image_reference: "ghcr.io/example/handler:second",
      image_digest: second.imageDigest,
      artifact_digest: second.imageDigest,
      runtime_socket: "/run/kcml/second.sock",
      registration_state: "REGISTERED_DISABLED",
      enabled: false
    });
    const revisions = await db.query("select revision from registration_revision where server_id=$1 order by created_at", [serverId]);
    expect(revisions.rows.map((row) => String((row as { revision: unknown }).revision))).toEqual(["db-test-1", "db-test-2"]);
  });

  it("requires manual quarantine release and keeps a resumed repair job waiting for a new revision", async () => {
    const created = await createIntegrationToken(db, config, adminId, randomUUID(), "Quarantine repair test");
    const principal = await authenticateIntegrationToken(db, created.token, config);
    const { manifest, digest: manifestDigest } = validateOnboardingManifest(manifestInput);
    const sourceDigest = `sha256:${"c".repeat(64)}`;
    const job = await createOnboardingJob(db, config, principal, "db-test-quarantine-repair", manifest, {
      archivePath: "/tmp/source.zip",
      sourceDigest,
      manifestDigest,
      requestDigest: requestDigest(manifestDigest, sourceDigest),
      validation: { fileCount: 5 }
    }, randomUUID());
    await db.query("update onboarding_job set state='QUARANTINED', completed_at=now() where id=$1", [job.id]);
    await expect(releaseQuarantinedOnboardingJob(db, job.id, "WRONG", "Valid repair reason", adminId, randomUUID())).rejects.toThrow("confirmation_code_mismatch");
    await releaseQuarantinedOnboardingJob(db, job.id, String(job.code), "Artifact registration metadata was repaired and a new source revision is required.", adminId, randomUUID());
    await createIntegrationToken(db, config, adminId, randomUUID(), "Quarantine repair resume", job.id);
    const stored = await db.query("select state,completed_at from onboarding_job where id=$1", [job.id]);
    expect(stored.rows[0]).toMatchObject({ state: "AWAITING_REVISION", completed_at: null });
    const transition = await db.query("select event_type from onboarding_event where job_id=$1 order by id desc limit 1", [job.id]);
    expect(transition.rows[0].event_type).toBe("quarantine.revision_approved");
  });
});
