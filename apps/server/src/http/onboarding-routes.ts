import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { ZodError } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import {
  authenticateIntegrationToken,
  cancelOnboardingJob,
  createIntegrationToken,
  createOnboardingJob,
  deleteIntegrationToken,
  getOnboardingJob,
  listIntegrationTokens,
  listOnboardingJobs,
  replaceOnboardingSource,
  requestDigest,
  revokeIntegrationToken
} from "../domain/onboarding.js";
import { validateOnboardingManifest } from "../domain/registration.js";
import { MAX_ARCHIVE_BYTES, validateAndQuarantineArchive } from "../domain/upload-validation.js";
import { requireCsrf, sessionAccountId } from "./admin-routes.js";
import { hostOf, sendError } from "./errors.js";

const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const ONBOARDING_CATALOG_FILE = "Connect_in_Catalog_KajovoMCPCML_v1.4.docx";

function bearer(request: FastifyRequest): string | null {
  const authorization = request.headers.authorization;
  return authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : null;
}

async function programmerPrincipal(db: Db, config: AppConfig, request: FastifyRequest, reply: FastifyReply) {
  const value = bearer(request);
  if (!value) {
    sendError(reply, 401, "invalid_integration_token", "Invalid integration token");
    return null;
  }
  try {
    return await authenticateIntegrationToken(db, value, config);
  } catch {
    sendError(reply, 401, "invalid_integration_token", "Invalid integration token");
    return null;
  }
}

function idempotencyKey(request: FastifyRequest): string | null {
  const value = request.headers["idempotency-key"];
  return typeof value === "string" && IDEMPOTENCY_KEY.test(value) ? value : null;
}

function statusCode(error: unknown): number {
  if (error instanceof ZodError) return 400;
  return Number((error as { statusCode?: number }).statusCode ?? 500);
}

function errorCode(error: unknown): string {
  if (error instanceof ZodError) return "invalid_manifest";
  return error instanceof Error ? error.message.split(":")[0] ?? "operation_failed" : "operation_failed";
}

async function multipartPayload(request: FastifyRequest): Promise<{ manifestInput: unknown; archive: Buffer }> {
  if (!request.isMultipart()) throw Object.assign(new Error("multipart_required"), { statusCode: 415 });
  let manifestText: string | null = null;
  let archive: Buffer | null = null;
  for await (const part of request.parts()) {
    if (part.type === "file") {
      if (part.fieldname !== "source" || archive) throw Object.assign(new Error("invalid_source_part"), { statusCode: 400 });
      if (part.mimetype !== "application/zip" && part.mimetype !== "application/x-zip-compressed") throw Object.assign(new Error("source_must_be_zip"), { statusCode: 415 });
      archive = await part.toBuffer();
    } else if (part.fieldname === "manifest" && typeof part.value === "string") {
      manifestText = part.value;
    }
  }
  if (!manifestText || !archive) throw Object.assign(new Error("manifest_and_source_required"), { statusCode: 400 });
  let manifestInput: unknown;
  try {
    manifestInput = JSON.parse(manifestText);
  } catch {
    throw Object.assign(new Error("invalid_manifest_json"), { statusCode: 400 });
  }
  return { manifestInput, archive };
}

async function validatedUpload(request: FastifyRequest, config: AppConfig) {
  const { manifestInput, archive } = await multipartPayload(request);
  const { manifest, digest: manifestDigest } = validateOnboardingManifest(manifestInput);
  const validation = await validateAndQuarantineArchive(archive, config.QUARANTINE_ROOT);
  return {
    manifest,
    validation,
    evidence: {
      archivePath: validation.archivePath,
      sourceDigest: validation.sourceDigest,
      manifestDigest,
      requestDigest: requestDigest(manifestDigest, validation.sourceDigest),
      validation: {
        fileCount: validation.fileCount,
        expandedBytes: validation.expandedBytes,
        files: validation.files,
        packageName: validation.packageName,
        dependencyCount: validation.dependencyCount
      }
    }
  };
}

function adminHost(config: AppConfig, request: FastifyRequest, reply: FastifyReply, correlationId?: string): boolean {
  if (hostOf(request.headers.host) === config.ADMIN_HOST) return true;
  sendError(reply, 404, "not_found", undefined, correlationId);
  return false;
}

async function adminIdentity(db: Db, config: AppConfig, request: FastifyRequest, reply: FastifyReply, correlationId?: string, csrfRequired = false): Promise<string | null> {
  if (!adminHost(config, request, reply, correlationId)) return null;
  const accountId = await sessionAccountId(db, request);
  if (!accountId) {
    sendError(reply, 401, "unauthorized", undefined, correlationId);
    return null;
  }
  if (csrfRequired && !requireCsrf(request)) {
    sendError(reply, 403, "csrf_failed", undefined, correlationId);
    return null;
  }
  return accountId;
}

export function registerOnboardingRoutes(app: FastifyInstance, db: Db, config: AppConfig): void {
  app.post("/api/integration-tokens", async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    if (!config.ONBOARDING_WORKER_ENABLED) {
      return sendError(reply, 503, "onboarding_unavailable", "Automatická integrace není na serveru připravená.", correlationId);
    }
    const body = request.body as { note?: unknown; label?: unknown; resumeJobId?: unknown };
    const note = typeof body.note === "string" ? body.note.trim() : "";
    const legacyLabel = typeof body.label === "string" ? body.label.trim() : "";
    const label = note || legacyLabel;
    const resumeJobId = typeof body.resumeJobId === "string" && body.resumeJobId ? body.resumeJobId : undefined;
    if (!label || label.length > 120) return sendError(reply, 400, "invalid_label", "Label is required and must be at most 120 characters", correlationId);
    try {
      await fs.access(path.resolve(process.cwd(), ONBOARDING_CATALOG_FILE));
    } catch {
      return sendError(reply, 503, "onboarding_catalog_unavailable", "Onboarding katalog v1.4 není na serveru dostupný.", correlationId);
    }
    try {
      reply.header("cache-control", "no-store");
      return {
        ...await createIntegrationToken(db, config, accountId, correlationId, label, resumeJobId),
        onboardingCatalogUrl: "/api/onboarding-catalog",
        onboardingCatalogFileName: ONBOARDING_CATALOG_FILE,
        programmerApiUrl: `https://${config.REGISTER_HOST}/v1/onboardings`
      };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.get("/api/onboarding-catalog", async (request, reply) => {
    if (!await adminIdentity(db, config, request, reply)) return;
    try {
      const catalog = await fs.readFile(path.resolve(process.cwd(), ONBOARDING_CATALOG_FILE));
      return reply
        .header("cache-control", "private, no-store")
        .header("content-disposition", `attachment; filename="${ONBOARDING_CATALOG_FILE}"`)
        .type("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        .send(catalog);
    } catch {
      return sendError(reply, 503, "onboarding_catalog_unavailable");
    }
  });

  app.get("/api/integration-tokens", async (request, reply) => {
    if (!await adminIdentity(db, config, request, reply)) return;
    reply.header("cache-control", "no-store");
    return { tokens: await listIntegrationTokens(db) };
  });

  app.get("/api/onboarding-jobs", async (request, reply) => {
    if (!await adminIdentity(db, config, request, reply)) return;
    return { jobs: await listOnboardingJobs(db) };
  });

  app.get("/api/onboarding-jobs/:id", async (request, reply) => {
    if (!await adminIdentity(db, config, request, reply)) return;
    const { id } = request.params as { id: string };
    try {
      return { job: await getOnboardingJob(db, id) };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error));
    }
  });

  app.post("/api/integration-tokens/:id/revoke", async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    const { id } = request.params as { id: string };
    try {
      await revokeIntegrationToken(db, id, accountId, correlationId);
      return { ok: true };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.post("/api/integration-tokens/:id/delete", async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    const { id } = request.params as { id: string };
    try {
      await deleteIntegrationToken(db, id, accountId, correlationId);
      return { ok: true };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.post("/api/onboarding-jobs/:id/cancel", async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    const { id } = request.params as { id: string };
    try {
      await cancelOnboardingJob(db, id, "admin", accountId, correlationId);
      return { ok: true };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.post("/v1/onboardings", {
    bodyLimit: MAX_ARCHIVE_BYTES + 1024 * 1024,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await programmerPrincipal(db, config, request, reply);
    if (!principal) return;
    const key = idempotencyKey(request);
    if (!key) return sendError(reply, 400, "invalid_idempotency_key", undefined, correlationId);
    let upload: Awaited<ReturnType<typeof validatedUpload>> | null = null;
    try {
      upload = await validatedUpload(request, config);
      const job = await createOnboardingJob(db, config, principal, key, upload.manifest, upload.evidence, correlationId);
      if (principal.jobId) await fs.rm(upload.validation.directory, { recursive: true, force: true });
      reply.code(202).header("etag", `"${job.lockVersion}"`).header("cache-control", "no-store");
      return { job };
    } catch (error) {
      if (upload) await fs.rm(upload.validation.directory, { recursive: true, force: true }).catch(() => undefined);
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.get("/v1/onboardings/:id", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await programmerPrincipal(db, config, request, reply);
    if (!principal) return;
    const { id } = request.params as { id: string };
    if (principal.jobId !== id) return sendError(reply, 401, "invalid_integration_token", "Invalid integration token", correlationId);
    try {
      const job = await getOnboardingJob(db, id);
      reply.header("etag", `"${job.lockVersion}"`).header("cache-control", "no-store");
      return { job };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.put("/v1/onboardings/:id/source", {
    bodyLimit: MAX_ARCHIVE_BYTES + 1024 * 1024,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await programmerPrincipal(db, config, request, reply);
    if (!principal) return;
    const { id } = request.params as { id: string };
    if (principal.jobId !== id) return sendError(reply, 401, "invalid_integration_token", "Invalid integration token", correlationId);
    const key = idempotencyKey(request);
    const match = request.headers["if-match"];
    const lockVersion = typeof match === "string" ? Number(match.replaceAll('"', "")) : Number.NaN;
    if (!key || !Number.isSafeInteger(lockVersion) || lockVersion < 0) return sendError(reply, 400, "idempotency_key_and_if_match_required", undefined, correlationId);
    let upload: Awaited<ReturnType<typeof validatedUpload>> | null = null;
    try {
      upload = await validatedUpload(request, config);
      const job = await replaceOnboardingSource(db, principal, id, lockVersion, key, upload.manifest, upload.evidence, correlationId);
      reply.code(202).header("etag", `"${job.lockVersion}"`).header("cache-control", "no-store");
      return { job };
    } catch (error) {
      if (upload) await fs.rm(upload.validation.directory, { recursive: true, force: true }).catch(() => undefined);
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.post("/v1/onboardings/:id/cancel", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await programmerPrincipal(db, config, request, reply);
    if (!principal) return;
    const { id } = request.params as { id: string };
    if (principal.jobId !== id) return sendError(reply, 401, "invalid_integration_token", "Invalid integration token", correlationId);
    try {
      await cancelOnboardingJob(db, id, "integration_token", principal.fingerprint, correlationId);
      return { ok: true };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });
}
