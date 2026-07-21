import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import argon2 from "argon2";
import { authenticator } from "otplib";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import type { AdminReauthConfig, HostRoutingConfig, OnboardingRouteConfig } from "../config.js";
import type { Db } from "../db.js";
import { createExternalApiManagedService, updateExternalApiManagedService, validateExternalApiManifest } from "../domain/external-api.js";
import {
  authenticateIntegrationToken,
  beginActiveServerRevision,
  cancelOnboardingJob,
  createIntegrationToken,
  createOnboardingJob,
  deleteIntegrationToken,
  getOnboardingJob,
  listIntegrationTokens,
  listOnboardingJobs,
  replaceOnboardingSource,
  releaseQuarantinedOnboardingJob,
  requestDigest,
  revokeIntegrationToken
} from "../domain/onboarding.js";
import {
  MCP_CATALOG_PATH,
  MCP_CATALOG_VERSION,
  MCP_CONNECT_FILE,
  verifyMcpOnboardingCatalog
} from "../domain/onboarding-catalog.js";
import { KCML_BLUEPRINT_RELEASE_MAX_CHILD_JOBS, KCML_GENERATED_BLUEPRINT_COMPONENT_IDS, KCML_MANAGED_SERVICE_IDS, KCML_RELEASE, KCML_RELEASE_WAVE_KEY } from "../domain/release.js";
import { evidenceReferencesForManifest, validateOnboardingManifest } from "../domain/registration.js";
import { MAX_ARCHIVE_BYTES, validateAndQuarantineArchive } from "../domain/upload-validation.js";
import { decryptMfaSecret } from "../security/secrets.js";
import { requireCsrf, sessionAccount } from "./admin-routes.js";
import { hostOf, sendError } from "./errors.js";

const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const repositoryRoot = fileURLToPath(new URL("../../../../", import.meta.url));
const onboardingDescriptorSchema = z.object({
  summary: z.string().trim().min(3).max(240),
  businessPurpose: z.string().trim().min(20).max(2_000),
  serviceOwner: z.string().trim().min(2).max(160),
  technicalOwner: z.string().trim().min(2).max(160),
  criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
}).strict();
const KCML_ALL_BLUEPRINT_COMPONENT_IDS = [...KCML_GENERATED_BLUEPRINT_COMPONENT_IDS, ...KCML_MANAGED_SERVICE_IDS] as unknown as [string, ...string[]];
const integrationTokenRequestSchema = z.object({
  label: z.string().trim().min(1).max(120),
  serviceKind: z.enum(["MCP", "EXTERNAL_API"]).default("MCP"),
  tokenKind: z.enum(["SINGLE_COMPONENT", "BLUEPRINT_RELEASE"]).default("SINGLE_COMPONENT"),
  releaseWave: z.literal(KCML_RELEASE_WAVE_KEY).default(KCML_RELEASE_WAVE_KEY),
  allowedBlueprintComponentIds: z.array(z.enum(KCML_ALL_BLUEPRINT_COMPONENT_IDS)).optional(),
  maxChildJobs: z.number().int().min(1).max(KCML_BLUEPRINT_RELEASE_MAX_CHILD_JOBS).optional(),
  descriptor: onboardingDescriptorSchema
}).strict();

export function verifyEncryptedMfaTotp(
  totp: string,
  encryptedSecret: string,
  config: AdminReauthConfig
): boolean {
  try {
    return authenticator.check(totp, decryptMfaSecret(encryptedSecret, config.MFA_ENCRYPTION_KEY_BASE64, {
      allowLegacyPlaintext: config.MFA_ALLOW_PLAINTEXT_LEGACY
    }));
  } catch {
    return false;
  }
}

function bearer(request: FastifyRequest): string | null {
  const authorization = request.headers.authorization;
  return authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : null;
}

async function programmerPrincipal(db: Db, config: Pick<OnboardingRouteConfig, "INTEGRATION_TOKEN_HMAC_KEY_BASE64" | "INTEGRATION_TOKEN_HMAC_KEY_ID">, request: FastifyRequest, reply: FastifyReply) {
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

function logOnboardingError(request: FastifyRequest, error: unknown, correlationId: string, operation: string): void {
  request.log.error({ err: error, correlationId, operation }, "onboarding.route_error");
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

async function validatedUpload(request: FastifyRequest, config: Pick<OnboardingRouteConfig, "QUARANTINE_ROOT">) {
  const { manifestInput, archive } = await multipartPayload(request);
  const { manifest, digest: manifestDigest } = validateOnboardingManifest(manifestInput);
  const validation = await validateAndQuarantineArchive(archive, config.QUARANTINE_ROOT);
  const missingEvidence = evidenceReferencesForManifest(manifest).filter((reference) => !validation.files.includes(reference));
  if (missingEvidence.length) {
    await fs.rm(validation.directory, { recursive: true, force: true });
    throw Object.assign(new Error(`manifest_evidence_missing:${missingEvidence[0]}`), { statusCode: 400 });
  }
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

function adminHost(config: Pick<HostRoutingConfig, "ADMIN_HOST">, request: FastifyRequest, reply: FastifyReply, correlationId?: string): boolean {
  if (hostOf(request.headers.host) === config.ADMIN_HOST) return true;
  sendError(reply, 404, "not_found", undefined, correlationId);
  return false;
}

function onboardingHandoffUrls(registerHost: string, serviceKind: "MCP" | "EXTERNAL_API") {
  const legacyServiceIntakeUrl = `https://${registerHost}/v1/service-onboardings`;
  const nativeComponentIntakeUrl = `https://${registerHost}/v2/component-onboardings`;
  const externalApiIntakeUrl = `https://${registerHost}/v1/service-onboardings`;
  const recommendedIntakeUrl = serviceKind === "EXTERNAL_API"
    ? externalApiIntakeUrl
    : nativeComponentIntakeUrl;
  return {
    recommendedIntakeUrl,
    nativeComponentIntakeUrl,
    legacyServiceIntakeUrl,
    externalApiIntakeUrl,
    componentCatalogUrl: `https://${registerHost}/api/onboarding-catalogs/component/${MCP_CATALOG_VERSION}`,
    externalApiCatalogUrl: `https://${registerHost}/api/onboarding-catalogs/external-api/1.0`
  };
}

async function adminIdentity(db: Db, config: OnboardingRouteConfig, request: FastifyRequest, reply: FastifyReply, correlationId?: string, csrfRequired = false): Promise<string | null> {
  if (!adminHost(config, request, reply, correlationId)) return null;
  const session = await sessionAccount(db, request, config);
  if (!session) {
    sendError(reply, 401, "unauthorized", undefined, correlationId);
    return null;
  }
  if (csrfRequired && !requireCsrf(request)) {
    sendError(reply, 403, "csrf_failed", undefined, correlationId);
    return null;
  }
  return session.accountId;
}

export function registerOnboardingRoutes(app: FastifyInstance, db: Db, config: OnboardingRouteConfig): void {
  const createExternalApiOnboarding = async (request: FastifyRequest, reply: FastifyReply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await programmerPrincipal(db, config, request, reply);
    if (!principal) return;
    if (principal.serviceKind !== "EXTERNAL_API") return sendError(reply, 409, "integration_token_kind_mismatch", undefined, correlationId);
    const key = idempotencyKey(request);
    if (!key) return sendError(reply, 400, "invalid_idempotency_key", undefined, correlationId);
    try {
      const { manifest, digest } = validateExternalApiManifest(request.body);
      const receipt = await createExternalApiManagedService(db, config, principal, key, manifest, digest, correlationId);
      reply.code(202).header("etag", `"${receipt.lockVersion}"`).header("cache-control", "no-store");
      return { job: receipt };
    } catch (error) {
      logOnboardingError(request, error, correlationId, "external_api.create");
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  };

  const createMcpOnboarding = async (request: FastifyRequest, reply: FastifyReply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await programmerPrincipal(db, config, request, reply);
    if (!principal) return;
    if (principal.serviceKind !== "MCP") return sendError(reply, 409, "integration_token_kind_mismatch", undefined, correlationId);
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
  };

  app.post("/api/mcp-servers/:id/revisions", async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    const { id } = request.params as { id: string };
    try {
      return { jobId: await beginActiveServerRevision(db, id, accountId, correlationId) };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.post("/api/integration-tokens", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute", groupId: "admin-integration-token-create" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    if (!config.ONBOARDING_WORKER_ENABLED) {
      return sendError(reply, 503, "onboarding_unavailable", "Automatická integrace není na serveru připravená.", correlationId);
    }
    let parsed: z.infer<typeof integrationTokenRequestSchema>;
    try {
      parsed = integrationTokenRequestSchema.parse(request.body);
    } catch (error) {
      return sendError(reply, 400, "invalid_integration_descriptor", error instanceof Error ? error.message : undefined, correlationId);
    }
    try {
      await fs.access(path.resolve(process.cwd(), MCP_CONNECT_FILE));
    } catch {
      return sendError(reply, 503, "onboarding_catalog_unavailable", `Onboarding katalog v${MCP_CATALOG_VERSION} není na serveru dostupný.`, correlationId);
    }
    try {
      reply.header("cache-control", "no-store");
      return {
        ...await createIntegrationToken(db, config, accountId, correlationId, parsed.label, parsed.descriptor, undefined, {
          serviceKind: parsed.serviceKind,
          allowedPipeline: parsed.serviceKind === "EXTERNAL_API" ? "EXTERNAL_API_REGISTRATION" : "MCP_ONBOARDING",
          releaseVersion: KCML_RELEASE.catalogVersion,
          releaseWaveKey: parsed.releaseWave,
          allowedBlueprintComponentIds: parsed.allowedBlueprintComponentIds
        }),
        onboardingCatalogUrl: "/api/onboarding-catalog",
        onboardingCatalogFileName: MCP_CONNECT_FILE,
        programmerApiUrl: onboardingHandoffUrls(config.REGISTER_HOST, parsed.serviceKind).recommendedIntakeUrl,
        intakeUrls: onboardingHandoffUrls(config.REGISTER_HOST, parsed.serviceKind)
      };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.post("/api/integration-intents", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute", groupId: "admin-integration-intent-create" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    let parsed: z.infer<typeof integrationTokenRequestSchema>;
    try {
      parsed = integrationTokenRequestSchema.parse(request.body);
    } catch (error) {
      return sendError(reply, 400, "invalid_integration_descriptor", error instanceof Error ? error.message : undefined, correlationId);
    }
    try {
      const intent = await createIntegrationToken(db, config, accountId, correlationId, parsed.label, parsed.descriptor, undefined, {
        serviceKind: parsed.serviceKind,
        allowedPipeline: parsed.serviceKind === "EXTERNAL_API" ? "EXTERNAL_API_REGISTRATION" : "MCP_ONBOARDING",
        releaseVersion: KCML_RELEASE.catalogVersion,
        releaseWaveKey: parsed.releaseWave,
        allowedBlueprintComponentIds: parsed.allowedBlueprintComponentIds
      });
      return {
        integrationIntentId: intent.id,
        integrationToken: intent.token,
        serviceKind: parsed.serviceKind,
        releaseWave: intent.releaseWaveKey,
        allowedBlueprintComponents: intent.allowedBlueprintComponents,
        expiresAt: intent.expiresAt,
        intakeUrl: onboardingHandoffUrls(config.REGISTER_HOST, parsed.serviceKind).recommendedIntakeUrl,
        intakeUrls: onboardingHandoffUrls(config.REGISTER_HOST, parsed.serviceKind),
        catalogUrl: `https://${config.REGISTER_HOST}/api/onboarding-catalogs/${parsed.serviceKind === "EXTERNAL_API" ? "external-api/1.0" : `component/${MCP_CATALOG_VERSION}`}`
      };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.get("/api/onboarding-catalogs/:kind/:version", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute", groupId: "onboarding-catalog-json" } }
  }, async (request, reply) => {
    const host = hostOf(request.headers.host);
    if (host === config.ADMIN_HOST) {
      if (!await adminIdentity(db, config, request, reply)) return;
    } else if (host === config.REGISTER_HOST) {
      const principal = await programmerPrincipal(db, config, request, reply);
      if (!principal) return;
    } else {
      return sendError(reply, 404, "not_found");
    }
    const { kind, version } = request.params as { kind: string; version: string };
    const file = ["mcp", "component"].includes(kind) && version === MCP_CATALOG_VERSION
      ? path.resolve(repositoryRoot, MCP_CATALOG_PATH)
      : kind === "external-api" && version === "1.0"
        ? path.resolve(repositoryRoot, "docs/onboarding-catalogs/external-api-1.0.json")
        : null;
    if (!file) return sendError(reply, 404, "catalog_not_found");
    try {
      const text = await fs.readFile(file, "utf8");
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (kind === "mcp" || kind === "component") verifyMcpOnboardingCatalog(parsed);
      else parsed.canonicalDigest = `sha256:${createHash("sha256").update(text).digest("hex")}`;
      return reply.header("cache-control", "private, no-store").type("application/json").send(parsed);
    } catch {
      return sendError(reply, 503, "onboarding_catalog_invalid");
    }
  });

  app.get("/api/onboarding-catalog", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute", groupId: "admin-onboarding-catalog" } }
  }, async (request, reply) => {
    if (!await adminIdentity(db, config, request, reply)) return;
    try {
      const catalog = await fs.readFile(path.resolve(repositoryRoot, "docs/releases", MCP_CATALOG_VERSION, MCP_CONNECT_FILE));
      return reply
        .header("cache-control", "private, no-store")
        .header("content-disposition", `attachment; filename="${MCP_CONNECT_FILE}"`)
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

  app.post("/api/onboarding-jobs/:id/release-quarantine", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute", groupId: "admin-quarantine-release" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await adminIdentity(db, config, request, reply, correlationId, true);
    if (!accountId) return;
    const { id } = request.params as { id: string };
    const body = request.body as { confirmedCode?: unknown; reason?: unknown; password?: unknown; totp?: unknown };
    const confirmedCode = typeof body.confirmedCode === "string" ? body.confirmedCode.trim() : "";
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const totp = typeof body.totp === "string" ? body.totp.trim() : "";
    if (!confirmedCode || reason.length < 10 || reason.length > 1000 || !password) {
      return sendError(reply, 400, "invalid_quarantine_release", "Vyžaduje se přesný KCML kód, důvod (10–1000 znaků) a heslo.", correlationId);
    }
    const account = await db.query("select password_hash,mfa_enabled,mfa_secret from admin_account where id=$1", [accountId]);
    const passwordOk = Boolean(account.rowCount && account.rows[0].password_hash) && await argon2.verify(String(account.rows[0].password_hash), password);
    const mfaOk = account.rowCount && account.rows[0].mfa_enabled
      ? verifyEncryptedMfaTotp(totp, String(account.rows[0].mfa_secret), config)
      : true;
    if (!passwordOk || !mfaOk) return sendError(reply, 403, "reauthentication_failed", "Opětovné ověření administrátora selhalo.", correlationId);
    try {
      await releaseQuarantinedOnboardingJob(db, id, confirmedCode, reason, accountId, correlationId);
      return { ok: true };
    } catch (error) {
      return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
    }
  });

  app.post("/v1/onboardings", {
    bodyLimit: MAX_ARCHIVE_BYTES + 1024 * 1024,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } }
  }, createMcpOnboarding);

  app.post("/v1/service-onboardings", {
    bodyLimit: MAX_ARCHIVE_BYTES + 1024 * 1024,
    config: { rateLimit: { max: 5, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const token = bearer(request);
    if (!token) return createMcpOnboarding(request, reply);
    try {
      const principal = await authenticateIntegrationToken(db, token, config);
      return principal.serviceKind === "EXTERNAL_API"
        ? createExternalApiOnboarding(request, reply)
        : createMcpOnboarding(request, reply);
    } catch {
      return createMcpOnboarding(request, reply);
    }
  });

  app.get("/v1/integration-intent", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await programmerPrincipal(db, config, request, reply);
    if (!principal) return;
    return reply.header("cache-control", "no-store").send({
      release: KCML_RELEASE,
      token: {
        id: principal.id,
        fingerprint: principal.fingerprint,
        serviceKind: principal.serviceKind,
        allowedPipeline: principal.allowedPipeline,
        releaseVersion: principal.releaseVersion,
        releaseWaveKey: principal.releaseWaveKey,
        maxChildJobs: principal.maxChildJobs,
        expiresAt: principal.expiresAt,
        maxExpiresAt: principal.maxExpiresAt
      },
      blueprintRelease: {
        releaseVersion: KCML_RELEASE.applicationVersion,
        releaseWave: principal.releaseWaveKey ?? KCML_RELEASE_WAVE_KEY,
        allowedBlueprintComponentIds: principal.allowedBlueprintComponents.length
          ? principal.allowedBlueprintComponents.map((component) => component.componentId)
          : KCML_ALL_BLUEPRINT_COMPONENT_IDS,
        allowedBlueprintComponents: principal.allowedBlueprintComponents,
        allowedRegistrationTypes: principal.allowedBlueprintComponents.length
          ? [...new Set(principal.allowedBlueprintComponents.map((component) => component.registrationType))]
          : ["KCML_ACCESS_CLIENT", "MCP_SERVER", "MANAGED_PLATFORM_SERVICE"],
        maxChildJobs: principal.maxChildJobs,
        autoActivateAfterPass: false,
        manualApprovalRequiredAfterIssuance: false
      },
      intakeUrl: onboardingHandoffUrls(config.REGISTER_HOST, principal.serviceKind).recommendedIntakeUrl,
      intakeUrls: onboardingHandoffUrls(config.REGISTER_HOST, principal.serviceKind),
      catalogUrl: `https://${config.REGISTER_HOST}/api/onboarding-catalogs/component/${MCP_CATALOG_VERSION}`,
      correlationId
    });
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

  app.get("/v1/service-onboardings/:id", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request, reply) => {
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
    if (principal.jobId !== id || principal.serviceKind !== "MCP") return sendError(reply, 401, "invalid_integration_token", "Invalid integration token", correlationId);
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

  app.put("/v1/service-onboardings/:id/revision", {
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
    if (principal.serviceKind === "EXTERNAL_API") {
      try {
        const { manifest, digest } = validateExternalApiManifest(request.body);
        const job = await updateExternalApiManagedService(db, config, principal, id, lockVersion, key, manifest, digest, correlationId);
        reply.code(202).header("etag", `"${job.lockVersion}"`).header("cache-control", "no-store");
        return { job };
      } catch (error) {
        logOnboardingError(request, error, correlationId, "external_api.revision");
        return sendError(reply, statusCode(error), errorCode(error), undefined, correlationId);
      }
    }
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

  app.post("/v1/service-onboardings/:id/cancel", async (request, reply) => {
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
