import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AppServerConfig } from "../config.js";
import type { Db } from "../db.js";
import { ingestComponentAuditEvent } from "../domain/component-audit.js";
import { authorizeComponentCall, componentSourceIdentityMatches } from "../domain/component-auth.js";
import {
  cancelComponentOnboarding,
  COMPONENT_CATALOG_VERSION,
  createComponentOnboarding,
  evaluateComponentReadiness,
  getComponent,
  getComponentOnboarding,
  ingestComponentOperationEvent,
  ingestComponentPulse,
  listComponents,
  queueComponentE2ERun,
  queueComponentHeartbeatChallenge,
  queueComponentStateQuery,
  recordComponentControlAck,
  recordComponentHeartbeat,
  recordComponentStateObservation,
  recordComponentStateSnapshot,
  revokeComponentAccessToken,
  reviseComponentOnboarding,
  rotateComponentAccessToken,
  setComponentActivation,
  setComponentLifecycle,
  setComponentPermissionEnabled,
  type ComponentPulseEnvelope,
  validateComponentManifest
} from "../domain/component.js";
import { authenticateIntegrationToken } from "../domain/onboarding.js";
import { fetchThroughEgress } from "../domain/egress-client.js";
import { getPlatformWorkerAccessStatus, rotatePlatformWorkerAccessToken } from "../domain/platform-worker-access.js";
import {
  createExternalPrincipal,
  createExternalTarget,
  dispatchExternalComponentCall,
  listExternalPermissions,
  listExternalInboundPermissions,
  listExternalPrincipals,
  listExternalTargets,
  rotateExternalPrincipalAccessToken,
  setExternalInboundPermission,
  setExternalEntityStatus,
  setExternalPermission
} from "../domain/external-component.js";
import { requireCsrf, sessionAccount } from "./admin-routes.js";
import { hostOf, sendError } from "./errors.js";

const idempotencyKeyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const activationSchema = z.object({ enabled: z.boolean() }).strict();
const lifecycleSchema = z.object({ action: z.enum(["QUARANTINE", "RESTORE", "RETIRE", "DEREGISTER"]) }).strict();
const permissionSchema = z.object({ enabled: z.boolean() }).strict();
const requiredJson = z.custom<unknown>((value) => value !== undefined);
const externalPrincipalSchema = z.object({ publicId: z.string().min(3).max(120).regex(/^KCML-EXT-[A-Z0-9-]+$/), displayName: z.string().min(2).max(200), description: z.string().max(2000).optional() }).strict();
const externalTargetSchema = z.object({ targetKey: z.string().min(3).max(120).regex(/^[a-z0-9][a-z0-9.-]*$/), displayName: z.string().min(2).max(200), baseUrl: z.string().url(), allowedPathPrefixes: z.array(z.string().min(1).max(500)).max(30).optional(), requestTimeoutMs: z.number().int().min(100).max(60000).default(15000), maxRetries: z.number().int().min(0).max(3).default(1), circuitFailureThreshold: z.number().int().min(1).max(100).default(5), circuitOpenSeconds: z.number().int().min(1).max(3600).default(60) }).strict();
const externalStatusSchema = z.object({ status: z.enum(["ACTIVE", "DISABLED", "REVOKED"]) }).strict();
const externalPermissionSchema = z.object({ componentId: z.string().uuid().optional(), externalPrincipalId: z.string().uuid().optional(), externalTargetId: z.string().uuid(), routePattern: z.string().min(1).max(500), scopeName: z.string().min(2).max(200), enabled: z.boolean() }).strict();
const externalInboundPermissionSchema = z.object({ externalPrincipalId: z.string().uuid(), targetComponentId: z.string().uuid(), routePattern: z.string().startsWith("/").max(500), scopeName: z.string().min(2).max(200), enabled: z.boolean() }).strict();
const outboundGatewaySchema = z.object({ targetKey: z.string().min(3).max(120), routePath: z.string().startsWith("/").max(500), scopeName: z.string().min(2).max(200), payload: requiredJson }).strict();
const identitySchema = z.object({
  clientId: z.string().min(3).max(160),
  componentCode: z.string().min(3).max(120),
  audience: z.string().url().optional()
}).passthrough();
const fullPulseSchema = z.object({
  pulseType: z.string().min(3).max(160),
  direction: z.enum(["INCOMING", "OUTGOING"]),
  source: identitySchema,
  target: identitySchema,
  state: z.record(z.unknown()),
  operation: z.record(z.unknown()),
  input: requiredJson,
  process: requiredJson,
  output: requiredJson,
  success: z.boolean(),
  correlationId: z.string().uuid(),
  causationId: z.string().uuid().optional(),
  traceId: z.string().min(3).max(200).optional(),
  accessTokenFingerprint: z.string().min(8).max(200),
  occurredAt: z.string().datetime({ offset: true })
}).strict();
const heartbeatSchema = z.object({
  heartbeatAt: z.string().datetime({ offset: true }),
  operationalState: z.enum(["HEALTHY", "DEGRADED", "UNHEALTHY", "MAINTENANCE"]),
  stateDigest: z.string().startsWith("sha256:").optional(),
  correlationId: z.string().uuid(),
  declaredClientId: z.string().min(3).max(160),
  componentCode: z.string().min(3).max(120),
  policyEpoch: z.number().int().nonnegative(),
  challengeId: z.string().uuid().optional(),
  challengeNonce: z.string().uuid().optional(),
  payload: z.unknown().optional()
}).strict();
const stateObservationSchema = z.object({
  stateKey: z.string().min(2).max(160),
  observedAt: z.string().datetime({ offset: true }),
  correlationId: z.string().uuid(),
  declaredClientId: z.string().min(3).max(160),
  componentCode: z.string().min(3).max(120),
  policyEpoch: z.number().int().nonnegative(),
  queryId: z.string().uuid().optional(),
  statePayload: requiredJson
}).strict();
const stateSnapshotSchema = z.object({
  queryId: z.string().uuid(), queryNonce: z.string().uuid(), observedAt: z.string().datetime({ offset: true }),
  correlationId: z.string().uuid(), declaredClientId: z.string().min(3).max(160), componentCode: z.string().min(3).max(120),
  policyEpoch: z.number().int().nonnegative(), states: z.record(z.unknown())
}).strict();
const controlAckSchema = z.object({
  commandId: z.string().uuid(),
  commandType: z.enum(["enable", "disable", "state", "heartbeat"]),
  status: z.enum(["ACKED", "FAILED"]),
  ackPayload: requiredJson,
  correlationId: z.string().uuid(),
  declaredClientId: z.string().min(3).max(160),
  componentCode: z.string().min(3).max(120),
  policyEpoch: z.number().int().nonnegative()
}).strict();
type StateObservationBody = {
  stateKey: string;
  observedAt: string;
  correlationId: string;
  declaredClientId: string;
  componentCode: string;
  policyEpoch: number;
  queryId?: string;
  statePayload: unknown;
};
type ControlAckBody = {
  commandId: string;
  commandType: "enable" | "disable" | "state" | "heartbeat";
  status: "ACKED" | "FAILED";
  ackPayload: unknown;
  correlationId: string;
  declaredClientId: string;
  componentCode: string;
  policyEpoch: number;
};
const auditEventSchema = z.object({
  sequenceNumber: z.number().int().positive(), eventType: z.string().min(2).max(160), workflow: z.string().max(160).optional(), workflowStep: z.string().max(160).optional(),
  initiatedByType: z.string().min(1).max(80), initiatedById: z.string().max(200).optional(), occurredAt: z.string().datetime({ offset: true }),
  modelName: z.string().max(200).optional(), toolName: z.string().max(200).optional(), serviceName: z.string().max(200).optional(),
  inputClassification: z.string().max(80).optional(), outputClassification: z.string().max(80).optional(),
  inputDigest: z.string().startsWith("sha256:"), inputPayload: requiredJson, processTrace: requiredJson, outputDigest: z.string().startsWith("sha256:"), outputPayload: requiredJson, success: z.boolean(),
  principalId: z.string().max(200).optional(), principalFingerprint: z.string().max(200).optional(), scopeName: z.string().max(200).optional(), route: z.string().max(500).optional(),
  authorizationDecision: z.string().max(80).optional(), authorizationReason: z.string().max(160).optional(), protocolResult: z.string().max(160).optional(),
  httpStatus: z.number().int().min(100).max(599).optional(), retryCount: z.number().int().nonnegative().optional(), idempotencyKey: z.string().max(200).optional(),
  correlationId: z.string().uuid(), causationId: z.string().uuid().optional(), traceId: z.string().max(200).optional(), spanId: z.string().max(200).optional(),
  stateChange: z.unknown().optional(), catalogVersion: z.literal(COMPONENT_CATALOG_VERSION), payload: z.unknown().optional()
}).strict();

function bearer(request: FastifyRequest): string | null {
  const authorization = request.headers.authorization;
  return authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : null;
}

function routeError(reply: FastifyReply, error: unknown, correlationId: string) {
  const statusCode = typeof error === "object" && error && "statusCode" in error ? Number(error.statusCode) : 500;
  const code = error instanceof Error ? error.message.split(":")[0] ?? "operation_failed" : "operation_failed";
  return sendError(reply, statusCode, code, undefined, correlationId);
}

function etagFor(job: Record<string, unknown>): string {
  return `"${Number(job.lockVersion ?? 0)}"`;
}

async function integrationPrincipal(db: Db, config: AppServerConfig, request: FastifyRequest, reply: FastifyReply, correlationId: string) {
  const token = bearer(request);
  if (!token) {
    sendError(reply, 401, "invalid_integration_token", undefined, correlationId);
    return null;
  }
  try {
    return await authenticateIntegrationToken(db, token, config);
  } catch {
    sendError(reply, 401, "invalid_integration_token", undefined, correlationId);
    return null;
  }
}

async function adminPrincipal(db: Db, config: AppServerConfig, request: FastifyRequest, reply: FastifyReply, correlationId: string, mutation = false) {
  if (hostOf(request.headers.host) !== config.ADMIN_HOST) {
    sendError(reply, 404, "not_found", undefined, correlationId);
    return null;
  }
  const session = await sessionAccount(db, request, config);
  if (!session) {
    sendError(reply, 401, "unauthorized", undefined, correlationId);
    return null;
  }
  if (mutation && !requireCsrf(request)) {
    sendError(reply, 403, "csrf_failed", undefined, correlationId);
    return null;
  }
  return session.accountId;
}

async function authorizeRuntime(db: Db, config: AppServerConfig, request: FastifyRequest, scope: string, route: string, correlationId: string) {
  const token = bearer(request);
  const host = hostOf(request.headers.host);
  if (!token) return null;
  return authorizeComponentCall(db, {
    token,
    audience: `https://${host}`,
    host,
    scope,
    route,
    hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
    correlationId
  });
}

function assertSourceIdentity(
  declared: { clientId: string; componentCode: string; audience?: string },
  decision: Awaited<ReturnType<typeof authorizeComponentCall>>
) {
  if (!decision?.allow) return;
  if (!componentSourceIdentityMatches(decision, declared)) throw Object.assign(new Error("source_identity_mismatch"), { statusCode: 403 });
}

function assertTargetIdentity(
  declared: { componentCode: string; audience?: string },
  decision: Awaited<ReturnType<typeof authorizeComponentCall>>
) {
  if (!decision?.allow) return;
  if (declared.componentCode !== decision.targetComponentCode) {
    throw Object.assign(new Error("target_component_mismatch"), { statusCode: 403 });
  }
  if (declared.audience && declared.audience !== decision.audience) {
    throw Object.assign(new Error("invalid_audience"), { statusCode: 403 });
  }
}

export function registerComponentRoutes(app: FastifyInstance, db: Db, config: AppServerConfig): void {
  app.post("/v2/component-onboardings", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await integrationPrincipal(db, config, request, reply, correlationId);
    if (!principal) return;
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !idempotencyKeyPattern.test(key)) return sendError(reply, 400, "invalid_idempotency_key", undefined, correlationId);
    try {
      const manifest = validateComponentManifest(request.body);
      const job = await createComponentOnboarding(db, {
        integrationTokenId: principal.id, idempotencyKey: key, manifest, correlationId
      });
      return reply.code(202).header("etag", etagFor(job)).header("cache-control", "no-store").send({ job });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.get("/v2/component-onboardings/:id", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await integrationPrincipal(db, config, request, reply, correlationId);
    if (!principal) return;
    try {
      const job = await getComponentOnboarding(db, (request.params as { id: string }).id, principal.id);
      return reply.header("etag", etagFor(job)).header("cache-control", "no-store").send({ job });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-onboardings/:id/revisions", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await integrationPrincipal(db, config, request, reply, correlationId);
    if (!principal) return;
    const key = request.headers["idempotency-key"];
    const match = request.headers["if-match"];
    const lockVersion = typeof match === "string" ? Number(match.replaceAll('"', "")) : Number.NaN;
    if (typeof key !== "string" || !idempotencyKeyPattern.test(key) || !Number.isSafeInteger(lockVersion) || lockVersion < 0) {
      return sendError(reply, 400, "idempotency_key_and_if_match_required", undefined, correlationId);
    }
    try {
      const job = await reviseComponentOnboarding(db, {
        jobId: (request.params as { id: string }).id, integrationTokenId: principal.id,
        expectedLockVersion: lockVersion,
        idempotencyKey: key,
        manifest: validateComponentManifest(request.body), correlationId
      });
      return reply.header("etag", etagFor(job)).header("cache-control", "no-store").send({ job });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-onboardings/:id/readiness", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await integrationPrincipal(db, config, request, reply, correlationId);
    if (!principal) return;
    try {
      const result = await evaluateComponentReadiness(db, {
        jobId: (request.params as { id: string }).id, integrationTokenId: principal.id,
        accessTokenHmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
        accessTokenHmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
        vaultMasterKey: config.CONFIG_VAULT_MASTER_KEY_BASE64,
        vaultMasterKeyId: config.CONFIG_VAULT_MASTER_KEY_ID,
        integrationTokenHmacKey: config.INTEGRATION_TOKEN_HMAC_KEY_BASE64,
        integrationTokenHmacKeyId: config.INTEGRATION_TOKEN_HMAC_KEY_ID,
        correlationId
      });
      if (!result.accessToken) {
        await queueComponentE2ERun(db, {
          jobId: (request.params as { id: string }).id,
          integrationTokenId: principal.id,
          correlationId
        });
      }
      return reply.header("etag", etagFor(result.job)).header("cache-control", "no-store").send(result);
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-onboardings/:id/credential-claims", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    return sendError(reply, 410, "credential_claim_replaced_by_access_token_handoff", undefined, correlationId);
  });

  app.post("/v2/component-onboardings/:id/e2e-results", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    return sendError(reply, 410, "client_supplied_e2e_results_forbidden", "KCML executes and records onboarding E2E evidence.", correlationId);
  });

  app.delete("/v2/component-onboardings/:id", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await integrationPrincipal(db, config, request, reply, correlationId);
    if (!principal) return;
    try {
      return { job: await cancelComponentOnboarding(db, (request.params as { id: string }).id, principal.id, correlationId) };
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.get("/api/components", async (request, reply) => {
    const correlationId = randomUUID();
    if (!await adminPrincipal(db, config, request, reply, correlationId)) return;
    return { components: await listComponents(db), catalogVersion: COMPONENT_CATALOG_VERSION };
  });

  app.get("/api/platform-worker-access", async (request, reply) => {
    const correlationId = randomUUID();
    if (!await adminPrincipal(db, config, request, reply, correlationId)) return;
    return { status: await getPlatformWorkerAccessStatus(db) };
  });

  app.post("/api/platform-worker-access/rotate", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      return reply.header("cache-control", "no-store").send(await rotatePlatformWorkerAccessToken(db, config, { actorId, correlationId }));
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.get("/api/external-principals", async (request, reply) => {
    const correlationId = randomUUID();
    if (!await adminPrincipal(db, config, request, reply, correlationId)) return;
    return { principals: await listExternalPrincipals(db) };
  });

  app.post("/api/external-principals", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { return { principal: await createExternalPrincipal(db, { ...externalPrincipalSchema.parse(request.body), actorId, correlationId }) }; }
    catch (error) { return routeError(reply, error, correlationId); }
  });

  app.post("/api/external-principals/:id/access-tokens/rotate", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { return reply.header("cache-control", "no-store").send(await rotateExternalPrincipalAccessToken(db, { principalId: (request.params as { id: string }).id, actorId, hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64, hmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID, correlationId })); }
    catch (error) { return routeError(reply, error, correlationId); }
  });

  app.post("/api/external-principals/:id/credentials/rotate", async (_request, reply) => sendError(reply, 410, "external_principal_credentials_retired"));

  app.post("/api/external-inbound-permissions", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { await setExternalInboundPermission(db, { ...externalInboundPermissionSchema.parse(request.body), actorId, correlationId }); return { ok: true }; }
    catch (error) { return routeError(reply, error, correlationId); }
  });

  app.get("/api/external-inbound-permissions", async (request, reply) => {
    const correlationId = randomUUID();
    if (!await adminPrincipal(db, config, request, reply, correlationId)) return;
    return { permissions: await listExternalInboundPermissions(db) };
  });

  app.post("/api/external-principals/:id/status", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { return { principal: await setExternalEntityStatus(db, { kind: "principal", id: (request.params as { id: string }).id, ...externalStatusSchema.parse(request.body), actorId, correlationId }) }; }
    catch (error) { return routeError(reply, error, correlationId); }
  });

  app.get("/api/external-targets", async (request, reply) => {
    const correlationId = randomUUID();
    if (!await adminPrincipal(db, config, request, reply, correlationId)) return;
    return { targets: await listExternalTargets(db) };
  });

  app.post("/api/external-targets", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { return { target: await createExternalTarget(db, { ...externalTargetSchema.parse(request.body), actorId, correlationId }) }; }
    catch (error) { return routeError(reply, error, correlationId); }
  });

  app.post("/api/external-targets/:id/status", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { return { target: await setExternalEntityStatus(db, { kind: "target", id: (request.params as { id: string }).id, ...externalStatusSchema.parse(request.body), actorId, correlationId }) }; }
    catch (error) { return routeError(reply, error, correlationId); }
  });

  app.get("/api/external-permissions", async (request, reply) => {
    const correlationId = randomUUID();
    if (!await adminPrincipal(db, config, request, reply, correlationId)) return;
    return { permissions: await listExternalPermissions(db) };
  });

  app.put("/api/external-permissions", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { await setExternalPermission(db, { ...externalPermissionSchema.parse(request.body), actorId, correlationId }); return reply.code(204).send(); }
    catch (error) { return routeError(reply, error, correlationId); }
  });

  app.get("/api/components/:id", async (request, reply) => {
    const correlationId = randomUUID();
    if (!await adminPrincipal(db, config, request, reply, correlationId)) return;
    try {
      return { component: await getComponent(db, (request.params as { id: string }).id) };
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/activation", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const body = activationSchema.parse(request.body);
      return { component: await setComponentActivation(db, { componentId: (request.params as { id: string }).id, enabled: body.enabled, actorId, correlationId }) };
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/lifecycle", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const body = lifecycleSchema.parse(request.body);
      return { component: await setComponentLifecycle(db, {
        componentId: (request.params as { id: string }).id, action: body.action, actorId, correlationId
      }) };
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/permissions/:permissionId", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const body = permissionSchema.parse(request.body);
      const params = request.params as { id: string; permissionId: string };
      return { component: await setComponentPermissionEnabled(db, {
        componentId: params.id, permissionId: params.permissionId, enabled: body.enabled, actorId, correlationId
      }) };
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/access-tokens/:tokenId/revoke", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const params = request.params as { id: string; tokenId: string };
      return { component: await revokeComponentAccessToken(db, {
        componentId: params.id, tokenId: params.tokenId, actorId, correlationId
      }) };
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/access-tokens/:tokenId/rotate", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const params = request.params as { id: string; tokenId: string };
      return reply.header("cache-control", "no-store").send(await rotateComponentAccessToken(db, {
        componentId: params.id, tokenId: params.tokenId, actorId,
        accessTokenHmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64, accessTokenHmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID, correlationId
      }));
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/credentials/:credentialId/revoke", async (_request, reply) =>
    sendError(reply, 410, "component_credentials_retired"));
  app.post("/api/components/:id/credentials/:credentialId/rotate", async (_request, reply) =>
    sendError(reply, 410, "component_credentials_retired"));

  app.post("/api/components/:id/e2e-runs", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const run = await queueComponentE2ERun(db, { componentId: (request.params as { id: string }).id, correlationId });
      return reply.code(202).send({ run, correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/state-queries", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const dispatch = await queueComponentStateQuery(db, { componentId: (request.params as { id: string }).id, actorId, correlationId });
      return reply.code(202).send({ dispatch, correlationId });
    } catch (error) { return routeError(reply, error, correlationId); }
  });

  app.post("/api/components/:id/heartbeat-challenges", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const dispatch = await queueComponentHeartbeatChallenge(db, { componentId: (request.params as { id: string }).id, actorId, correlationId });
      return reply.code(202).send({ dispatch, correlationId });
    } catch (error) { return routeError(reply, error, correlationId); }
  });

  app.get("/.well-known/kcml-component", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const host = hostOf(request.headers.host);
    if (!host || host === config.ADMIN_HOST || host === config.AUTH_HOST || host === config.REGISTER_HOST) {
      return sendError(reply, 404, "not_found", undefined, correlationId);
    }
    return reply.header("cache-control", "public, max-age=300").send({
      mcpEndpoint: `https://${host}/mcp`,
      protectedResourceMetadata: `https://${host}/.well-known/oauth-protected-resource`,
      catalogVersion: COMPONENT_CATALOG_VERSION
    });
  });

  app.post("/v2/component-mcp", { config: { rateLimit: { max: 240, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    return sendError(reply, 410, "component_mcp_moved", "Use the canonical POST /mcp endpoint.", correlationId);
  });

  app.post("/v2/component-pulse", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.pulse", "/v2/component-pulse", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const body = fullPulseSchema.parse(request.body) as ComponentPulseEnvelope;
      assertSourceIdentity(body.source as { clientId: string; componentCode: string }, decision);
      assertTargetIdentity(body.target as { componentCode: string; audience?: string }, decision);
      if (body.accessTokenFingerprint !== decision.tokenFingerprint) return sendError(reply, 403, "access_token_fingerprint_mismatch", undefined, correlationId);
      const receipt = await ingestComponentPulse(db, decision.targetComponentId, body, {
        tokenFingerprint: decision.tokenFingerprint ?? "", permissionEpoch: decision.policyEpoch ?? 0, sourceClientId: decision.sourceClientId ?? ""
      });
      return reply.code(202).send({ ...receipt, policyEpoch: decision.policyEpoch });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-outbound-pulse", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.outbound.pulse", "/v2/component-outbound-pulse", correlationId);
    if (!decision?.allow || !decision.sourceComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const gateway = outboundGatewaySchema.safeParse(request.body);
      if (gateway.success) {
        const accessToken = bearer(request);
        if (!accessToken || !decision.tokenFingerprint) return sendError(reply, 401, "invalid_token", undefined, correlationId);
        return reply.code(202).send(await dispatchExternalComponentCall(db, {
          sourceComponentId: decision.sourceComponentId,
          targetKey: gateway.data.targetKey,
          routePath: gateway.data.routePath,
          scopeName: gateway.data.scopeName,
          payload: gateway.data.payload,
          correlationId,
          accessToken,
          tokenFingerprint: decision.tokenFingerprint
        }));
      }
      const body = fullPulseSchema.parse(request.body) as ComponentPulseEnvelope;
      if (body.direction !== "OUTGOING") return sendError(reply, 400, "invalid_pulse_direction", undefined, correlationId);
      assertSourceIdentity(body.source as { clientId: string; componentCode: string }, decision);
      if (body.accessTokenFingerprint !== decision.tokenFingerprint) return sendError(reply, 403, "access_token_fingerprint_mismatch", undefined, correlationId);
      const rawTargetCode = (body.target as Record<string, unknown>).componentCode;
      const targetCode = typeof rawTargetCode === "string" ? rawTargetCode : "";
      const target = await db.query("select id,hostname from component where code=$1 and lifecycle_state<>'DEREGISTERED'", [targetCode]);
      if (!target.rowCount) return sendError(reply, 404, "target_component_not_found", undefined, correlationId);
      const targetHostname = String(target.rows[0].hostname);
      const token = bearer(request);
      if (!token) return sendError(reply, 401, "invalid_token", undefined, correlationId);
      const deliveredEnvelope = { ...body, direction: "INCOMING" as const };
      try {
        const delivered = await fetchThroughEgress(config, {
          url: `https://${targetHostname}/v2/component-pulse`, method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: Buffer.from(JSON.stringify(deliveredEnvelope)), allowlist: [targetHostname],
          purpose: "component.pulse.registered_dispatch", correlationId: body.correlationId, ttlSeconds: 45
        });
        if (delivered.status < 200 || delivered.status >= 300) throw new Error(`pulse_delivery_http_${delivered.status}`);
        const receipt = await ingestComponentPulse(db, decision.sourceComponentId, body, {
          tokenFingerprint: decision.tokenFingerprint ?? "", permissionEpoch: decision.policyEpoch ?? 0, sourceClientId: decision.sourceClientId ?? ""
        });
        return reply.code(202).send({ ...receipt, delivered: true, targetHostname, policyEpoch: decision.policyEpoch });
      } catch (error) {
        const output = { error: error instanceof Error ? error.message : "pulse_delivery_failed", targetHostname };
        await ingestComponentOperationEvent(db, decision.sourceComponentId, {
          operationKey: `pulse:${body.pulseType}:delivery`, inputDigest: `sha256:${createHash("sha256").update(JSON.stringify(body.input)).digest("hex")}`,
          inputPayload: body.input, processTrace: { transport: "KCML_EGRESS", targetHostname },
          outputDigest: `sha256:${createHash("sha256").update(JSON.stringify(output)).digest("hex")}`, outputPayload: output,
          success: false, correlationId: body.correlationId, causationId: body.causationId, traceId: body.traceId,
          accessTokenFingerprint: decision.tokenFingerprint ?? undefined, occurredAt: new Date().toISOString()
        });
        return sendError(reply, 502, "pulse_delivery_failed", undefined, correlationId);
      }
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-heartbeat", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.heartbeat", "/v2/component-heartbeat", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const body = heartbeatSchema.parse(request.body);
      if (body.declaredClientId !== decision.sourceClientId || body.componentCode !== decision.targetComponentCode) {
        return sendError(reply, 403, "client_id_mismatch", undefined, correlationId);
      }
      const receipt = await recordComponentHeartbeat(db, decision.targetComponentId, {
        ...body,
        declaredComponentCode: body.componentCode
      });
      return reply.code(receipt.accepted ? 202 : 422).send({ ...receipt, correlationId: body.correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-state-push", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.state.query", "/v2/component-state-push", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const body = stateObservationSchema.parse(request.body) as StateObservationBody;
      if (body.declaredClientId !== decision.sourceClientId || body.componentCode !== decision.targetComponentCode) {
        return sendError(reply, 403, "client_id_mismatch", undefined, correlationId);
      }
      const receipt = await recordComponentStateObservation(db, decision.targetComponentId, {
        ...body,
        declaredComponentCode: body.componentCode
      });
      return reply.code(receipt.accepted ? 202 : 422).send({ ...receipt, correlationId: body.correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-state-query", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    return sendError(reply, 410, "state_query_requires_control_dispatch", "KCML issues state queries through the durable control-dispatch worker.", correlationId);
  });

  app.post("/v2/component-state-response", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.state.query", "/v2/component-state-response", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const body = stateSnapshotSchema.parse(request.body);
      if (body.declaredClientId !== decision.sourceClientId || body.componentCode !== decision.targetComponentCode) {
        return sendError(reply, 403, "client_id_mismatch", undefined, correlationId);
      }
      const receipt = await recordComponentStateSnapshot(db, decision.targetComponentId, { ...body, declaredComponentCode: body.componentCode });
      return reply.code(receipt.accepted ? 202 : 422).send({ ...receipt, correlationId: body.correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-control-ack", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.control.ack", "/v2/component-control-ack", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const body = controlAckSchema.parse(request.body) as ControlAckBody;
      if (body.declaredClientId !== decision.sourceClientId || body.componentCode !== decision.targetComponentCode) {
        return sendError(reply, 403, "client_id_mismatch", undefined, correlationId);
      }
      const receipt = await recordComponentControlAck(db, decision.targetComponentId, {
        ...body,
        declaredComponentCode: body.componentCode
      });
      return reply.code(202).send({ ...receipt, correlationId: body.correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-audit-events", { config: { rateLimit: { max: 600, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.audit.write", "/v2/component-audit-events", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const event = auditEventSchema.parse(request.body);
      await ingestComponentOperationEvent(db, decision.targetComponentId, {
        operationKey: event.eventType,
        inputDigest: event.inputDigest,
        inputPayload: event.inputPayload,
        processTrace: event.processTrace,
        outputDigest: event.outputDigest,
        outputPayload: event.outputPayload,
        success: event.success,
        correlationId: event.correlationId,
        causationId: event.causationId,
        traceId: event.traceId,
        accessTokenFingerprint: event.principalFingerprint,
        occurredAt: event.occurredAt
      });
      const receipt = await ingestComponentAuditEvent(db, decision.targetComponentId, event);
      return reply.code(receipt.accepted ? 202 : 409).send({ ...receipt, correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });
}
