import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AppServerConfig } from "../config.js";
import type { Db } from "../db.js";
import { ingestComponentAuditEvent } from "../domain/component-audit.js";
import { authorizeComponentCall } from "../domain/component-auth.js";
import {
  cancelComponentOnboarding,
  claimComponentCredential,
  COMPONENT_CATALOG_VERSION,
  createComponentOnboarding,
  evaluateComponentReadiness,
  getComponent,
  getComponentDiscovery,
  getComponentOnboarding,
  ingestComponentOperationEvent,
  ingestComponentPulse,
  listComponents,
  recordComponentControlAck,
  recordComponentE2EResult,
  recordComponentHeartbeat,
  recordComponentStateObservation,
  revokeComponentCredential,
  reviseComponentOnboarding,
  rotateComponentCredential,
  setComponentActivation,
  setComponentLifecycle,
  setComponentPermissionEnabled,
  type ComponentPulseEnvelope,
  validateComponentManifest
} from "../domain/component.js";
import { authenticateIntegrationToken } from "../domain/onboarding.js";
import { resolveSecret } from "../domain/secret-manager.js";
import {
  createExternalPrincipal,
  createExternalTarget,
  dispatchExternalComponentCall,
  listExternalPermissions,
  listExternalPrincipals,
  listExternalTargets,
  rotateExternalPrincipalCredential,
  setExternalEntityStatus,
  setExternalPermission
} from "../domain/external-component.js";
import { requireCsrf, sessionAccount } from "./admin-routes.js";
import { hostOf, sendError } from "./errors.js";

const idempotencyKeyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const claimSchema = z.object({ claimToken: z.string().min(32) }).strict();
const activationSchema = z.object({ enabled: z.boolean() }).strict();
const lifecycleSchema = z.object({ action: z.enum(["QUARANTINE", "RESTORE", "RETIRE", "DEREGISTER"]) }).strict();
const permissionSchema = z.object({ enabled: z.boolean() }).strict();
const requiredJson = z.custom<unknown>((value) => value !== undefined);
const externalPrincipalSchema = z.object({ publicId: z.string().min(3).max(120).regex(/^KCML-EXT-[A-Z0-9-]+$/), displayName: z.string().min(2).max(200), description: z.string().max(2000).optional() }).strict();
const externalTargetSchema = z.object({ targetKey: z.string().min(3).max(120).regex(/^[a-z0-9][a-z0-9.-]*$/), displayName: z.string().min(2).max(200), baseUrl: z.string().url(), allowedPathPrefixes: z.array(z.string().min(1).max(500)).max(30).optional(), requestTimeoutMs: z.number().int().min(100).max(60000).default(15000), maxRetries: z.number().int().min(0).max(3).default(1), circuitFailureThreshold: z.number().int().min(1).max(100).default(5), circuitOpenSeconds: z.number().int().min(1).max(3600).default(60) }).strict();
const externalStatusSchema = z.object({ status: z.enum(["ACTIVE", "DISABLED", "REVOKED"]) }).strict();
const externalPermissionSchema = z.object({ componentId: z.string().uuid().optional(), externalPrincipalId: z.string().uuid().optional(), externalTargetId: z.string().uuid(), routePattern: z.string().min(1).max(500), scopeName: z.string().min(2).max(200), enabled: z.boolean() }).strict();
const outboundGatewaySchema = z.object({ targetKey: z.string().min(3).max(120), routePath: z.string().startsWith("/").max(500), scopeName: z.string().min(2).max(200), payload: requiredJson }).strict();
const componentMcpSchema = z.object({ jsonrpc: z.literal("2.0"), id: z.union([z.string(), z.number(), z.null()]).optional(), method: z.enum(["initialize", "notifications/initialized", "tools/list", "tools/call"]), params: z.unknown().optional() }).strict();
const componentMcpCallSchema = z.object({ name: z.string(), arguments: z.record(z.unknown()).default({}) }).strict();
const COMPONENT_RUNTIME_TOOLS = [
  "kcml.pulse.accept", "kcml.pulse.emit", "kcml.audit.append", "kcml.state.push",
  "kcml.state.query", "kcml.control.ack", "kcml.heartbeat.push", "kcml.heartbeat.challenge", "kcml.secret.resolve"
] as const;
const COMPONENT_RUNTIME_TOOL_SCHEMAS: Record<typeof COMPONENT_RUNTIME_TOOLS[number], Record<string, unknown>> = {
  "kcml.pulse.accept": { type: "object", required: ["pulseType", "direction", "source", "target", "input", "output", "correlationId", "occurredAt"], additionalProperties: true },
  "kcml.pulse.emit": { type: "object", required: ["targetKey", "routePath", "scopeName", "payload"], additionalProperties: false },
  "kcml.audit.append": { type: "object", required: ["sequenceNumber", "eventType", "occurredAt", "inputDigest", "inputPayload", "processTrace", "outputDigest", "outputPayload", "success", "correlationId", "catalogVersion"], additionalProperties: true },
  "kcml.state.push": { type: "object", required: ["stateKey", "observedAt", "correlationId", "declaredClientId", "componentCode", "policyEpoch", "statePayload"], additionalProperties: false },
  "kcml.state.query": { type: "object", additionalProperties: false },
  "kcml.control.ack": { type: "object", required: ["commandId", "commandType", "status", "ackPayload", "correlationId", "declaredClientId", "componentCode", "policyEpoch"], additionalProperties: false },
  "kcml.heartbeat.push": { type: "object", required: ["heartbeatAt", "operationalState", "correlationId", "declaredClientId", "componentCode", "policyEpoch"], additionalProperties: true },
  "kcml.heartbeat.challenge": { type: "object", additionalProperties: false },
  "kcml.secret.resolve": { type: "object", required: ["stableName"], additionalProperties: false, properties: { stableName: { type: "string", minLength: 3, maxLength: 128 } } }
};
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
const e2eResultSchema = z.object({
  scenarioKey: z.string().min(2).max(160),
  generatedOutput: requiredJson,
  generatedOutputDigest: z.string().startsWith("sha256:").optional(),
  correlationId: z.string().uuid()
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
  if (declared.clientId !== decision.sourceClientId) {
    throw Object.assign(new Error("client_id_mismatch"), { statusCode: 403 });
  }
  if (declared.componentCode !== decision.sourceComponentCode) {
    throw Object.assign(new Error("source_component_mismatch"), { statusCode: 403 });
  }
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
        integrationTokenId: principal.id, idempotencyKey: key, manifest,
        claimHmacKey: config.INTEGRATION_TOKEN_HMAC_KEY_BASE64, baseDomain: config.PUBLIC_BASE_DOMAIN, correlationId
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
        claimHmacKey: config.INTEGRATION_TOKEN_HMAC_KEY_BASE64, correlationId
      });
      return reply.header("etag", etagFor(result.job)).header("cache-control", "no-store").send(result);
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-onboardings/:id/credential-claims", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await integrationPrincipal(db, config, request, reply, correlationId);
    if (!principal) return;
    try {
      const body = claimSchema.parse(request.body);
      const credential = await claimComponentCredential(db, {
        jobId: (request.params as { id: string }).id, integrationTokenId: principal.id, claimToken: body.claimToken,
        claimHmacKey: config.INTEGRATION_TOKEN_HMAC_KEY_BASE64,
        credentialHmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
        keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
        correlationId
      });
      return reply.header("cache-control", "no-store").send({ credential });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-onboardings/:id/e2e-results", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.REGISTER_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const principal = await integrationPrincipal(db, config, request, reply, correlationId);
    if (!principal) return;
    try {
      const body = e2eResultSchema.parse(request.body);
      const result = await recordComponentE2EResult(db, {
        jobId: (request.params as { id: string }).id,
        integrationTokenId: principal.id,
        scenarioKey: body.scenarioKey,
        generatedOutput: body.generatedOutput,
        generatedOutputDigest: body.generatedOutputDigest,
        correlationId: body.correlationId
      });
      return reply.code(result.status === "PASS" ? 202 : 409).header("cache-control", "no-store").send({ ...result, correlationId: body.correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
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

  app.post("/api/external-principals/:id/credentials/rotate", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try { return await rotateExternalPrincipalCredential(db, { principalId: (request.params as { id: string }).id, actorId, hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64, keyId: config.ACCESS_TOKEN_HMAC_KEY_ID, correlationId }); }
    catch (error) { return routeError(reply, error, correlationId); }
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

  app.post("/api/components/:id/credentials/:credentialId/revoke", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const params = request.params as { id: string; credentialId: string };
      return { component: await revokeComponentCredential(db, {
        componentId: params.id, credentialId: params.credentialId, actorId, correlationId
      }) };
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/api/components/:id/credentials/:credentialId/rotate", async (request, reply) => {
    const correlationId = randomUUID();
    const actorId = await adminPrincipal(db, config, request, reply, correlationId, true);
    if (!actorId) return;
    try {
      const params = request.params as { id: string; credentialId: string };
      return reply.header("cache-control", "no-store").send(await rotateComponentCredential(db, {
        componentId: params.id, credentialId: params.credentialId, actorId,
        credentialHmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64, keyId: config.ACCESS_TOKEN_HMAC_KEY_ID, correlationId
      }));
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.get("/.well-known/kcml-component", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const host = hostOf(request.headers.host);
    try {
      const component = await getComponentDiscovery(db, host);
      return reply.header("cache-control", "no-store").send({ component, catalogVersion: COMPONENT_CATALOG_VERSION });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-mcp", { config: { rateLimit: { max: 240, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const body = componentMcpSchema.safeParse(request.body);
    if (!body.success) return reply.send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request", data: { correlationId } } });
    const requiredScope = body.data.method === "initialize" ? "mcp.initialize" : body.data.method === "notifications/initialized" ? "mcp.notifications.initialized" : body.data.method === "tools/list" ? "mcp.tools.list" : "mcp.tools.call";
    const decision = await authorizeRuntime(db, config, request, requiredScope, "/v2/component-mcp", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return reply.send({ jsonrpc: "2.0", id: body.data.id ?? null, error: { code: -32001, message: "Unauthorized", data: { code: decision?.reasonCode ?? "invalid_token", correlationId } } });
    if (body.data.method === "initialize") return reply.send({ jsonrpc: "2.0", id: body.data.id ?? null, result: { protocolVersion: "2025-11-25", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "kcml-component-runtime", version: COMPONENT_CATALOG_VERSION } } });
    if (body.data.method === "notifications/initialized") return reply.code(202).send();
    if (body.data.method === "tools/list") return reply.send({ jsonrpc: "2.0", id: body.data.id ?? null, result: { tools: COMPONENT_RUNTIME_TOOLS.map((name) => ({ name, description: `KCML component runtime operation ${name}`, inputSchema: COMPONENT_RUNTIME_TOOL_SCHEMAS[name] })) } });
    const call = componentMcpCallSchema.safeParse(body.data.params);
    if (!call.success || !COMPONENT_RUNTIME_TOOLS.includes(call.data.name as typeof COMPONENT_RUNTIME_TOOLS[number])) return reply.send({ jsonrpc: "2.0", id: body.data.id ?? null, error: { code: -32602, message: "Invalid tool", data: { correlationId } } });
    try {
      const args = call.data.arguments;
      let result: unknown;
      if (call.data.name === "kcml.pulse.accept") { const pulse = fullPulseSchema.parse(args) as ComponentPulseEnvelope; assertSourceIdentity(pulse.source as { clientId: string; componentCode: string }, decision); assertTargetIdentity(pulse.target as { componentCode: string; audience?: string }, decision); result = await ingestComponentPulse(db, decision.targetComponentId, pulse); }
      else if (call.data.name === "kcml.audit.append") result = await ingestComponentAuditEvent(db, decision.targetComponentId, auditEventSchema.parse(args));
      else if (call.data.name === "kcml.state.push") { const state = stateObservationSchema.parse(args) as StateObservationBody; if (state.declaredClientId !== decision.sourceClientId || state.componentCode !== decision.targetComponentCode) throw Object.assign(new Error("client_id_mismatch"), { statusCode: 403 }); result = await recordComponentStateObservation(db, decision.targetComponentId, { ...state, declaredComponentCode: state.componentCode }); }
      else if (call.data.name === "kcml.control.ack") { const ack = controlAckSchema.parse(args) as ControlAckBody; if (ack.declaredClientId !== decision.sourceClientId || ack.componentCode !== decision.targetComponentCode) throw Object.assign(new Error("client_id_mismatch"), { statusCode: 403 }); result = await recordComponentControlAck(db, decision.targetComponentId, { ...ack, declaredComponentCode: ack.componentCode }); }
      else if (call.data.name === "kcml.heartbeat.push") { const heartbeat = heartbeatSchema.parse(args); if (heartbeat.declaredClientId !== decision.sourceClientId || heartbeat.componentCode !== decision.targetComponentCode) throw Object.assign(new Error("client_id_mismatch"), { statusCode: 403 }); result = await recordComponentHeartbeat(db, decision.targetComponentId, { ...heartbeat, declaredComponentCode: heartbeat.componentCode }); }
      else if (call.data.name === "kcml.pulse.emit") { const outbound = outboundGatewaySchema.parse(args); result = await dispatchExternalComponentCall(db, { sourceComponentId: decision.sourceComponentId ?? decision.targetComponentId, targetKey: outbound.targetKey, routePath: outbound.routePath, scopeName: outbound.scopeName, payload: outbound.payload, correlationId, hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64, keyId: config.ACCESS_TOKEN_HMAC_KEY_ID }); }
      else if (call.data.name === "kcml.state.query") result = (await db.query("select id,status,requested_at,deadline_at from component_state_query_run where component_id=$1 order by requested_at desc limit 1", [decision.targetComponentId])).rows[0] ?? null;
      else if (call.data.name === "kcml.heartbeat.challenge") result = (await db.query("select id,challenge_nonce,expires_at,status from component_heartbeat_challenge where component_id=$1 order by created_at desc limit 1", [decision.targetComponentId])).rows[0] ?? null;
      else { if (!decision.sourceComponentId || !decision.sourceClientId) throw Object.assign(new Error("component_identity_required"), { statusCode: 403 }); result = await resolveSecret(db, config, { kind: "COMPONENT", id: decision.sourceComponentId, publicId: decision.sourceClientId, auditActorType: "component" }, String(args.stableName), correlationId); }
      return reply.send({ jsonrpc: "2.0", id: body.data.id ?? null, result: { structuredContent: result } });
    } catch (error) {
      const code = error instanceof Error ? error.message.split(":")[0] : "runtime_tool_failed";
      return reply.send({ jsonrpc: "2.0", id: body.data.id ?? null, error: { code: -32602, message: code, data: { correlationId } } });
    }
  });

  app.post("/v2/component-pulse", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.pulse", "/v2/component-pulse", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const body = fullPulseSchema.parse(request.body) as ComponentPulseEnvelope;
      assertSourceIdentity(body.source as { clientId: string; componentCode: string }, decision);
      assertTargetIdentity(body.target as { componentCode: string; audience?: string }, decision);
      const receipt = await ingestComponentPulse(db, decision.targetComponentId, body);
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
        return reply.code(202).send(await dispatchExternalComponentCall(db, {
          sourceComponentId: decision.sourceComponentId,
          targetKey: gateway.data.targetKey,
          routePath: gateway.data.routePath,
          scopeName: gateway.data.scopeName,
          payload: gateway.data.payload,
          correlationId,
          hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
          keyId: config.ACCESS_TOKEN_HMAC_KEY_ID
        }));
      }
      const body = fullPulseSchema.parse(request.body) as ComponentPulseEnvelope;
      if (body.direction !== "OUTGOING") return sendError(reply, 400, "invalid_pulse_direction", undefined, correlationId);
      assertSourceIdentity(body.source as { clientId: string; componentCode: string }, decision);
      const receipt = await ingestComponentPulse(db, decision.sourceComponentId, body);
      return reply.code(202).send({ ...receipt, policyEpoch: decision.policyEpoch });
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
      return reply.code(202).send({ ...receipt, correlationId: body.correlationId });
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
      return reply.code(202).send({ ...receipt, correlationId: body.correlationId });
    } catch (error) {
      return routeError(reply, error, correlationId);
    }
  });

  app.post("/v2/component-state-query", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.state.query", "/v2/component-state-query", correlationId);
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
      return reply.code(202).header("warning", `299 - legacy state query endpoint acts as state.push; use /v2/component-state-push`).send({ ...receipt, correlationId: body.correlationId });
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
