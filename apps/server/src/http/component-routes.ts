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
import { requireCsrf, sessionAccount } from "./admin-routes.js";
import { hostOf, sendError } from "./errors.js";

const idempotencyKeyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const claimSchema = z.object({ claimToken: z.string().min(32) }).strict();
const activationSchema = z.object({ enabled: z.boolean() }).strict();
const lifecycleSchema = z.object({ action: z.enum(["QUARANTINE", "RESTORE", "RETIRE", "DEREGISTER"]) }).strict();
const permissionSchema = z.object({ enabled: z.boolean() }).strict();
const requiredJson = z.custom<unknown>((value) => value !== undefined);
const fullPulseSchema = z.object({
  pulseType: z.string().min(3).max(160),
  direction: z.enum(["INCOMING", "OUTGOING"]),
  source: z.record(z.unknown()),
  target: z.record(z.unknown()),
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
  payload: z.unknown().optional()
}).strict();
const stateObservationSchema = z.object({
  stateKey: z.string().min(2).max(160),
  observedAt: z.string().datetime({ offset: true }),
  correlationId: z.string().uuid(),
  statePayload: requiredJson
}).strict();
const controlAckSchema = z.object({
  commandType: z.enum(["enable", "disable", "state", "heartbeat"]),
  status: z.enum(["ACKED", "FAILED"]),
  ackPayload: requiredJson,
  correlationId: z.string().uuid()
}).strict();
const e2eResultSchema = z.object({
  scenarioKey: z.string().min(2).max(160),
  generatedOutput: requiredJson,
  generatedOutputDigest: z.string().startsWith("sha256:"),
  correlationId: z.string().uuid()
}).strict();
type StateObservationBody = {
  stateKey: string;
  observedAt: string;
  correlationId: string;
  statePayload: unknown;
};
type ControlAckBody = {
  commandType: "enable" | "disable" | "state" | "heartbeat";
  status: "ACKED" | "FAILED";
  ackPayload: unknown;
  correlationId: string;
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

  app.post("/v2/component-pulse", { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    const decision = await authorizeRuntime(db, config, request, "component.pulse", "/v2/component-pulse", correlationId);
    if (!decision?.allow || !decision.targetComponentId) return sendError(reply, 403, decision?.reasonCode ?? "invalid_token", undefined, correlationId);
    try {
      const body = fullPulseSchema.parse(request.body) as ComponentPulseEnvelope;
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
      const body = fullPulseSchema.parse(request.body) as ComponentPulseEnvelope;
      if (body.direction !== "OUTGOING") return sendError(reply, 400, "invalid_pulse_direction", undefined, correlationId);
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
      const receipt = await recordComponentHeartbeat(db, decision.targetComponentId, body);
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
      const receipt = await recordComponentStateObservation(db, decision.targetComponentId, body);
      return reply.code(202).send({ ...receipt, correlationId: body.correlationId });
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
      const receipt = await recordComponentControlAck(db, decision.targetComponentId, body);
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
