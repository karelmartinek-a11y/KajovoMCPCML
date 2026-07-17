import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import type { McpHttpConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { getServerByHostname, isKcmlHostname, resourceFor } from "../domain/catalog.js";
import { getManagedServiceByHostname } from "../domain/managed-service.js";
import { beginInvocation, finalizeInvocation, recordFinalizationFailure } from "../domain/invocation.js";
import {
  acquireServerExecutionLease,
  BoundedValidatorCache,
  idempotencyMode,
  invokeWithDeadline,
  releaseServerExecutionLease,
  serializeWithinLimit,
  requiresIdempotencyKey
} from "../domain/mcp-policy.js";
import { evaluateRecertification } from "../domain/recertification.js";
import type { McpServer } from "../domain/types.js";
import { validateBearer } from "../domain/auth.js";
import { getHandler } from "../handlers/registry.js";
import { redact } from "../security/secrets.js";
import { hostOf, sendError } from "./errors.js";
import {
  jsonRpcError,
  jsonRpcResult,
  mapMcpRuntimeError,
  respondToJsonRpc,
  sendJsonRpc,
  type JsonRpcResponse
} from "./json-rpc.js";

const validatorCache = new BoundedValidatorCache(256);

const jsonRpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite(), z.null()]).optional(),
  method: z.string().min(1),
  params: z.unknown().optional()
}).strict();

const toolCallParamsSchema = z.object({
  name: z.string().min(1),
  arguments: z.unknown().optional()
}).strict();

type JsonRpcRequest = z.infer<typeof jsonRpcRequestSchema>;
type IdempotencyReservation = {
  key: string;
  requestDigest: string;
  replay?: JsonRpcResponse;
};

const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{8,160}$/;

function requestDigest(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

function safeErrorMetadata(error: unknown): { errorType: string; errorDigest: string } {
  const errorType = error instanceof Error ? error.name.slice(0, 80) : typeof error;
  const material = error instanceof Error ? `${error.name}:${error.message}` : String(error);
  return { errorType, errorDigest: createHash("sha256").update(material).digest("hex") };
}

async function reserveIdempotency(
  db: Db,
  server: McpServer,
  credentialId: string,
  key: string,
  digest: string,
  correlationId: string
): Promise<IdempotencyReservation> {
  return tx(db, async (client) => {
    const inserted = await client.query(
      `insert into mcp_invocation_idempotency(
         server_id,credential_id,idempotency_key,request_digest,status,correlation_id,pending_expires_at
       )
       values ($1,$2,$3,$4,'PENDING',$5,now()+(($6 + 5000) || ' milliseconds')::interval)
       on conflict (server_id, credential_id, idempotency_key) do nothing
       returning idempotency_key`,
      [server.id, credentialId, key, digest, correlationId, server.timeoutMs]
    );
    if (inserted.rowCount) return { key, requestDigest: digest };
    const existing = await client.query(
      `select request_digest,status,response_json,pending_expires_at
         from mcp_invocation_idempotency
        where server_id=$1 and credential_id=$2 and idempotency_key=$3
        for update`,
      [server.id, credentialId, key]
    );
    if (!existing.rowCount) return { key, requestDigest: digest };
    const row = existing.rows[0];
    if (String(row.request_digest) !== digest) {
      throw Object.assign(new Error("idempotency_key_reused"), { statusCode: 409 });
    }
    if (row.status === "COMPLETED" && row.response_json && idempotencyMode(server.effectClass) === "REPLAY_COMPLETED") {
      return { key, requestDigest: digest, replay: row.response_json as JsonRpcResponse };
    }
    if (row.status === "COMPLETED") {
      throw Object.assign(new Error("idempotency_replay_forbidden"), { statusCode: 409 });
    }
    const recovered = await client.query(
      `update mcp_invocation_idempotency
          set correlation_id=$4,
              created_at=now(),
              updated_at=now(),
              pending_expires_at=now()+(($5 + 5000) || ' milliseconds')::interval
        where server_id=$1 and credential_id=$2 and idempotency_key=$3
          and status='PENDING' and pending_expires_at <= now()
        returning idempotency_key`,
      [server.id, credentialId, key, correlationId, server.timeoutMs]
    );
    if (recovered.rowCount) return { key, requestDigest: digest };
    throw Object.assign(new Error("idempotency_in_progress"), { statusCode: 409 });
  });
}

type RateLimitScope = "SERVER" | "CREDENTIAL" | "SERVER_CREDENTIAL";

function rateLimitKey(scope: RateLimitScope, serverId: string, credentialId: string): Buffer {
  const material = scope === "SERVER" ? serverId : scope === "CREDENTIAL" ? credentialId : `${serverId}:${credentialId}`;
  return createHash("sha256").update(`${scope}:${material}`).digest();
}

async function consumeHierarchicalRateLimit(db: Db, server: McpServer, credentialId: string): Promise<void> {
  const limits: Array<{ scope: RateLimitScope; maximum: number; serverId: string | null; credentialId: string | null }> = [
    { scope: "SERVER_CREDENTIAL", maximum: server.rateMaxRequests, serverId: server.id, credentialId },
    { scope: "CREDENTIAL", maximum: server.rateMaxRequests * 2, serverId: null, credentialId },
    { scope: "SERVER", maximum: server.rateMaxRequests * Math.max(10, server.maxConcurrency), serverId: server.id, credentialId: null }
  ];
  await tx(db, async (client) => {
    for (const limit of limits) {
      const result = await client.query(
        `insert into mcp_rate_bucket(scope_type,scope_key,server_id,credential_id,window_started_at,request_count)
         values ($1,$2,$3,$4,now(),1)
         on conflict (scope_type,scope_key) do update set
           window_started_at=case when mcp_rate_bucket.window_started_at <= now()-($5 || ' seconds')::interval then now() else mcp_rate_bucket.window_started_at end,
           request_count=case when mcp_rate_bucket.window_started_at <= now()-($5 || ' seconds')::interval then 1 else mcp_rate_bucket.request_count+1 end,
           updated_at=now()
         returning request_count,
           greatest(0,ceil(extract(epoch from (window_started_at+($5 || ' seconds')::interval-now()))*1000))::int as retry_after_ms`,
        [limit.scope, rateLimitKey(limit.scope, server.id, credentialId), limit.serverId, limit.credentialId, server.rateWindowSeconds]
      );
      if (Number(result.rows[0].request_count) > limit.maximum) {
        throw Object.assign(new Error("rate_limit_exceeded"), {
          classification: "rate",
          scope: limit.scope,
          retryAfterMs: Math.max(1, Number(result.rows[0].retry_after_ms ?? server.rateWindowSeconds * 1000))
        });
      }
    }
  });
}

async function recordUnauthorized(db: Db, serverId: string): Promise<void> {
  await db.query(
    `insert into function_statistics(server_id, unauthorized_count, last_unauthorized_at)
     values ($1,1,now())
     on conflict (server_id) do update set unauthorized_count=function_statistics.unauthorized_count+1, last_unauthorized_at=now()`,
    [serverId]
  );
}

function contentTextForOutput(output: unknown): string {
  return JSON.stringify(output);
}

function originAllowed(origin: unknown, hostname: string): boolean {
  if (typeof origin !== "string" || !origin) return true;
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "https:" && parsed.host.toLowerCase() === hostname.toLowerCase();
  } catch {
    return false;
  }
}

function accepts(requestAccept: unknown, contentType: string): boolean {
  if (typeof requestAccept !== "string" || !requestAccept) return true;
  const [targetType, targetSubtype] = contentType.toLowerCase().split("/");
  return requestAccept.split(",").some((part) => {
    const mediaType = part.split(";")[0]?.trim().toLowerCase();
    if (!mediaType) return false;
    if (mediaType === "*/*" || mediaType === contentType.toLowerCase()) return true;
    const [type, subtype] = mediaType.split("/");
    if (!type || !subtype) return false;
    return (type === "*" || type === targetType) && (subtype === "*" || subtype === targetSubtype);
  });
}

function hasJsonContentType(contentType: unknown): boolean {
  return typeof contentType === "string"
    && contentType.split(";")[0]?.trim().toLowerCase() === "application/json";
}

function serverAvailability(server: McpServer): ReturnType<typeof evaluateRecertification> {
  return evaluateRecertification({
    activeRevisionId: server.activeRevisionId,
    validationState: server.registrationValidationState,
    approvedAt: server.reviewApprovedAt,
    reviewDueAt: server.reviewDueAt,
    reviewIntervalDays: server.reviewIntervalDays
  });
}

function serverCanServe(server: McpServer): boolean {
  return server.enabled
    && ["ACTIVE", "TRIAL"].includes(server.registrationState)
    && server.monitoringEnabled
    && Boolean(server.monitoringProfileDigest)
    && serverAvailability(server).canServeExisting;
}

export function registerMcpRoutes(app: FastifyInstance, db: Db, config: McpHttpConfig): void {
  app.setErrorHandler((error, request, reply) => {
    if (request.url.split("?")[0] === "/mcp") {
      const correlationId = randomUUID();
      reply.header("x-correlation-id", correlationId);
      if ((error as { code?: string }).code === "FST_ERR_CTP_INVALID_JSON_BODY" || error instanceof SyntaxError) {
        return sendJsonRpc(reply, jsonRpcError(null, -32700, "Parse error", correlationId));
      }
      const parsed = jsonRpcRequestSchema.safeParse(request.body);
      if (parsed.success) {
        return respondToJsonRpc(reply, parsed.data.id, jsonRpcError(parsed.data.id, -32603, "Internal error", correlationId));
      }
    }
    request.log.error({ ...safeErrorMetadata(error), url: request.url }, "Unhandled request error");
    return sendError(reply, 500, "internal_error", "Operation failed");
  });

  app.get("/.well-known/oauth-protected-resource", async (request, reply) => {
    const hostname = hostOf(request.headers.host);
    if (!isKcmlHostname(hostname, config.PUBLIC_BASE_DOMAIN)) return sendError(reply, 404, "not_found");
    const managedService = await getManagedServiceByHostname(db, hostname);
    if (managedService?.serviceKind === "EXTERNAL_API") {
      if (managedService.apiState !== "ENABLED") return sendError(reply, 503, "service_unavailable", "Resource is unavailable");
      return {
        resource: managedService.resourceUri,
        authorization_servers: [`https://${config.AUTH_HOST}`],
        bearer_methods_supported: ["header"]
      };
    }
    if (managedService && managedService.apiState !== "ENABLED") return sendError(reply, 503, "service_unavailable", "Resource is unavailable");
    const server = await getServerByHostname(db, hostname);
    if (!server) return sendError(reply, 404, "not_found");
    if (!serverCanServe(server)) {
      await appendAudit(db, {
        eventType: "mcp.discovery.unavailable",
        actorType: "anonymous",
        objectType: "mcp_server",
        objectId: server.id,
        after: { reason: "resource_unavailable" },
        correlationId: randomUUID()
      });
      return sendError(reply, 503, "service_unavailable", "Resource is unavailable");
    }
    return {
      resource: resourceFor(hostname),
      authorization_servers: [`https://${config.AUTH_HOST}`],
      bearer_methods_supported: ["header"]
    };
  });

  app.get("/.well-known/oauth-protected-resource/mcp", async (request, reply) => {
    const hostname = hostOf(request.headers.host);
    if (!isKcmlHostname(hostname, config.PUBLIC_BASE_DOMAIN)) return sendError(reply, 404, "not_found");
    const managedService = await getManagedServiceByHostname(db, hostname);
    if (managedService?.serviceKind === "EXTERNAL_API") {
      if (managedService.apiState !== "ENABLED") return sendError(reply, 503, "service_unavailable", "Resource is unavailable");
      return {
        resource: managedService.resourceUri,
        authorization_servers: [`https://${config.AUTH_HOST}`],
        bearer_methods_supported: ["header"]
      };
    }
    if (managedService && managedService.apiState !== "ENABLED") return sendError(reply, 503, "service_unavailable", "Resource is unavailable");
    const server = await getServerByHostname(db, hostname);
    if (!server) return sendError(reply, 404, "not_found");
    if (!serverCanServe(server)) {
      await appendAudit(db, {
        eventType: "mcp.discovery.unavailable",
        actorType: "anonymous",
        objectType: "mcp_server",
        objectId: server.id,
        after: { reason: "resource_unavailable" },
        correlationId: randomUUID()
      });
      return sendError(reply, 503, "service_unavailable", "Resource is unavailable");
    }
    return {
      resource: resourceFor(hostname),
      authorization_servers: [`https://${config.AUTH_HOST}`],
      bearer_methods_supported: ["header"]
    };
  });

  app.all("/mcp", {
    config: { rateLimit: { max: 120, timeWindow: "1 minute", groupId: "mcp-http" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    reply.header("x-correlation-id", correlationId);
    const hostname = hostOf(request.headers.host);
    request.log.info({ eventType: "mcp.request.received", correlationId, hostname, method: request.method }, "MCP request received");
    if (!originAllowed(request.headers.origin, hostname)) {
      return sendError(reply, 403, "invalid_origin", "Origin is not allowed for this MCP resource", correlationId);
    }
    if (request.method !== "POST") {
      reply.header("allow", "POST");
      return sendError(reply, 405, "method_not_allowed", "This deployment supports POST Streamable HTTP requests only", correlationId);
    }
    if (!isKcmlHostname(hostname, config.PUBLIC_BASE_DOMAIN)) return sendError(reply, 404, "not_found", "Unknown resource", correlationId);

    const managedService = await getManagedServiceByHostname(db, hostname);
    if (managedService && managedService.apiState !== "ENABLED") {
      await appendAudit(db, { eventType: "managed_service.api.disabled", actorType: "anonymous", objectType: "managed_service", objectId: managedService.id, correlationId });
      return sendError(reply, 503, "service_unavailable", "Resource is unavailable", correlationId);
    }
    const server = await getServerByHostname(db, hostname);
    if (!server) {
      await appendAudit(db, { eventType: "mcp.unknown_host", actorType: "anonymous", objectType: "hostname", objectId: hostname, correlationId });
      return sendError(reply, 404, "not_found", "Unknown resource", correlationId);
    }
    if (!serverCanServe(server)) {
      await appendAudit(db, { eventType: "mcp.disabled", actorType: "anonymous", objectType: "mcp_server", objectId: server.id, correlationId });
      return sendError(reply, 503, "service_unavailable", "Resource is unavailable", correlationId);
    }

    const challenge = `Bearer resource_metadata="https://${hostname}/.well-known/oauth-protected-resource/mcp", scope="mcp:${server.code}"`;
    const auth = request.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      await recordUnauthorized(db, server.id);
      await appendAudit(db, { eventType: "mcp.unauthorized", actorType: "anonymous", objectType: "mcp_server", objectId: server.id, after: { reason: "missing_bearer" }, correlationId });
      reply.header("WWW-Authenticate", challenge);
      return sendError(reply, 401, "invalid_token", "Bearer token is required", correlationId);
    }

    let principal: Awaited<ReturnType<typeof validateBearer>>;
    try {
      principal = await validateBearer(db, auth.slice("Bearer ".length), hostname, config.ACCESS_TOKEN_HMAC_KEY_BASE64);
    } catch (error) {
      await recordUnauthorized(db, server.id);
      const reasonCode = error && typeof error === "object" && "reasonCode" in error && typeof error.reasonCode === "string"
        ? error.reasonCode
        : "invalid_bearer";
      await appendAudit(db, { eventType: "mcp.unauthorized", actorType: "anonymous", objectType: "mcp_server", objectId: server.id, after: { reason: reasonCode }, correlationId });
      reply.header("WWW-Authenticate", challenge);
      return sendError(reply, 401, "invalid_token", "Invalid token", correlationId);
    }

    if (!hasJsonContentType(request.headers["content-type"])) {
      return sendError(reply, 415, "unsupported_media_type", "POST /mcp requires Content-Type: application/json", correlationId);
    }
    if (!accepts(request.headers.accept, "application/json")) {
      return sendError(reply, 406, "not_acceptable", "POST /mcp requires Accept: application/json", correlationId);
    }

    if (Array.isArray(request.body)) {
      return sendJsonRpc(reply, jsonRpcError(null, -32600, "Batch requests are not supported", correlationId));
    }

    const parsed = jsonRpcRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendJsonRpc(reply, jsonRpcError(null, -32600, "Invalid Request", correlationId));
    }
    const body: JsonRpcRequest = parsed.data;
    const respond = (payload: JsonRpcResponse): FastifyReply => respondToJsonRpc(reply, body.id, payload);

    if (body.method === "initialize") {
      return respond(jsonRpcResult(body.id, {
          protocolVersion: "2025-11-25",
          capabilities: { tools: {} },
          serverInfo: { name: server.code, version: server.handlerVersion }
      }));
    }

    if (body.method === "notifications/initialized") return reply.code(204).send();

    if (body.method === "tools/list") {
      return respond(jsonRpcResult(body.id, {
        tools: [{
            name: server.toolName,
            title: server.displayName,
            description: server.description,
            inputSchema: server.inputSchema,
            outputSchema: server.outputSchema,
            annotations: {
              readOnlyHint: server.readOnlyHint,
              destructiveHint: server.destructiveHint,
              idempotentHint: server.idempotentHint,
              openWorldHint: server.openWorldHint
            }
          }]
      }));
    }

    if (body.method !== "tools/call") {
      return respond(jsonRpcError(body.id, -32601, "Method not found", correlationId));
    }

    const parsedParams = toolCallParamsSchema.safeParse(body.params ?? {});
    if (!parsedParams.success) {
      return respond(jsonRpcError(body.id, -32602, "Invalid params", correlationId));
    }
    const params = parsedParams.data;
    if (params.name !== server.toolName) {
      return respond(jsonRpcError(body.id, -32602, "Invalid tool for resource", correlationId));
    }

    const serializedInput = JSON.stringify(params.arguments ?? {});
    if (Buffer.byteLength(serializedInput) > server.requestMaxBytes) {
      await appendAudit(db, { eventType: "mcp.request_too_large", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { classification: "size" }, correlationId });
      return respond(jsonRpcError(body.id, -32001, "Tool input exceeds the registered limit", correlationId));
    }

    const validateInput = validatorCache.get(server, "input", server.inputSchema);
    if (!validateInput(params.arguments ?? {})) {
      request.log.info({ eventType: "mcp.input_schema_failed", correlationId, code: server.code, hostname, toolName: server.toolName, errorCode: "input_schema_failed", classification: "schema" }, "MCP input schema rejected");
      await appendAudit(db, { eventType: "mcp.input_schema_failed", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { errorCode: "input_schema_failed", classification: "schema" }, correlationId });
      return respond(jsonRpcError(body.id, -32602, "Input schema validation failed", correlationId, { issues: validateInput.errors ?? [] }));
    }

    const handler = getHandler(server);
    if (!handler) {
      await appendAudit(db, { eventType: "mcp.handler_unavailable", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { errorCode: "handler_unavailable", classification: "configuration" }, correlationId });
      return respond(jsonRpcError(body.id, -32003, "Handler is not registered in this build", correlationId));
    }

    let idempotency: IdempotencyReservation | null = null;
    const idempotencyKey = request.headers["idempotency-key"];
    const normalizedIdempotencyKey = typeof idempotencyKey === "string" ? idempotencyKey.trim() : "";
    if (requiresIdempotencyKey(server.effectClass) && !normalizedIdempotencyKey) {
      await appendAudit(db, { eventType: "mcp.idempotency_missing", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { policy: server.idempotencyPolicy }, correlationId });
      return respond(jsonRpcError(body.id, -32602, "Idempotency-Key header is required for this tool", correlationId));
    }
    if (normalizedIdempotencyKey) {
      if (!IDEMPOTENCY_KEY_PATTERN.test(normalizedIdempotencyKey)) {
        return respond(jsonRpcError(body.id, -32602, "Invalid Idempotency-Key header", correlationId));
      }
      try {
        idempotency = await reserveIdempotency(db, server, principal.credentialId, normalizedIdempotencyKey, requestDigest(params.arguments ?? {}), correlationId);
      } catch (error) {
        const message = error instanceof Error && error.message === "idempotency_in_progress"
          ? "Idempotent request is already in progress"
          : error instanceof Error && error.message === "idempotency_replay_forbidden"
            ? "Completed non-idempotent requests cannot be replayed"
            : "Idempotency-Key was already used for different input";
        return respond(jsonRpcError(body.id, -32007, message, correlationId));
      }
      if (idempotency.replay) return respond(idempotency.replay);
    }

    try {
      await consumeHierarchicalRateLimit(db, server, principal.credentialId);
    } catch (error) {
      const retryAfterMs = Math.max(1, Number((error as { retryAfterMs?: unknown }).retryAfterMs ?? server.rateWindowSeconds * 1000));
      const rawScope = (error as { scope?: unknown }).scope;
      const scope = typeof rawScope === "string" ? rawScope : "SERVER_CREDENTIAL";
      await appendAudit(db, { eventType: "mcp.rate_limited", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { classification: "rate" }, correlationId });
      reply.header("retry-after", String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
      return respond(jsonRpcError(body.id, -32002, "Registered tool rate limit exceeded", correlationId, { retryAfterMs, scope }));
    }

    let leaseId = "";
    try {
      leaseId = await acquireServerExecutionLease(db, server);
    } catch {
      await appendAudit(db, {
        eventType: "mcp.concurrency_rejected",
        actorType: "kaja",
        actorId: principal.credentialId,
        objectType: "mcp_server",
        objectId: server.id,
        after: { classification: "saturation" },
        correlationId
      });
      return respond(jsonRpcError(body.id, -32004, "Registered tool concurrency limit exceeded", correlationId));
    }

    const runtimeLog = async (level: "info" | "error", eventName: string, fields: object): Promise<void> => {
      const safeFields = redact({ ...fields, serverCode: server.code, handlerVersion: server.handlerVersion }) as object;
      const safeEventName = String(redact(eventName)).slice(0, 160);
      if (level === "error") request.log.error(safeFields, safeEventName);
      else request.log.info(safeFields, safeEventName);
      await db.query(
        `insert into runtime_log_event(server_id,level,event_name,fields,correlation_id,image_digest)
         values ($1,$2,$3,$4,$5,$6)`,
        [server.id, level, safeEventName, JSON.stringify(safeFields), correlationId, server.imageDigest]
      );
    };
    const reportFinalizationFailure = async (input: { invocationId: string }): Promise<void> => {
      try {
        await recordFinalizationFailure(db, {
          invocationId: input.invocationId,
          serverId: server.id,
          correlationId,
          error: "finalization_failed"
        });
      } catch (alertError) {
        request.log.error(
          { eventType: "mcp.invocation.finalization_alert_failed", correlationId, invocationId: input.invocationId, code: server.code, ...safeErrorMetadata(alertError) },
          "MCP invocation finalization failure could not be persisted"
        );
      }
    };
    let invocationId = "";
    try {
      invocationId = await beginInvocation(db, {
        serverId: server.id,
        credentialId: principal.credentialId,
        correlationId,
        requestDigest: requestDigest(params.arguments ?? {}),
        idempotencyKey: idempotency?.key ?? null
      });
      await runtimeLog("info", "mcp.invocation.accepted", { actorId: principal.credentialId, toolName: server.toolName });
    } catch (error) {
      if (invocationId) {
        await reportFinalizationFailure({ invocationId });
      }
      try {
        await releaseServerExecutionLease(db, leaseId);
      } catch (releaseError) {
        request.log.error({ eventType: "mcp.concurrency_release_failed", correlationId, leaseId, code: server.code, ...safeErrorMetadata(releaseError) }, "MCP concurrency lease release failed");
      }
      request.log.error({ eventType: "mcp.invocation.acceptance_failed", correlationId, code: server.code, ...safeErrorMetadata(error) }, "MCP invocation acceptance failed");
      return respond(jsonRpcError(body.id, -32603, "Invocation acceptance failed", correlationId));
    }

    const started = Date.now();
    try {
      const output = await invokeWithDeadline(server.timeoutMs, server.shutdownPolicy, (signal) => handler.invoke(params.arguments ?? {}, {
          correlationId,
          server,
          signal,
          logger: {
            info: (fields, message) => runtimeLog("info", message ?? "handler.info", fields),
            error: (fields, message) => runtimeLog("error", message ?? "handler.error", fields)
          }
        }));

      serializeWithinLimit(output, server.responseMaxBytes, "worker_response_too_large");
      const validateOutput = validatorCache.get(server, "output", server.outputSchema);
      if (!validateOutput(output)) {
        throw Object.assign(new Error("output_schema_failed"), { classification: "schema" });
      }

      const latencyMs = Date.now() - started;
      const response: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: {
          content: [{ type: "text", text: contentTextForOutput(output) }],
          structuredContent: output
        }
      };
      try {
        await finalizeInvocation(db, {
          invocationId,
          serverId: server.id,
          credentialId: principal.credentialId,
          correlationId,
          outcome: {
            success: true,
            latencyMs,
            errorClass: null,
            eventType: "mcp.invocation.completed",
            response,
            idempotency: idempotency ? { key: idempotency.key, credentialId: principal.credentialId } : null
          }
        });
      } catch {
        await reportFinalizationFailure({ invocationId });
        return respond(jsonRpcError(body.id, -32603, "Invocation finalization failed", correlationId));
      }
      await runtimeLog("info", "mcp.invocation.completed", { latencyMs, invocationId }).catch((error) => {
        request.log.error({ eventType: "mcp.runtime_log.failed", correlationId, invocationId, ...safeErrorMetadata(error) }, "MCP completion runtime log failed");
      });
      request.log.info({ eventType: "mcp.invocation.completed", correlationId, invocationId, code: server.code, hostname, toolName: server.toolName, handlerKey: server.handlerKey, handlerVersion: server.handlerVersion, credentialId: principal.credentialId, result: "success", latencyMs }, "MCP invocation completed");
      return respond(response);
    } catch (error) {
      const latencyMs = Date.now() - started;
      const mapped = mapMcpRuntimeError(error);
      const { classification, eventType: classifiedEvent } = mapped;
      const errorCode = classifiedEvent;
      const response = jsonRpcError(body.id, mapped.code, mapped.message, correlationId);
      try {
        await finalizeInvocation(db, {
          invocationId,
          serverId: server.id,
          credentialId: principal.credentialId,
          correlationId,
          outcome: {
            success: false,
            latencyMs,
            errorClass: classification,
            eventType: classifiedEvent,
            response,
            idempotency: idempotency ? { key: idempotency.key, credentialId: principal.credentialId } : null
          }
        });
      } catch {
        await reportFinalizationFailure({ invocationId });
        return respond(jsonRpcError(body.id, -32603, "Invocation finalization failed", correlationId));
      }
      await runtimeLog("error", classifiedEvent, { latencyMs, errorCode, classification, invocationId }).catch((runtimeLogError) => {
        request.log.error({ eventType: "mcp.runtime_log.failed", correlationId, invocationId, ...safeErrorMetadata(runtimeLogError) }, "MCP failure runtime log failed");
      });
      request.log.error({ eventType: classifiedEvent, correlationId, invocationId, code: server.code, hostname, toolName: server.toolName, handlerKey: server.handlerKey, handlerVersion: server.handlerVersion, credentialId: principal.credentialId, result: "failure", latencyMs, errorCode, classification }, "MCP invocation failed");
      return respond(response);
    } finally {
      if (leaseId) await releaseServerExecutionLease(db, leaseId);
    }
  });
}
