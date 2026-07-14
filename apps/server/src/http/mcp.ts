import { createHash, randomUUID } from "node:crypto";
import { Ajv2020, type AnySchema, type ValidateFunction } from "ajv/dist/2020.js";
import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { getServerByHostname, isKcmlHostname, resourceFor } from "../domain/catalog.js";
import { beginInvocation, finalizeInvocation, recordFinalizationFailure } from "../domain/invocation.js";
import { evaluateRecertification } from "../domain/recertification.js";
import type { McpServer } from "../domain/types.js";
import { validateBearer } from "../domain/auth.js";
import { getHandler } from "../handlers/registry.js";
import { redact } from "../security/secrets.js";
import { hostOf, sendError } from "./errors.js";

const ajv = new Ajv2020({ strict: true, allErrors: true });

const inputValidatorCache = new Map<string, ValidateFunction>();
const outputValidatorCache = new Map<string, ValidateFunction>();

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
type JsonRpcError = {
  jsonrpc: "2.0";
  id: string | number | null;
  error: {
    code: number;
    message: string;
    data?: Record<string, unknown>;
  };
};
type JsonRpcResponse = JsonRpcError | {
  jsonrpc: "2.0";
  id: string | number | null;
  result: Record<string, unknown>;
};
type IdempotencyReservation = {
  key: string;
  requestDigest: string;
  replay?: JsonRpcResponse;
};

const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{8,160}$/;

function validatorFor(cache: Map<string, ValidateFunction>, server: McpServer, kind: "input" | "output", schema: unknown): ValidateFunction {
  const key = `${server.id}:${server.contractVersion}:${server.manifestDigest}:${kind}`;
  const cached = cache.get(key);
  if (cached) return cached;
  const compiled = ajv.compile(schema as AnySchema);
  cache.set(key, compiled);
  return compiled;
}

function jsonRpcError(id: unknown, code: number, message: string, correlationId: string, extra?: Record<string, unknown>): JsonRpcError {
  return {
    jsonrpc: "2.0",
    id: typeof id === "string" || typeof id === "number" ? id : null,
    error: {
      code,
      message,
      data: { correlationId, ...(extra ?? {}) }
    }
  };
}

function requestDigest(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

function idempotencyRequired(server: McpServer): boolean {
  return !server.idempotentHint || !/read\s*only/i.test(server.idempotencyPolicy);
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
      `insert into mcp_invocation_idempotency(server_id,credential_id,idempotency_key,request_digest,status,correlation_id)
       values ($1,$2,$3,$4,'PENDING',$5)
       on conflict (server_id, credential_id, idempotency_key) do nothing
       returning idempotency_key`,
      [server.id, credentialId, key, digest, correlationId]
    );
    if (inserted.rowCount) return { key, requestDigest: digest };
    const existing = await client.query(
      `select request_digest,status,response_json
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
    if (row.status === "COMPLETED" && row.response_json) {
      return { key, requestDigest: digest, replay: row.response_json as JsonRpcResponse };
    }
    throw Object.assign(new Error("idempotency_in_progress"), { statusCode: 409 });
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

async function acquireConcurrencyLease(db: Db, server: McpServer): Promise<string> {
  const lease = await tx(db, async (client) => {
    await client.query("delete from function_concurrency_lease where expires_at <= now()");
    const locked = await client.query("select max_concurrency, timeout_ms from mcp_server where id=$1 for update", [server.id]);
    if (!locked.rowCount) throw new Error("server_missing");
    const active = await client.query("select count(*)::int as count from function_concurrency_lease where server_id=$1 and expires_at > now()", [server.id]);
    if (Number(active.rows[0].count) >= Number(locked.rows[0].max_concurrency)) {
      throw Object.assign(new Error("concurrency_limit_exceeded"), { classification: "saturation" });
    }
    const inserted = await client.query(
      "insert into function_concurrency_lease(server_id, expires_at) values ($1, now() + (($2 + 5000) || ' milliseconds')::interval) returning lease_id",
      [server.id, Number(locked.rows[0].timeout_ms)]
    );
    return String(inserted.rows[0].lease_id);
  });
  return lease;
}

async function releaseConcurrencyLease(db: Db, leaseId: string): Promise<void> {
  await db.query("delete from function_concurrency_lease where lease_id=$1", [leaseId]);
}

function contentTextForOutput(output: unknown): string {
  const table = output && typeof output === "object" && "markdown_table" in output
    ? (output as { markdown_table?: unknown }).markdown_table
    : undefined;
  return typeof table === "string" ? table : JSON.stringify(output);
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
  return requestAccept.split(",").some((part) => part.split(";")[0]?.trim().toLowerCase() === contentType);
}

function sendSsePoll(reply: FastifyReply, correlationId: string): void {
  reply.hijack();
  reply.raw.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-store",
    connection: "keep-alive",
    "x-correlation-id": correlationId
  });
  reply.raw.end(`id: ${correlationId}\nretry: 15000\ndata:\n\n`);
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

export function registerMcpRoutes(app: FastifyInstance, db: Db, config: AppConfig): void {
  app.get("/.well-known/oauth-protected-resource", async (request, reply) => {
    const hostname = hostOf(request.headers.host);
    if (!isKcmlHostname(hostname, config.PUBLIC_BASE_DOMAIN)) return sendError(reply, 404, "not_found");
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
    if (!["POST", "GET"].includes(request.method)) return sendError(reply, 405, "method_not_allowed", "Only POST and GET are supported", correlationId);
    if (!isKcmlHostname(hostname, config.PUBLIC_BASE_DOMAIN)) return sendError(reply, 404, "not_found", "Unknown resource", correlationId);

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
    } catch {
      await recordUnauthorized(db, server.id);
      await appendAudit(db, { eventType: "mcp.unauthorized", actorType: "anonymous", objectType: "mcp_server", objectId: server.id, after: { reason: "invalid_bearer" }, correlationId });
      reply.header("WWW-Authenticate", challenge);
      return sendError(reply, 401, "invalid_token", "Invalid token", correlationId);
    }

    if (request.method === "GET") {
      if (!accepts(request.headers.accept, "text/event-stream")) {
        return sendError(reply, 406, "not_acceptable", "GET /mcp requires Accept: text/event-stream", correlationId);
      }
      await appendAudit(db, { eventType: "mcp.sse_poll", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, correlationId });
      return sendSsePoll(reply, correlationId);
    }

    if (Array.isArray(request.body)) {
      return reply.send(jsonRpcError(null, -32600, "Batch requests are not supported", correlationId));
    }

    const parsed = jsonRpcRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.send(jsonRpcError(null, -32600, "Invalid Request", correlationId));
    }
    const body: JsonRpcRequest = parsed.data;

    if (body.method === "initialize") {
      return reply.send({
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: {
          protocolVersion: "2025-11-25",
          capabilities: { tools: {} },
          serverInfo: { name: server.code, version: server.handlerVersion }
        }
      });
    }

    if (body.method === "notifications/initialized") return reply.code(202).send();

    if (body.method === "tools/list") {
      return reply.send({
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: {
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
        }
      });
    }

    if (body.method !== "tools/call") {
      return reply.send(jsonRpcError(body.id, -32601, "Method not found", correlationId));
    }

    const parsedParams = toolCallParamsSchema.safeParse(body.params ?? {});
    if (!parsedParams.success) {
      return reply.send(jsonRpcError(body.id, -32602, "Invalid params", correlationId));
    }
    const params = parsedParams.data;
    if (params.name !== server.toolName) {
      return reply.send(jsonRpcError(body.id, -32602, "Invalid tool for resource", correlationId));
    }

    const serializedInput = JSON.stringify(params.arguments ?? {});
    if (Buffer.byteLength(serializedInput) > server.requestMaxBytes) {
      await appendAudit(db, { eventType: "mcp.request_too_large", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { classification: "size" }, correlationId });
      return reply.send(jsonRpcError(body.id, -32001, "Tool input exceeds the registered limit", correlationId));
    }

    const validateInput = validatorFor(inputValidatorCache, server, "input", server.inputSchema);
    if (!validateInput(params.arguments ?? {})) {
      request.log.info({ eventType: "mcp.input_schema_failed", correlationId, code: server.code, hostname, toolName: server.toolName, errorCode: "input_schema_failed", classification: "schema" }, "MCP input schema rejected");
      await appendAudit(db, { eventType: "mcp.input_schema_failed", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { errorCode: "input_schema_failed", classification: "schema" }, correlationId });
      return reply.send(jsonRpcError(body.id, -32602, "Input schema validation failed", correlationId, { issues: validateInput.errors ?? [] }));
    }

    const handler = getHandler(server);
    if (!handler) {
      await appendAudit(db, { eventType: "mcp.handler_unavailable", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { errorCode: "handler_unavailable", classification: "configuration" }, correlationId });
      return reply.send(jsonRpcError(body.id, -32003, "Handler is not registered in this build", correlationId));
    }

    let idempotency: IdempotencyReservation | null = null;
    const idempotencyKey = request.headers["idempotency-key"];
    const normalizedIdempotencyKey = typeof idempotencyKey === "string" ? idempotencyKey.trim() : "";
    if (idempotencyRequired(server) && !normalizedIdempotencyKey) {
      await appendAudit(db, { eventType: "mcp.idempotency_missing", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { policy: server.idempotencyPolicy }, correlationId });
      return reply.send(jsonRpcError(body.id, -32602, "Idempotency-Key header is required for this tool", correlationId));
    }
    if (normalizedIdempotencyKey) {
      if (!IDEMPOTENCY_KEY_PATTERN.test(normalizedIdempotencyKey)) {
        return reply.send(jsonRpcError(body.id, -32602, "Invalid Idempotency-Key header", correlationId));
      }
      try {
        idempotency = await reserveIdempotency(db, server, principal.credentialId, normalizedIdempotencyKey, requestDigest(params.arguments ?? {}), correlationId);
      } catch (error) {
        const message = error instanceof Error && error.message === "idempotency_in_progress"
          ? "Idempotent request is already in progress"
          : "Idempotency-Key was already used for different input";
        return reply.send(jsonRpcError(body.id, -32007, message, correlationId));
      }
      if (idempotency.replay) return reply.send(idempotency.replay);
    }

    const rate = await db.query(
      `insert into function_rate_bucket(server_id,credential_id,window_started_at,request_count)
       values ($1,$2,now(),1)
       on conflict (server_id, credential_id) do update set
         window_started_at=case when function_rate_bucket.window_started_at <= now()-($3 || ' seconds')::interval then now() else function_rate_bucket.window_started_at end,
         request_count=case when function_rate_bucket.window_started_at <= now()-($3 || ' seconds')::interval then 1 else function_rate_bucket.request_count+1 end
       returning request_count`,
      [server.id, principal.credentialId, server.rateWindowSeconds]
    );
    if (Number(rate.rows[0].request_count) > server.rateMaxRequests) {
      await appendAudit(db, { eventType: "mcp.rate_limited", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { classification: "rate" }, correlationId });
      reply.header("retry-after", String(server.rateWindowSeconds));
      return reply.send(jsonRpcError(body.id, -32002, "Registered tool rate limit exceeded", correlationId));
    }

    let leaseId = "";
    try {
      leaseId = await acquireConcurrencyLease(db, server);
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
      return reply.send(jsonRpcError(body.id, -32004, "Registered tool concurrency limit exceeded", correlationId));
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
    const reportFinalizationFailure = async (input: { invocationId: string; error: unknown }): Promise<void> => {
      try {
        await recordFinalizationFailure(db, {
          invocationId: input.invocationId,
          serverId: server.id,
          correlationId,
          error: input.error instanceof Error ? input.error.message
            : typeof input.error === "string" ? input.error
              : "finalization_failed"
        });
      } catch (alertError) {
        request.log.error(
          { eventType: "mcp.invocation.finalization_alert_failed", correlationId, invocationId: input.invocationId, code: server.code, alertError },
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
        await reportFinalizationFailure({ invocationId, error });
      }
      try {
        await releaseConcurrencyLease(db, leaseId);
      } catch (releaseError) {
        request.log.error({ eventType: "mcp.concurrency_release_failed", correlationId, leaseId, code: server.code, releaseError }, "MCP concurrency lease release failed");
      }
      request.log.error({ eventType: "mcp.invocation.acceptance_failed", correlationId, code: server.code, error }, "MCP invocation acceptance failed");
      return reply.send(jsonRpcError(body.id, -32603, "Invocation acceptance failed", correlationId));
    }

    const started = Date.now();
    try {
      const output = await Promise.race([
        handler.invoke(params.arguments ?? {}, {
          correlationId,
          server,
          logger: {
            info: (fields, message) => runtimeLog("info", message ?? "handler.info", fields),
            error: (fields, message) => runtimeLog("error", message ?? "handler.error", fields)
          }
        }),
        new Promise<never>((_, reject) => {
          setTimeout(() => reject(Object.assign(new Error("handler_timeout"), { classification: "timeout" })), server.timeoutMs);
        })
      ]);

      const serializedOutput = JSON.stringify(output);
      if (serializedOutput === undefined || Buffer.byteLength(serializedOutput) > server.responseMaxBytes) {
        throw Object.assign(new Error("worker_response_too_large"), { classification: "size" });
      }
      const validateOutput = validatorFor(outputValidatorCache, server, "output", server.outputSchema);
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
      } catch (error) {
        await reportFinalizationFailure({ invocationId, error });
        return reply.send(jsonRpcError(body.id, -32603, "Invocation finalization failed", correlationId));
      }
      await runtimeLog("info", "mcp.invocation.completed", { latencyMs, invocationId }).catch((error) => {
        request.log.error({ eventType: "mcp.runtime_log.failed", correlationId, invocationId, error }, "MCP completion runtime log failed");
      });
      request.log.info({ eventType: "mcp.invocation.completed", correlationId, invocationId, code: server.code, hostname, toolName: server.toolName, handlerKey: server.handlerKey, handlerVersion: server.handlerVersion, credentialId: principal.credentialId, result: "success", latencyMs }, "MCP invocation completed");
      return reply.send(response);
    } catch (error) {
      const latencyMs = Date.now() - started;
      const errorCode = error instanceof Error ? error.message : "unknown";
      const classification = typeof error === "object" && error && "classification" in error ? String(error.classification) : "handler";
      const classifiedEvent = errorCode === "output_schema_failed" ? "mcp.output_schema_failed"
        : classification === "timeout" ? "mcp.timeout"
          : classification === "schema" ? "mcp.output_schema_failed"
            : classification === "size" ? "mcp.response_too_large"
              : classification === "saturation" ? "mcp.concurrency_rejected"
                : classification === "upstream" ? "mcp.upstream_failed"
                  : "mcp.invocation.failed";
      const code = classification === "timeout" ? -32005
        : classification === "size" ? -32006
          : classification === "schema" ? -32603
            : classification === "saturation" ? -32004
              : -32603;
      const message = classification === "timeout" ? "Handler timed out"
        : classification === "size" ? "Handler response exceeded the registered limit"
          : errorCode === "output_schema_failed" ? "Output schema validation failed"
            : "Handler failed";
      const response = jsonRpcError(body.id, code, message, correlationId);
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
      } catch (finalizationError) {
        await reportFinalizationFailure({ invocationId, error: finalizationError });
        return reply.send(jsonRpcError(body.id, -32603, "Invocation finalization failed", correlationId));
      }
      await runtimeLog("error", classifiedEvent, { latencyMs, errorCode, classification, invocationId }).catch((runtimeLogError) => {
        request.log.error({ eventType: "mcp.runtime_log.failed", correlationId, invocationId, error: runtimeLogError }, "MCP failure runtime log failed");
      });
      request.log.error({ eventType: classifiedEvent, correlationId, invocationId, code: server.code, hostname, toolName: server.toolName, handlerKey: server.handlerKey, handlerVersion: server.handlerVersion, credentialId: principal.credentialId, result: "failure", latencyMs, errorCode, classification }, "MCP invocation failed");
      return reply.send(response);
    } finally {
      if (leaseId) await releaseConcurrencyLease(db, leaseId);
    }
  });
}
