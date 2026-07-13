import { randomUUID } from "node:crypto";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import type { FastifyInstance } from "fastify";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { getServerByHostname, isKcmlHostname, resourceFor } from "../domain/catalog.js";
import { validateBearer } from "../domain/auth.js";
import { getHandler } from "../handlers/registry.js";
import { redact } from "../security/secrets.js";
import { hostOf, sendError } from "./errors.js";

const ajv = new Ajv2020({ strict: true, allErrors: true });

async function recordUnauthorized(db: Db, serverId: string): Promise<void> {
  await db.query(
    `insert into function_statistics(server_id, unauthorized_count, last_unauthorized_at)
     values ($1,1,now())
     on conflict (server_id) do update set unauthorized_count=function_statistics.unauthorized_count+1, last_unauthorized_at=now()`,
    [serverId]
  );
}

async function recordInvocationMetric(db: Db, serverId: string, success: boolean, latencyMs: number, classification: string | null, correlationId: string): Promise<void> {
  await db.query(
    "insert into mcp_invocation_metric(server_id,success,latency_ms,classification,correlation_id) values ($1,$2,$3,$4,$5)",
    [serverId, success, latencyMs, classification, correlationId]
  );
}

export function registerMcpRoutes(app: FastifyInstance, db: Db, config: AppConfig): void {
  app.get("/.well-known/oauth-protected-resource", async (request, reply) => {
    const hostname = hostOf(request.headers.host);
    if (!isKcmlHostname(hostname, config.PUBLIC_BASE_DOMAIN)) return sendError(reply, 404, "not_found");
    const server = await getServerByHostname(db, hostname);
    if (!server) return sendError(reply, 404, "not_found");
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
    return {
      resource: resourceFor(hostname),
      authorization_servers: [`https://${config.AUTH_HOST}`],
      bearer_methods_supported: ["header"]
    };
  });

  app.all("/mcp", async (request, reply) => {
    const correlationId = randomUUID();
    reply.header("x-correlation-id", correlationId);
    const hostname = hostOf(request.headers.host);
    request.log.info({ eventType: "mcp.request.received", correlationId, hostname, method: request.method }, "MCP request received");
    if (request.method !== "POST") return sendError(reply, 405, "method_not_allowed", "Only POST is supported", correlationId);
    if (!isKcmlHostname(hostname, config.PUBLIC_BASE_DOMAIN)) return sendError(reply, 404, "not_found", "Unknown resource", correlationId);
    const server = await getServerByHostname(db, hostname);
    if (!server) {
      await appendAudit(db, { eventType: "mcp.unknown_host", actorType: "anonymous", objectType: "hostname", objectId: hostname, correlationId });
      return sendError(reply, 404, "not_found", "Unknown resource", correlationId);
    }
    if (!server.enabled || !["ACTIVE", "TRIAL"].includes(server.registrationState)) {
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
    const body = request.body as { jsonrpc?: string; id?: unknown; method?: string; params?: unknown };
    if (body.method === "initialize") {
      return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: server.code, version: server.handlerVersion } } };
    }
    if (body.method === "notifications/initialized") return reply.code(202).send();
    if (body.method === "tools/list") {
      return {
        jsonrpc: "2.0",
        id: body.id,
        result: {
          tools: [{
            name: server.toolName,
            title: server.displayName,
            description: server.description,
            inputSchema: server.inputSchema,
            outputSchema: server.outputSchema,
            annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
          }]
        }
      };
    }
    if (body.method !== "tools/call") {
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32601, message: "Method not found" } };
    }
    const params = body.params as { name?: string; arguments?: unknown } | undefined;
    if (params?.name !== server.toolName) {
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32602, message: "Invalid tool for resource" } };
    }
    const serializedInput = Buffer.byteLength(JSON.stringify(params.arguments ?? {}));
    if (serializedInput > server.requestMaxBytes) return sendError(reply, 413, "request_too_large", "Tool input exceeds the registered limit", correlationId);
    const validateInput = ajv.compile(server.inputSchema as AnySchema);
    if (!validateInput(params.arguments ?? {})) {
      request.log.info({ eventType: "mcp.input_schema_failed", correlationId, code: server.code, hostname, toolName: server.toolName, errorCode: "input_schema_failed", classification: "schema" }, "MCP input schema rejected");
      await appendAudit(db, { eventType: "mcp.input_schema_failed", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { errorCode: "input_schema_failed", classification: "schema" }, correlationId });
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32602, message: "Input schema validation failed" } };
    }
    const handler = getHandler(server);
    if (!handler) {
      await appendAudit(db, { eventType: "mcp.handler_unavailable", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { errorCode: "handler_unavailable", classification: "configuration" }, correlationId });
      return sendError(reply, 503, "handler_unavailable", "Handler is not registered in this build", correlationId);
    }
    const rate = await db.query(
      `insert into function_rate_bucket(server_id,window_started_at,request_count)
       values ($1,now(),1)
       on conflict (server_id) do update set
         window_started_at=case when function_rate_bucket.window_started_at <= now()-($2 || ' seconds')::interval then now() else function_rate_bucket.window_started_at end,
         request_count=case when function_rate_bucket.window_started_at <= now()-($2 || ' seconds')::interval then 1 else function_rate_bucket.request_count+1 end
       returning request_count`,
      [server.id, server.rateWindowSeconds]
    );
    if (Number(rate.rows[0].request_count) > server.rateMaxRequests) return sendError(reply, 429, "rate_limit_exceeded", "Registered tool rate limit exceeded", correlationId);
    await appendAudit(db, { eventType: "mcp.invocation.accepted", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, correlationId });
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
    await runtimeLog("info", "mcp.invocation.accepted", { actorId: principal.credentialId, toolName: server.toolName });
    const started = Date.now();
    try {
      const output = await handler.invoke(params.arguments ?? {}, {
        correlationId,
        server,
        logger: {
          info: (fields, message) => runtimeLog("info", message ?? "handler.info", fields),
          error: (fields, message) => runtimeLog("error", message ?? "handler.error", fields)
        }
      });
      const serializedOutput = JSON.stringify(output);
      if (serializedOutput === undefined || Buffer.byteLength(serializedOutput) > server.responseMaxBytes) throw Object.assign(new Error("worker_response_too_large"), { classification: "size" });
      const validateOutput = ajv.compile(server.outputSchema as AnySchema);
      if (!validateOutput(output)) throw Object.assign(new Error("output_schema_failed"), { classification: "schema" });
      const latencyMs = Date.now() - started;
      await db.query(
        `insert into function_statistics(server_id, success_count, last_success_at)
         values ($1,1,now())
         on conflict (server_id) do update set success_count=function_statistics.success_count+1, last_success_at=now()`,
        [server.id]
      );
      await recordInvocationMetric(db, server.id, true, latencyMs, null, correlationId);
      await appendAudit(db, { eventType: "mcp.invocation.completed", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { latencyMs }, correlationId });
      await runtimeLog("info", "mcp.invocation.completed", { latencyMs });
      request.log.info({ eventType: "mcp.invocation.completed", correlationId, code: server.code, hostname, toolName: server.toolName, handlerKey: server.handlerKey, handlerVersion: server.handlerVersion, credentialId: principal.credentialId, result: "success", latencyMs }, "MCP invocation completed");
      const table = output && typeof output === "object" && "markdown_table" in output
        ? (output as { markdown_table?: unknown }).markdown_table
        : undefined;
      return {
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: {
          content: [{ type: "text", text: typeof table === "string" ? table : JSON.stringify(output) }],
          structuredContent: output
        }
      };
    } catch (error) {
      const latencyMs = Date.now() - started;
      const errorCode = error instanceof Error ? error.message : "unknown";
      const classification = typeof error === "object" && error && "classification" in error ? String(error.classification) : "handler";
      await db.query(
        `insert into function_statistics(server_id, failure_count, last_failure_at)
         values ($1,1,now())
         on conflict (server_id) do update set failure_count=function_statistics.failure_count+1, last_failure_at=now()`,
        [server.id]
      );
      await recordInvocationMetric(db, server.id, false, latencyMs, classification, correlationId);
      const classifiedEvent = errorCode === "output_schema_failed" ? "mcp.output_schema_failed"
        : classification === "timeout" ? "mcp.timeout"
          : classification === "upstream" ? "mcp.upstream_failed"
            : "mcp.invocation.failed";
      await appendAudit(db, { eventType: classifiedEvent, actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { latencyMs, errorCode, classification }, correlationId });
      await runtimeLog("error", classifiedEvent, { latencyMs, errorCode, classification });
      request.log.error({ eventType: classifiedEvent, correlationId, code: server.code, hostname, toolName: server.toolName, handlerKey: server.handlerKey, handlerVersion: server.handlerVersion, credentialId: principal.credentialId, result: "failure", latencyMs, errorCode, classification }, "MCP invocation failed");
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32603, message: "Handler failed" } };
    }
  });
}
