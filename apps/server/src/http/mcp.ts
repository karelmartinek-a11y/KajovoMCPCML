import { randomUUID } from "node:crypto";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import type { FastifyInstance } from "fastify";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { getServerByHostname, isKcmlHostname, resourceFor } from "../domain/catalog.js";
import { validateBearer } from "../domain/auth.js";
import { getHandler } from "../handlers/registry.js";
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
    const hostname = hostOf(request.headers.host);
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
    const auth = request.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      await recordUnauthorized(db, server.id);
      await appendAudit(db, { eventType: "mcp.unauthorized", actorType: "anonymous", objectType: "mcp_server", objectId: server.id, after: { reason: "missing_bearer" }, correlationId });
      return sendError(reply, 401, "invalid_token", "Bearer token is required", correlationId);
    }
    let principal: Awaited<ReturnType<typeof validateBearer>>;
    try {
      principal = await validateBearer(db, auth.slice("Bearer ".length), hostname, config.ACCESS_TOKEN_HMAC_KEY_BASE64);
    } catch {
      await recordUnauthorized(db, server.id);
      await appendAudit(db, { eventType: "mcp.unauthorized", actorType: "anonymous", objectType: "mcp_server", objectId: server.id, after: { reason: "invalid_bearer" }, correlationId });
      return sendError(reply, 401, "invalid_token", "Invalid token", correlationId);
    }
    const body = request.body as { jsonrpc?: string; id?: unknown; method?: string; params?: unknown };
    if (body.method === "initialize") {
      return { jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: server.code, version: server.handlerVersion } } };
    }
    if (body.method === "notifications/initialized") return reply.code(202).send();
    if (body.method === "tools/list") {
      return { jsonrpc: "2.0", id: body.id, result: { tools: [{ name: server.toolName, title: server.displayName, description: server.description, inputSchema: server.inputSchema }] } };
    }
    if (body.method !== "tools/call") {
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32601, message: "Method not found" } };
    }
    const params = body.params as { name?: string; arguments?: unknown } | undefined;
    if (params?.name !== server.toolName) {
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32602, message: "Invalid tool for resource" } };
    }
    const validateInput = ajv.compile(server.inputSchema as AnySchema);
    if (!validateInput(params.arguments ?? {})) {
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32602, message: "Input schema validation failed" } };
    }
    const handler = getHandler(server);
    if (!handler) return sendError(reply, 503, "handler_unavailable", "Handler is not registered in this build", correlationId);
    await appendAudit(db, { eventType: "mcp.invocation.accepted", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, correlationId });
    const started = Date.now();
    try {
      const output = await handler.invoke(params.arguments ?? {}, { correlationId, server, logger: request.log });
      const validateOutput = ajv.compile(server.outputSchema as AnySchema);
      if (!validateOutput(output)) throw Object.assign(new Error("output_schema_failed"), { classification: "schema" });
      await db.query(
        `insert into function_statistics(server_id, success_count, last_success_at)
         values ($1,1,now())
         on conflict (server_id) do update set success_count=function_statistics.success_count+1, last_success_at=now()`,
        [server.id]
      );
      await appendAudit(db, { eventType: "mcp.invocation.completed", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { latencyMs: Date.now() - started }, correlationId });
      return { jsonrpc: "2.0", id: body.id ?? null, result: { content: [{ type: "text", text: JSON.stringify(output) }], structuredContent: output } };
    } catch (error) {
      await db.query(
        `insert into function_statistics(server_id, failure_count, last_failure_at)
         values ($1,1,now())
         on conflict (server_id) do update set failure_count=function_statistics.failure_count+1, last_failure_at=now()`,
        [server.id]
      );
      await appendAudit(db, { eventType: "mcp.invocation.failed", actorType: "kaja", actorId: principal.credentialId, objectType: "mcp_server", objectId: server.id, after: { latencyMs: Date.now() - started, error: error instanceof Error ? error.message : "unknown" }, correlationId });
      return { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32603, message: "Handler failed" } };
    }
  });
}
