import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AppServerConfig } from "../config.js";
import type { Db } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { isKcmlHostname, resourceForHostname } from "../domain/hostnames.js";
import { hostOf, sendError } from "./errors.js";
import { canonicalMcpComponent, handleCanonicalMcp } from "./component-mcp-runtime.js";
import { jsonRpcError, respondToJsonRpc, sendJsonRpc } from "./json-rpc.js";

const requestIdentitySchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite(), z.null()]).optional()
}).passthrough();

function originAllowed(origin: string | undefined, hostname: string): boolean {
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "https:" && parsed.hostname.toLowerCase() === hostname.toLowerCase();
  } catch {
    return false;
  }
}

export function registerMcpRoutes(app: FastifyInstance, db: Db, config: AppServerConfig): void {
  app.setErrorHandler((error, request, reply) => {
    if (request.url.split("?")[0] === "/mcp") {
      const correlationId = randomUUID();
      reply.header("x-correlation-id", correlationId);
      if ((error as { code?: string }).code === "FST_ERR_CTP_INVALID_JSON_BODY" || error instanceof SyntaxError) {
        return sendJsonRpc(reply, jsonRpcError(null, -32700, "Parse error", correlationId));
      }
      const parsed = requestIdentitySchema.safeParse(request.body);
      if (parsed.success) return respondToJsonRpc(reply, parsed.data.id, jsonRpcError(parsed.data.id, -32603, "Internal error", correlationId));
    }
    request.log.error({
      errorName: error instanceof Error ? error.name : "UnknownError",
      errorMessage: error instanceof Error ? error.message : "Operation failed",
      url: request.url
    }, "Unhandled request error");
    return sendError(reply, 500, "internal_error", "Operation failed");
  });

  const resourceMetadata = async (request: FastifyRequest, reply: FastifyReply) => {
    const hostname = hostOf(request.headers.host);
    if (!isKcmlHostname(hostname)) return sendError(reply, 404, "not_found");
    const component = await canonicalMcpComponent(db, hostname);
    if (!component) return sendError(reply, 404, "not_found");
    return {
      resource: resourceForHostname(hostname),
      authorization_servers: [`https://${config.AUTH_HOST}`],
      bearer_methods_supported: ["header"]
    };
  };
  app.get("/.well-known/oauth-protected-resource", resourceMetadata);
  app.get("/.well-known/oauth-protected-resource/mcp", resourceMetadata);

  app.all("/mcp", { config: { rateLimit: { max: 120, timeWindow: "1 minute", groupId: "mcp-http" } } }, async (request, reply) => {
    const correlationId = randomUUID();
    reply.header("x-correlation-id", correlationId);
    const hostname = hostOf(request.headers.host);
    if (!originAllowed(request.headers.origin, hostname)) return sendError(reply, 403, "invalid_origin", "Origin is not allowed for this MCP resource", correlationId);
    if (request.method !== "POST") {
      reply.header("allow", "POST");
      return sendError(reply, 405, "method_not_allowed", "This deployment supports POST Streamable HTTP requests only", correlationId);
    }
    if (!isKcmlHostname(hostname)) return sendError(reply, 404, "not_found", "Unknown resource", correlationId);
    const component = await canonicalMcpComponent(db, hostname);
    if (!component) {
      await appendAudit(db, { eventType: "mcp.unknown_host", actorType: "anonymous", objectType: "hostname", objectId: hostname, correlationId });
      return sendError(reply, 404, "not_found", "Unknown resource", correlationId);
    }
    return handleCanonicalMcp(request, reply, db, config, component, correlationId);
  });
}
