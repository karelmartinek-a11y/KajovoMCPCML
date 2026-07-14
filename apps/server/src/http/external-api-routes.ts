import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { authorizeManagedServiceToken } from "../domain/managed-service.js";
import { loadExternalApiGatewayService, matchExternalApiOperation, proxyExternalApiOperation } from "../domain/external-api.js";
import { hmacToken } from "../security/secrets.js";
import { hostOf, sendError } from "./errors.js";

export function registerExternalApiRoutes(app: FastifyInstance, db: Db, config: AppConfig): void {
  app.route({
    method: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    url: "/*",
    handler: async (request, reply) => {
      const correlationId = randomUUID();
      const hostname = hostOf(request.headers.host);
      if (!hostname.startsWith("kcml")) return sendError(reply, 404, "not_found", undefined, correlationId);
      const service = await loadExternalApiGatewayService(db, hostname);
      if (!service) return sendError(reply, 404, "not_found", undefined, correlationId);
      const path = request.url.split("?")[0] ?? "/";
      const match = matchExternalApiOperation(service.manifest, request.method, path);
      if (!match) return sendError(reply, 404, "operation_not_found", undefined, correlationId);
      const authorization = request.headers.authorization;
      if (!authorization?.startsWith("Bearer ")) return sendError(reply, 401, "invalid_token", undefined, correlationId);
      const decision = await authorizeManagedServiceToken(db, {
        tokenDigest: hmacToken(authorization.slice("Bearer ".length), config.ACCESS_TOKEN_HMAC_KEY_BASE64),
        audience: service.resourceUri,
        environment: service.manifest.environment,
        requiredScopes: match.operation.requiredScopes,
        correlationId,
        operationId: match.operation.operationId,
        requestMethod: request.method,
        requestPath: path
      });
      if (!decision.allow || !decision.principalId) return sendError(reply, 401, decision.reasonCode, undefined, correlationId);
      const body = request.body
        ? Buffer.from(typeof request.body === "string" ? request.body : JSON.stringify(request.body))
        : Buffer.alloc(0);
      if (body.length > match.operation.maxPayloadBytes) return sendError(reply, 413, "payload_too_large", undefined, correlationId);
      try {
        const queryIndex = request.url.indexOf("?");
        const proxied = await proxyExternalApiOperation(db, {
          config,
          service,
          operation: match.operation,
          requestPath: path,
          queryString: queryIndex >= 0 ? request.url.slice(queryIndex) : "",
          body,
          principalId: decision.principalId,
          correlationId
        });
        for (const [name, value] of Object.entries(proxied.headers)) reply.header(name, value);
        reply.header("x-correlation-id", correlationId);
        return reply.code(proxied.status).send(proxied.body);
      } catch (error) {
        return sendError(reply, 502, error instanceof Error ? error.message : "gateway_failed", undefined, correlationId);
      }
    }
  });
}
