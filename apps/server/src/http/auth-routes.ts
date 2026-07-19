import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { OAuthConfig } from "../config.js";
import type { Db } from "../db.js";
import { issueAccessToken } from "../domain/auth.js";
import { authorizeComponentCall, issueComponentAccessToken } from "../domain/component-auth.js";
import { authorizeManagedServiceToken } from "../domain/managed-service.js";
import { hmacToken } from "../security/secrets.js";
import { hostOf, sendError } from "./errors.js";

export function registerAuthRoutes(app: FastifyInstance, db: Db, config: OAuthConfig): void {
  app.get("/.well-known/oauth-authorization-server", async () => ({
    issuer: `https://${config.AUTH_HOST}`,
    token_endpoint: `https://${config.AUTH_HOST}/oauth/token`,
    introspection_endpoint: `https://${config.AUTH_HOST}/oauth/introspect`,
    grant_types_supported: ["client_credentials"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"],
    introspection_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["mcp.invoke", "component.invoke"],
    resource_indicators_supported: true,
    client_id_metadata_document_supported: false
  }));

  app.post("/oauth/token", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.AUTH_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const contentType = request.headers["content-type"] ?? "";
    if (!String(contentType).includes("application/x-www-form-urlencoded")) return sendError(reply, 415, "unsupported_media_type", undefined, correlationId);
    const auth = request.headers.authorization ?? "";
    if (!auth.startsWith("Basic ")) return sendError(reply, 401, "invalid_client", undefined, correlationId);
    const decoded = Buffer.from(auth.slice("Basic ".length), "base64").toString("utf8");
    const sep = decoded.indexOf(":");
    if (sep < 1) return sendError(reply, 401, "invalid_client", undefined, correlationId);
    const clientId = decodeURIComponent(decoded.slice(0, sep));
    const clientSecret = decodeURIComponent(decoded.slice(sep + 1));
    const body = request.body as { grant_type?: string; resource?: string };
    if (body.grant_type !== "client_credentials") return sendError(reply, 400, "unsupported_grant_type", undefined, correlationId);
    if (!body.resource) return sendError(reply, 400, "invalid_resource", undefined, correlationId);
    try {
      const issuer = /^KCML[0-9]{4,}-C[0-9]{2,}$/i.test(clientId) ? issueComponentAccessToken : issueAccessToken;
      return await issuer(db, {
        clientId,
        clientSecret,
        resource: body.resource,
        hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
        keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
        correlationId
      });
    } catch (error) {
      const statusCode = typeof error === "object" && error && "statusCode" in error ? Number(error.statusCode) : 500;
      const code = error instanceof Error ? error.message : "server_error";
      return sendError(reply, statusCode, code, undefined, correlationId);
    }
  });

  app.post("/oauth/introspect", {
    config: { rateLimit: { max: 60, timeWindow: "1 minute", groupId: "oauth-introspect" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.AUTH_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const contentType = request.headers["content-type"] ?? "";
    if (!String(contentType).includes("application/x-www-form-urlencoded")) return sendError(reply, 415, "unsupported_media_type", undefined, correlationId);
    const body = request.body as { token?: string; resource?: string; operationId?: string; scope?: string; method?: string; path?: string };
    if (!body.token || !body.resource) return sendError(reply, 400, "invalid_request", undefined, correlationId);
    const digest = hmacToken(body.token, config.ACCESS_TOKEN_HMAC_KEY_BASE64);
    const componentToken = await db.query("select 1 from component_access_token where lookup_digest=$1", [digest]);
    if (componentToken.rowCount) {
      let resource: URL;
      try {
        resource = new URL(body.resource);
      } catch {
        return { active: false, code: "invalid_audience", correlationId };
      }
      const decision = await authorizeComponentCall(db, {
        token: body.token,
        audience: body.resource,
        host: resource.hostname,
        scope: body.scope ?? "component.invoke",
        route: body.path ?? "/",
        hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
        correlationId
      });
      return {
        active: decision.allow,
        code: decision.reasonCode,
        decisionId: decision.decisionId,
        correlationId: decision.correlationId,
        sourceComponentId: decision.sourceComponentId,
        targetComponentId: decision.targetComponentId,
        scopes: decision.scopes,
        policyEpoch: decision.policyEpoch
      };
    }
    const decision = await authorizeManagedServiceToken(db, {
      tokenDigest: digest,
      audience: body.resource,
      environment: "production",
      requiredScopes: [body.scope ?? "mcp.invoke"],
      correlationId,
      operationId: body.operationId ?? null,
      requestMethod: body.method ?? null,
      requestPath: body.path ?? null
    });
    return {
      active: decision.allow,
      code: decision.reasonCode,
      decisionId: decision.decisionId,
      correlationId: decision.correlationId,
      serviceId: decision.serviceId,
      principalId: decision.principalId,
      operationId: decision.operationId,
      scopes: decision.scopes,
      apiState: decision.apiState,
      lifecycleState: decision.lifecycleState,
      permissionEpoch: decision.permissionEpoch,
      serviceTokenEpoch: decision.serviceTokenEpoch,
      activeRevisionEpoch: decision.activeRevisionEpoch
    };
  });
}
