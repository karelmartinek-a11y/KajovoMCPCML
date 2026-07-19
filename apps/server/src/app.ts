import path from "node:path";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import formbody from "@fastify/formbody";
import helmet from "@fastify/helmet";
import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import type { AppServerConfig } from "./config.js";
import type { Db } from "./db.js";
import { isKcmlHostname } from "./domain/catalog.js";
import { isReferenceExternalApiHostname } from "./domain/reference-external-api.js";
import { registerAdminRoutes } from "./http/admin-routes.js";
import { registerAuthRoutes } from "./http/auth-routes.js";
import { registerExternalApiRoutes } from "./http/external-api-routes.js";
import { registerComponentRoutes } from "./http/component-routes.js";
import { registerMcpRoutes } from "./http/mcp.js";
import { registerOnboardingRoutes } from "./http/onboarding-routes.js";
import { registerReferenceExternalApiRoutes } from "./http/reference-external-api-routes.js";
import { hostOf, sendError } from "./http/errors.js";
import { createPostgresRateLimitStore } from "./http/postgres-rate-limit-store.js";
import { buildMetadata, KCML_RELEASE } from "./domain/release.js";

export async function buildApp(config: AppServerConfig, db: Db) {
  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      redact: {
        paths: ["req.headers.authorization", "req.headers.cookie", "res.headers['set-cookie']"],
        censor: "[REDACTED]"
      }
    },
    bodyLimit: 1024 * 1024,
    trustProxy: config.TRUSTED_PROXY_CIDRS
  });
  await app.register(helmet, {
    global: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: process.env.NODE_ENV === "production" ? [] : null
      }
    }
  });
  await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
  await app.register(formbody);
  await app.register(multipart, {
    limits: { files: 1, fields: 2, fileSize: 10 * 1024 * 1024, fieldSize: 512 * 1024, parts: 3 }
  });
  await app.register(rateLimit, {
    max: 120,
    timeWindow: "1 minute",
    store: createPostgresRateLimitStore(db, config.SESSION_SECRET_BASE64),
    skipOnError: false,
    allowList: (request) => request.url === "/health"
      || (hostOf(request.headers.host) === config.ADMIN_HOST && !request.url.startsWith("/api/")),
    errorResponseBuilder: (_request, context) => ({
      statusCode: 429,
      error: "rate_limited",
      message: "Too many requests",
      retryAfterSeconds: Math.max(1, Math.ceil(context.ttl / 1000))
    })
  });

  app.addHook("onRequest", async (request, reply) => {
    const host = hostOf(request.headers.host);
    const isKnownHost = host === config.ADMIN_HOST
      || host === config.AUTH_HOST
      || host === config.REGISTER_HOST
      || isReferenceExternalApiHostname(host, config.PUBLIC_BASE_DOMAIN)
      || isKcmlHostname(host, config.PUBLIC_BASE_DOMAIN);
    if (!isKnownHost) return sendError(reply, 404, "not_found");
  });

  registerAdminRoutes(app, db, config);
  registerAuthRoutes(app, db, config);
  registerMcpRoutes(app, db, config);
  registerReferenceExternalApiRoutes(app, config);
  registerExternalApiRoutes(app, db, config);
  registerOnboardingRoutes(app, db, config);
  registerComponentRoutes(app, db, config);

  app.get("/api/version", async (_request, reply) => reply
    .header("cache-control", "no-store")
    .send({ ...KCML_RELEASE, ...buildMetadata() }));

  const adminDist = path.resolve(process.cwd(), "apps/admin-ui/dist");
  app.addHook("onRequest", async (request, reply) => {
    const host = hostOf(request.headers.host);
    if (host === config.ADMIN_HOST) return;
    if (host === config.AUTH_HOST && (request.url === "/oauth/token" || request.url === "/oauth/introspect" || request.url === "/.well-known/oauth-authorization-server")) return;
    if (host === config.REGISTER_HOST && (request.url.startsWith("/v1/") || request.url.startsWith("/v2/"))) return;
    if (isReferenceExternalApiHostname(host, config.PUBLIC_BASE_DOMAIN)) return;
    if (isKcmlHostname(host, config.PUBLIC_BASE_DOMAIN)) return;
    return sendError(reply, 404, "not_found");
  });
  await app.register(fastifyStatic, { root: adminDist, wildcard: false });
  app.setNotFoundHandler(async (request, reply) => {
    const host = hostOf(request.headers.host);
    if (host === config.ADMIN_HOST && request.method === "GET" && !request.url.startsWith("/api/")) {
      return reply.sendFile("index.html");
    }
    return sendError(reply, 404, "not_found");
  });

  return app;
}
