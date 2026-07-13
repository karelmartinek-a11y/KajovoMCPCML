import path from "node:path";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import formbody from "@fastify/formbody";
import helmet from "@fastify/helmet";
import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import type { AppConfig } from "./config.js";
import type { Db } from "./db.js";
import { isKcmlHostname } from "./domain/catalog.js";
import { registerAdminRoutes } from "./http/admin-routes.js";
import { registerAuthRoutes } from "./http/auth-routes.js";
import { registerMcpRoutes } from "./http/mcp.js";
import { registerOnboardingRoutes } from "./http/onboarding-routes.js";
import { hostOf, sendError } from "./http/errors.js";

export async function buildApp(config: AppConfig, db: Db) {
  const app = Fastify({
    logger: { level: config.LOG_LEVEL },
    bodyLimit: 1024 * 1024,
    trustProxy: true
  });
  await app.register(helmet, {
    global: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        frameAncestors: ["'none'"]
      }
    }
  });
  await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
  await app.register(formbody);
  await app.register(multipart, {
    limits: { files: 1, fields: 2, fileSize: 10 * 1024 * 1024, fieldSize: 512 * 1024, parts: 3 }
  });
  await app.register(rateLimit, { max: 120, timeWindow: "1 minute" });

  app.addHook("onRequest", async (request, reply) => {
    const host = hostOf(request.headers.host);
    const isKnownHost = host === config.ADMIN_HOST
      || host === config.AUTH_HOST
      || host === config.REGISTER_HOST
      || isKcmlHostname(host, config.PUBLIC_BASE_DOMAIN);
    if (!isKnownHost) return sendError(reply, 404, "not_found");
  });

  registerAdminRoutes(app, db, config);
  registerAuthRoutes(app, db, config);
  registerMcpRoutes(app, db, config);
  registerOnboardingRoutes(app, db, config);

  const adminDist = path.resolve(process.cwd(), "apps/admin-ui/dist");
  app.addHook("onRequest", async (request, reply) => {
    const host = hostOf(request.headers.host);
    if (host === config.ADMIN_HOST) return;
    if (host === config.AUTH_HOST && (request.url === "/oauth/token" || request.url === "/.well-known/oauth-authorization-server")) return;
    if (host === config.REGISTER_HOST && request.url.startsWith("/v1/")) return;
    if (isKcmlHostname(host, config.PUBLIC_BASE_DOMAIN) && (request.url === "/mcp" || request.url.startsWith("/.well-known/oauth-protected-resource"))) return;
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
