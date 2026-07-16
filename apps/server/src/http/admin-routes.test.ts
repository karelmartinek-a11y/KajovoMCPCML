import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { registerAdminRoutes } from "./admin-routes.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("automatic-onboarding-only registration surface", () => {
  let app: FastifyInstance;
  let config: AppConfig;
  let routeRateLimits: Map<string, unknown>;

  beforeEach(async () => {
    config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: "postgres://unused/test",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret(1),
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: secret(2),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: secret(3),
      SESSION_SECRET_BASE64: secret(4),
      CSRF_SECRET_BASE64: secret(5),
      MFA_ENCRYPTION_KEY_BASE64: secret(6)
    });
    const db = { query: async () => ({ rowCount: 0, rows: [] }) } as unknown as Db;
    app = Fastify();
    routeRateLimits = new Map();
    app.addHook("onRoute", (route) => {
      const rateLimit = (route.config as { rateLimit?: unknown } | undefined)?.rateLimit;
      if (rateLimit) routeRateLimits.set(`${String(route.method)} ${route.url}`, rateLimit);
    });
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();
  });

  afterEach(async () => app?.close());

  it.each([
    "/api/mcp-servers/home-assistant-inventory",
    "/api/mcp-servers/example/trial",
    "/api/mcp-servers/example/mcp-test",
    "/api/mcp-servers/example/bind-manifest",
    "/api/mcp-servers/example/disable",
    "/api/mcp-servers/example/resume",
    "/api/mcp-servers/example/acceptance",
    "/api/mcp-servers/example/activate"
  ])("does not expose the legacy manual route %s", async (url) => {
    const response = await app.inject({ method: "POST", url, headers: { host: config.ADMIN_HOST } });
    expect(response.statusCode).toBe(404);
  });

  it("advertises the guarded bootstrap flow only while no owner exists", async () => {
    const response = await app.inject({ method: "GET", url: "/api/session", headers: { host: config.ADMIN_HOST } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ authenticated: false, bootstrapRequired: true, role: null });
  });

  it("does not expose an endpoint that can create the primary administrator", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/bootstrap/setup",
      headers: { host: config.ADMIN_HOST },
      payload: { username: "bootstrap", password: "very-strong-password", mfaSecret: "" }
    });
    expect(response.statusCode).toBe(404);
  });

  it("rate limits reauthentication and individual audit-event reads", () => {
    expect(routeRateLimits.get("POST /api/reauth")).toEqual({
      max: 5,
      timeWindow: "1 minute",
      groupId: "admin-reauth"
    });
    expect(routeRateLimits.get("GET /api/audit/events/:id")).toEqual({
      max: 60,
      timeWindow: "1 minute",
      groupId: "admin-audit-read"
    });
  });
});
