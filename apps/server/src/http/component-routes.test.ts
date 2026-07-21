import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { KCML_RELEASE } from "../domain/release.js";
import { registerComponentRoutes } from "./component-routes.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("component public route protection", () => {
  let app: FastifyInstance;
  let routeRateLimits: Map<string, unknown>;

  beforeEach(async () => {
    const config: AppConfig = loadConfig({
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
    registerComponentRoutes(app, db, config);
    await app.ready();
  });

  afterEach(async () => app?.close());

  it("rate limits discovery, Pulse and sequential audit ingest", () => {
    expect(routeRateLimits.get("GET /.well-known/kcml-component")).toEqual({ max: 60, timeWindow: "1 minute" });
    expect(routeRateLimits.get("POST /v2/component-pulse")).toEqual({ max: 120, timeWindow: "1 minute" });
    expect(routeRateLimits.get("POST /v2/component-audit-events")).toEqual({ max: 600, timeWindow: "1 minute" });
    expect(routeRateLimits.get("POST /v2/component-outbound-pulse")).toEqual({ max: 120, timeWindow: "1 minute" });
    expect(routeRateLimits.get("POST /v2/component-mcp")).toEqual({ max: 240, timeWindow: "1 minute" });
  });

  it("returns only endpoint metadata and does not query component identity or state", async () => {
    const query = vi.fn(async () => ({ rowCount: 0, rows: [] }));
    const discoveryApp = Fastify();
    registerComponentRoutes(discoveryApp, { query } as unknown as Db, loadConfig({
      NODE_ENV: "test", DATABASE_URL: "postgres://unused/test", PUBLIC_BASE_DOMAIN: "hcasc.cz",
      ADMIN_HOST: "admin.hcasc.cz", AUTH_HOST: "auth.hcasc.cz", REGISTER_HOST: "register.hcasc.cz",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret(1), INTEGRATION_TOKEN_HMAC_KEY_BASE64: secret(2),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: secret(3), SESSION_SECRET_BASE64: secret(4),
      CSRF_SECRET_BASE64: secret(5), MFA_ENCRYPTION_KEY_BASE64: secret(6)
    }));
    await discoveryApp.ready();
    const response = await discoveryApp.inject({ method: "GET", url: "/.well-known/kcml-component", headers: { host: "kcml0002.hcasc.cz" } });
    await discoveryApp.close();

    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("public, max-age=300");
    expect(response.json()).toEqual({
      mcpEndpoint: "https://kcml0002.hcasc.cz/mcp",
      protectedResourceMetadata: "https://kcml0002.hcasc.cz/.well-known/oauth-protected-resource",
      catalogVersion: KCML_RELEASE.catalogVersion
    });
    expect(query).not.toHaveBeenCalled();
  });

  it("requires idempotency key and If-Match for v2 component revisions", async () => {
    const query = vi.fn(async () => ({
      rowCount: 1,
      rows: [{
        id: "10000000-0000-0000-0000-000000000001",
        onboarding_job_id: null,
        fingerprint: "fp-test",
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        max_expires_at: new Date(Date.now() + 120_000).toISOString(),
        service_kind: "MCP",
        allowed_pipeline: "MCP_ONBOARDING",
        token_kind: "BLUEPRINT_RELEASE",
        release_version: KCML_RELEASE.catalogVersion,
        release_wave_key: "baseline-2026-07-24",
        max_child_jobs: 20
      }]
    }));
    const revisionApp = Fastify();
    registerComponentRoutes(revisionApp, { query } as unknown as Db, loadConfig({
      NODE_ENV: "test", DATABASE_URL: "postgres://unused/test", PUBLIC_BASE_DOMAIN: "hcasc.cz",
      ADMIN_HOST: "admin.hcasc.cz", AUTH_HOST: "auth.hcasc.cz", REGISTER_HOST: "register.hcasc.cz",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret(1), INTEGRATION_TOKEN_HMAC_KEY_BASE64: secret(2),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: secret(3), SESSION_SECRET_BASE64: secret(4),
      CSRF_SECRET_BASE64: secret(5), MFA_ENCRYPTION_KEY_BASE64: secret(6)
    }));
    await revisionApp.ready();
    const response = await revisionApp.inject({
      method: "POST",
      url: "/v2/component-onboardings/20000000-0000-0000-0000-000000000002/revisions",
      headers: { host: "register.hcasc.cz", authorization: `Bearer kci_${"a".repeat(80)}` },
      payload: {}
    });
    await revisionApp.close();

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: "idempotency_key_and_if_match_required" });
    expect(query).toHaveBeenCalledTimes(2);
  });

  it("retires the parallel component MCP endpoint", async () => {
    const response = await app.inject({ method: "POST", url: "/v2/component-mcp", headers: { host: "kcml0002.hcasc.cz" }, payload: { method: "tools/list" } });
    expect(response.statusCode).toBe(410);
    expect(response.json()).toMatchObject({ error: "component_mcp_moved" });
  });
});
