import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { registerExternalApiRoutes } from "./external-api-routes.js";
import { registerReferenceExternalApiRoutes } from "./reference-external-api-routes.js";

const state: {
  service: Record<string, unknown> | null;
  match: { operation: { operationId: string; requiredScopes: string[]; method: string; maxPayloadBytes: number }; params: Record<string, string> } | null;
  decision: { allow: boolean; reasonCode: string; principalId: string | null };
  proxied: { status: number; body: Buffer; headers: Record<string, string | string[]> };
} = {
  service: null,
  match: null,
  decision: { allow: true, reasonCode: "ok", principalId: "principal-1" },
  proxied: {
    status: 200,
    body: Buffer.from(JSON.stringify({ ok: true })),
    headers: { "content-type": "application/json" }
  }
};

vi.mock("../domain/managed-service.js", () => ({
  authorizeManagedServiceToken: vi.fn(async () => state.decision)
}));

vi.mock("../domain/external-api.js", () => ({
  loadExternalApiGatewayService: vi.fn(async () => state.service),
  matchExternalApiOperation: vi.fn(() => state.match),
  proxyExternalApiOperation: vi.fn(async () => state.proxied)
}));

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("external API gateway route", () => {
  let app: FastifyInstance;
  let config: AppConfig;

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
    state.service = {
      managedServiceId: "service-1",
      code: "KCML0007",
      hostname: "kcml0007.kajovocml.hcasc.cz",
      resourceUri: "https://kcml0007.kajovocml.hcasc.cz",
      manifest: { environment: "production" },
      upstreamBaseUrl: "https://upstream.example.com",
      loggingContract: { correlationHeader: "x-correlation-id", redactHeaders: ["authorization", "cookie", "set-cookie"] },
      timeoutMs: 5000
    };
    state.match = {
      operation: {
        operationId: "attendance.listShifts",
        requiredScopes: ["attendance.shifts.read"],
        method: "GET",
        maxPayloadBytes: 64
      },
      params: {}
    };
    state.decision = { allow: true, reasonCode: "ok", principalId: "principal-1" };
    state.proxied = {
      status: 200,
      body: Buffer.from(JSON.stringify({ ok: true })),
      headers: { "content-type": "application/json" }
    };
    app = Fastify();
    registerReferenceExternalApiRoutes(app, config);
    registerExternalApiRoutes(app, { query: vi.fn() } as unknown as Db, config);
    await app.ready();
  });

  afterEach(async () => {
    await app?.close();
  });

  it("rejects missing bearer tokens before contacting the upstream", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: { host: "kcml0007.kajovocml.hcasc.cz" }
    });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: "invalid_token" });
  });

  it("does not bind the gateway route to the legacy public base domain", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: { host: "kcml0007.example.invalid" }
    });
    expect(response.statusCode).toBe(404);
  });

  it("returns 413 before proxying oversized bodies", async () => {
    state.match = {
      operation: {
        operationId: "attendance.requestTimeOff",
        requiredScopes: ["attendance.time_off.write"],
        method: "POST",
        maxPayloadBytes: 10
      },
      params: {}
    };
    const response = await app.inject({
      method: "POST",
      url: "/v1/time-off",
      headers: { host: "kcml0007.kajovocml.hcasc.cz", authorization: "Bearer token" },
      payload: { employeeId: "emp-42", days: 2 }
    });
    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({ error: "payload_too_large" });
  });

  it("proxies authorized requests through the managed-service gateway", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: { host: "kcml0007.kajovocml.hcasc.cz", authorization: "Bearer token" }
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["x-correlation-id"]).toBeTruthy();
    expect(response.json()).toEqual({ ok: true });
  });

  it("keeps the reference backend reachable on its own host without shadowing kcml routes", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: { host: "reference-api.example.invalid" }
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ code: "REFERENCE_DIRECT_BYPASS_BLOCKED" });
  });
});
