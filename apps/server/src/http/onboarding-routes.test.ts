import Fastify, { type FastifyInstance } from "fastify";
import multipart from "@fastify/multipart";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { registerOnboardingRoutes } from "./onboarding-routes.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("programmer onboarding API authorization", () => {
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
    const db = { query: async () => ({ rowCount: 0, rows: [] }) } as unknown as Db;
    app = Fastify();
    await app.register(multipart);
    registerOnboardingRoutes(app, db, config);
    await app.ready();
  });

  afterEach(async () => app.close());

  it("returns the same 401 for a missing or invalid integration token", async () => {
    const missing = await app.inject({ method: "POST", url: "/v1/onboardings", headers: { host: config.REGISTER_HOST } });
    const invalid = await app.inject({ method: "POST", url: "/v1/onboardings", headers: { host: config.REGISTER_HOST, authorization: `Bearer kci_${"a".repeat(86)}` } });
    expect(missing.statusCode).toBe(401);
    expect(invalid.statusCode).toBe(401);
    expect((JSON.parse(missing.body) as { error: string }).error).toBe("invalid_integration_token");
    expect((JSON.parse(invalid.body) as { error: string }).error).toBe("invalid_integration_token");
  });

  it("does not expose the registration API on another host", async () => {
    const response = await app.inject({ method: "GET", url: "/v1/onboardings/example", headers: { host: config.ADMIN_HOST } });
    expect(response.statusCode).toBe(404);
  });
});
