import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import multipart from "@fastify/multipart";
import argon2 from "argon2";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { registerOnboardingRoutes } from "./onboarding-routes.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("programmer onboarding API authorization", () => {
  let app: FastifyInstance;
  let config: AppConfig;
  const sessionValue = "test-onboarding-admin-session";

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
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const db = {
      query: async (sql: string) => sql.includes("from admin_session")
        ? { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash }] }
        : { rowCount: 0, rows: [] }
    } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    await app.register(multipart);
    registerOnboardingRoutes(app, db, config);
    await app.ready();
  });

  afterEach(async () => app?.close());

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

  it("serves the approved v1.4 onboarding catalog to an authenticated administrator", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/onboarding-catalog",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    expect(response.headers["content-disposition"]).toContain("Connect_in_Catalog_KajovoMCPCML_v1.4.docx");
    expect(response.rawPayload.subarray(0, 2).toString()).toBe("PK");
  });
});
