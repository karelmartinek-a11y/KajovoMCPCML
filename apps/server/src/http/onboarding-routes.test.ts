import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import multipart from "@fastify/multipart";
import argon2 from "argon2";
import { authenticator } from "otplib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { encryptMfaSecret } from "../security/secrets.js";
import { registerOnboardingRoutes, verifyEncryptedMfaTotp } from "./onboarding-routes.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("programmer onboarding API authorization", () => {
  let app: FastifyInstance;
  let config: AppConfig;
  const sessionValue = "test-onboarding-admin-session";
  const csrfValue = "test-onboarding-csrf";

  beforeEach(async () => {
    config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: "postgres://unused/test",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret(1),
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: secret(2),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: secret(3),
      SESSION_SECRET_BASE64: secret(4),
      CSRF_SECRET_BASE64: secret(5),
      MFA_ENCRYPTION_KEY_BASE64: secret(6),
      ONBOARDING_WORKER_ENABLED: "true",
      GITHUB_OWNER: "example",
      GITHUB_REPO: "repository",
      GITHUB_TOKEN: "github-token-with-sufficient-length",
      OCI_IMAGE_NAMESPACE: "example/handlers",
      OCI_CERTIFICATE_IDENTITY: "https://github.com/example/repository/.github/workflows/onboarding-build.yml@refs/heads/main"
    });
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const db = {
      query: async (sql: string) => sql.includes("from admin_session")
        ? { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "admin" }] }
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

  it("serves the approved v1.5 onboarding catalog to an authenticated administrator", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/onboarding-catalog",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    expect(response.headers["content-disposition"]).toContain("Connect_in_Catalog_KajovoMCPCML_v1.5.docx");
    expect(response.rawPayload.subarray(0, 2).toString()).toBe("PK");
  });

  it.each([
    { label: "Legacy note", note: "A free-form note is no longer a descriptor" },
    { label: "Missing descriptor" },
    {
      label: "Incomplete descriptor",
      descriptor: { summary: "Incomplete", businessPurpose: "A sufficiently long business purpose." }
    }
  ])("rejects incomplete or legacy integration-token requests before issuing a token", async (payload) => {
    const response = await app.inject({
      method: "POST",
      url: "/api/integration-tokens",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: "invalid_integration_descriptor" });
  });
});

describe("quarantine release MFA", () => {
  it("verifies TOTP against the decrypted administrator seed", () => {
    const key = Buffer.alloc(32, 9);
    const seed = "JBSWY3DPEHPK3PXP";
    const encrypted = encryptMfaSecret(seed, key);
    expect(verifyEncryptedMfaTotp(authenticator.generate(seed), encrypted, key)).toBe(true);
    expect(verifyEncryptedMfaTotp("000000", encrypted, key)).toBe(false);
  });
});

describe("machine-readable onboarding catalogs", () => {
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
    const db = {
      query: async (sql: string) => {
        if (sql.includes("select it.id, it.onboarding_job_id, it.fingerprint, it.expires_at, it.max_expires_at, it.service_kind, it.allowed_pipeline")) {
          return {
            rowCount: 1,
            rows: [{
              id: "token-id",
              onboarding_job_id: null,
              fingerprint: "integration-token-fingerprint",
              expires_at: new Date(Date.now() + 60_000).toISOString(),
              max_expires_at: new Date(Date.now() + 120_000).toISOString(),
              service_kind: "EXTERNAL_API",
              allowed_pipeline: "EXTERNAL_API_REGISTRATION"
            }]
          };
        }
        return { rowCount: 0, rows: [] };
      }
    } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    await app.register(multipart);
    registerOnboardingRoutes(app, db, config);
    await app.ready();
  });

  afterEach(async () => app?.close());

  it("serves the JSON onboarding catalog to an authenticated programmer on the register host", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/onboarding-catalogs/external-api/1.0",
      headers: {
        host: config.REGISTER_HOST,
        authorization: `Bearer kci_${"a".repeat(86)}`
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      version: "1.0",
      serviceKind: "EXTERNAL_API"
    });
  });
});
