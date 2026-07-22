import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import multipart from "@fastify/multipart";
import argon2 from "argon2";
import { authenticator } from "otplib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { KCML_RELEASE } from "../domain/release.js";
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
    const query = async (sql: string, params?: unknown[]) => {
      if (sql.includes("from admin_session")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "admin" }] };
      }
      if (sql.includes("insert into integration_token")) {
        return {
          rowCount: 1,
          rows: [{
            id: "intent-id",
            label: params?.[0] ?? "label",
            fingerprint: "integration-token-fingerprint",
            descriptor: params?.[6] ?? {},
            service_kind: params?.[7] ?? "COMPONENT",
            allowed_pipeline: params?.[8] ?? "COMPONENT_ONBOARDING",
            token_kind: params?.[9] ?? "SINGLE_COMPONENT",
            release_version: params?.[10] ?? KCML_RELEASE.catalogVersion,
            max_child_jobs: params?.[11] ?? 1,
            onboarding_job_id: null,
            issued_at: new Date().toISOString(),
            initial_expires_at: new Date(Date.now() + 60_000).toISOString(),
            expires_at: new Date(Date.now() + 60_000).toISOString(),
            max_expires_at: new Date(Date.now() + 60_000).toISOString()
          }]
        };
      }
      return { rowCount: 0, rows: [] };
    };
    const db = {
      query,
      connect: async () => ({
        query,
        release: () => undefined
      })
    } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    await app.register(multipart);
    registerOnboardingRoutes(app, db, config);
    await app.ready();
  });

  afterEach(async () => app?.close());

  it("retires the legacy onboarding intake without authenticating or mutating state", async () => {
    const missing = await app.inject({ method: "POST", url: "/v1/onboardings", headers: { host: config.REGISTER_HOST } });
    const invalid = await app.inject({ method: "POST", url: "/v1/onboardings", headers: { host: config.REGISTER_HOST, authorization: `Bearer kci_${"a".repeat(86)}` } });
    expect(missing.statusCode).toBe(410);
    expect(invalid.statusCode).toBe(410);
    expect((JSON.parse(missing.body) as { error: string }).error).toBe("legacy_onboarding_retired_use_component_intake");
    expect((JSON.parse(invalid.body) as { error: string }).error).toBe("legacy_onboarding_retired_use_component_intake");
  });

  it("does not expose the registration API on another host", async () => {
    const response = await app.inject({ method: "GET", url: "/v1/onboardings/example", headers: { host: config.ADMIN_HOST } });
    expect(response.statusCode).toBe(404);
  });

  it(`serves the approved ${KCML_RELEASE.catalogVersion} onboarding catalog to an authenticated administrator`, async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/onboarding-catalog",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/json");
    expect(response.headers["content-disposition"]).toContain(`component-${KCML_RELEASE.catalogVersion}.json`);
    expect(response.json()).toMatchObject({ version: KCML_RELEASE.catalogVersion, serviceKind: "COMPONENT" });
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

  it("issues an EXTERNAL_API integration intent with the service onboarding intake", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/integration-intents",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: {
        label: "Reference external API",
        serviceKind: "EXTERNAL_API",
        descriptor: {
          summary: "Reference external API",
          businessPurpose: "Production smoke validation for the managed external API registration pipeline.",
          serviceOwner: "KCML Managed Services",
          technicalOwner: "KCML Managed Services",
          criticality: "HIGH"
        }
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      serviceKind: "EXTERNAL_API",
      intakeUrl: `https://${config.REGISTER_HOST}/v1/service-onboardings`,
      intakeUrls: {
        recommendedIntakeUrl: `https://${config.REGISTER_HOST}/v1/service-onboardings`,
        externalApiIntakeUrl: `https://${config.REGISTER_HOST}/v1/service-onboardings`
      },
      catalogUrl: `https://${config.REGISTER_HOST}/api/onboarding-catalogs/external-api/1.0`
    });
  });
});

describe("quarantine release MFA", () => {
  it("verifies TOTP against the decrypted administrator seed", () => {
    const key = Buffer.alloc(32, 9);
    const seed = "JBSWY3DPEHPK3PXP";
    const encrypted = encryptMfaSecret(seed, key);
    expect(verifyEncryptedMfaTotp(authenticator.generate(seed), encrypted, {
      MFA_ENCRYPTION_KEY_BASE64: key,
      MFA_ALLOW_PLAINTEXT_LEGACY: false
    })).toBe(true);
    expect(verifyEncryptedMfaTotp("000000", encrypted, {
      MFA_ENCRYPTION_KEY_BASE64: key,
      MFA_ALLOW_PLAINTEXT_LEGACY: false
    })).toBe(false);
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
        if (sql.includes("select it.id, it.onboarding_job_id, it.fingerprint, it.expires_at, it.max_expires_at")) {
          return {
            rowCount: 1,
            rows: [{
              id: "token-id",
              onboarding_job_id: null,
              fingerprint: "integration-token-fingerprint",
              expires_at: new Date(Date.now() + 60_000).toISOString(),
              max_expires_at: new Date(Date.now() + 120_000).toISOString(),
              service_kind: "COMPONENT",
              allowed_pipeline: "COMPONENT_ONBOARDING",
              token_kind: "SINGLE_COMPONENT",
              release_version: KCML_RELEASE.catalogVersion,
              max_child_jobs: 1
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
      url: `/api/onboarding-catalogs/component/${KCML_RELEASE.catalogVersion}`,
      headers: {
        host: config.REGISTER_HOST,
        authorization: `Bearer kci_${"a".repeat(86)}`
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      version: KCML_RELEASE.catalogVersion,
      serviceKind: "COMPONENT"
    });
  });

  it("returns the native generic component intake for an integration token", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/integration-intent",
      headers: {
        host: config.REGISTER_HOST,
        authorization: `Bearer kci_${"a".repeat(86)}`
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      token: { maxRegistrations: 1 },
      registration: { componentKind: "GENERIC", identityAssignedBy: "KCML" },
      intakeUrl: `https://${config.REGISTER_HOST}/v2/component-onboardings`,
      intakeUrls: {
        recommendedIntakeUrl: `https://${config.REGISTER_HOST}/v2/component-onboardings`
      }
    });
  });

  it("returns the external API intake contract for an EXTERNAL_API integration token", async () => {
    const db = {
      query: async (sql: string) => {
        if (sql.includes("select it.id, it.onboarding_job_id, it.fingerprint, it.expires_at, it.max_expires_at")) {
          return {
            rowCount: 1,
            rows: [{
              id: "token-id",
              onboarding_job_id: null,
              fingerprint: "integration-token-fingerprint",
              expires_at: new Date(Date.now() + 60_000).toISOString(),
              max_expires_at: new Date(Date.now() + 120_000).toISOString(),
              service_kind: "EXTERNAL_API",
              allowed_pipeline: "EXTERNAL_API_REGISTRATION",
              token_kind: "SINGLE_COMPONENT",
              release_version: KCML_RELEASE.catalogVersion,
              max_child_jobs: 1
            }]
          };
        }
        return { rowCount: 0, rows: [] };
      }
    } as unknown as Db;
    const externalApp = Fastify();
    await externalApp.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    await externalApp.register(multipart);
    registerOnboardingRoutes(externalApp, db, config);
    await externalApp.ready();

    const response = await externalApp.inject({
      method: "GET",
      url: "/v1/integration-intent",
      headers: {
        host: config.REGISTER_HOST,
        authorization: `Bearer kci_${"a".repeat(86)}`
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      token: { maxRegistrations: 1 },
      registration: { serviceKind: "EXTERNAL_API", identityAssignedBy: "KCML" },
      intakeUrl: `https://${config.REGISTER_HOST}/v1/service-onboardings`,
      intakeUrls: {
        recommendedIntakeUrl: `https://${config.REGISTER_HOST}/v1/service-onboardings`,
        externalApiIntakeUrl: `https://${config.REGISTER_HOST}/v1/service-onboardings`
      },
      catalogUrl: `https://${config.REGISTER_HOST}/api/onboarding-catalogs/external-api/1.0`
    });

    await externalApp.close();
  });

  it("does not expose a fixed component allowlist", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/integration-intent",
      headers: {
        host: config.REGISTER_HOST,
        authorization: `Bearer kci_${"a".repeat(86)}`
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ token: { maxRegistrations: 1 } });
    expect(JSON.stringify(response.json())).not.toMatch(/allowedBlueprint|blueprintRelease/);
  });

  it.each(["/v1/onboardings", "/v1/service-onboardings"])(
    "returns Gone for retired legacy intake %s",
    async (url) => {
      const response = await app.inject({
        method: "POST",
        url,
        headers: {
          host: config.REGISTER_HOST,
          authorization: `Bearer kci_${"a".repeat(86)}`,
          "idempotency-key": "release-token-must-use-native-intake"
        }
      });
      expect(response.statusCode).toBe(410);
      expect(response.json()).toMatchObject({ error: "legacy_onboarding_retired_use_component_intake" });
    }
  );
});
