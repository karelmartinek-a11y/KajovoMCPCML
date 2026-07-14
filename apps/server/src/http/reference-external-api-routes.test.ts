import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import { registerReferenceExternalApiRoutes } from "./reference-external-api-routes.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("reference external API routes", () => {
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
    app = Fastify();
    registerReferenceExternalApiRoutes(app, config);
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  it("publishes machine-readable acceptance state", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/state/api-acceptance",
      headers: { host: "reference-api.hcasc.cz" }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      serviceKind: "EXTERNAL_API",
      gatewayEnforced: true,
      directBypassBlocked: true
    });
  });

  it("blocks direct business calls that bypass the KCML gateway headers", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: { host: "reference-api.hcasc.cz" }
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ code: "REFERENCE_DIRECT_BYPASS_BLOCKED" });
  });

  it("serves the business operation when the managed-service gateway headers are present", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: {
        host: "reference-api.hcasc.cz",
        "x-kcml-gateway-mode": "managed-service",
        "x-kcml-managed-service": "KCML0001",
        "x-kcml-principal-id": "principal-1",
        "x-kcml-operation-id": "reference.listShifts",
        "x-correlation-id": "corr-1"
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ items: [{ employeeId: "emp-42" }] });
  });
});
