import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import type { Db } from "../db.js";
import { registerAuthRoutes } from "./auth-routes.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("OAuth authorization server metadata", () => {
  it("declares the supported pre-registered machine client flow explicitly", async () => {
    const app = Fastify();
    const config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: "postgres://unused/test",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret(1),
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: secret(2),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: secret(3),
      SESSION_SECRET_BASE64: secret(4),
      CSRF_SECRET_BASE64: secret(5),
      MFA_ENCRYPTION_KEY_BASE64: secret(6)
    });
    registerAuthRoutes(app, {} as Db, config);
    await app.ready();

    const response = await app.inject({
      method: "GET",
      url: "/.well-known/oauth-authorization-server",
      headers: { host: config.AUTH_HOST }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      issuer: `https://${config.AUTH_HOST}`,
      token_endpoint: `https://${config.AUTH_HOST}/oauth/token`,
      introspection_endpoint: `https://${config.AUTH_HOST}/oauth/introspect`,
      grant_types_supported: ["client_credentials"],
      token_endpoint_auth_methods_supported: ["client_secret_basic"],
      scopes_supported: ["mcp.invoke", "component.invoke"],
      resource_indicators_supported: true,
      client_id_metadata_document_supported: false
    });
    await app.close();
  });
});
