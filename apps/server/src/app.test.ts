import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import type { Db } from "./db.js";
import { buildApp } from "./app.js";

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("application route composition", () => {
  const apps: Awaited<ReturnType<typeof buildApp>>[] = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0, apps.length).map((app) => app.close()));
  });

  it("starts with Secret API routes without duplicating the global health route", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: "postgres://unused/test",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret(1),
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: secret(2),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: secret(3),
      SESSION_SECRET_BASE64: secret(4),
      CSRF_SECRET_BASE64: secret(5),
      MFA_ENCRYPTION_KEY_BASE64: secret(6),
      CONFIG_VAULT_MASTER_KEY_BASE64: secret(9),
      CONFIG_VAULT_MASTER_KEY_ID: "test-v1"
    });
    const db = { query: async () => ({ rowCount: 0, rows: [] }) } as unknown as Db;

    const app = await buildApp(config, db);
    apps.push(app);

    await app.ready();

    const canonical = await app.inject({ method: "GET", url: "/health", headers: { host: "kcml0001.kajovocml.hcasc.cz" } });
    const retiredShortHost = await app.inject({ method: "GET", url: "/health", headers: { host: "kcml0001.hcasc.cz" } });
    expect(canonical.statusCode).not.toBe(404);
    expect(retiredShortHost.statusCode).toBe(404);
  });
});
