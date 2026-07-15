import { readdirSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../config.js";
import type { Db } from "../db.js";
import { buildReadinessReport } from "./readiness.js";

vi.mock("./catalog.js", () => ({
  listServers: vi.fn(async () => [])
}));

vi.mock("./audit.js", () => ({
  appendAudit: vi.fn(async () => undefined),
  verifyAuditChain: vi.fn(async () => ({
    valid: true,
    eventCount: 0,
    latestEventId: 0,
    brokenEventId: null
  }))
}));

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("readiness report", () => {
  it("treats the on-disk migration set as ready when all migrations are applied", async () => {
    const migrations = readdirSync(new URL("../migrations", import.meta.url))
      .filter((name) => !name.startsWith("._") && name.endsWith(".sql"))
      .sort();
    const query = vi.fn(async (sql: string) => {
      if (sql === "select 1") return { rowCount: 1, rows: [{ "?column?": 1 }] };
      if (sql === "select version from schema_migration order by sequence_number,version") {
        return { rowCount: migrations.length, rows: migrations.map((version) => ({ version })) };
      }
      if (sql === "select last_completed_at,last_error from monitoring_scheduler_heartbeat where singleton=true") {
        return { rowCount: 0, rows: [] };
      }
      if (sql === "begin" || sql === "rollback") return { rowCount: 0, rows: [] };
      throw new Error(`unexpected_query:${sql}`);
    });
    const db = {
      query,
      connect: vi.fn(async () => ({ query, release: vi.fn() }))
    } as unknown as Db;
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

    const report = await buildReadinessReport(db, config);

    expect(report.ready).toBe(true);
    expect(report.migrations).toMatchObject({
      ok: true,
      expected: migrations.length,
      applied: migrations.length,
      missing: [],
      unexpected: []
    });
  });
});
