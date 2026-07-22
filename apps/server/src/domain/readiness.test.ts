import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../config.js";
import type { Db } from "../db.js";
import { buildReadinessReport } from "./readiness.js";

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
      if (sql === "select version,sequence_number,checksum_sha256 from schema_migration order by sequence_number,version") {
        return { rowCount: migrations.length, rows: migrations.map((version) => ({ version, sequence_number: Number(version.slice(0, 3)),
          checksum_sha256: createHash("sha256").update(readFileSync(new URL(`../migrations/${version}`, import.meta.url))).digest("hex") })) };
      }
      if (sql === "select last_completed_at,last_error from monitoring_scheduler_heartbeat where singleton=true") {
        return { rowCount: 0, rows: [] };
      }
      if (sql.includes("from component c") && sql.includes("gates_valid")) return { rowCount: 0, rows: [] };
      if (sql === "select worker_kind,worker_id,build_id,last_heartbeat_at,last_error from platform_worker_heartbeat order by worker_kind") {
        return { rowCount: 2, rows: [
          { worker_kind: "COMPONENT_CONTROL", worker_id: "control-test", build_id: "test-build", last_heartbeat_at: new Date(), last_error: null },
          { worker_kind: "COMPONENT_E2E", worker_id: "e2e-test", build_id: "test-build", last_heartbeat_at: new Date(), last_error: null }
        ] };
      }
      if (sql.includes("expired_dispatches") && sql.includes("invalid_token_bindings")) {
        return { rowCount: 1, rows: [{ expired_dispatches: 0, stale_heartbeats: 0, invalid_token_bindings: 0, platform_worker_access_configured: true }] };
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
      MFA_ENCRYPTION_KEY_BASE64: secret(6),
      BUILD_ID: "test-build",
      MONITOR_ENABLED: "false"
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
    const catalogQuery = query.mock.calls.find(([sql]) => sql.includes("gates_valid"))?.[0];
    const operationsQuery = query.mock.calls.find(([sql]) => sql.includes("stale_heartbeats"))?.[0];
    expect(catalogQuery).toContain("c.registration_type='GENERIC_COMPONENT'");
    expect(operationsQuery).toContain("c.registration_type='GENERIC_COMPONENT'");
  });
});
