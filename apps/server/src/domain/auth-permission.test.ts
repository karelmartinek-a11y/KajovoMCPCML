import { describe, expect, it, vi } from "vitest";
import type { Db } from "../db.js";
import { replaceKajaPermissions } from "./auth.js";

function fakeDb(previous: Array<{ server_id: string; access_level: string }>) {
  const query = vi.fn(async (sql: string, params?: unknown[]) => {
    void params;
    if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
    if (sql.startsWith("select id, public_id from kaja_credential")) {
      return { rowCount: 1, rows: [{ id: "credential", public_id: "Kaja0001" }] };
    }
    if (sql.startsWith("select server_id,access_level from kaja_permission")) {
      return { rowCount: previous.length, rows: previous };
    }
    if (sql.includes("from managed_service") && sql.includes("legacy_mcp_server_id = any")) {
      const legacyIds = previous.map((row) => row.server_id);
      return {
        rowCount: legacyIds.length,
        rows: legacyIds.map((id) => ({ legacy_mcp_server_id: id, id: `managed-${id}` }))
      };
    }
    return { rowCount: 1, rows: [] };
  });
  const client = { query, release: vi.fn() };
  return {
    db: {
      query,
      connect: vi.fn(async () => client)
    } as unknown as Db,
    query
  };
}

describe("Kaja permission revocation", () => {
  it("keeps existing tokens but stops relying on token revocation for permission removal", async () => {
    const serverId = "11111111-1111-4111-8111-111111111111";
    const { db, query } = fakeDb([{ server_id: serverId, access_level: "EXECUTE" }]);
    await replaceKajaPermissions(db, "admin", "22222222-2222-4222-8222-222222222222", "credential", []);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("update access_token set revoked_at"))).toBe(false);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("select legacy_mcp_server_id, id"))).toBe(true);
  });

  it("does not revoke access tokens when execute permission remains", async () => {
    const serverId = "11111111-1111-4111-8111-111111111111";
    const { db, query } = fakeDb([{ server_id: serverId, access_level: "EXECUTE" }]);
    await replaceKajaPermissions(
      db,
      "admin",
      "22222222-2222-4222-8222-222222222222",
      "credential",
      [{ serverId, accessLevel: "EXECUTE" }]
    );
    expect(query.mock.calls.some(([sql]) => String(sql).includes("update access_token set revoked_at"))).toBe(false);
    const grantCall = query.mock.calls.find(([sql]) => String(sql).includes("insert into managed_service_permission"));
    expect(grantCall?.[0]).toContain("$3::jsonb");
    expect(grantCall?.[0]).not.toContain("$4");
    expect(grantCall?.[1]).toHaveLength(3);
  });
});
