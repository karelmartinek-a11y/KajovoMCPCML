import { describe, expect, it, vi } from "vitest";
import type { Db } from "../db.js";
import { replaceKajaPermissions } from "./auth.js";

function fakeDb(previous: Array<{ server_id: string; access_level: string }>) {
  const query = vi.fn(async (sql: string) => {
    if (sql.startsWith("select id, public_id from kaja_credential")) {
      return { rowCount: 1, rows: [{ id: "credential", public_id: "Kaja0001" }] };
    }
    if (sql.startsWith("select server_id,access_level from kaja_permission")) {
      return { rowCount: previous.length, rows: previous };
    }
    return { rowCount: 1, rows: [] };
  });
  return { db: { query } as unknown as Db, query };
}

describe("Kaja permission revocation", () => {
  it("revokes existing access tokens when execute permission is removed", async () => {
    const serverId = "11111111-1111-4111-8111-111111111111";
    const { db, query } = fakeDb([{ server_id: serverId, access_level: "EXECUTE" }]);
    await replaceKajaPermissions(db, "admin", "22222222-2222-4222-8222-222222222222", "credential", []);
    expect(query).toHaveBeenCalledWith(
      expect.stringContaining("update access_token set revoked_at"),
      ["credential", [serverId]]
    );
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
  });
});
