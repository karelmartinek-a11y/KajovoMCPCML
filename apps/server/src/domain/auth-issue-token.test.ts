import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Db } from "../db.js";

const verifyPasswordLikeSecret = vi.fn(async () => true);
const issueOpaqueSecret = vi.fn(() => ({ value: "opaque-token", fingerprint: "token-fingerprint" }));
const hmacToken = vi.fn(() => Buffer.from("digest"));
const currentManagedServiceScopes = vi.fn(async () => ["mcp.invoke"]);
const appendAudit = vi.fn(async () => undefined);

vi.mock("../security/secrets.js", () => ({
  verifyPasswordLikeSecret,
  issueOpaqueSecret,
  hmacToken,
  hashPasswordLikeSecret: vi.fn(),
  fingerprintSecret: vi.fn(() => "fingerprint")
}));

vi.mock("./managed-service.js", () => ({
  authorizeManagedServiceToken: vi.fn(),
  bumpManagedServicePermissionEpoch: vi.fn(),
  currentManagedServiceScopes
}));

vi.mock("./audit.js", () => ({
  appendAudit
}));

vi.mock("./catalog.js", () => ({
  resourceFor: vi.fn()
}));

describe("issueAccessToken", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("accepts an MCP managed service with a valid active revision", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.startsWith("select * from kaja_credential")) {
        return {
          rowCount: 1,
          rows: [{
            id: "credential-id",
            active: true,
            revoked_at: null,
            deleted_at: null,
            expires_at: null,
            secret_hash: "secret-hash",
            revocation_epoch: "credential-epoch",
            principal_token_epoch: "principal-epoch"
          }]
        };
      }
      if (sql.includes("from managed_service ms")) {
        return {
          rowCount: 1,
          rows: [{
            id: "managed-service-id",
            code: "KCML0002",
            service_kind: "MCP",
            legacy_mcp_server_id: "legacy-server-id",
            resource_uri: "https://kcml0002.example.test/mcp",
            environment: "production",
            active_revision_id: "revision-id",
            service_token_epoch: "service-epoch",
            permission_epoch: "permission-epoch",
            active_revision_epoch: 4,
            active_revision_validation_state: "VALID",
            registration_state: "ACTIVE",
            api_state: "ENABLED",
            monitoring_enabled: true,
            monitoring_profile_digest: "sha256:monitoring",
            approved_at: "2026-01-13T00:00:00.000Z",
            review_due_at: "2027-01-13T00:00:00.000Z",
            review_interval_days: 365
          }]
        };
      }
      if (sql.startsWith("insert into managed_service_access_token")) {
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith("insert into access_token")) {
        return { rowCount: 1, rows: [] };
      }
      return { rowCount: 0, rows: [] };
    });

    const db = { query } as unknown as Db;
    const { issueAccessToken } = await import("./auth.js");

    const token = await issueAccessToken(db, {
      clientId: "Kaja9999",
      clientSecret: "secret",
      resource: "https://kcml0002.example.test/mcp",
      hmacKey: Buffer.from("key"),
      keyId: "kid",
      correlationId: "correlation-id"
    });

    expect(token).toMatchObject({
      access_token: "opaque-token",
      token_type: "Bearer",
      scope: "mcp.invoke"
    });
    expect(query.mock.calls.some(([sql]) => String(sql).includes("ms.active_revision_id"))).toBe(true);
    expect(currentManagedServiceScopes).toHaveBeenCalledWith(db, "credential-id", "managed-service-id");
  });
});
