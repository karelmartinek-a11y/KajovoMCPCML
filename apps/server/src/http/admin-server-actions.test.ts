import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import argon2 from "argon2";
import { authenticator } from "otplib";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { hashAuditEvent } from "../domain/audit.js";
import { encryptMfaSecret } from "../security/secrets.js";
import { registerAdminRoutes } from "./admin-routes.js";

const handlerState: {
  invoke: ((input: unknown) => Promise<unknown>) | null;
} = {
  invoke: null
};

vi.mock("../handlers/registry.js", () => ({
  getHandler: vi.fn(() => handlerState.invoke ? {
    key: "mock",
    version: "1",
    invoke: (input: unknown) => handlerState.invoke!(input)
  } : null)
}));

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("admin server actions", () => {
  let app: FastifyInstance;
  let config: AppConfig;
  const sessionValue = "test-admin-session";
  const csrfValue = "csrf-token";

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
    handlerState.invoke = null;
  });

  afterEach(async () => {
    await app?.close();
  });

  it("disables a server and revokes issued access tokens", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "admin" }] };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (sql.includes("select id,enabled,registration_state,operational_state") && sql.includes("from mcp_server where id=$1")) {
        return { rowCount: 1, rows: [{ id: "server-id", enabled: true, registration_state: "ACTIVE", operational_state: "HEALTHY" }] };
      }
      if (sql.includes("from mcp_server ms") && sql.includes("review_due_at")) {
        return { rowCount: 1, rows: [{
          id: "server-id", code: "KCML0001", enabled: true, registration_state: "ACTIVE", operational_state: "HEALTHY",
          revision_id: "revision-id", validation_state: "VALID", approved_at: "2026-01-01T00:00:00.000Z",
          review_due_at: "2027-01-01T00:00:00.000Z", review_interval_days: 365,
          monitoring_enabled: true, profile_digest: "sha256:monitoring"
        }] };
      }
      if (sql.includes("select id, code, enabled, registration_state")) {
        return { rowCount: 1, rows: [{ id: "server-id", code: "KCML0001", enabled: true, registration_state: "ACTIVE", operational_state: "HEALTHY" }] };
      }
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/api/mcp-servers/server-id/enabled",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { enabled: false }
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({ registrationState: "REGISTERED_DISABLED", operationalState: "DISABLED" });
    expect(query.mock.calls.some(([sql]) => String(sql).includes("update access_token set revoked_at"))).toBe(true);
  });

  it("enables a disabled server without redeploying runtime from the web process", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "admin" }] };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (sql.includes("select id,enabled,registration_state,operational_state") && sql.includes("from mcp_server where id=$1")) {
        return { rowCount: 1, rows: [{ id: "server-id", enabled: false, registration_state: "REGISTERED_DISABLED", operational_state: "DISABLED" }] };
      }
      if (sql.includes("from mcp_server ms") && sql.includes("review_due_at")) {
        return { rowCount: 1, rows: [{
          id: "server-id", code: "KCML0001", enabled: false, registration_state: "REGISTERED_DISABLED", operational_state: "DISABLED",
          revision_id: "revision-id", validation_state: "VALID", approved_at: "2026-01-01T00:00:00.000Z",
          review_due_at: "2027-01-01T00:00:00.000Z", review_interval_days: 365,
          monitoring_enabled: true, profile_digest: "sha256:monitoring"
        }] };
      }
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/api/mcp-servers/server-id/enabled",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { enabled: true }
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({ registrationState: "TRIAL", operationalState: "UNKNOWN" });
    expect(query.mock.calls.some(([sql]) => String(sql).includes("insert into egress_capability"))).toBe(false);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("podman"))).toBe(false);
  });

  it("runs the registered safe test contract for a server", async () => {
    handlerState.invoke = async (input) => ({ ok: true, echoed: input });
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "admin" }] };
      }
      if (sql.includes("from mcp_server ms") && sql.includes("where ms.id=$1")) {
        return {
          rowCount: 1,
          rows: [{
            id: "server-id",
            code: "KCML0001",
            kcml_number: 1,
            hostname: "kcml0001.hcasc.cz",
            tool_name: "example_tool",
            display_name: "Example",
            description: "Example",
            enabled: true,
            registration_state: "ACTIVE",
            operational_state: "HEALTHY",
            input_schema: { type: "object", additionalProperties: false },
            output_schema: { type: "object", additionalProperties: true },
            handler_key: "mock",
            handler_version: "1.0.0",
            contract_version: "rev-1",
            artifact_digest: "sha256:artifact",
            manifest_digest: "sha256:manifest",
            registration_revision: "rev-1",
            active_revision_id: "revision-id",
            registration_schema_version: "1.5",
            registration_validation_state: "VALID",
            review_approved_at: "2026-01-01T00:00:00.000Z",
            review_due_at: "2027-01-01T00:00:00.000Z",
            review_interval_days: 365,
            monitoring_enabled: true,
            monitoring_profile_digest: "sha256:monitoring",
            image_reference: null,
            image_digest: "sha256:image",
            sbom_digest: null,
            provenance_digest: null,
            runtime_socket: "/tmp/socket",
            timeout_ms: 1000,
            max_concurrency: 1,
            request_max_bytes: 1024,
            response_max_bytes: 1024,
            rate_window_seconds: 60,
            rate_max_requests: 10,
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
            effect_class: "READ_ONLY",
            shutdown_policy: "COMPLETE_IN_FLIGHT",
            idempotency_policy: "read only",
            revocation_epoch: "epoch",
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }]
        };
      }
      if (sql.includes("from registration_revision")) {
        return {
          rowCount: 1,
          rows: [{ manifest: { testContract: { safeInput: { name: "Alice" }, expectedResult: { ok: true } } } }]
        };
      }
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/api/mcp-servers/server-id/test",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: {}
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({ ok: true });
  });

  it("reads and updates monitoring profile for a server", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    let registrationState = "REGISTERED_DISABLED";
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "admin" }] };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (sql.includes("select enabled, profile from monitoring_profile")) {
        return {
          rowCount: 1,
          rows: [{
            enabled: true,
            profile: {
              sloTargets: { availability: 99.9 },
              probeIntervals: { readiness: "5m" },
              alertRules: [{ severity: "critical" }],
              runbookRef: "docs/runbook",
              primaryAlertChannel: "ops-primary",
              backupAlertChannel: "ops-backup"
            }
          }]
        };
      }
      if (sql.includes("select id,code,registration_state,active_revision_id from mcp_server")) {
        return { rowCount: 1, rows: [{ id: "server-id", code: "KCML0001", registration_state: registrationState, active_revision_id: "revision-id" }] };
      }
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const read = await app.inject({
      method: "GET",
      url: "/api/mcp-servers/server-id/monitoring-profile",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(read.statusCode).toBe(200);
    expect(read.json()).toMatchObject({ enabled: true, profile: { runbookRef: "docs/runbook" } });

    const write = await app.inject({
      method: "PUT",
      url: "/api/mcp-servers/server-id/monitoring-profile",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: {
        enabled: false,
        profile: {
          sloTargets: {},
          probeIntervals: {},
          alertRules: [],
          runbookRef: "runbook",
          primaryAlertChannel: "primary",
          backupAlertChannel: "backup"
        }
      }
    });
    expect(write.statusCode, write.body).toBe(200);
    expect(write.json()).toMatchObject({ enabled: false, profile: { runbookRef: "runbook" } });

    registrationState = "ACTIVE";
    const blocked = await app.inject({
      method: "PUT",
      url: "/api/mcp-servers/server-id/monitoring-profile",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: {
        enabled: true,
        profile: {
          sloTargets: {}, probeIntervals: {}, alertRules: [], runbookRef: "runbook",
          primaryAlertChannel: "primary", backupAlertChannel: "backup"
        }
      }
    });
    expect(blocked.statusCode).toBe(409);
    expect(blocked.json()).toMatchObject({ error: "monitoring_revision_required" });
  });

  it("returns admin security overview with active sessions", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const db = {
      query: vi.fn(async (sql: string) => {
        if (sql.includes("from admin_session s")) {
          return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "karel" }] };
        }
        if (sql === "select username, password_changed_at from admin_account where id=$1") {
          return { rowCount: 1, rows: [{ username: "karel", password_changed_at: "2026-07-14T10:00:00.000Z" }] };
        }
        if (sql.includes("from admin_session") && sql.includes("order by created_at desc")) {
          return {
            rowCount: 2,
            rows: [
              { id: "session-id", created_at: "2026-07-14T10:00:00.000Z", expires_at: "2026-07-14T18:00:00.000Z" },
              { id: "session-2", created_at: "2026-07-14T09:00:00.000Z", expires_at: "2026-07-14T17:00:00.000Z" }
            ]
          };
        }
        return { rowCount: 0, rows: [] };
      })
    } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "GET",
      url: "/api/admin-security",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({
      username: "karel",
      passwordChangedAt: "2026-07-14T10:00:00.000Z",
      sessions: [
        expect.objectContaining({ id: "session-id", current: true }),
        expect.objectContaining({ id: "session-2", current: false })
      ]
    });
  });

  it("changes admin password and revokes other sessions", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const passwordHash = await argon2.hash("current-password", { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    let accountUsername = "karel";
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session s")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "karel" }] };
      }
      if (sql === "select username,password_hash from admin_account where id=$1") {
        return { rowCount: 1, rows: [{ username: accountUsername, password_hash: passwordHash }] };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/api/admin-password",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { currentPassword: "current-password", nextPassword: "very-strong-password" }
    });
    expect(response.statusCode).toBe(200);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("update admin_account set password_hash"))).toBe(true);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("update admin_session set revoked_at=now() where account_id=$1 and id<>$2"))).toBe(true);

    accountUsername = "karmar78";
    const deploymentManaged = await app.inject({
      method: "POST",
      url: "/api/admin-password",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { currentPassword: "current-password", nextPassword: "another-strong-password" }
    });
    expect(deploymentManaged.statusCode).toBe(409);
    expect(deploymentManaged.json()).toMatchObject({ error: "admin_password_deployment_managed" });
  });

  it("revokes other admin sessions on demand", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session s")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "karel" }] };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/api/admin-sessions/revoke-others",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: {}
    });
    expect(response.statusCode).toBe(200);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("update admin_session set revoked_at=now() where account_id=$1 and id<>$2"))).toBe(true);
  });

  it("authenticates login with encrypted MFA seed", async () => {
    const passwordHash = await argon2.hash("correct horse battery staple", { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const totpSecret = "JBSWY3DPEHPK3PXP";
    const encrypted = encryptMfaSecret(totpSecret, config.MFA_ENCRYPTION_KEY_BASE64);
    const db = {
      query: vi.fn(async (sql: string) => {
        if (sql.startsWith("select * from admin_account where username=$1")) {
          return {
            rowCount: 1,
            rows: [{
              id: "account-id",
              password_hash: passwordHash,
              mfa_enabled: true,
              mfa_secret: encrypted
            }]
          };
        }
        return { rowCount: 1, rows: [] };
      })
    } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/api/login",
      headers: { host: config.ADMIN_HOST },
      payload: {
        username: "admin",
        password: "correct horse battery staple",
        totp: authenticator.generate(totpSecret)
      }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ ok: true });
  });

  it("returns audit integrity and export for administrators", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const hash = hashAuditEvent(null, {
      eventType: "admin.login.succeeded",
      actorType: "admin",
      actorId: "account-id",
      objectType: "admin_account",
      objectId: "account-id",
      before: null,
      after: null,
      correlationId: "00000000-0000-0000-0000-000000000001"
    });
    const db = {
      query: vi.fn(async (sql: string) => {
        if (sql.includes("from admin_session s")) {
          return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "karel" }] };
        }
        if (sql === "select * from verify_audit_chain()") {
          return { rowCount: 1, rows: [{ valid: true, event_count: 1, latest_event_id: 1, broken_event_id: null }] };
        }
        if (sql.includes("select id, event_type")) {
          return {
            rowCount: 1,
            rows: [{
              id: 1,
              event_type: "admin.login.succeeded",
              actor_type: "admin",
              actor_id: "account-id",
              object_type: "admin_account",
              object_id: "account-id",
              before_json: null,
              after_json: null,
              correlation_id: "00000000-0000-0000-0000-000000000001",
              prev_hash: null,
              event_hash: hash
            }]
          };
        }
        if (sql.includes("encode(prev_hash, 'hex')")) {
          return {
            rowCount: 1,
            rows: [{
              id: 1,
              event_type: "admin.login.succeeded",
              actor_type: "admin",
              actor_id: "account-id",
              object_type: "admin_account",
              object_id: "account-id",
              correlation_id: "00000000-0000-0000-0000-000000000001",
              created_at: "2026-07-14T10:00:00.000Z",
              before_json: null,
              after_json: null,
              prev_hash_hex: null,
              event_hash_hex: hash.toString("hex")
            }]
          };
        }
        return { rowCount: 0, rows: [] };
      })
    } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const integrity = await app.inject({
      method: "GET",
      url: "/api/audit/integrity",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(integrity.statusCode).toBe(200);
    expect(integrity.json()).toMatchObject({ valid: true, eventCount: 1 });

    const exported = await app.inject({
      method: "GET",
      url: "/api/audit/export",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(exported.statusCode).toBe(200);
    expect(exported.headers["content-disposition"]).toContain("audit-export.json");
  });

  it("lists and creates admin accounts", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session s")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "karel" }] };
      }
      if (sql.includes("from admin_account a")) {
        return {
          rowCount: 1,
          rows: [{
            id: "account-id",
            username: "karel",
            password_changed_at: "2026-07-14T10:00:00.000Z",
            mfa_enabled: true,
            created_at: "2026-07-14T09:00:00.000Z",
            active_session_count: 1,
            recovery_code_count: 8
          }]
        };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (sql.includes("insert into admin_account")) {
        return { rowCount: 1, rows: [{ id: "new-account", username: "newadmin" }] };
      }
      return { rowCount: 0, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const listed = await app.inject({
      method: "GET",
      url: "/api/admin-accounts",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.json()).toMatchObject({ accounts: [expect.objectContaining({ username: "karel" })] });

    const created = await app.inject({
      method: "POST",
      url: "/api/admin-accounts",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { username: "newadmin", password: "very-strong-password", mfaSecret: "" }
    });
    expect(created.statusCode).toBe(200);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("insert into admin_account"))).toBe(true);
  });

  it("lists and updates operational configuration through the registry", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session s")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "account-id", session_hash: sessionHash, username: "karel" }] };
      }
      if (sql.includes("from operational_config_setting") && sql.includes("updated_at")) {
        return {
          rowCount: 1,
          rows: [{
            key: "logLevel",
            value_json: "debug",
            value_ciphertext: null,
            updated_at: "2026-07-14T10:00:00.000Z"
          }]
        };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (sql.includes("select event_hash from audit_event")) return { rowCount: 0, rows: [] };
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const listed = await app.inject({
      method: "GET",
      url: "/api/operational-config",
      headers: { host: config.ADMIN_HOST, cookie: `__Host-kcml_session=${sessionValue}` }
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.json().settings).toContainEqual(expect.objectContaining({
      key: "logLevel",
      value: "debug",
      source: "database"
    }));
    expect(listed.json().settings).toHaveLength(3);

    const updated = await app.inject({
      method: "PUT",
      url: "/api/operational-config/logLevel",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { value: "warn" }
    });
    expect(updated.statusCode).toBe(200);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("insert into operational_config_setting"))).toBe(true);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("append_audit_event"))).toBe(true);
  });

  it("updates managed admin password, MFA and sessions", async () => {
    const sessionHash = await argon2.hash(sessionValue, { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("from admin_session s")) {
        return { rowCount: 1, rows: [{ id: "session-id", account_id: "operator-id", session_hash: sessionHash, username: "operator" }] };
      }
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (sql.includes("update admin_account set password_hash")) {
        return { rowCount: 1, rows: [{ username: "managed" }] };
      }
      if (sql.includes("update admin_account set mfa_enabled")) {
        return { rowCount: 1, rows: [{ username: "managed" }] };
      }
      if (sql.startsWith("select username from admin_account where id=$1")) {
        return { rowCount: 1, rows: [{ username: "managed" }] };
      }
      return { rowCount: 1, rows: [] };
    });
    const db = { query, connect: vi.fn(async () => ({ query, release: vi.fn() })) } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const password = await app.inject({
      method: "POST",
      url: "/api/admin-accounts/managed-id/password",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { nextPassword: "another-very-strong-password" }
    });
    expect(password.statusCode, password.body).toBe(200);

    const mfa = await app.inject({
      method: "PUT",
      url: "/api/admin-accounts/managed-id/mfa",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: { enabled: true, secret: "JBSWY3DPEHPK3PXP" }
    });
    expect(mfa.statusCode).toBe(200);

    const revoke = await app.inject({
      method: "POST",
      url: "/api/admin-accounts/managed-id/sessions/revoke",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: {}
    });
    expect(revoke.statusCode).toBe(200);

    const recovery = await app.inject({
      method: "POST",
      url: "/api/admin-accounts/managed-id/recovery/rotate",
      headers: {
        host: config.ADMIN_HOST,
        cookie: `__Host-kcml_session=${sessionValue}; __Host-kcml_csrf=${csrfValue}`,
        "x-csrf-token": csrfValue
      },
      payload: {}
    });
    expect(recovery.statusCode).toBe(200);
    expect(recovery.json().recoveryCodes).toHaveLength(8);
  });

  it("authenticates login with a recovery code and consumes it", async () => {
    const passwordHash = await argon2.hash("correct horse battery staple", { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const recoveryHash = await argon2.hash("ABCDEF-123456-789ABC", { type: argon2.argon2id, memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const query = vi.fn(async (sql: string) => {
      if (sql.startsWith("select * from admin_account where username=$1")) {
        return {
          rowCount: 1,
          rows: [{
            id: "account-id",
            password_hash: passwordHash,
            mfa_enabled: true,
            mfa_secret: encryptMfaSecret("JBSWY3DPEHPK3PXP", config.MFA_ENCRYPTION_KEY_BASE64)
          }]
        };
      }
      if (sql.includes("from admin_recovery_code")) {
        return { rowCount: 1, rows: [{ id: "recovery-id", code_hash: recoveryHash }] };
      }
      return { rowCount: 1, rows: [] };
    });
    const db = { query } as unknown as Db;
    app = Fastify();
    await app.register(cookie, { secret: config.SESSION_SECRET_BASE64.toString("base64url") });
    registerAdminRoutes(app, db, config);
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/api/login",
      headers: { host: config.ADMIN_HOST },
      payload: {
        username: "admin",
        password: "correct horse battery staple",
        totp: "ABCDEF-123456-789ABC"
      }
    });
    expect(response.statusCode).toBe(200);
    expect(query.mock.calls.some(([sql]) => String(sql).includes("update admin_recovery_code set consumed_at"))).toBe(true);
  });
});
