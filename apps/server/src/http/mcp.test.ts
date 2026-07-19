import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import type { Db } from "../db.js";
import type { HandlerContext } from "../handlers/registry.js";
import { registerMcpRoutes } from "./mcp.js";

const handlerState: {
  invoke: ((input: unknown, ctx: HandlerContext) => Promise<unknown>) | null;
} = {
  invoke: null
};

vi.mock("../domain/auth.js", () => ({
  validateBearer: vi.fn(async () => ({
    credentialId: "credential-id",
    serverId: "server-id",
    code: "KCML0001",
    toolName: "example_tool"
  }))
}));

vi.mock("../handlers/registry.js", () => ({
  getHandler: vi.fn(() => handlerState.invoke ? {
    key: "mock",
    version: "1",
    invoke: (input: unknown, ctx: HandlerContext) => handlerState.invoke!(input, ctx)
  } : null)
}));

const secret = (byte: number) => Buffer.alloc(32, byte).toString("base64");

function createDb(serverOverrides: Partial<Record<string, unknown>> = {}): Db {
  const serverRow = {
    id: "server-id",
    code: "KCML0001",
    kcml_number: 1,
    hostname: "kcml0001.example.invalid",
    tool_name: "example_tool",
    display_name: "Example Tool",
    description: "Example description",
    enabled: true,
    registration_state: "ACTIVE",
    operational_state: "HEALTHY",
    input_schema: { type: "object", additionalProperties: false, properties: { name: { type: "string" } } },
    output_schema: { type: "object", additionalProperties: false, properties: { ok: { type: "boolean" } }, required: ["ok"] },
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
    runtime_socket: "/tmp/mock.sock",
    timeout_ms: 25,
    max_concurrency: 1,
    request_max_bytes: 1024,
    response_max_bytes: 1024,
    rate_window_seconds: 60,
    rate_max_requests: 100,
    read_only_hint: false,
    destructive_hint: true,
    idempotent_hint: false,
    open_world_hint: true,
    effect_class: "NON_IDEMPOTENT_WRITE",
    shutdown_policy: "CANCEL_SAFE",
    idempotency_policy: "required",
    revocation_epoch: "epoch",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...serverOverrides
  };

  const leaseRows = new Map<string, { serverId: string }>();
  const rateKeys: unknown[][] = [];
  const query = vi.fn(async (sql: string, params?: unknown[]) => {
    if (sql.includes("from mcp_server ms") && sql.includes("where lower(ms.hostname)=lower")) return { rowCount: 1, rows: [serverRow] };
    if (sql.startsWith("insert into mcp_invocation_idempotency")) return { rowCount: 1, rows: [{ idempotency_key: params?.[2] }] };
    if (sql.startsWith("select request_digest,status,response_json")) return { rowCount: 0, rows: [] };
    if (sql.startsWith("update mcp_invocation_idempotency")) return { rowCount: 1, rows: [] };
    if (sql.includes("insert into mcp_rate_bucket")) {
      rateKeys.push(params ?? []);
      return { rowCount: 1, rows: [{ request_count: 1, retry_after_ms: 60_000 }] };
    }
    if (sql.startsWith("insert into function_statistics")) return { rowCount: 1, rows: [] };
    if (sql.startsWith("insert into mcp_invocation_metric")) return { rowCount: 1, rows: [] };
    if (sql.startsWith("insert into mcp_invocation(")) return { rowCount: 1, rows: [{ id: "invocation-id" }] };
    if (sql.startsWith("update mcp_invocation")) return { rowCount: 1, rows: [{ id: "invocation-id" }] };
    if (sql.includes("append_audit_event")) return { rowCount: 1, rows: [] };
    if (sql.startsWith("insert into runtime_log_event")) return { rowCount: 1, rows: [] };
    if (sql.startsWith("update access_token")) return { rowCount: 1, rows: [] };
    if (sql === "delete from function_concurrency_lease where expires_at <= now()") return { rowCount: 0, rows: [] };
    if (sql.includes("select max_concurrency, timeout_ms from mcp_server where id=")) {
      return { rowCount: 1, rows: [{ max_concurrency: serverRow.max_concurrency, timeout_ms: serverRow.timeout_ms }] };
    }
    if (sql.includes("select count(*)::int as count from function_concurrency_lease")) {
      return { rowCount: 1, rows: [{ count: leaseRows.size }] };
    }
    if (sql.startsWith("insert into function_concurrency_lease")) {
      const leaseId = `lease-${leaseRows.size + 1}`;
      leaseRows.set(leaseId, { serverId: typeof params?.[0] === "string" ? params[0] : "server-id" });
      return { rowCount: 1, rows: [{ lease_id: leaseId }] };
    }
    if (sql.startsWith("delete from function_concurrency_lease where lease_id=")) {
      leaseRows.delete(typeof params?.[0] === "string" ? params[0] : "");
      return { rowCount: 1, rows: [] };
    }
    return { rowCount: 0, rows: [] };
  });
  const client = { query, release: vi.fn() };
  return {
    query,
    connect: vi.fn(async () => client),
    rateKeys
  } as unknown as Db & { rateKeys: unknown[][] };
}

describe("MCP route", () => {
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
    handlerState.invoke = null;
  });

  afterEach(async () => {
    await app?.close();
  });

  it("returns manifest annotations unchanged in tools/list", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", id: 1, method: "tools/list" }
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.result.tools[0].annotations).toEqual({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true
    });
  });

  it("rejects malformed JSON-RPC envelopes with JSON-RPC error", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { method: "tools/list" }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().error.code).toBe(-32600);
  });

  it("maps malformed raw JSON to the JSON-RPC parse error", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: {
        host: "kcml0001.example.invalid",
        authorization: "Bearer token",
        "content-type": "application/json"
      },
      payload: "{\"jsonrpc\":\"2.0\","
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ jsonrpc: "2.0", id: null, error: { code: -32700 } });
  });

  it("requires JSON POST transport headers for MCP JSON-RPC", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();

    const unsupportedMediaType = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token", "content-type": "text/plain" },
      payload: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })
    });
    expect(unsupportedMediaType.statusCode).toBe(415);
    expect(unsupportedMediaType.json()).toMatchObject({ error: "unsupported_media_type" });

    const notAcceptable = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: {
        host: "kcml0001.example.invalid",
        authorization: "Bearer token",
        "content-type": "application/json",
        accept: "text/plain"
      },
      payload: { jsonrpc: "2.0", id: 1, method: "tools/list" }
    });
    expect(notAcceptable.statusCode).toBe(406);
    expect(notAcceptable.json()).toMatchObject({ error: "not_acceptable" });
  });

  it("rejects cross-origin MCP transport requests", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", origin: "https://evil.example", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", id: 1, method: "tools/list" }
    });
    expect(response.statusCode).toBe(403);
    expect(response.json().error).toBe("invalid_origin");
  });

  it("honestly rejects GET when no Streamable HTTP session transport is implemented", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();
    const response = await app.inject({
      method: "GET",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", accept: "text/event-stream", authorization: "Bearer token" }
    });
    expect(response.statusCode).toBe(405);
    expect(response.headers.allow).toBe("POST");
    expect(response.json()).toMatchObject({ error: "method_not_allowed" });
  });

  it("accepts wildcard JSON response negotiation and returns no body for initialized notification", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();

    const initialize = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: {
        host: "kcml0001.example.invalid",
        authorization: "Bearer token",
        "content-type": "application/json; charset=utf-8",
        accept: "*/*"
      },
      payload: { jsonrpc: "2.0", id: 1, method: "initialize" }
    });
    expect(initialize.statusCode).toBe(200);
    expect(initialize.headers["content-type"]).toContain("application/json");

    const initialized = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: {
        host: "kcml0001.example.invalid",
        authorization: "Bearer token",
        "content-type": "application/json",
        accept: "application/json"
      },
      payload: { jsonrpc: "2.0", method: "notifications/initialized" }
    });
    expect(initialized.statusCode).toBe(202);
    expect(initialized.body).toBe("");
  });

  it("rejects unsupported initialize and protocol header versions", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();

    const unsupportedInitialize = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: {
        jsonrpc: "2.0",
        id: 21,
        method: "initialize",
        params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "old", version: "1" } }
      }
    });
    expect(unsupportedInitialize.statusCode).toBe(200);
    expect(unsupportedInitialize.json()).toMatchObject({
      error: {
        code: -32602,
        data: {
          code: "UNSUPPORTED_MCP_PROTOCOL_VERSION",
          retryable: false,
          supported: ["2025-11-25"],
          requested: "2024-11-05"
        }
      }
    });

    const unsupportedHeader = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: {
        host: "kcml0001.example.invalid",
        authorization: "Bearer token",
        "mcp-protocol-version": "2024-11-05"
      },
      payload: { jsonrpc: "2.0", id: 22, method: "tools/list" }
    });
    expect(unsupportedHeader.statusCode).toBe(400);
    expect(unsupportedHeader.json()).toMatchObject({ error: "unsupported_mcp_protocol_version" });
  });

  it("does not send method errors for JSON-RPC notifications", async () => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", method: "unknown/notification" }
    });
    expect(response.statusCode).toBe(202);
    expect(response.body).toBe("");
  });

  it("accepts cancellation notifications and aborts an in-flight request", async () => {
    handlerState.invoke = async (_input, ctx) => new Promise((resolve, reject) => {
      ctx.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { classification: "cancelled" })), { once: true });
      setTimeout(() => resolve({ ok: true }), 200);
    });
    app = Fastify();
    registerMcpRoutes(app, createDb({ timeout_ms: 500 }), config);
    await app.ready();

    const call = app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token", "idempotency-key": "cancel-test-0001" },
      payload: { jsonrpc: "2.0", id: "cancel-1", method: "tools/call", params: { name: "example_tool", arguments: { name: "A" } } }
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const cancel = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "cancel-1", reason: "test" } }
    });
    expect(cancel.statusCode).toBe(202);
    const response = await call;
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ error: { code: -32008, data: { code: "REQUEST_CANCELLED", retryable: false } } });
  });

  it("classifies timed out handlers as JSON-RPC timeout failures", async () => {
    let aborted = false;
    handlerState.invoke = async (_input, ctx) => new Promise((resolve) => {
      ctx.signal?.addEventListener("abort", () => {
        aborted = true;
      }, { once: true });
      setTimeout(() => resolve({ ok: true }), 60);
    });
    app = Fastify();
    registerMcpRoutes(app, createDb({ timeout_ms: 10 }), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token", "idempotency-key": "timeout-test-0001" },
      payload: { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "example_tool", arguments: { name: "A" } } }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().error.code).toBe(-32005);
    expect(aborted).toBe(true);
  });

  it("keys tool rate limits by server and credential", async () => {
    handlerState.invoke = async () => ({ ok: true });
    const db = createDb() as Db & { rateKeys: unknown[][] };
    app = Fastify();
    registerMcpRoutes(app, db, config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token", "idempotency-key": "rate-test-0001" },
      payload: { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "example_tool", arguments: { name: "A" } } }
    });
    expect(response.statusCode).toBe(200);
    expect(db.rateKeys).toHaveLength(3);
    expect(db.rateKeys.map((params) => [params[0], params[2], params[3], params[4]])).toEqual([
      ["SERVER_CREDENTIAL", "server-id", "credential-id", 60],
      ["CREDENTIAL", null, "credential-id", 60],
      ["SERVER", "server-id", null, 60]
    ]);
  });

  it("requires an Idempotency-Key for non-idempotent tools", async () => {
    handlerState.invoke = async () => ({ ok: true });
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", id: 10, method: "tools/call", params: { name: "example_tool", arguments: { name: "A" } } }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().error.message).toContain("Idempotency-Key");
  });

  it("does not require an Idempotency-Key for read-only tools", async () => {
    handlerState.invoke = async () => ({ ok: true });
    app = Fastify();
    registerMcpRoutes(app, createDb({
      effect_class: "READ_ONLY",
      read_only_hint: true,
      destructive_hint: false,
      idempotent_hint: true,
      idempotency_policy: "read only"
    }), config);
    await app.ready();
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "example_tool", arguments: { name: "A" } } }
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().result.structuredContent).toEqual({ ok: true });
  });

  it.each([
    ["missing active revision", { active_revision_id: null }],
    ["invalid revision", { registration_validation_state: "INVALID" }],
    ["missing monitoring profile", { monitoring_profile_digest: null }],
    ["disabled monitoring", { monitoring_enabled: false }]
  ])("fails closed for %s without exposing catalog details", async (_reason, overrides) => {
    app = Fastify();
    registerMcpRoutes(app, createDb(overrides), config);
    await app.ready();
    const response = await app.inject({
      method: "GET",
      url: "/.well-known/oauth-protected-resource/mcp",
      headers: { host: "kcml0001.example.invalid" }
    });
    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ error: "service_unavailable" });
    expect(response.body).not.toContain("example_tool");
  });

  it("continues existing MCP operation during grace and suspends it after 30 days", async () => {
    const due = new Date(Date.now() - 24 * 60 * 60 * 1_000);
    const approved = new Date(due.getTime() - 365 * 24 * 60 * 60 * 1_000);
    app = Fastify();
    registerMcpRoutes(app, createDb({
      review_approved_at: approved.toISOString(),
      review_due_at: due.toISOString()
    }), config);
    await app.ready();
    const grace = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", id: 12, method: "tools/list" }
    });
    expect(grace.statusCode).toBe(200);
    await app.close();

    const suspendedDue = new Date(Date.now() - 31 * 24 * 60 * 60 * 1_000);
    const suspendedApproved = new Date(suspendedDue.getTime() - 365 * 24 * 60 * 60 * 1_000);
    app = Fastify();
    registerMcpRoutes(app, createDb({
      review_approved_at: suspendedApproved.toISOString(),
      review_due_at: suspendedDue.toISOString()
    }), config);
    await app.ready();
    const suspended = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { host: "kcml0001.example.invalid", authorization: "Bearer token" },
      payload: { jsonrpc: "2.0", id: 13, method: "tools/list" }
    });
    expect(suspended.statusCode).toBe(503);
  });
});
