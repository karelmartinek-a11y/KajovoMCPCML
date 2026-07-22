import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppServerConfig } from "../config.js";
import type { Db } from "../db.js";
import { registerMcpRoutes } from "./mcp.js";

const component = {
  id: "90000000-0000-4000-8000-000000000001",
  code: "KCML0001",
  hostname: "kcml0001.example.invalid",
  active_revision_id: "90000000-0000-4000-8000-000000000002",
  revision: "1.0.0"
};

function createDb(found = true): Db {
  const query = vi.fn(async (sql: string) => {
    if (sql.includes("from component c") && sql.includes("join component_revision r")) return found ? { rowCount: 1, rows: [{
      ...component,
      enabled: true,
      ingress_enabled: true,
      lifecycle_state: "ACTIVE",
      activation_state: "ACTIVE",
      operational_state: "HEALTHY"
    }] } : { rowCount: 0, rows: [] };
    if (sql.includes("from principal_access_token token")) return { rowCount: 1, rows: [{
      source_client_id: component.code,
      source_principal_kind: "COMPONENT",
      source_principal_status: "ACTIVE",
      current_source_revocation_epoch: 1,
      issued_revocation_epoch: 1,
      source_component_id: component.id,
      source_component_code: component.code,
      source_enabled: true,
      source_lifecycle_state: "ACTIVE",
      target_component_id: component.id,
      target_component_code: component.code,
      target_hostname: component.hostname,
      target_enabled: true,
      target_ingress_enabled: true,
      target_lifecycle_state: "ACTIVE",
      target_activation_state: "ACTIVE",
      target_operational_state: "HEALTHY",
      policy_epoch: 1,
      audience: "*",
      token_expired: false,
      revoked_at: null,
      scope_names: ["mcp.initialize", "mcp.notifications.initialized", "mcp.tools.list", "mcp.tools.call"],
      fingerprint: "test-fingerprint"
    }] };
    if (sql.includes("from component_permission")) return { rowCount: 1, rows: [{ route_pattern: "/mcp" }] };
    if (sql.includes("from component_tool_contract")) return { rowCount: 1, rows: [{
      name: "example_tool",
      title: "Example tool",
      description: "Example tool description",
      input_schema: { type: "object", additionalProperties: false },
      output_schema: { type: "object", additionalProperties: false },
      annotations: {},
      scope_name: "mcp.tools.call",
      timeout_ms: 5000,
      limits: {}
    }] };
    return { rowCount: 1, rows: [{}] };
  });
  const client = { query, release: () => undefined };
  return { query, connect: async () => client } as unknown as Db;
}

const config = {
  PUBLIC_BASE_DOMAIN: "example.invalid",
  AUTH_HOST: "auth.example.invalid",
  ACCESS_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 7)
} as AppServerConfig;

describe("canonical MCP HTTP surface", () => {
  let app: FastifyInstance;
  beforeEach(() => {
    app = Fastify();
    registerMcpRoutes(app, createDb(), config);
  });
  afterEach(async () => app.close());

  it("publishes minimal protected-resource metadata only for a registered canonical host", async () => {
    const response = await app.inject({ method: "GET", url: "/.well-known/oauth-protected-resource/mcp", headers: { host: component.hostname } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      resource: `https://${component.hostname}`,
      authorization_servers: ["https://auth.example.invalid"],
      bearer_methods_supported: ["header"]
    });
    expect(response.body).not.toContain("capabilities");
  });

  it("rejects an unknown host without falling back to legacy registries", async () => {
    await app.close();
    app = Fastify();
    registerMcpRoutes(app, createDb(false), config);
    const response = await app.inject({ method: "POST", url: "/mcp", headers: { host: component.hostname }, payload: { jsonrpc: "2.0", id: 1, method: "initialize" } });
    expect(response.statusCode).toBe(404);
  });

  it("requires a bearer token before exposing component availability", async () => {
    const response = await app.inject({ method: "POST", url: "/mcp", headers: { host: component.hostname }, payload: { jsonrpc: "2.0", id: 1, method: "initialize" } });
    expect(response.statusCode).toBe(401);
    expect(response.json().code).toBe("invalid_token");
  });

  it("returns canonical initialize and tool-list contracts", async () => {
    const initialize = await app.inject({ method: "POST", url: "/mcp", headers: { host: component.hostname, authorization: "Bearer access-token" }, payload: { jsonrpc: "2.0", id: 1, method: "initialize" } });
    expect(initialize.statusCode).toBe(200);
    expect(initialize.json().result.serverInfo).toEqual({ name: component.code, version: component.revision });
    const list = await app.inject({ method: "POST", url: "/mcp", headers: { host: component.hostname, authorization: "Bearer access-token" }, payload: { jsonrpc: "2.0", id: 2, method: "tools/list" } });
    expect(list.statusCode).toBe(200);
    expect(list.json().result.tools).toHaveLength(1);
    expect(list.json().result.tools[0].name).toBe("example_tool");
  });

  it("rejects cross-origin, non-POST, batch and unsupported methods", async () => {
    expect((await app.inject({ method: "POST", url: "/mcp", headers: { host: component.hostname, origin: "https://evil.invalid" }, payload: {} })).statusCode).toBe(403);
    expect((await app.inject({ method: "GET", url: "/mcp", headers: { host: component.hostname } })).statusCode).toBe(405);
    const batch = await app.inject({ method: "POST", url: "/mcp", headers: { host: component.hostname, authorization: "Bearer access-token" }, payload: [{ jsonrpc: "2.0", id: 1, method: "tools/list" }] });
    expect(batch.json().error.code).toBe(-32600);
    const unsupported = await app.inject({ method: "POST", url: "/mcp", headers: { host: component.hostname, authorization: "Bearer access-token" }, payload: { jsonrpc: "2.0", id: 3, method: "unknown" } });
    expect(unsupported.json().error.code).toBe(-32601);
  });
});
