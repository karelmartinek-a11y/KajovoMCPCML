import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import Fastify from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import type { AppServerConfig } from "../config.js";
import type { Db } from "../db.js";
import { handleCanonicalMcp } from "./component-mcp-runtime.js";

const hmacKey = Buffer.alloc(32, 7);
const component = {
  id: "90000000-0000-4000-8000-000000000001", code: "KCML90001", hostname: "kcml90001.kajovocml.hcasc.cz",
  enabled: true, ingressEnabled: true, lifecycleState: "ACTIVE", activationState: "ACTIVE", operationalState: "HEALTHY",
  activeRevisionId: "90000000-0000-4000-8000-000000000002", revision: "1.0.0"
};

const cleanup: string[] = [];
afterEach(async () => Promise.all(cleanup.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))));

function fakeDb(socketPath: string): Db {
  const query = async (sql: string) => {
    if (sql.includes("from component_tool_contract")) return { rowCount: 1, rows: [{
      name: "inventory", title: "Inventory", description: "Return inventory", scope_name: "mcp.tools.call", timeout_ms: 5_000,
      input_schema: { type: "object", additionalProperties: false }, output_schema: { type: "object", required: ["ok"], properties: { ok: { type: "boolean" } }, additionalProperties: false },
      annotations: { readOnlyHint: true }, limits: { requestMaxBytes: 10_000, responseMaxBytes: 10_000 }
    }] };
    if (sql.includes("from principal_access_token token")) return { rowCount: 1, rows: [{
      source_client_id: "KCML90001", source_principal_status: "ACTIVE", current_source_revocation_epoch: 1,
      issued_revocation_epoch: 1, source_component_id: component.id, source_component_code: component.code,
      source_enabled: true, source_lifecycle_state: "ACTIVE", target_component_id: component.id,
      target_component_code: component.code, target_hostname: component.hostname, target_enabled: true,
      target_ingress_enabled: true, target_lifecycle_state: "ACTIVE", target_operational_state: "HEALTHY",
      policy_epoch: 3, release_version: "2026.07.24", token_expired: false, revoked_at: null,
      scope_names: ["component.invoke"], fingerprint: "access-fingerprint"
    }] };
    if (sql.includes("from component_permission")) return { rowCount: 1, rows: [{}] };
    if (sql.includes("from component_runtime_target")) return { rowCount: 1, rows: [{
      transport: "UDS", upstream: socketPath, socket_path: socketPath, status: "HEALTHY"
    }] };
    if (sql.includes("insert into component_operation_lease")) return { rowCount: 1, rows: [{ id: "90000000-0000-4000-8000-000000000003" }] };
    return { rowCount: 1, rows: [{}] };
  };
  const client = { query, release: () => undefined };
  return { query, connect: async () => client } as unknown as Db;
}

describe("canonical component MCP runtime", () => {
  it("authorizes, dispatches over UDS, validates output and returns MCP structured content", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "kcml-component-runtime-"));
    cleanup.push(directory);
    const socketPath = path.join(directory, "runtime.sock");
    const received: Array<Record<string, unknown>> = [];
    const runtime = http.createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      request.on("end", () => {
        received.push(JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>);
        expect(request.headers.authorization).toBe("Bearer long-lived-token");
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ result: { ok: true } }));
      });
    });
    await new Promise<void>((resolve) => runtime.listen(socketPath, resolve));
    const app = Fastify();
    const db = fakeDb(socketPath);
    const config = { ACCESS_TOKEN_HMAC_KEY_BASE64: hmacKey } as AppServerConfig;
    app.post("/mcp", (request, reply) => handleCanonicalMcp(request, reply, db, config, component, "90000000-0000-4000-8000-000000000004"));
    const reply = await app.inject({
      method: "POST", url: "/mcp", headers: { authorization: "Bearer long-lived-token", host: component.hostname },
      payload: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "inventory", arguments: {} } }
    });
    expect(reply.statusCode).toBe(200);
    expect(reply.json().result).toMatchObject({ structuredContent: { ok: true }, isError: false });
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ operation: "tools/call", tool: "inventory" });
    await app.close();
    await new Promise<void>((resolve, reject) => runtime.close((error) => error ? reject(error) : resolve()));
  });
});
