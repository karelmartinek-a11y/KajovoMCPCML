import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { WorkerConfig } from "../config.js";
import type { Db } from "../db.js";
vi.mock("../domain/platform-worker-access.js", () => ({
  authorizePlatformWorkerCall: vi.fn(async () => ({ token: "platform-long-lived-access-token", decision: { allow: true } }))
}));
import { processNextComponentE2ERun } from "./component-e2e-worker.js";

describe("KCML E2E worker", () => {
  let directory: string | null = null;
  let server: http.Server | null = null;
  afterEach(async () => {
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  it("sends only fixture input to the runtime and records exact output", async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), "kcml-e2e-"));
    const socketPath = path.join(directory, "runtime.sock");
    let received = "";
    let receivedAuthorization = "";
    let receivedPath = "";
    server = http.createServer((request, response) => {
      receivedAuthorization = String(request.headers.authorization ?? "");
      receivedPath = request.url ?? "";
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        received = Buffer.concat(chunks).toString("utf8");
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"available":true}');
      });
    });
    await new Promise<void>((resolve, reject) => server!.listen(socketPath, () => resolve()).once("error", reject));

    const writes: Array<{ sql: string; params: unknown[] }> = [];
    let claimed = false;
    const query = async (sql: string, params: unknown[] = []) => {
      writes.push({ sql, params });
      if (sql.includes("from component_e2e_run run")) {
        if (claimed) return { rowCount: 0, rows: [] };
        claimed = true;
        return { rowCount: 1, rows: [{ id: "10000000-0000-4000-8000-000000000001", component_id: "10000000-0000-4000-8000-000000000002", revision_id: "10000000-0000-4000-8000-000000000003", revision_digest: "sha256:revision", runtime_digest: "sha256:runtime", correlation_id: "10000000-0000-4000-8000-000000000004", deadline_at: new Date(Date.now() + 60_000), hostname: "kcml10001.kajovocml.hcasc.cz", transport: "UDS", socket_path: socketPath, upstream: null, expected_tls_identity: null }] };
      }
      if (sql.startsWith("select * from component_e2e_fixture")) return { rowCount: 1, rows: [{
        id: "10000000-0000-4000-8000-000000000005", scenario_key: "lookup", variant_key: "known", input_content: Buffer.from('{"sku":"SKU-1"}'), input_media_type: "application/json",
        expected_content: Buffer.from('{"available":true}'), expected_media_type: "application/json",
        expected_digest: "sha256:631f4d836f9d199ee9721cc528112d8b61d2b90455bb214dd364596b487fe6b6",
        invocation_kind: "TOOL", invocation_name: "inventory.lookup", timeout_ms: 5000, cleanup_contract: { required: false }
      }] };
      if (sql.startsWith("select name,output_schema from component_tool_contract")) return { rowCount: 1, rows: [{
        name: "inventory.lookup",
        output_schema: { type: "object", required: ["available"], properties: { available: { type: "boolean" } }, additionalProperties: false }
      }] };
      if (sql.startsWith("select endpoint_id,path from component_endpoint_contract") || sql.startsWith("select direction,pulse_type from component_pulse_mask")) {
        return { rowCount: 0, rows: [] };
      }
      return { rowCount: 1, rows: [] };
    };
    const client = { query, release: () => undefined };
    const db = { query, connect: async () => client } as unknown as Db;
    const worked = await processNextComponentE2ERun(db, {} as WorkerConfig, "e2e-test-worker");

    expect(worked).toBe(true);
    expect(receivedAuthorization).toBe("Bearer platform-long-lived-access-token");
    expect(receivedPath).toBe("/v1/kcml/runtime/tools/call");
    const runtimeRequest = JSON.parse(received) as { operation: string; tool: string; arguments: { sku: string } };
    expect(runtimeRequest).toMatchObject({ operation: "tools/call", tool: "inventory.lookup", arguments: { sku: "SKU-1" } });
    expect(received).not.toContain("available");
    const resultWrite = writes.find((write) => write.sql.includes("insert into component_e2e_run_result"));
    expect(resultWrite?.params.slice(4, 7)).toEqual([true, "PASS", null]);
    const completed = writes.find((write) => write.sql.includes("set status=$2,completed_at"));
    expect(completed?.params[1]).toBe("PASS");
  });
});
