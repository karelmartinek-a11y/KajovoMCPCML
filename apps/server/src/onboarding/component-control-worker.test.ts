import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { WorkerConfig } from "../config.js";
import type { Db } from "../db.js";

const { recordAck } = vi.hoisted(() => ({ recordAck: vi.fn(async () => ({})) }));
vi.mock("../domain/component.js", () => ({ recordComponentControlAck: recordAck }));
vi.mock("../domain/platform-worker-access.js", () => ({
  authorizePlatformWorkerCall: vi.fn(async () => ({ token: "platform-long-lived-access-token", decision: { allow: true } }))
}));
import { processNextComponentControlDispatch } from "./component-control-worker.js";

describe("KCML component control worker", () => {
  let directory: string | null = null;
  let server: http.Server | null = null;
  afterEach(async () => {
    recordAck.mockClear();
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
    if (directory) await rm(directory, { recursive: true, force: true });
    server = null;
    directory = null;
  });

  it("authorizes and writes the bearer request before persisting ACK_PENDING", async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), "kcml-control-"));
    const socketPath = path.join(directory, "runtime.sock");
    const events: string[] = [];
    let authorization = "";
    let payload: Record<string, unknown> = {};
    server = http.createServer((request, response) => {
      authorization = String(request.headers.authorization ?? "");
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        events.push("network-write");
        payload = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"accepted":true}');
      });
    });
    await new Promise<void>((resolve, reject) => server!.listen(socketPath, resolve).once("error", reject));

    let claimed = false;
    const query = async (sql: string, params: unknown[] = []) => {
      if (sql.includes("from component_control_dispatch d")) {
        if (claimed) return { rowCount: 0, rows: [] };
        claimed = true;
        return { rowCount: 1, rows: [{
          id: "20000000-0000-4000-8000-000000000001", component_id: "20000000-0000-4000-8000-000000000002",
          revision_id: "20000000-0000-4000-8000-000000000003", command_type: "enable", target_hostname: "kcml10002.kajovocml.hcasc.cz",
          endpoint_path: "/v1/kcml/control/enable", request_body: { commandId: "20000000-0000-4000-8000-000000000001" },
          requested_policy_epoch: 2, correlation_id: "20000000-0000-4000-8000-000000000004", attempt_count: 0,
          retry_policy: { maxAttempts: 3 }, transport: "UDS", upstream: null, expected_tls_identity: null, socket_path: socketPath,
          principal_public_id: "KCML10002", state_query_id: null, state_query_nonce: null, heartbeat_challenge_id: null, heartbeat_nonce: null,
          request_schema: { type: "object", required: ["commandId"], properties: { commandId: { type: "string" }, stateQuery: {}, heartbeatChallenge: {} } },
          response_schema: { type: "object", required: ["accepted"], properties: { accepted: { const: true } } }
        }] };
      }
      if (sql.includes("set state='ACK_PENDING'")) events.push("ack-persisted");
      return { rowCount: 1, rows: params.length ? [{}] : [] };
    };
    const client = { query, release: () => undefined };
    const db = { query, connect: async () => client } as unknown as Db;
    const worked = await processNextComponentControlDispatch(db, {} as WorkerConfig, "control-test-worker");

    expect(worked).toBe(true);
    expect(authorization).toBe("Bearer platform-long-lived-access-token");
    expect(payload.commandId).toBe("20000000-0000-4000-8000-000000000001");
    expect(events).toEqual(["network-write", "ack-persisted"]);
    expect(recordAck).toHaveBeenCalledOnce();
  });
});
