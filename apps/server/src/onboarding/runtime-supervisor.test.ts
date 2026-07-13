import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const bootstrapPath = path.resolve(new URL("../../../../deploy/handler-runtime/bootstrap.mjs", import.meta.url).pathname);
const runnerPath = path.resolve(new URL("../../../../deploy/handler-runtime/handler-runner.mjs", import.meta.url).pathname);
const processes: ChildProcess[] = [];
const directories: string[] = [];

async function request(socketPath: string, requestPath: string, method = "GET", body?: unknown): Promise<{ status: number; body: unknown }> {
  const payload = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const outgoing = http.request({
      socketPath,
      path: requestPath,
      method,
      headers: payload.length ? { "content-type": "application/json", "content-length": String(payload.length) } : undefined,
      timeout: 2_000
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("error", reject);
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: response.statusCode ?? 0, body: text ? JSON.parse(text) : null });
      });
    });
    outgoing.on("timeout", () => outgoing.destroy(new Error("test_request_timeout")));
    outgoing.on("error", reject);
    outgoing.end(payload);
  });
}

async function startSupervisor(moduleSource: string, timeoutMs = 500): Promise<{ socketPath: string; process: ChildProcess }> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "kcml-supervisor-test-"));
  directories.push(directory);
  const modulePath = path.join(directory, "handler.mjs");
  const socketPath = path.join(directory, "worker.sock");
  await fs.writeFile(modulePath, moduleSource);
  const child = spawn(process.execPath, [bootstrapPath], {
    env: {
      ...process.env,
      KCML_SOCKET_PATH: socketPath,
      KCML_HANDLER_RUNNER_PATH: runnerPath,
      KCML_HANDLER_MODULE_PATH: modulePath,
      KCML_HANDLER_TIMEOUT_MS: String(timeoutMs),
      KCML_REQUEST_MAX_BYTES: "65536",
      KCML_RESPONSE_MAX_BYTES: "65536",
      KCML_SERVER_CODE: "KCML0001",
      KCML_IMAGE_DIGEST: `sha256:${"0".repeat(64)}`
    },
    stdio: "ignore"
  });
  processes.push(child);
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try {
      await fs.stat(socketPath);
      return { socketPath, process: child };
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  throw new Error("supervisor_socket_not_ready");
}

afterEach(async () => {
  await Promise.all(processes.splice(0).map((child) => new Promise<void>((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) { resolve(); return; }
    child.once("exit", () => resolve());
    child.kill("SIGTERM");
  })));
  await Promise.all(directories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("fixed OCI handler supervisor", () => {
  it("executes the uploaded module only in the child runner and returns structured logs", async () => {
    const supervisor = await startSupervisor(`
      export async function invoke(input, context) {
        context.logger.info({ phase: "test" }, "handler.called");
        return { echoed: input.value };
      }
    `);
    const result = await request(supervisor.socketPath, "/invoke", "POST", { input: { value: 42 }, context: {} });
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ output: { echoed: 42 }, logs: [{ level: "info", message: "handler.called" }] });
  });

  it("kills a CPU-bound handler at the hard timeout while keeping the supervisor healthy", async () => {
    const supervisor = await startSupervisor("export async function invoke() { while (true) {} }", 150);
    const result = await request(supervisor.socketPath, "/invoke", "POST", { input: {}, context: {} });
    expect(result.status).toBe(500);
    expect(result.body).toMatchObject({ error: { code: "handler_timeout" } });
    const health = await request(supervisor.socketPath, "/health");
    expect(health).toMatchObject({ status: 200, body: { status: "ready", serverCode: "KCML0001" } });
  });
});
