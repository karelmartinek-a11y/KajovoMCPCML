import fs from "node:fs";
import http from "node:http";
import { spawn } from "node:child_process";

const socketPath = process.env.KCML_SOCKET_PATH ?? "/run/kcml/worker.sock";
const handlerRunnerPath = process.env.KCML_HANDLER_RUNNER_PATH ?? "/app/handler-runner.mjs";
const handlerTimeoutMs = boundedInteger(process.env.KCML_HANDLER_TIMEOUT_MS, 30_000, 100, 60_000);
const requestMaxBytes = boundedInteger(process.env.KCML_REQUEST_MAX_BYTES, 1024 * 1024, 1, 1024 * 1024);
const responseMaxBytes = boundedInteger(process.env.KCML_RESPONSE_MAX_BYTES, 5 * 1024 * 1024, 1, 5 * 1024 * 1024);
const requestWireLimit = requestMaxBytes + 64 * 1024;
const responseWireLimit = responseMaxBytes + 128 * 1024;

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function response(reply, status, payload) {
  const body = JSON.stringify(payload);
  reply.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  reply.end(body);
}

function runHandler(payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [handlerRunnerPath], {
      env: process.env,
      stdio: ["pipe", "ignore", "ignore", "pipe"]
    });
    const protocol = child.stdio[3];
    const chunks = [];
    let size = 0;
    let timedOut = false;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, handlerTimeoutMs);
    protocol.on("data", (chunk) => {
      size += chunk.length;
      if (size > responseWireLimit) {
        child.kill("SIGKILL");
        finish(new Error("worker_response_too_large"));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    protocol.on("error", (error) => finish(error));
    child.on("error", (error) => finish(error));
    child.on("close", (code) => {
      clearTimeout(timer);
      if (timedOut) {
        finish(new Error("handler_timeout"));
        return;
      }
      if (code !== 0) {
        finish(new Error("handler_process_failed"));
        return;
      }
      try {
        finish(null, JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        finish(new Error("handler_invalid_response"));
      }
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(payload);
  });
}

const server = http.createServer((request, reply) => {
  if (request.method === "GET" && request.url === "/health") {
    response(reply, 200, { status: "ready", serverCode: process.env.KCML_SERVER_CODE, imageDigest: process.env.KCML_IMAGE_DIGEST });
    return;
  }
  if (request.method !== "POST" || request.url !== "/invoke") {
    response(reply, 404, { error: { code: "not_found" } });
    return;
  }
  const chunks = [];
  let size = 0;
  request.on("data", (chunk) => {
    size += chunk.length;
    if (size > requestWireLimit) request.destroy(new Error("request_too_large"));
    else chunks.push(Buffer.from(chunk));
  });
  request.on("error", () => {
    if (!reply.headersSent) response(reply, 400, { error: { code: "invalid_request" } });
  });
  request.on("end", () => {
    void (async () => {
      const payload = Buffer.concat(chunks);
      try {
        JSON.parse(payload.toString("utf8"));
      } catch {
        response(reply, 400, { error: { code: "invalid_json" } });
        return;
      }
      try {
        response(reply, 200, await runHandler(payload));
      } catch (error) {
        response(reply, 500, { error: { code: error instanceof Error ? error.message : "handler_failed" } });
      }
    })();
  });
});

try { fs.unlinkSync(socketPath); } catch (error) { if (error?.code !== "ENOENT") throw error; }
server.listen(socketPath, () => fs.chmodSync(socketPath, 0o600));

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
