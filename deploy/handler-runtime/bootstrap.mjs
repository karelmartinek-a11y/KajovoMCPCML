import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";

const socketPath = process.env.KCML_SOCKET_PATH ?? "/run/kcml/worker.sock";
const handlerModulePath = process.env.KCML_HANDLER_MODULE_PATH ?? "/app/handler/dist/index.js";
const handlerTimeoutMs = boundedInteger(process.env.KCML_HANDLER_TIMEOUT_MS, 30_000, 100, 300_000);
const requestMaxBytes = boundedInteger(process.env.KCML_REQUEST_MAX_BYTES, 1024 * 1024, 1, 1024 * 1024);
const responseMaxBytes = boundedInteger(process.env.KCML_RESPONSE_MAX_BYTES, 5 * 1024 * 1024, 1, 5 * 1024 * 1024);
const requestWireLimit = requestMaxBytes + 64 * 1024;
const dataPath = process.env.KCML_DATA_PATH ?? "/var/lib/kcml-data";
const runtimeModePath = process.env.KCML_RUNTIME_MODE_PATH ?? "/run/kcml/runtime-mode.json";
const initialLifecycleMode = process.env.KCML_RUNTIME_MODE ?? "ACTIVE";
const runtimeExecutionMode = process.env.KCML_RUNTIME_EXECUTION_MODE ?? "REQUEST_RESPONSE";
const shutdownGraceSeconds = boundedInteger(process.env.KCML_RUNTIME_GRACEFUL_SHUTDOWN_SECONDS, 30, 1, 600);
const singleActiveWorker = process.env.KCML_RUNTIME_SINGLE_ACTIVE_WORKER === "1";
const leasePath = process.env.KCML_RUNTIME_LEASE_PATH ?? path.join(dataPath, "worker.lease.json");

let moduleRef;
let started = false;
let stopping = false;
let lifecycleMode = initialLifecycleMode;
let statePayload = {};
let heartbeatPayload = null;
let readyState = {
  status: "INITIALIZING",
  ready: false,
  dependencySummary: {},
  checkedAt: new Date().toISOString(),
  evidenceDigest: null
};
let lastErrorCode = null;
let leaseHeld = false;
let modeWatcher;

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function response(reply, status, payload) {
  const body = JSON.stringify(payload);
  reply.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  reply.end(body);
}

function digest(value) {
  return `sha256:${Buffer.from(JSON.stringify(value)).toString("hex").slice(0, 64).padEnd(64, "0")}`;
}

function createLogger() {
  return Object.freeze({
    info(fields, message) {
      statePayload = { ...statePayload, lastLog: { level: "info", fields: fields ?? {}, message: String(message ?? "handler.info"), at: new Date().toISOString() } };
    },
    error(fields, message) {
      lastErrorCode = String(message ?? "handler.error");
      statePayload = { ...statePayload, lastLog: { level: "error", fields: fields ?? {}, message: String(message ?? "handler.error"), at: new Date().toISOString() } };
    }
  });
}

async function egressFetch(url, init = {}) {
  const proxySocket = process.env.KCML_EGRESS_SOCKET_PATH;
  const capability = process.env.KCML_EGRESS_CAPABILITY;
  if (!proxySocket || !capability) throw new Error("egress_not_configured");
  const body = Buffer.from(typeof init.body === "string" ? init.body : init.body == null ? "" : JSON.stringify(init.body));
  const payload = Buffer.from(JSON.stringify({
    url: String(url),
    method: init.method ?? "GET",
    headers: init.headers ?? {},
    body: body.toString("base64")
  }));
  return new Promise((resolve, reject) => {
    const request = http.request({
      socketPath: proxySocket,
      path: "/fetch",
      method: "POST",
      headers: { authorization: `Bearer ${capability}`, "content-type": "application/json", "content-length": String(payload.length) },
      timeout: 35_000
    }, (proxyResponse) => {
      const chunks = [];
      proxyResponse.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      proxyResponse.on("error", reject);
      proxyResponse.on("end", () => {
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          const responseBody = Buffer.from(parsed.body ?? "", "base64");
          resolve(Object.freeze({
            status: parsed.status,
            ok: parsed.status >= 200 && parsed.status < 300,
            headers: Object.freeze(parsed.headers ?? {}),
            text: async () => responseBody.toString("utf8"),
            json: async () => JSON.parse(responseBody.toString("utf8")),
            bytes: async () => Uint8Array.from(responseBody)
          }));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("timeout", () => request.destroy(new Error("egress_timeout")));
    request.on("error", reject);
    request.end(payload);
  });
}

async function connectTls({ host, port, servername, protocol = "TCP_TLS" }) {
  const proxySocket = process.env.KCML_EGRESS_SOCKET_PATH;
  const capability = process.env.KCML_EGRESS_CAPABILITY;
  if (!proxySocket || !capability) throw new Error("egress_not_configured");
  return new Promise((resolve, reject) => {
    const request = http.request({
      socketPath: proxySocket,
      path: `/tcp-tls?host=${encodeURIComponent(String(host))}&port=${encodeURIComponent(String(port))}&servername=${encodeURIComponent(String(servername))}&protocol=${encodeURIComponent(String(protocol))}`,
      method: "CONNECT",
      headers: { authorization: `Bearer ${capability}` }
    });
    request.on("connect", (_response, socket) => resolve(socket));
    request.on("error", reject);
    request.end();
  });
}

async function resolveSecret(name) {
  const proxySocket = process.env.KCML_SECRET_BROKER_SOCKET_PATH;
  const capability = process.env.KCML_SECRET_BROKER_CAPABILITY;
  if (!proxySocket || !capability) throw new Error("secret_broker_not_configured");
  const payload = Buffer.from(JSON.stringify({ name }));
  return new Promise((resolve, reject) => {
    const request = http.request({
      socketPath: proxySocket,
      path: "/resolve",
      method: "POST",
      headers: { authorization: `Bearer ${capability}`, "content-type": "application/json", "content-length": String(payload.length) },
      timeout: 15_000
    }, (proxyResponse) => {
      const chunks = [];
      proxyResponse.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      proxyResponse.on("error", reject);
      proxyResponse.on("end", () => {
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if ((proxyResponse.statusCode ?? 500) >= 400) {
            reject(new Error(typeof parsed?.error === "string" ? parsed.error : "secret_unavailable"));
            return;
          }
          resolve(parsed);
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("timeout", () => request.destroy(new Error("secret_timeout")));
    request.on("error", reject);
    request.end(payload);
  });
}

function runtimeApi() {
  return Object.freeze({
    currentMode() {
      return lifecycleMode;
    },
    async reportReady(input) {
      readyState = {
        status: input?.status ?? (input?.ready ? "READY" : "BLOCKED"),
        ready: Boolean(input?.ready),
        dependencySummary: input?.dependencySummary ?? {},
        checkedAt: new Date().toISOString(),
        evidenceDigest: digest(input ?? {})
      };
    },
    async reportState(input) {
      statePayload = { ...statePayload, ...(input ?? {}) };
    },
    async reportHeartbeat(input) {
      heartbeatPayload = { ...(input ?? {}), at: new Date().toISOString() };
    }
  });
}

async function acquireLeaseIfNeeded() {
  if (!singleActiveWorker || lifecycleMode !== "ACTIVE" || leaseHeld) return;
  await fsp.mkdir(path.dirname(leasePath), { recursive: true });
  try {
    await fsp.writeFile(leasePath, JSON.stringify({ pid: process.pid, acquiredAt: new Date().toISOString(), serverCode: process.env.KCML_SERVER_CODE }), { flag: "wx", mode: 0o600 });
    leaseHeld = true;
  } catch (error) {
    if (error?.code === "EEXIST") throw new Error("worker_single_active_lease_unavailable");
    throw error;
  }
}

async function releaseLease() {
  if (!leaseHeld) return;
  leaseHeld = false;
  await fsp.rm(leasePath, { force: true }).catch(() => undefined);
}

async function readModeFromDisk() {
  try {
    const payload = JSON.parse(await fsp.readFile(runtimeModePath, "utf8"));
    return typeof payload.mode === "string" ? payload.mode : lifecycleMode;
  } catch {
    return lifecycleMode;
  }
}

async function setMode(nextMode) {
  if (nextMode === lifecycleMode) return;
  lifecycleMode = nextMode;
  if (nextMode === "ACTIVE") {
    await acquireLeaseIfNeeded();
  } else {
    await releaseLease();
  }
  if (nextMode === "DRAINING") {
    readyState = { ...readyState, status: "DRAINING", ready: false, checkedAt: new Date().toISOString() };
  }
  if (nextMode === "STOPPED") {
    readyState = { ...readyState, status: "STOPPED", ready: false, checkedAt: new Date().toISOString() };
  }
}

async function loadModule() {
  if (!moduleRef) moduleRef = await import(handlerModulePath);
  if (typeof moduleRef.invoke !== "function") throw new Error("handler_invoke_missing");
  return moduleRef;
}

function baseContext(extraContext = {}) {
  return Object.freeze({
    ...extraContext,
    logger: createLogger(),
    egress: Object.freeze({ fetch: egressFetch, connectTls }),
    secrets: Object.freeze({ get: resolveSecret }),
    storage: Object.freeze({ dataPath }),
    runtime: runtimeApi()
  });
}

async function startModule() {
  if (started) return;
  await fsp.mkdir(dataPath, { recursive: true });
  const module = await loadModule();
  await setMode(initialLifecycleMode);
  if (runtimeExecutionMode === "LONG_RUNNING" && typeof module.start === "function") {
    await module.start(baseContext());
  }
  started = true;
  if (!readyState.ready) {
    readyState = { status: lifecycleMode === "PREPARE" ? "PREPARED" : "READY", ready: true, dependencySummary: {}, checkedAt: new Date().toISOString(), evidenceDigest: digest({ lifecycleMode, dataPath }) };
  }
}

async function stopModule() {
  if (!started || stopping) return;
  stopping = true;
  const module = await loadModule();
  await setMode("STOPPED");
  if (runtimeExecutionMode === "LONG_RUNNING" && typeof module.stop === "function") {
    await module.stop(baseContext());
  }
  await releaseLease();
}

async function invokeModule(payload) {
  const module = await loadModule();
  const context = baseContext(payload.context ?? {});
  return await Promise.race([
    module.invoke(payload.input, context),
    new Promise((_, reject) => setTimeout(() => reject(new Error("handler_timeout")), handlerTimeoutMs))
  ]);
}

async function refreshModeLoop() {
  const nextMode = await readModeFromDisk();
  if (nextMode !== lifecycleMode) await setMode(nextMode);
}

const server = http.createServer((request, reply) => {
  if (request.method === "GET" && request.url === "/health") {
    response(reply, 200, { status: "alive", serverCode: process.env.KCML_SERVER_CODE, imageDigest: process.env.KCML_IMAGE_DIGEST, executionMode: runtimeExecutionMode });
    return;
  }
  if (request.method === "GET" && request.url === "/ready") {
    response(reply, readyState.ready ? 200 : 503, { ...readyState, lifecycleMode, leaseHeld });
    return;
  }
  if (request.method === "GET" && request.url === "/state") {
    response(reply, 200, {
      lifecycleMode,
      executionMode: runtimeExecutionMode,
      singleActiveWorker,
      leaseHeld,
      dataPath,
      ready: readyState,
      heartbeat: heartbeatPayload,
      reportedState: statePayload,
      lastErrorCode
    });
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
      try {
        const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        const output = await invokeModule(payload);
        const serialized = JSON.stringify(output);
        if (Buffer.byteLength(serialized) > responseMaxBytes) throw new Error("worker_response_too_large");
        response(reply, 200, { output });
      } catch (error) {
        lastErrorCode = error instanceof Error ? error.message : "handler_failed";
        response(reply, 500, { error: { code: lastErrorCode } });
      }
    })();
  });
});

async function main() {
  try {
    await startModule();
    modeWatcher = setInterval(() => {
      void refreshModeLoop().catch((error) => {
        lastErrorCode = error instanceof Error ? error.message : "mode_refresh_failed";
      });
    }, 500).unref();
    try { fs.unlinkSync(socketPath); } catch (error) { if (error?.code !== "ENOENT") throw error; }
    // The wrapper probes the UDS from the host namespace after the container starts.
    // Parent runtime directories stay host-restricted, so a world-accessible socket is acceptable here.
    server.listen(socketPath, () => fs.chmodSync(socketPath, 0o666));
  } catch (error) {
    lastErrorCode = error instanceof Error ? error.message : "bootstrap_failed";
    readyState = { status: "FAILED", ready: false, dependencySummary: { errorCode: lastErrorCode }, checkedAt: new Date().toISOString(), evidenceDigest: null };
    throw error;
  }
}

async function shutdown() {
  clearInterval(modeWatcher);
  await stopModule().catch(() => undefined);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), shutdownGraceSeconds * 1000).unref();
}

process.on("SIGTERM", () => { void shutdown(); });
process.on("SIGINT", () => { void shutdown(); });

await main();
