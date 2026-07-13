import fs from "node:fs";
import http from "node:http";

const LOG_BUDGET = 64 * 1024;
const PROXY_RESPONSE_LIMIT = 8 * 1024 * 1024;
const logs = [];
let logBytes = 0;

function normalizedFields(value) {
  try {
    const serialized = JSON.stringify(value ?? {});
    if (serialized.length <= 4096) return JSON.parse(serialized);
    return { truncated: true, value: serialized.slice(0, 4096) };
  } catch {
    return { serializationError: true };
  }
}

function capture(level, values, fields = { source: "stdout" }) {
  if (logBytes >= LOG_BUDGET) return;
  const message = values.map((value) => {
    if (typeof value === "string") return value;
    try { return JSON.stringify(value); } catch { return "[unserializable]"; }
  }).join(" ").slice(0, 4096);
  const frame = { level, message, fields: normalizedFields(fields) };
  logBytes += Buffer.byteLength(JSON.stringify(frame));
  if (logBytes <= LOG_BUDGET) logs.push(frame);
}

console.log = (...values) => capture("info", values);
console.info = (...values) => capture("info", values);
console.warn = (...values) => capture("error", values);
console.error = (...values) => capture("error", values);
process.stdout.write = (chunk) => { capture("info", [String(chunk)]); return true; };
process.stderr.write = (chunk) => { capture("error", [String(chunk)]); return true; };

function egressFetch(url, init = {}) {
  const proxySocket = process.env.KCML_EGRESS_SOCKET_PATH;
  const capability = process.env.KCML_EGRESS_CAPABILITY;
  if (!proxySocket || !capability) throw new Error("egress_not_configured");
  const requestBody = Buffer.from(typeof init.body === "string" ? init.body : init.body == null ? "" : JSON.stringify(init.body));
  const payload = Buffer.from(JSON.stringify({
    url: String(url),
    method: init.method ?? "GET",
    headers: init.headers ?? {},
    body: requestBody.toString("base64")
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
      let size = 0;
      proxyResponse.on("data", (chunk) => {
        size += chunk.length;
        if (size > PROXY_RESPONSE_LIMIT) proxyResponse.destroy(new Error("egress_response_too_large"));
        else chunks.push(Buffer.from(chunk));
      });
      proxyResponse.on("error", reject);
      proxyResponse.on("end", () => {
        if (proxyResponse.statusCode !== 200) { reject(new Error("egress_request_rejected")); return; }
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          const body = Buffer.from(result.body, "base64");
          resolve(Object.freeze({
            status: result.status,
            ok: result.status >= 200 && result.status < 300,
            headers: Object.freeze(result.headers),
            text: async () => body.toString("utf8"),
            json: async () => JSON.parse(body.toString("utf8")),
            bytes: async () => Uint8Array.from(body)
          }));
        } catch { reject(new Error("egress_invalid_response")); }
      });
    });
    request.on("timeout", () => request.destroy(new Error("egress_timeout")));
    request.on("error", reject);
    request.end(payload);
  });
}

function protocolWrite(payload) {
  try {
    fs.writeFileSync(3, JSON.stringify(payload));
  } catch {
    fs.writeFileSync(3, JSON.stringify({ error: { code: "handler_output_not_serializable" }, logs }));
  }
}

const chunks = [];
let inputBytes = 0;
for await (const chunk of process.stdin) {
  inputBytes += chunk.length;
  if (inputBytes > 1024 * 1024 + 64 * 1024) throw new Error("handler_input_too_large");
  chunks.push(Buffer.from(chunk));
}

try {
  const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const module = await import(process.env.KCML_HANDLER_MODULE_PATH ?? "/app/handler/dist/index.js");
  if (typeof module.invoke !== "function") throw new Error("handler_invoke_missing");
  const context = Object.freeze({
    ...payload.context,
    egress: Object.freeze({ fetch: egressFetch }),
    logger: Object.freeze({
      info(fields, message) { capture("info", [String(message ?? "handler.info")], fields); },
      error(fields, message) { capture("error", [String(message ?? "handler.error")], fields); }
    })
  });
  const output = await module.invoke(payload.input, context);
  protocolWrite({ output, logs });
} catch (error) {
  protocolWrite({ error: { code: "handler_failed", message: error instanceof Error ? error.message : "Handler failed" }, logs });
}
