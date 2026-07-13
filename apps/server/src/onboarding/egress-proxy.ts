import dns from "node:dns/promises";
import fs from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { validateEgressCapability } from "../domain/egress.js";

const REQUEST_LIMIT = 1024 * 1024;
const RESPONSE_LIMIT = 5 * 1024 * 1024;
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const DROP_HEADERS = new Set(["host", "connection", "proxy-authorization", "proxy-connection", "transfer-encoding", "content-length", "upgrade"]);

function forbiddenIpv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a = 0, b = 0] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && (b === 0 || b === 168))
    || (a === 198 && (b === 18 || b === 19));
}

export function isForbiddenAddress(address: string): boolean {
  const kind = net.isIP(address);
  if (kind === 4) return forbiddenIpv4(address);
  if (kind !== 6) return true;
  const lower = address.toLowerCase();
  if (lower.startsWith("::ffff:")) return forbiddenIpv4(lower.slice("::ffff:".length));
  return lower === "::" || lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd")
    || /^fe[89ab]/.test(lower) || lower.startsWith("ff") || lower.startsWith("2001:db8");
}

export function isAllowedDestination(url: URL, allowlist: string[]): boolean {
  if (url.protocol !== "https:" || url.username || url.password) return false;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  const port = url.port || "443";
  if (["localhost", "metadata.google.internal", "metadata.aws.internal"].includes(host) || host.endsWith(".localhost")) return false;
  return allowlist.some((entry) => {
    const [allowedHost, allowedPort = "443"] = entry.toLowerCase().split(":");
    return allowedHost === host && allowedPort === port;
  });
}

async function publicAddresses(hostname: string): Promise<Array<{ address: string; family: number }>> {
  if (net.isIP(hostname)) {
    if (isForbiddenAddress(hostname)) throw new Error("egress_private_address_blocked");
    return [{ address: hostname, family: net.isIP(hostname) }];
  }
  const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((entry) => isForbiddenAddress(entry.address))) throw new Error("egress_private_address_blocked");
  return addresses;
}

function upstream(input: {
  url: URL;
  address: { address: string; family: number };
  method: string;
  headers: Record<string, string>;
  body: Buffer;
}): Promise<{ status: number; headers: Record<string, string | string[]>; body: string }> {
  return new Promise((resolve, reject) => {
    const headers = Object.fromEntries(Object.entries(input.headers).filter(([name]) => !DROP_HEADERS.has(name.toLowerCase())));
    headers.host = input.url.host;
    if (input.body.length) headers["content-length"] = String(input.body.length);
    const request = https.request({
      host: input.address.address,
      family: input.address.family,
      servername: input.url.hostname,
      port: Number(input.url.port || 443),
      path: `${input.url.pathname}${input.url.search}`,
      method: input.method,
      headers,
      timeout: 30_000,
      rejectUnauthorized: true
    }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > RESPONSE_LIMIT) response.destroy(new Error("egress_response_too_large"));
        else chunks.push(Buffer.from(chunk));
      });
      response.on("error", reject);
      response.on("end", () => resolve({
        status: response.statusCode ?? 502,
        headers: Object.fromEntries(Object.entries(response.headers).filter(([name, value]) => !DROP_HEADERS.has(name) && value !== undefined)) as Record<string, string | string[]>,
        body: Buffer.concat(chunks).toString("base64")
      }));
    });
    request.on("timeout", () => request.destroy(new Error("egress_timeout")));
    request.on("error", reject);
    if (input.body.length) request.write(input.body);
    request.end();
  });
}

export async function buildEgressProxy(db: Db, config: AppConfig): Promise<http.Server> {
  return http.createServer((request, reply) => {
    void (async () => {
      if (request.method !== "POST" || request.url !== "/fetch") {
        reply.writeHead(404).end();
        return;
      }
      const authorization = request.headers.authorization;
      if (!authorization?.startsWith("Bearer ")) {
        reply.writeHead(401).end();
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > REQUEST_LIMIT) throw new Error("egress_request_too_large");
        chunks.push(Buffer.from(chunk));
      }
      const payload = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { url?: string; method?: string; headers?: Record<string, string>; body?: string };
      const capability = await validateEgressCapability(db, config, authorization.slice("Bearer ".length));
      const url = new URL(String(payload.url ?? ""));
      if (!isAllowedDestination(url, capability.allowlist)) throw new Error("egress_destination_not_allowed");
      const method = String(payload.method ?? "GET").toUpperCase();
      if (!METHODS.has(method)) throw new Error("egress_method_not_allowed");
      const body = payload.body ? Buffer.from(payload.body, "base64") : Buffer.alloc(0);
      if (body.length > REQUEST_LIMIT) throw new Error("egress_request_too_large");
      const addresses = await publicAddresses(url.hostname);
      const result = await upstream({ url, address: addresses[0]!, method, headers: payload.headers ?? {}, body });
      if (capability.serverId) {
        await db.query(
          `insert into runtime_log_event(server_id,level,event_name,fields,correlation_id)
           values ($1,'info','egress.request',$2,gen_random_uuid())`,
          [capability.serverId, JSON.stringify({ hostname: url.hostname, port: url.port || "443", method, status: result.status })]
        );
      }
      const response = JSON.stringify(result);
      reply.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(response) });
      reply.end(response);
    })().catch((error) => {
      const code = error instanceof SyntaxError ? 400 : error instanceof Error && error.message === "invalid_egress_capability" ? 401 : 403;
      const body = JSON.stringify({ error: code === 401 ? "invalid_egress_capability" : "egress_request_rejected" });
      if (!reply.headersSent) reply.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
      reply.end(body);
    });
  });
}

export async function listenEgressProxy(server: http.Server, socketPath: string): Promise<void> {
  await fs.mkdir(path.dirname(socketPath), { recursive: true, mode: 0o700 });
  await fs.rm(socketPath, { force: true });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  await fs.chmod(socketPath, 0o600);
}
