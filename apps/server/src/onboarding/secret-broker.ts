import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { randomUUID } from "node:crypto";
import type { SecretBrokerConfig } from "../config.js";
import type { Db } from "../db.js";
import { authenticatePrincipalAccessToken, resolveSecret } from "../domain/secret-manager.js";

const REQUEST_LIMIT = 16 * 1024;

export async function buildSecretBroker(db: Db, config: SecretBrokerConfig): Promise<http.Server> {
  return http.createServer((request, reply) => {
    void (async () => {
      if (request.method !== "POST" || request.url !== "/resolve") {
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
        if (size > REQUEST_LIMIT) throw new Error("secret_request_too_large");
        chunks.push(Buffer.from(chunk));
      }
      const payload = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { name?: string };
      const stableName = String(payload.name ?? "").trim();
      if (!stableName) throw new Error("invalid_secret_request");
      const principal = await authenticatePrincipalAccessToken(db, authorization.slice("Bearer ".length), config);
      if (!principal) {
        reply.writeHead(401, { "content-type": "application/json" });
        reply.end(JSON.stringify({ error: "invalid_client" }));
        return;
      }
      const resolved = await resolveSecret(db, config, principal, stableName, randomUUID());
      const body = JSON.stringify(resolved);
      reply.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(body), "cache-control": "no-store" });
      reply.end(body);
    })().catch((error) => {
      const code = error instanceof SyntaxError ? 400 : Number((error as { statusCode?: number })?.statusCode ?? 403);
      const body = JSON.stringify({ error: error instanceof Error ? error.message : "secret_request_rejected" });
      if (!reply.headersSent) reply.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
      reply.end(body);
    });
  });
}

export async function listenSecretBroker(server: http.Server, socketPath: string): Promise<void> {
  await fs.mkdir(path.dirname(socketPath), { recursive: true, mode: 0o700 });
  await fs.rm(socketPath, { force: true });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  await fs.chmod(socketPath, 0o600);
}
