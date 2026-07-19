import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AppServerConfig } from "../config.js";
import type { Db } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import {
  authenticateClientSecret,
  authenticateSecretIntegrationToken,
  resolveSecret,
  secretRequestDigest,
  type SecretPrincipal
} from "../domain/secret-manager.js";
import { hostOf, sendError } from "./errors.js";

const resolveSchema = z.object({
  name: z.string().trim().min(3).max(128)
}).strict();

function secretHost(config: Pick<AppServerConfig, "PUBLIC_BASE_DOMAIN">): string {
  return `secrets.${config.PUBLIC_BASE_DOMAIN}`;
}

function bearer(request: FastifyRequest): string | null {
  const authorization = request.headers.authorization;
  return authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : null;
}

function requestedCredentialKind(request: FastifyRequest): "client_secret" | "integration_token" | "missing" {
  if (basicCredential(request)) return "client_secret";
  if (bearer(request)) return "integration_token";
  return "missing";
}

export function parseSecretApiBasicAuthorization(authorization: string | undefined): { clientId: string; clientSecret: string } | null {
  authorization ??= "";
  if (!authorization.startsWith("Basic ")) return null;
  const encoded = authorization.slice("Basic ".length).trim();
  if (!encoded) return null;
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const sep = decoded.indexOf(":");
  if (sep < 1) return null;
  return {
    clientId: decoded.slice(0, sep),
    clientSecret: decoded.slice(sep + 1)
  };
}

function basicCredential(request: FastifyRequest): { clientId: string; clientSecret: string } | null {
  return parseSecretApiBasicAuthorization(request.headers.authorization);
}

async function principalFor(db: Db, config: AppServerConfig, request: FastifyRequest): Promise<SecretPrincipal | null> {
  const basic = basicCredential(request);
  if (basic) return authenticateClientSecret(db, config, basic.clientId, basic.clientSecret);
  const token = bearer(request);
  if (token) return authenticateSecretIntegrationToken(db, token, config);
  return null;
}

export function isSecretApiHostname(host: string, config: Pick<AppServerConfig, "PUBLIC_BASE_DOMAIN">): boolean {
  return host === secretHost(config);
}

export function registerSecretApiRoutes(app: FastifyInstance, db: Db, config: AppServerConfig): void {
  app.get("/.well-known/kcml-secret-api", async (request, reply) => {
    const correlationId = randomUUID();
    if (!isSecretApiHostname(hostOf(request.headers.host), config)) return sendError(reply, 404, "not_found", undefined, correlationId);
    return reply.header("cache-control", "no-store").send({
      issuer: `https://${secretHost(config)}`,
      resolveEndpoint: `https://${secretHost(config)}/v1/secrets/resolve`,
      auth: ["client_secret_basic", "integration_token_bearer"],
      catalogVersion: "2026.07.22"
    });
  });

  app.get("/health", async (request, reply) => {
    if (!isSecretApiHostname(hostOf(request.headers.host), config)) return;
    return reply.header("cache-control", "no-store").send({ ok: true, service: "secret-api" });
  });

  app.post("/v1/secrets/resolve", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute", groupId: "secret-api-resolve" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (!isSecretApiHostname(hostOf(request.headers.host), config)) return sendError(reply, 404, "not_found", undefined, correlationId);
    const contentType = request.headers["content-type"] ?? "";
    if (!String(contentType).includes("application/json")) return sendError(reply, 415, "unsupported_media_type", undefined, correlationId);
    try {
      const parsed = resolveSchema.parse(request.body);
      const principal = await principalFor(db, config, request);
      if (!principal) {
        await appendAudit(db, {
          eventType: "secret.auth.denied",
          actorType: "secret_api",
          actorId: null,
          objectType: "secret",
          objectId: null,
          after: { stableName: parsed.name, credentialKind: requestedCredentialKind(request), result: "invalid_client" },
          correlationId
        });
        return sendError(reply, 401, "invalid_client", undefined, correlationId);
      }
      const idempotencyKey = String(request.headers["idempotency-key"] ?? "").trim();
      const requestDigest = secretRequestDigest({ name: parsed.name });
      if (idempotencyKey) {
        const identity = `${principal.kind}:${principal.id ?? principal.publicId}`;
        const existing = await db.query(
          `select request_digest from secret_resolve_idempotency
            where principal_kind=$1 and principal_identity=$2 and idempotency_key=$3 and expires_at > now()`,
          [principal.kind, identity, idempotencyKey]
        );
        if (existing.rowCount && String(existing.rows[0].request_digest) !== requestDigest) {
          return sendError(reply, 409, "idempotency_key_reused", undefined, correlationId);
        }
      }
      const resolved = await resolveSecret(db, config, principal, parsed.name, correlationId);
      if (idempotencyKey) {
        const identity = `${principal.kind}:${principal.id ?? principal.publicId}`;
        await db.query(
          `insert into secret_resolve_idempotency(principal_kind, principal_identity, idempotency_key, request_digest, response_digest, expires_at)
           values ($1,$2,$3,$4,$5,now()+interval '10 minutes')
           on conflict (principal_kind, principal_identity, idempotency_key) do update
             set request_digest=excluded.request_digest,response_digest=excluded.response_digest,expires_at=excluded.expires_at`,
          [principal.kind, identity, idempotencyKey, requestDigest, secretRequestDigest({ name: resolved.name, version: resolved.version, fingerprint: resolved.fingerprint })]
        );
      }
      return reply
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .send(resolved);
    } catch (error) {
      if (error instanceof z.ZodError) return sendError(reply, 400, "invalid_request", undefined, correlationId);
      const statusCode = Number((error as { statusCode?: number }).statusCode ?? 500);
      const code = error instanceof Error ? error.message : "operation_failed";
      const publicCode = code === "secret_unavailable" ? "secret_unavailable" : code;
      return sendError(reply, statusCode, publicCode, undefined, correlationId);
    }
  });
}
