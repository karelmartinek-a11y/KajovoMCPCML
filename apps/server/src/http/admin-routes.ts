import { randomBytes, randomUUID } from "node:crypto";
import argon2 from "argon2";
import { authenticator } from "otplib";
import type { FastifyInstance, FastifyRequest } from "fastify";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { createKajaCredential, listKajaCredentials } from "../domain/auth.js";
import { listServers } from "../domain/catalog.js";
import { hostOf, sendError } from "./errors.js";

const SESSION_COOKIE = "__Host-kcml_session";
const CSRF_COOKIE = "__Host-kcml_csrf";

async function sessionAccountId(db: Db, request: FastifyRequest): Promise<string | null> {
  const value = request.cookies[SESSION_COOKIE];
  if (!value) return null;
  const hash = await argon2.hash(value, { type: argon2.argon2id, memoryCost: 16384, timeCost: 2, parallelism: 1 });
  const sessions = await db.query(
    "select id, account_id, session_hash from admin_session where expires_at > now() and revoked_at is null"
  );
  for (const row of sessions.rows) {
    if (await argon2.verify(String(row.session_hash), value)) return String(row.account_id);
  }
  void hash;
  return null;
}

function requireCsrf(request: FastifyRequest): boolean {
  const cookie = request.cookies[CSRF_COOKIE];
  const header = request.headers["x-csrf-token"];
  return Boolean(cookie && header && cookie === header);
}

export function registerAdminRoutes(app: FastifyInstance, db: Db, config: AppConfig): void {
  app.get("/api/session", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const accountId = await sessionAccountId(db, request);
    return { authenticated: Boolean(accountId), account: accountId ? "karmar78" : null };
  });

  app.post("/api/login", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const body = request.body as { username?: string; password?: string; totp?: string };
    const result = await db.query("select * from admin_account where username=$1", [body.username ?? ""]);
    if (!result.rowCount || !result.rows[0].password_hash) {
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: body.username ?? null, correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    const account = result.rows[0];
    const passwordOk = await argon2.verify(String(account.password_hash), body.password ?? "");
    const mfaOk = account.mfa_enabled ? authenticator.check(body.totp ?? "", String(account.mfa_secret)) : true;
    if (!passwordOk || !mfaOk) {
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: body.username ?? null, correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    const session = randomBytes(64).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    const sessionHash = await argon2.hash(session, { type: argon2.argon2id, memoryCost: 32768, timeCost: 2, parallelism: 1 });
    await db.query("insert into admin_session(account_id, session_hash, expires_at) values ($1,$2,now()+interval '8 hours')", [account.id, sessionHash]);
    reply.setCookie(SESSION_COOKIE, session, { httpOnly: true, secure: true, sameSite: "strict", path: "/" });
    reply.setCookie(CSRF_COOKIE, csrf, { httpOnly: false, secure: true, sameSite: "strict", path: "/" });
    await appendAudit(db, { eventType: "admin.login.succeeded", actorType: "admin", actorId: account.id, correlationId });
    return { ok: true, csrfToken: csrf };
  });

  app.post("/api/logout", async (request, reply) => {
    const accountId = await sessionAccountId(db, request);
    if (accountId) await db.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [accountId]);
    reply.clearCookie(SESSION_COOKIE, { path: "/" });
    reply.clearCookie(CSRF_COOKIE, { path: "/" });
    return { ok: true };
  });

  app.get("/api/mcp-servers", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const accountId = await sessionAccountId(db, request);
    if (!accountId) return sendError(reply, 401, "unauthorized");
    return { servers: await listServers(db) };
  });

  app.post("/api/kaja", async (request, reply) => {
    const correlationId = randomUUID();
    const accountId = await sessionAccountId(db, request);
    if (!accountId) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const body = request.body as { label?: string };
    const label = (body.label ?? "").trim();
    if (label.length < 1 || label.length > 120) return sendError(reply, 400, "invalid_label", "Label is required and must be at most 120 characters", correlationId);
    return await createKajaCredential(db, accountId, correlationId, label);
  });

  app.get("/api/kaja", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const accountId = await sessionAccountId(db, request);
    if (!accountId) return sendError(reply, 401, "unauthorized");
    return { credentials: await listKajaCredentials(db) };
  });

  app.get("/api/audit", async (request, reply) => {
    const accountId = await sessionAccountId(db, request);
    if (!accountId) return sendError(reply, 401, "unauthorized");
    const result = await db.query("select id,event_type,actor_type,object_type,object_id,correlation_id,created_at from audit_event order by id desc limit 100");
    return { events: result.rows };
  });

  app.get("/health", async (_request, reply) => {
    try {
      await db.query("select 1");
      return { status: "ok", buildId: process.env.GITHUB_SHA ?? "local" };
    } catch {
      return reply.code(503).send({ status: "unready" });
    }
  });
}
