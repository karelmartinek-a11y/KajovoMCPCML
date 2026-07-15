import { randomBytes, randomUUID } from "node:crypto";
import argon2 from "argon2";
import { authenticator } from "otplib";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit, verifyAuditChain } from "../domain/audit.js";
import { raiseAlert } from "../domain/alerts.js";
import {
  createKajaCredential,
  deleteKajaCredential,
  listKajaCredentials,
  listKajaPermissions,
  listManagedServicePermissions,
  replaceManagedServicePermissions,
  replaceKajaPermissions,
  renameKajaCredential,
  revokeKajaCredential
} from "../domain/auth.js";
import { getServerById, listServers } from "../domain/catalog.js";
import { listManagedServices, managedServiceLogs, managedServiceStateView, setManagedServiceApiState } from "../domain/managed-service.js";
import { listOperationalConfig, updateOperationalConfig } from "../domain/operational-config.js";
import { buildReadinessReport } from "../domain/readiness.js";
import { evaluateRecertification } from "../domain/recertification.js";
import { digestCanonicalJson } from "../domain/registration.js";
import { transitionServerState } from "../domain/server-state.js";
import { matchesExpectedResult } from "../onboarding/activation.js";
import { decryptMfaSecret, encryptMfaSecret, hmacToken } from "../security/secrets.js";
import { getHandler } from "../handlers/registry.js";
import { hostOf, sendError } from "./errors.js";

const SESSION_COOKIE = "__Host-kcml_session";
const CSRF_COOKIE = "__Host-kcml_csrf";
const LOGIN_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_BASE_MS = 30 * 1000;
const registrationManifestSchema = z.object({
  testContract: z.object({
    safeInput: z.record(z.unknown()),
    expectedResult: z.unknown()
  })
});
const monitoringProfileSchema = z.object({
  enabled: z.boolean(),
  profile: z.object({
    sloTargets: z.record(z.unknown()),
    probeIntervals: z.record(z.unknown()),
    alertRules: z.array(z.record(z.unknown())),
    runbookRef: z.string().min(1),
    primaryAlertChannel: z.string().min(1),
    backupAlertChannel: z.string().min(1)
  })
});
const adminAccountCreateSchema = z.object({
  username: z.string().trim().min(3).max(120),
  password: z.string().min(12),
  mfaSecret: z.string().trim().min(16).optional().or(z.literal(""))
});
const adminAccountPasswordSchema = z.object({
  nextPassword: z.string().min(12)
});
const adminAccountMfaSchema = z.object({
  enabled: z.boolean(),
  secret: z.string().trim().min(16).optional().or(z.literal(""))
});
const operationalConfigUpdateSchema = z.object({
  value: z.union([z.string(), z.number(), z.boolean()])
});
const alertSuppressSchema = z.object({
  reason: z.string().trim().min(5).max(500),
  until: z.string().datetime({ offset: true })
}).strict();

type AdminSession = {
  accountId: string;
  accountName: string;
  sessionId: string;
};

export async function sessionAccount(db: Db, request: FastifyRequest, config: AppConfig): Promise<AdminSession | null> {
  const value = request.cookies[SESSION_COOKIE];
  if (!value) return null;
  const lookupDigest = hmacToken(value, config.SESSION_SECRET_BASE64);
  const indexed = await db.query(
    `select s.id, s.account_id, s.session_hash, a.username
       from admin_session s
       join admin_account a on a.id=s.account_id
      where s.lookup_digest=$1 and s.expires_at > now() and s.revoked_at is null`,
    [lookupDigest]
  );
  if (indexed.rowCount && await argon2.verify(String(indexed.rows[0].session_hash), value)) {
    return {
      accountId: String(indexed.rows[0].account_id),
      accountName: String(indexed.rows[0].username),
      sessionId: String(indexed.rows[0].id)
    };
  }
  const sessions = await db.query(
    `select s.id, s.account_id, s.session_hash, a.username
       from admin_session s
       join admin_account a on a.id=s.account_id
      where s.lookup_digest is null and s.expires_at > now() and s.revoked_at is null`
  );
  for (const row of sessions.rows) {
    if (await argon2.verify(String(row.session_hash), value)) {
      await db.query("update admin_session set lookup_digest=$2 where id=$1 and lookup_digest is null", [row.id, lookupDigest]);
      return {
        accountId: String(row.account_id),
        accountName: String(row.username),
        sessionId: String(row.id)
      };
    }
  }
  return null;
}

export function requireCsrf(request: FastifyRequest): boolean {
  const cookie = request.cookies[CSRF_COOKIE];
  const header = request.headers["x-csrf-token"];
  return Boolean(cookie && header && cookie === header);
}

function loginAttemptKey(request: FastifyRequest, username: string, config: AppConfig): Buffer {
  return hmacToken(`${request.ip.toLowerCase()}:${username.trim().toLowerCase()}`, config.SESSION_SECRET_BASE64);
}

async function getLoginLockState(db: Db, request: FastifyRequest, username: string, config: AppConfig): Promise<{ blocked: boolean; retryAfterSeconds: number }> {
  const key = loginAttemptKey(request, username, config);
  const result = await db.query(
    `select greatest(0, ceil(extract(epoch from (locked_until-now()))))::int as retry_after_seconds
       from admin_login_throttle
      where attempt_key=$1 and locked_until > now()`,
    [key]
  );
  const retryAfterSeconds = Number(result.rows[0]?.retry_after_seconds ?? 0);
  return { blocked: retryAfterSeconds > 0, retryAfterSeconds };
}

async function recordLoginFailure(db: Db, request: FastifyRequest, username: string, config: AppConfig): Promise<void> {
  const key = loginAttemptKey(request, username, config);
  await tx(db, async (client) => {
    await client.query("select pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'),0))", [key]);
    const result = await client.query(
      "select failure_count,last_failed_at from admin_login_throttle where attempt_key=$1 for update",
      [key]
    );
    const now = Date.now();
    const lastFailedAt = result.rows[0]?.last_failed_at ? new Date(result.rows[0].last_failed_at).getTime() : 0;
    const count = !result.rowCount || lastFailedAt < now - LOGIN_ATTEMPT_WINDOW_MS
      ? 1
      : Number(result.rows[0].failure_count) + 1;
    const lockSteps = Math.max(0, count - 3);
    const lockDurationMs = lockSteps > 0 ? Math.min(24 * 60 * 60 * 1000, LOGIN_LOCK_BASE_MS * 2 ** (lockSteps - 1)) : 0;
    await client.query(
      `insert into admin_login_throttle(attempt_key,failure_count,first_failed_at,last_failed_at,locked_until)
       values ($1,$2,now(),now(),$3)
       on conflict (attempt_key) do update
         set failure_count=excluded.failure_count,
             first_failed_at=case when admin_login_throttle.last_failed_at < now()-interval '15 minutes' then now() else admin_login_throttle.first_failed_at end,
             last_failed_at=now(),
             locked_until=excluded.locked_until,
             updated_at=now()`,
      [key, count, lockDurationMs ? new Date(now + lockDurationMs) : null]
    );
  });
}

async function clearLoginFailures(db: Db, request: FastifyRequest, username: string, config: AppConfig): Promise<void> {
  await db.query("delete from admin_login_throttle where attempt_key=$1", [loginAttemptKey(request, username, config)]);
}

function generateRecoveryCode(): string {
  return `${randomBytes(3).toString("hex")}-${randomBytes(3).toString("hex")}-${randomBytes(3).toString("hex")}`.toUpperCase();
}

async function consumeRecoveryCode(db: Db, accountId: string, code: string): Promise<boolean> {
  if (!code.trim()) return false;
  const result = await db.query(
    "select id, code_hash from admin_recovery_code where account_id=$1 and consumed_at is null order by created_at asc",
    [accountId]
  );
  for (const row of result.rows) {
    if (await argon2.verify(String(row.code_hash), code.trim())) {
      await db.query("update admin_recovery_code set consumed_at=now() where id=$1 and consumed_at is null", [row.id]);
      return true;
    }
  }
  return false;
}

async function requireAdminReauthentication(
  db: Db,
  config: AppConfig,
  accountId: string,
  body: Record<string, unknown>
): Promise<boolean> {
  const password = typeof body.password === "string" ? body.password : "";
  const totp = typeof body.totp === "string" ? body.totp.trim() : "";
  if (!password) return false;
  const account = await db.query("select password_hash,mfa_enabled,mfa_secret from admin_account where id=$1", [accountId]);
  if (!account.rowCount) return false;
  const passwordOk = await argon2.verify(String(account.rows[0].password_hash), password);
  if (!passwordOk) return false;
  if (!account.rows[0].mfa_enabled) return true;
  return authenticator.check(totp, decryptMfaSecret(String(account.rows[0].mfa_secret), config.MFA_ENCRYPTION_KEY_BASE64));
}

async function setServerEnabled(
  db: Db,
  actorId: string,
  correlationId: string,
  serverId: string,
  enabled: boolean
): Promise<{ registrationState: string; operationalState: string }> {
  const current = await db.query(
    `select id,enabled,registration_state,operational_state
       from mcp_server where id=$1`,
    [serverId]
  );
  if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const row = current.rows[0];
  if (Boolean(row.enabled) === enabled) {
    return {
      registrationState: String(row.registration_state),
      operationalState: String(row.operational_state)
    };
  }
  return tx(db, async (client) => {
    const latest = await client.query(
      `select id,enabled,registration_state,operational_state
         from mcp_server where id=$1`,
      [serverId]
    );
    if (!latest.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const currentRow = latest.rows[0];
    if (Boolean(currentRow.enabled) === enabled) {
      return {
        registrationState: String(currentRow.registration_state),
        operationalState: String(currentRow.operational_state)
      };
    }
    const transition = await transitionServerState(client, {
      serverId,
      to: enabled ? "TRIAL" : "REGISTERED_DISABLED",
      actorType: "admin",
      actorId,
      reason: enabled ? "manual_trial_started" : "manual_disable",
      correlationId
    });
    return {
      registrationState: transition.to,
      operationalState: transition.operationalState
    };
  });
}

async function runServerTest(db: Db, serverId: string, correlationId: string, actorId: string): Promise<{
  ok: boolean;
  latencyMs: number;
  output?: unknown;
}> {
  const server = await getServerById(db, serverId);
  if (!server) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const recertification = evaluateRecertification({
    activeRevisionId: server.activeRevisionId,
    validationState: server.registrationValidationState,
    approvedAt: server.reviewApprovedAt,
    reviewDueAt: server.reviewDueAt,
    reviewIntervalDays: server.reviewIntervalDays
  });
  if (!recertification.canActivate) throw Object.assign(new Error(recertification.reason ?? "recertification_blocks_test"), { statusCode: 409 });
  if (!server.monitoringEnabled || !server.monitoringProfileDigest) throw Object.assign(new Error("active_monitoring_profile_required"), { statusCode: 409 });
  const manifestResult = await db.query(
    `select manifest
       from registration_revision
      where server_id=$1
      order by created_at desc
      limit 1`,
    [serverId]
  );
  if (!manifestResult.rowCount) throw Object.assign(new Error("manifest_not_found"), { statusCode: 404 });
  const parsed = registrationManifestSchema.safeParse(manifestResult.rows[0].manifest);
  if (!parsed.success) throw Object.assign(new Error("manifest_test_contract_missing"), { statusCode: 409 });
  const handler = getHandler(server);
  if (!handler) throw Object.assign(new Error("handler_unavailable"), { statusCode: 503 });
  const started = Date.now();
  const output = await Promise.race([
    handler.invoke(parsed.data.testContract.safeInput, {
      correlationId,
      server,
      logger: {
        info: async (fields, message) => {
          await db.query(
            `insert into runtime_log_event(server_id,level,event_name,fields,correlation_id,image_digest)
             values ($1,'info',$2,$3,$4,$5)`,
            [server.id, String(message ?? "admin.test.info"), JSON.stringify(fields), correlationId, server.imageDigest]
          );
        },
        error: async (fields, message) => {
          await db.query(
            `insert into runtime_log_event(server_id,level,event_name,fields,correlation_id,image_digest)
             values ($1,'error',$2,$3,$4,$5)`,
            [server.id, String(message ?? "admin.test.error"), JSON.stringify(fields), correlationId, server.imageDigest]
          );
        }
      }
    }),
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(Object.assign(new Error("handler_timeout"), { statusCode: 504 })), server.timeoutMs);
    })
  ]);
  const latencyMs = Date.now() - started;
  const ok = matchesExpectedResult(output, parsed.data.testContract.expectedResult);
  await appendAudit(db, {
    eventType: ok ? "mcp_server.test.passed" : "mcp_server.test.failed",
    actorType: "admin",
    actorId,
    objectType: "mcp_server",
    objectId: serverId,
    after: { latencyMs, correlationId, ok },
    correlationId
  });
  if (ok && server.registrationState === "TRIAL") {
    await tx(db, async (client) => {
      await transitionServerState(client, {
        serverId,
        to: "ACTIVE",
        actorType: "admin",
        actorId,
        reason: "manual_test_passed",
        correlationId,
        activationEvidence: {
          contractVersion: server.contractVersion,
          handlerVersion: server.handlerVersion,
          manifestDigest: server.manifestDigest,
          artifactDigest: server.artifactDigest,
          latencyMs
        }
      });
    });
  }
  return { ok, latencyMs, output };
}

async function getMonitoringProfile(db: Db, serverId: string): Promise<{ enabled: boolean; profile: Record<string, unknown> }> {
  const result = await db.query("select enabled, profile from monitoring_profile where server_id=$1", [serverId]);
  if (result.rowCount) {
    return {
      enabled: Boolean(result.rows[0].enabled),
      profile: result.rows[0].profile as Record<string, unknown>
    };
  }
  const manifestResult = await db.query(
    `select manifest
       from registration_revision
      where server_id=$1
      order by created_at desc
      limit 1`,
    [serverId]
  );
  if (!manifestResult.rowCount) throw Object.assign(new Error("monitoring_profile_not_found"), { statusCode: 404 });
  const manifest = manifestResult.rows[0].manifest as { monitoringProfile?: Record<string, unknown> };
  return {
    enabled: false,
    profile: manifest.monitoringProfile ?? {
      sloTargets: {},
      probeIntervals: {},
      alertRules: [],
      runbookRef: "",
      primaryAlertChannel: "",
      backupAlertChannel: ""
    }
  };
}

async function saveMonitoringProfile(
  db: Db,
  actorId: string,
  correlationId: string,
  serverId: string,
  input: unknown
): Promise<{ enabled: boolean; profile: Record<string, unknown> }> {
  const parsed = monitoringProfileSchema.parse(input);
  return tx(db, async (client) => {
    const server = await client.query("select id,code,registration_state,active_revision_id from mcp_server where id=$1 for update", [serverId]);
    if (!server.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (["ACTIVE", "TRIAL"].includes(String(server.rows[0].registration_state))) {
      throw Object.assign(new Error("monitoring_revision_required"), { statusCode: 409 });
    }
    await client.query(
      `insert into monitoring_profile(server_id, profile, enabled, registration_revision_id, profile_digest, next_probe_at)
       values ($1, $2, $3, $4, $5, now())
       on conflict (server_id) do update
         set profile=excluded.profile,
             enabled=excluded.enabled,
             registration_revision_id=excluded.registration_revision_id,
             profile_digest=excluded.profile_digest,
             next_probe_at=now(),
             updated_at=now()`,
      [serverId, parsed.profile, parsed.enabled, server.rows[0].active_revision_id, digestCanonicalJson(parsed.profile)]
    );
    await appendAudit(client, {
      eventType: "monitoring_profile.updated",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      after: { code: server.rows[0].code, enabled: parsed.enabled, profile: parsed.profile },
      correlationId
    });
    return parsed;
  });
}

async function listAdminSessions(db: Db, accountId: string, currentSessionId: string): Promise<Array<{
  id: string;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}>> {
  const result = await db.query(
    `select id, created_at, expires_at
       from admin_session
      where account_id=$1 and revoked_at is null and expires_at > now()
      order by created_at desc`,
    [accountId]
  );
  return result.rows.map((row) => ({
    id: String(row.id),
    createdAt: String(row.created_at),
    expiresAt: String(row.expires_at),
    current: String(row.id) === currentSessionId
  }));
}

async function changeAdminPassword(
  db: Db,
  session: AdminSession,
  correlationId: string,
  currentPassword: string,
  nextPassword: string,
  deploymentManagedUsername: string
): Promise<void> {
  const account = await db.query("select username,password_hash from admin_account where id=$1", [session.accountId]);
  if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  if (String(account.rows[0].username) === deploymentManagedUsername) {
    throw Object.assign(new Error("admin_password_deployment_managed"), { statusCode: 409 });
  }
  const currentHash = String(account.rows[0].password_hash ?? "");
  if (!currentHash || !await argon2.verify(currentHash, currentPassword)) {
    throw Object.assign(new Error("invalid_login"), { statusCode: 401 });
  }
  if (nextPassword.length < 12) {
    throw Object.assign(new Error("weak_password"), { statusCode: 400 });
  }
  const nextHash = await argon2.hash(nextPassword, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  await tx(db, async (client) => {
    await client.query("update admin_account set password_hash=$2, password_changed_at=now() where id=$1", [session.accountId, nextHash]);
    await client.query("update admin_session set revoked_at=now() where account_id=$1 and id<>$2 and revoked_at is null", [session.accountId, session.sessionId]);
    await appendAudit(client, {
      eventType: "admin.password.changed",
      actorType: "admin",
      actorId: session.accountId,
      objectType: "admin_account",
      objectId: session.accountId,
      correlationId
    });
  });
}

async function revokeOtherAdminSessions(db: Db, session: AdminSession, correlationId: string): Promise<void> {
  await tx(db, async (client) => {
    await client.query(
      "update admin_session set revoked_at=now() where account_id=$1 and id<>$2 and revoked_at is null",
      [session.accountId, session.sessionId]
    );
    await appendAudit(client, {
      eventType: "admin.sessions.revoked_others",
      actorType: "admin",
      actorId: session.accountId,
      objectType: "admin_account",
      objectId: session.accountId,
      correlationId
    });
  });
}

async function listAdminAccounts(db: Db, currentAccountId: string): Promise<Array<{
  id: string;
  username: string;
  passwordChangedAt: string | null;
  mfaEnabled: boolean;
  createdAt: string;
  activeSessionCount: number;
  recoveryCodeCount: number;
  current: boolean;
}>> {
  const result = await db.query(
    `select a.id, a.username, a.password_changed_at, a.mfa_enabled, a.created_at,
            count(distinct s.id) filter (where s.revoked_at is null and s.expires_at > now())::int as active_session_count,
            count(distinct rc.id) filter (where rc.consumed_at is null)::int as recovery_code_count
       from admin_account a
       left join admin_session s on s.account_id = a.id
       left join admin_recovery_code rc on rc.account_id = a.id
      group by a.id
      order by a.created_at asc`
  );
  return result.rows.map((row) => ({
    id: String(row.id),
    username: String(row.username),
    passwordChangedAt: row.password_changed_at ? String(row.password_changed_at) : null,
    mfaEnabled: Boolean(row.mfa_enabled),
    createdAt: String(row.created_at),
    activeSessionCount: Number(row.active_session_count),
    recoveryCodeCount: Number(row.recovery_code_count),
    current: String(row.id) === currentAccountId
  }));
}

async function createAdminAccount(
  db: Db,
  actorId: string,
  correlationId: string,
  input: unknown,
  encryptionKey: Buffer
): Promise<void> {
  const parsed = adminAccountCreateSchema.parse(input);
  const passwordHash = await argon2.hash(parsed.password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  const storedMfaSecret = parsed.mfaSecret?.trim() ? encryptMfaSecret(parsed.mfaSecret.trim(), encryptionKey) : null;
  await tx(db, async (client) => {
    const inserted = await client.query(
      `insert into admin_account(username, password_hash, password_changed_at, mfa_enabled, mfa_secret)
       values ($1,$2,now(),$3,$4)
       returning id, username`,
      [parsed.username, passwordHash, Boolean(storedMfaSecret), storedMfaSecret]
    );
    await appendAudit(client, {
      eventType: "admin.account.created",
      actorType: "admin",
      actorId,
      objectType: "admin_account",
      objectId: String(inserted.rows[0].id),
      after: { username: inserted.rows[0].username, mfaEnabled: Boolean(storedMfaSecret) },
      correlationId
    });
  });
}

async function setManagedAdminPassword(db: Db, actorId: string, correlationId: string, accountId: string, nextPassword: string, deploymentManagedUsername: string): Promise<void> {
  if (nextPassword.length < 12) throw Object.assign(new Error("weak_password"), { statusCode: 400 });
  const nextHash = await argon2.hash(nextPassword, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  await tx(db, async (client) => {
    const account = await client.query("select username from admin_account where id=$1 for update", [accountId]);
    if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (String(account.rows[0].username) === deploymentManagedUsername) {
      throw Object.assign(new Error("admin_password_deployment_managed"), { statusCode: 409 });
    }
    const updated = await client.query(
      "update admin_account set password_hash=$2, password_changed_at=now() where id=$1 returning username",
      [accountId, nextHash]
    );
    if (!updated.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await client.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [accountId]);
    await appendAudit(client, {
      eventType: "admin.account.password.set",
      actorType: "admin",
      actorId,
      objectType: "admin_account",
      objectId: accountId,
      after: { username: updated.rows[0].username },
      correlationId
    });
  });
}

async function setManagedAdminMfa(db: Db, actorId: string, correlationId: string, accountId: string, input: unknown, encryptionKey: Buffer, deploymentManagedUsername: string): Promise<void> {
  const parsed = adminAccountMfaSchema.parse(input);
  const trimmed = parsed.secret?.trim() ?? "";
  if (parsed.enabled && !trimmed) throw Object.assign(new Error("invalid_mfa_secret"), { statusCode: 400 });
  const storedSecret = parsed.enabled ? encryptMfaSecret(trimmed, encryptionKey) : null;
  await tx(db, async (client) => {
    const account = await client.query("select username from admin_account where id=$1 for update", [accountId]);
    if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (String(account.rows[0].username) === deploymentManagedUsername) {
      throw Object.assign(new Error("admin_mfa_deployment_managed"), { statusCode: 409 });
    }
    const updated = await client.query(
      "update admin_account set mfa_enabled=$2, mfa_secret=$3 where id=$1 returning username",
      [accountId, parsed.enabled, storedSecret]
    );
    if (!updated.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await client.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [accountId]);
    await appendAudit(client, {
      eventType: "admin.account.mfa.updated",
      actorType: "admin",
      actorId,
      objectType: "admin_account",
      objectId: accountId,
      after: { username: updated.rows[0].username, mfaEnabled: parsed.enabled },
      correlationId
    });
  });
}

async function revokeAdminAccountSessions(db: Db, actorId: string, correlationId: string, accountId: string): Promise<void> {
  await tx(db, async (client) => {
    const account = await client.query("select username from admin_account where id=$1", [accountId]);
    if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await client.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [accountId]);
    await appendAudit(client, {
      eventType: "admin.account.sessions.revoked",
      actorType: "admin",
      actorId,
      objectType: "admin_account",
      objectId: accountId,
      after: { username: account.rows[0].username },
      correlationId
    });
  });
}

async function rotateAdminRecoveryCodes(db: Db, actorId: string, correlationId: string, accountId: string): Promise<{ recoveryCodes: string[] }> {
  const recoveryCodes = Array.from({ length: 8 }, generateRecoveryCode);
  const recoveryHashes = await Promise.all(recoveryCodes.map((code) => argon2.hash(code, { type: argon2.argon2id, memoryCost: 32768, timeCost: 2, parallelism: 1 })));
  await tx(db, async (client) => {
    const account = await client.query("select username from admin_account where id=$1", [accountId]);
    if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await client.query("update admin_recovery_code set consumed_at=coalesce(consumed_at, now()) where account_id=$1", [accountId]);
    for (const hash of recoveryHashes) {
      await client.query("insert into admin_recovery_code(account_id, code_hash) values ($1,$2)", [accountId, hash]);
    }
    await appendAudit(client, {
      eventType: "admin.account.recovery.rotated",
      actorType: "admin",
      actorId,
      objectType: "admin_account",
      objectId: accountId,
      after: { username: account.rows[0].username, recoveryCodeCount: recoveryCodes.length },
      correlationId
    });
  });
  return { recoveryCodes };
}

export function registerAdminRoutes(app: FastifyInstance, db: Db, config: AppConfig): void {
  const dummyPasswordHash = argon2.hash(randomBytes(32), { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  app.get("/api/session", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    return {
      authenticated: Boolean(session),
      account: session?.accountName ?? null,
      bootstrapRequired: false
    };
  });

  app.get("/api/admin-security", {
    config: { rateLimit: { max: 60, timeWindow: "1 minute", groupId: "admin-security-read" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    const account = await db.query(
      "select username, password_changed_at from admin_account where id=$1",
      [session.accountId]
    );
    const sessions = await listAdminSessions(db, session.accountId, session.sessionId);
    return {
      username: String(account.rows[0].username),
      passwordChangedAt: account.rows[0].password_changed_at ? String(account.rows[0].password_changed_at) : null,
      sessions
    };
  });

  app.get("/api/admin-accounts", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    return { accounts: await listAdminAccounts(db, session.accountId) };
  });

  app.get("/api/operational-config", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    try {
      return { settings: await listOperationalConfig(db, config) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.put("/api/operational-config/:key", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { key } = request.params as { key: string };
    try {
      const parsed = operationalConfigUpdateSchema.parse(request.body);
      await updateOperationalConfig(db, session.accountId, correlationId, key, parsed.value);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/login", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute", groupId: "admin-login" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const body = request.body as { username?: string; password?: string; totp?: string; recoveryCode?: string };
    const throttle = await getLoginLockState(db, request, body.username ?? "", config);
    if (throttle.blocked) {
      reply.header("retry-after", String(throttle.retryAfterSeconds));
      await appendAudit(db, { eventType: "admin.login.rate_limited", actorType: "admin", actorId: body.username ?? null, correlationId });
      return sendError(reply, 429, "login_rate_limited", "Too many login attempts", correlationId);
    }
    const result = await db.query("select * from admin_account where username=$1", [body.username ?? ""]);
    const account = result.rows[0] as Record<string, unknown> | undefined;
    const passwordHash = typeof account?.password_hash === "string" ? account.password_hash : await dummyPasswordHash;
    const passwordOk = await argon2.verify(passwordHash, body.password ?? "");
    if (!account || !account.password_hash) {
      await recordLoginFailure(db, request, body.username ?? "", config);
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: body.username ?? null, correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    const decryptedMfaSecret = account.mfa_enabled && account.mfa_secret
      ? decryptMfaSecret(typeof account.mfa_secret === "string" ? account.mfa_secret : "", config.MFA_ENCRYPTION_KEY_BASE64)
      : null;
    const totpOk = passwordOk && account.mfa_enabled ? authenticator.check(body.totp ?? "", decryptedMfaSecret ?? "") : !account.mfa_enabled;
    const recoveryOk = passwordOk && account.mfa_enabled && !totpOk
      ? await consumeRecoveryCode(db, String(account.id), body.recoveryCode ?? body.totp ?? "")
      : false;
    const mfaOk = account.mfa_enabled ? totpOk || recoveryOk : true;
    if (!passwordOk || !mfaOk) {
      await recordLoginFailure(db, request, body.username ?? "", config);
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: body.username ?? null, correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    await clearLoginFailures(db, request, body.username ?? "", config);
    const session = randomBytes(64).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    const sessionHash = await argon2.hash(session, { type: argon2.argon2id, memoryCost: 32768, timeCost: 2, parallelism: 1 });
    const lookupDigest = hmacToken(session, config.SESSION_SECRET_BASE64);
    await db.query(
      "insert into admin_session(account_id, session_hash, lookup_digest, expires_at) values ($1,$2,$3,now()+interval '8 hours')",
      [account.id, sessionHash, lookupDigest]
    );
    reply.setCookie(SESSION_COOKIE, session, { httpOnly: true, secure: true, sameSite: "strict", path: "/" });
    reply.setCookie(CSRF_COOKIE, csrf, { httpOnly: false, secure: true, sameSite: "strict", path: "/" });
    await appendAudit(db, { eventType: "admin.login.succeeded", actorType: "admin", actorId: String(account.id), correlationId });
    if (recoveryOk) {
      await appendAudit(db, { eventType: "admin.login.recovery_code_used", actorType: "admin", actorId: String(account.id), objectType: "admin_account", objectId: String(account.id), correlationId });
    }
    return { ok: true, csrfToken: csrf };
  });

  app.post("/api/logout", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute", groupId: "admin-session-write" } }
  }, async (request, reply) => {
    const session = await sessionAccount(db, request, config);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed");
    if (session) await db.query("update admin_session set revoked_at=now() where id=$1 and revoked_at is null", [session.sessionId]);
    reply.clearCookie(SESSION_COOKIE, { path: "/" });
    reply.clearCookie(CSRF_COOKIE, { path: "/" });
    return { ok: true };
  });

  app.post("/api/admin-password", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const body = request.body as { currentPassword?: unknown; nextPassword?: unknown };
    try {
      await changeAdminPassword(
        db,
        session,
        correlationId,
        typeof body.currentPassword === "string" ? body.currentPassword : "",
        typeof body.nextPassword === "string" ? body.nextPassword : "",
        config.ADMIN_BOOTSTRAP_USERNAME
      );
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/admin-sessions/revoke-others", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    await revokeOtherAdminSessions(db, session, correlationId);
    return { ok: true };
  });

  app.post("/api/admin-accounts", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    try {
      await createAdminAccount(db, session.accountId, correlationId, request.body, config.MFA_ENCRYPTION_KEY_BASE64);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/admin-accounts/:id/password", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = adminAccountPasswordSchema.parse(request.body);
      await setManagedAdminPassword(db, session.accountId, correlationId, id, parsed.nextPassword, config.ADMIN_BOOTSTRAP_USERNAME);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.put("/api/admin-accounts/:id/mfa", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      await setManagedAdminMfa(db, session.accountId, correlationId, id, request.body, config.MFA_ENCRYPTION_KEY_BASE64, config.ADMIN_BOOTSTRAP_USERNAME);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/admin-accounts/:id/sessions/revoke", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      await revokeAdminAccountSessions(db, session.accountId, correlationId, id);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/admin-accounts/:id/recovery/rotate", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      return await rotateAdminRecoveryCodes(db, session.accountId, correlationId, id);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/mcp-servers", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const servers = await listServers(db);
    return {
      servers: servers.map((server) => ({
        ...server,
        recertification: evaluateRecertification({
          activeRevisionId: server.activeRevisionId,
          validationState: server.registrationValidationState,
          approvedAt: server.reviewApprovedAt,
          reviewDueAt: server.reviewDueAt,
          reviewIntervalDays: server.reviewIntervalDays
        })
      }))
    };
  });

  app.get("/api/managed-services", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    return { services: await listManagedServices(db) };
  });

  app.get("/api/managed-services/:id/state", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      return await managedServiceStateView(db, id);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/managed-services/:id/logs", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    const { id } = request.params as { id: string };
    const query = request.query as { before?: string; limit?: string };
    try {
      return {
        logs: await managedServiceLogs(db, {
          managedServiceId: id,
          before: typeof query.before === "string" ? query.before : null,
          limit: Number(query.limit ?? 100)
        })
      };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/managed-services/:id/api::disable", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute", groupId: "managed-service-api-state-write" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    const expected = Number(String(request.headers["if-match"] ?? "").replaceAll('"', ""));
    if (reason.length < 5 || !Number.isSafeInteger(expected)) return sendError(reply, 400, "invalid_disable_request", undefined, correlationId);
    if (!await requireAdminReauthentication(db, config, session.accountId, body)) return sendError(reply, 403, "reauthentication_failed", undefined, correlationId);
    try {
      return await setManagedServiceApiState(db, {
        managedServiceId: id,
        actorId: session.accountId,
        actorType: "admin",
        nextState: "DISABLED",
        reason,
        expectedLockVersion: expected,
        correlationId
      });
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/managed-services/:id/api::enable", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute", groupId: "managed-service-api-state-write" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    const expected = Number(String(request.headers["if-match"] ?? "").replaceAll('"', ""));
    if (reason.length < 5 || !Number.isSafeInteger(expected)) return sendError(reply, 400, "invalid_enable_request", undefined, correlationId);
    if (!await requireAdminReauthentication(db, config, session.accountId, body)) return sendError(reply, 403, "reauthentication_failed", undefined, correlationId);
    try {
      return await setManagedServiceApiState(db, {
        managedServiceId: id,
        actorId: session.accountId,
        actorType: "admin",
        nextState: "ENABLED",
        reason,
        expectedLockVersion: expected,
        correlationId
      });
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/mcp-servers/:id/enabled", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    const body = request.body as { enabled?: unknown };
    if (typeof body.enabled !== "boolean") return sendError(reply, 400, "invalid_enabled", undefined, correlationId);
    try {
      return await setServerEnabled(db, session.accountId, correlationId, id, body.enabled);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/mcp-servers/:id/test", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      return await runServerTest(db, id, correlationId, session.accountId);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/mcp-servers/:id/monitoring-profile", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      return await getMonitoringProfile(db, id);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.put("/api/mcp-servers/:id/monitoring-profile", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      return await saveMonitoringProfile(db, session.accountId, correlationId, id, request.body);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/kaja", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const body = request.body as { label?: string; expiresAt?: string | null };
    const label = (body.label ?? "").trim();
    if (label.length < 1 || label.length > 120) return sendError(reply, 400, "invalid_label", "Label is required and must be at most 120 characters", correlationId);
    const expiresAt = body.expiresAt ? new Date(body.expiresAt) : null;
    if (expiresAt && (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now())) {
      return sendError(reply, 400, "invalid_expiration", "Expiration must be in the future", correlationId);
    }
    return await createKajaCredential(db, session.accountId, correlationId, label, expiresAt ? expiresAt.toISOString() : null);
  });

  app.get("/api/kaja", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    return { credentials: await listKajaCredentials(db) };
  });

  app.patch("/api/kaja/:id/label", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    const body = request.body as { label?: unknown };
    const label = typeof body.label === "string" ? body.label.trim() : "";
    if (label.length < 1 || label.length > 120) {
      return sendError(reply, 400, "invalid_label", "Label is required and must be at most 120 characters", correlationId);
    }
    try {
      await renameKajaCredential(db, session.accountId, correlationId, id, label);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/kaja/:id/revoke", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      await revokeKajaCredential(db, session.accountId, correlationId, id);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/kaja/:id/delete", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      await deleteKajaCredential(db, session.accountId, correlationId, id);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/kaja/:id/permissions", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const { id } = request.params as { id: string };
    try {
      return { permissions: await listKajaPermissions(db, id) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed");
    }
  });

  app.put("/api/kaja/:id/permissions", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    const body = request.body as { serverIds?: unknown; permissions?: unknown };
    const permissions = Array.isArray(body.permissions)
      ? body.permissions
      : Array.isArray(body.serverIds)
        ? body.serverIds.map((serverId) => ({ serverId, accessLevel: "EXECUTE" }))
        : null;
    if (!permissions || permissions.some((permission) => {
      if (typeof permission !== "object" || permission === null) return true;
      const item = permission as { serverId?: unknown; accessLevel?: unknown };
      return typeof item.serverId !== "string" || String(item.accessLevel) !== "EXECUTE";
    })) {
      return sendError(reply, 400, "invalid_permissions", "permissions must include serverId and accessLevel", correlationId);
    }
    try {
      await replaceKajaPermissions(db, session.accountId, correlationId, id, permissions as Array<{ serverId: string; accessLevel: "EXECUTE" }>);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/kaja/:id/managed-service-permissions", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const { id } = request.params as { id: string };
    try {
      return { permissions: await listManagedServicePermissions(db, id) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed");
    }
  });

  app.put("/api/kaja/:id/managed-service-permissions", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    const body = request.body as { permissions?: Array<{ managedServiceId?: unknown; scopeNames?: unknown }> };
    const permissions = Array.isArray(body.permissions)
      ? body.permissions.map((permission) => ({
        managedServiceId: typeof permission.managedServiceId === "string" ? permission.managedServiceId : "",
        scopeNames: Array.isArray(permission.scopeNames) ? permission.scopeNames.filter((scopeName): scopeName is string => typeof scopeName === "string") : []
      }))
      : null;
    if (!permissions || permissions.some((permission) => !permission.managedServiceId)) {
      return sendError(reply, 400, "invalid_permissions", "permissions must include managedServiceId and scopeNames", correlationId);
    }
    try {
      await replaceManagedServicePermissions(db, session.accountId, correlationId, id, permissions);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/audit", {
    config: { rateLimit: { max: 60, timeWindow: "1 minute", groupId: "admin-audit-read" } }
  }, async (request, reply) => {
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const query = request.query as {
      cursor?: string;
      eventType?: string;
      objectId?: string;
      correlationId?: string;
    };
    const clauses = ["1=1"];
    const values: unknown[] = [];
    if (query.cursor) {
      values.push(Number(query.cursor));
      clauses.push(`id < $${values.length}`);
    }
    if (query.eventType && query.eventType !== "all") {
      values.push(query.eventType);
      clauses.push(`event_type = $${values.length}`);
    }
    if (query.objectId) {
      values.push(query.objectId);
      clauses.push(`object_id = $${values.length}`);
    }
    if (query.correlationId) {
      values.push(query.correlationId);
      clauses.push(`correlation_id::text = $${values.length}`);
    }
    const result = await db.query(
      `select id,event_type,actor_type,actor_id,object_type,object_id,correlation_id,created_at,before_json,after_json
         from audit_event
        where ${clauses.join(" and ")}
        order by id desc
        limit 101`,
      values
    );
    const events = result.rows.slice(0, 100);
    return {
      events,
      nextCursor: result.rows.length > 100 ? String(events[events.length - 1]?.id ?? "") : null
    };
  });

  app.get("/api/audit/integrity", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute", groupId: "admin-audit-integrity" } }
  }, async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    return verifyAuditChain(db);
  });

  app.get("/api/audit/export", {
    config: { rateLimit: { max: 2, timeWindow: "1 minute", groupId: "admin-audit-export" } }
  }, async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const result = await db.query(
      `select id,event_type,actor_type,actor_id,object_type,object_id,correlation_id,created_at,before_json,after_json,
              encode(prev_hash, 'hex') as prev_hash_hex,
              encode(event_hash, 'hex') as event_hash_hex
         from audit_event
        order by id asc`
    );
    reply.header("content-type", "application/json; charset=utf-8");
    reply.header("content-disposition", "attachment; filename=\"audit-export.json\"");
    return { exportedAt: new Date().toISOString(), events: result.rows };
  });

  app.get("/api/monitoring-probes", {
    config: { rateLimit: { max: 60, timeWindow: "1 minute", groupId: "admin-monitoring-read" } }
  }, async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const result = await db.query(`
      select mpr.id,mpr.server_id,ms.code,ms.hostname,mpr.probe_type,mpr.status,mpr.latency_ms,
             mpr.evidence,mpr.correlation_id,mpr.checked_at
        from monitoring_probe_result mpr
        join mcp_server ms on ms.id=mpr.server_id
       where mpr.checked_at>now()-interval '30 days'
       order by mpr.checked_at desc limit 1000
    `);
    return { probes: result.rows };
  });

  app.get("/api/monitoring-overview", {
    config: { rateLimit: { max: 60, timeWindow: "1 minute", groupId: "admin-monitoring-read" } }
  }, async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const [alerts, deliveries, history, heartbeat] = await Promise.all([
      db.query(
        `select alert.*,server.code,server.hostname
           from operational_alert alert
           left join mcp_server server on server.id=alert.server_id
          order by case alert.status when 'OPEN' then 1 when 'ACKNOWLEDGED' then 2 when 'SUPPRESSED' then 3 else 4 end,
                   case alert.severity when 'CRITICAL' then 1 when 'HIGH' then 2 else 3 end,
                   alert.last_seen_at desc
          limit 500`
      ),
      db.query(
        `select delivery.*,alert.severity,alert.alert_type,server.code
           from alert_webhook_delivery delivery
           join operational_alert alert on alert.id=delivery.alert_id
           left join mcp_server server on server.id=alert.server_id
          order by delivery.created_at desc limit 500`
      ),
      db.query(
        `select history.*,server.code
           from server_state_history history
           join mcp_server server on server.id=history.server_id
          order by history.recorded_at desc limit 500`
      ),
      db.query("select * from monitoring_scheduler_heartbeat where singleton=true")
    ]);
    return { alerts: alerts.rows, deliveries: deliveries.rows, stateHistory: history.rows, scheduler: heartbeat.rows[0] ?? null };
  });

  app.post("/api/alerts/test", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const result = await tx(db, async (client) => raiseAlert(client, {
      serverId: null,
      severity: "WARNING",
      alertType: `webhook.test.${correlationId}`,
      title: "KCML webhook test",
      detail: { requestedBy: session.accountName, buildId: config.BUILD_ID },
      correlationId
    }));
    return { ok: true, alertId: result.id };
  });

  app.post("/api/alerts/:id/acknowledge", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    await tx(db, async (client) => {
      const result = await client.query(
        "update operational_alert set status='ACKNOWLEDGED',acknowledged_by=$2,acknowledged_at=now() where id=$1 and status='OPEN' returning id",
        [id, session.accountId]
      );
      if (!result.rowCount) throw Object.assign(new Error("alert_not_open"), { statusCode: 409 });
      await appendAudit(client, { eventType: "alert.acknowledged", actorType: "admin", actorId: session.accountId, objectType: "operational_alert", objectId: id, correlationId });
    });
    return { ok: true };
  });

  app.post("/api/alerts/:id/suppress", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const body = alertSuppressSchema.parse(request.body);
      if (new Date(body.until).getTime() <= Date.now()) throw Object.assign(new Error("suppression_must_be_future"), { statusCode: 400 });
      await tx(db, async (client) => {
        const result = await client.query(
          `update operational_alert
              set status='SUPPRESSED',suppression_reason=$2,suppression_owner=$3,suppressed_until=$4
            where id=$1 and status in ('OPEN','ACKNOWLEDGED') returning id`,
          [id, body.reason, session.accountId, body.until]
        );
        if (!result.rowCount) throw Object.assign(new Error("alert_not_suppressible"), { statusCode: 409 });
        await appendAudit(client, { eventType: "alert.suppressed", actorType: "admin", actorId: session.accountId, objectType: "operational_alert", objectId: id, after: body, correlationId });
      });
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "invalid_suppression", undefined, correlationId);
    }
  });

  app.post("/api/alert-deliveries/:id/retry", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    await tx(db, async (client) => {
      const result = await client.query(
        "update alert_webhook_delivery set state='RETRY',next_attempt_at=now(),last_error=null,updated_at=now() where id=$1 and state in ('RETRY','DEAD_LETTER') returning alert_id",
        [id]
      );
      if (!result.rowCount) throw Object.assign(new Error("delivery_not_retryable"), { statusCode: 409 });
      await appendAudit(client, { eventType: "alert.delivery.manual_retry", actorType: "admin", actorId: session.accountId, objectType: "operational_alert", objectId: String(result.rows[0].alert_id), after: { deliveryId: id }, correlationId });
    });
    return { ok: true };
  });

  app.get("/api/readiness", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    try {
      const report = await buildReadinessReport(db, config);
      return reply.code(report.ready ? 200 : 503).send(report);
    } catch {
      return reply.code(503).send({ ready: false, buildId: config.BUILD_ID, checkedAt: new Date().toISOString() });
    }
  });

  app.get("/health", { config: { rateLimit: false } }, async (_request, reply) => {
    try {
      const report = await buildReadinessReport(db, config);
      return reply.code(report.ready ? 200 : 503).send({ status: report.ready ? "ok" : "unready" });
    } catch {
      return reply.code(503).send({ status: "unready" });
    }
  });
}
