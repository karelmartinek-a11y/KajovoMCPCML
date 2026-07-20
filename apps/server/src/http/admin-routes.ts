import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { Readable } from "node:stream";
import argon2 from "argon2";
import { authenticator } from "otplib";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AdminReauthConfig, AdminRoutesConfig, AdminSessionConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit, verifyAuditChain } from "../domain/audit.js";
import { buildAuditWhere, encodeAuditCursor, parseAuditQuery, sanitizeAuditRow } from "../domain/audit-view.js";
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
import {
  acquireServerExecutionLease,
  compileSchemaValidator,
  invokeWithDeadline,
  releaseServerExecutionLease,
  serializeWithinLimit
} from "../domain/mcp-policy.js";
import { monitoringPolicySchema, monitoringProfileUpdateSchema } from "../domain/monitoring-policy.js";
import { deleteRegisteredServer } from "../domain/onboarding.js";
import { listOperationalConfig, rotateMfaEncryptionKey, updateDomainConfiguration, updateOperationalConfig } from "../domain/operational-config.js";
import { buildReadinessReport } from "../domain/readiness.js";
import { evaluateRecertification } from "../domain/recertification.js";
import { digestCanonicalJson } from "../domain/registration.js";
import {
  auditRevealUiEvent,
  consumeRevealGrant,
  createRevealGrant,
  createSecret,
  deleteSecret,
  grantSecret,
  listSecretGrants,
  listSecrets,
  listSecretVersions,
  revokeSecretGrant,
  restoreSecret,
  rotateSecret,
  setSecretStatus
} from "../domain/secret-manager.js";
import { setServerEnabled, transitionServerState } from "../domain/server-state.js";
import { matchesExpectedResult } from "../onboarding/activation.js";
import { decryptMfaSecret, encryptMfaSecret, hmacToken, redact } from "../security/secrets.js";
import { getHandler } from "../handlers/registry.js";
import { hostOf, sendError } from "./errors.js";

const SESSION_COOKIE = "__Host-kcml_session";
const CSRF_COOKIE = "__Host-kcml_csrf";
const LOGIN_CHALLENGE_COOKIE = "__Host-kcml_login_challenge";
const TRUSTED_DEVICE_COOKIE = "__Host-kcml_trusted_device";
const LOGIN_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_BASE_MS = 30 * 1000;
const RECENT_REAUTH_MS = 10 * 60 * 1000;
const LOGIN_CHALLENGE_MS = 10 * 60 * 1000;
const MFA_TRUST_WINDOW_MS = 48 * 60 * 60 * 1000;
const MFA_ENROLLMENT_MS = 10 * 60 * 1000;
type LoginThrottleScope = "ip" | "account" | "ip_account";
const ADMIN_ROLES = ["OWNER", "ADMIN", "AUDITOR"] as const;
type AdminRole = typeof ADMIN_ROLES[number];
const registrationManifestSchema = z.object({
  testContract: z.object({
    safeInput: z.record(z.unknown()),
    expectedResult: z.unknown(),
    executionMode: z.enum(["READ_ONLY", "SANDBOX", "COMPENSATED"]).optional()
  })
});
const adminAccountCreateSchema = z.object({
  username: z.string().trim().min(3).max(120),
  password: z.string().min(12),
  role: z.enum(ADMIN_ROLES).default("ADMIN")
});
const adminAccountUpdateSchema = z.object({
  role: z.enum(ADMIN_ROLES).optional(),
  active: z.boolean().optional()
}).strict().refine((value) => value.role !== undefined || value.active !== undefined, "admin_update_empty");
const adminBootstrapSchema = z.object({
  username: z.string().trim().min(3).max(120),
  password: z.string().min(12),
  bootstrapSecret: z.string().optional()
}).strict();
const adminAccountPasswordSchema = z.object({
  nextPassword: z.string().min(12)
});
const adminAccountMfaSchema = z.object({
  enabled: z.boolean(),
  secret: z.string().trim().min(16).optional().or(z.literal(""))
});
const adminMfaEnrollmentVerifySchema = z.object({
  enrollmentToken: z.string().min(32),
  code: z.string().trim().min(6).max(32)
}).strict();

type SignedAdminTokenPayload = {
  purpose: "login_challenge" | "trusted_device" | "mfa_enrollment";
  accountId: string;
  sessionEpoch: string;
  expiresAt: string;
  uaDigest: string;
  secret?: string;
  username?: string;
};
const operationalConfigUpdateSchema = z.object({
  value: z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]),
  expectedVersion: z.number().int().min(0)
}).strict();
const secretCreateSchema = z.object({
  stableName: z.string().trim().min(3).max(128),
  displayName: z.string().trim().min(1).max(160),
  description: z.string().max(2000).optional(),
  value: z.string().min(1).max(64 * 1024),
  ownerKind: z.enum(["PLATFORM", "COMPONENT", "MANAGED_SERVICE", "KAJA"]).optional(),
  ownerId: z.string().uuid().nullable().optional()
}).strict();
const secretRotateSchema = z.object({
  value: z.string().min(1).max(64 * 1024),
  expectedVersion: z.number().int().min(0)
}).strict();
const secretDeleteSchema = z.object({
  expectedVersion: z.number().int().min(0)
}).strict();
const secretStatusSchema = z.object({
  expectedVersion: z.number().int().min(0),
  status: z.enum(["ACTIVE", "DISABLED"])
}).strict();
const secretGrantSchema = z.object({
  principalKind: z.enum(["KAJA", "COMPONENT", "INTEGRATION_TOKEN"]),
  principalId: z.string().uuid().nullable().optional(),
  principalPublicId: z.string().trim().min(1).max(160).nullable().optional()
}).strict();
const secretRevealGrantSchema = z.object({
  password: z.string().min(1),
  totp: z.string().trim().min(6).max(32),
  purpose: z.string().trim().min(3).max(240).default("admin reveal")
}).strict();
const secretRevealConsumeSchema = z.object({
  revealGrantId: z.string().uuid()
}).strict();
const secretRevealUiEventSchema = z.object({
  revealGrantId: z.string().uuid().nullable().optional(),
  eventType: z.enum(["copy", "cut", "contextmenu", "blur", "visibility_hidden", "expired", "cleared"])
}).strict();
const domainConfigUpdateSchema = z.object({
  baseDomain: z.string(),
  expectedVersions: z.record(z.string(), z.number().int().min(0))
}).strict();
const alertSuppressSchema = z.object({
  reason: z.string().trim().min(5).max(500),
  until: z.string().datetime({ offset: true })
}).strict();

type AdminSession = {
  accountId: string;
  accountName: string;
  sessionId: string;
  role: AdminRole;
  reauthenticatedAt: string;
};

const requestSessionCache = new WeakMap<FastifyRequest, Promise<AdminSession | null>>();

function isDeploymentManagedAdmin(username: string, config: Pick<AdminRoutesConfig, "ADMIN_BOOTSTRAP_USERNAME">): boolean {
  return username === config.ADMIN_BOOTSTRAP_USERNAME;
}

type LoginThrottleKey = {
  scope: LoginThrottleScope;
  value: Buffer;
};

function normalizedLoginUsername(username: string): string {
  return username.trim().toLowerCase();
}

function canonicalAdminPassword(value: string): string {
  let end = value.length;
  while (end > 0 && (value.charCodeAt(end - 1) === 10 || value.charCodeAt(end - 1) === 13)) {
    end -= 1;
  }
  return end === value.length ? value : value.slice(0, end);
}

function loginFailureAuditAfter(reason: "account_not_found" | "account_inactive" | "password_hash_missing" | "password_mismatch", body: { username?: string; password?: string }, loginUsername: string): Record<string, unknown> {
  const password = typeof body.password === "string" ? body.password : "";
  const canonicalPassword = canonicalAdminPassword(password);
  return {
    reason,
    usernamePresent: typeof body.username === "string" && body.username.length > 0,
    proofPresent: password.length > 0,
    proofLineEndingNormalized: password !== canonicalPassword,
    proofLength: password.length,
    canonicalProofLength: canonicalPassword.length,
    usernameNormalized: typeof body.username === "string" && body.username !== loginUsername
  };
}

function userAgentDigest(request: FastifyRequest, key: Buffer): string {
  const userAgent = String(request.headers["user-agent"] ?? "");
  return hmacToken(`ua:${userAgent}`, key).toString("base64url");
}

function signAdminToken(payload: SignedAdminTokenPayload, key: Buffer): string {
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", key).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifyAdminToken(token: string | undefined, key: Buffer): SignedAdminTokenPayload | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const encoded = parts[0];
  const provided = parts[1];
  if (!encoded || !provided) return null;
  const expected = createHmac("sha256", key).update(encoded).digest("base64url");
  const providedBuffer = Buffer.from(provided);
  const expectedBuffer = Buffer.from(expected);
  if (providedBuffer.length !== expectedBuffer.length || !timingSafeEqual(providedBuffer, expectedBuffer)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as SignedAdminTokenPayload;
    if (!payload?.purpose || !payload.accountId || !payload.sessionEpoch || !payload.expiresAt || !payload.uaDigest) return null;
    if (new Date(payload.expiresAt).getTime() <= Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function issueLoginChallenge(reply: FastifyReply, request: FastifyRequest, key: Buffer, account: { id: string; session_epoch: unknown; username: unknown }): { expiresAt: string } {
  const expiresAt = new Date(Date.now() + LOGIN_CHALLENGE_MS).toISOString();
  const token = signAdminToken({
    purpose: "login_challenge",
    accountId: String(account.id),
    sessionEpoch: String(account.session_epoch),
    expiresAt,
    uaDigest: userAgentDigest(request, key),
    username: String(account.username)
  }, key);
  reply.setCookie(LOGIN_CHALLENGE_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: Math.floor(LOGIN_CHALLENGE_MS / 1000)
  });
  return { expiresAt };
}

function clearLoginChallenge(reply: FastifyReply): void {
  reply.clearCookie(LOGIN_CHALLENGE_COOKIE, { path: "/" });
}

function setTrustedDeviceCookie(reply: FastifyReply, request: FastifyRequest, key: Buffer, account: { id: string; session_epoch: unknown }): { expiresAt: string } {
  const expiresAt = new Date(Date.now() + MFA_TRUST_WINDOW_MS).toISOString();
  const token = signAdminToken({
    purpose: "trusted_device",
    accountId: String(account.id),
    sessionEpoch: String(account.session_epoch),
    expiresAt,
    uaDigest: userAgentDigest(request, key)
  }, key);
  reply.setCookie(TRUSTED_DEVICE_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: Math.floor(MFA_TRUST_WINDOW_MS / 1000)
  });
  return { expiresAt };
}

function clearTrustedDeviceCookie(reply: FastifyReply): void {
  reply.clearCookie(TRUSTED_DEVICE_COOKIE, { path: "/" });
}

function trustedDeviceMatches(request: FastifyRequest, key: Buffer, account: { id: string; session_epoch: unknown }): boolean {
  const payload = verifyAdminToken(request.cookies[TRUSTED_DEVICE_COOKIE], key);
  return Boolean(
    payload
    && payload.purpose === "trusted_device"
    && payload.accountId === String(account.id)
    && payload.sessionEpoch === String(account.session_epoch)
    && payload.uaDigest === userAgentDigest(request, key)
  );
}

async function createAdminSession(
  db: Db,
  reply: FastifyReply,
  request: FastifyRequest,
  config: AdminSessionConfig,
  account: { id: unknown; session_epoch: unknown },
  trustDevice = false
): Promise<{ csrfToken: string; trustedDeviceExpiresAt: string | null }> {
  const session = randomBytes(64).toString("base64url");
  const csrf = randomBytes(32).toString("base64url");
  const sessionHash = await argon2.hash(session, { type: argon2.argon2id, memoryCost: 32768, timeCost: 2, parallelism: 1 });
  const lookupDigest = hmacToken(session, config.SESSION_SECRET_BASE64);
  await tx(db, async (client) => {
    await client.query(
      "update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null and expires_at > now()",
      [account.id]
    );
    await client.query(
      `insert into admin_session(account_id,session_hash,lookup_digest,expires_at,reauthenticated_at,session_epoch)
       values ($1,$2,$3,now()+interval '8 hours',now(),$4)`,
      [account.id, sessionHash, lookupDigest, account.session_epoch]
    );
  });
  reply.setCookie(SESSION_COOKIE, session, { httpOnly: true, secure: true, sameSite: "strict", path: "/" });
  reply.setCookie(CSRF_COOKIE, csrf, { httpOnly: false, secure: true, sameSite: "strict", path: "/" });
  const trustedDeviceExpiresAt = trustDevice ? setTrustedDeviceCookie(reply, request, config.SESSION_SECRET_BASE64, {
    id: String(account.id),
    session_epoch: String(account.session_epoch)
  }).expiresAt : null;
  return { csrfToken: csrf, trustedDeviceExpiresAt };
}

function loginThrottleKeys(request: FastifyRequest, username: string, config: AdminSessionConfig): LoginThrottleKey[] {
  const normalizedUsername = normalizedLoginUsername(username);
  const normalizedIp = request.ip.trim().toLowerCase();
  return [
    { scope: "ip", value: hmacToken(`ip:${normalizedIp}`, config.SESSION_SECRET_BASE64) },
    { scope: "account", value: hmacToken(`account:${normalizedUsername}`, config.SESSION_SECRET_BASE64) },
    { scope: "ip_account", value: hmacToken(`ip_account:${normalizedIp}:${normalizedUsername}`, config.SESSION_SECRET_BASE64) }
  ];
}

export async function sessionAccount(db: Db, request: FastifyRequest, config: AdminSessionConfig): Promise<AdminSession | null> {
  const cached = requestSessionCache.get(request);
  if (cached) return cached;
  const lookup = findSessionAccount(db, request, config);
  requestSessionCache.set(request, lookup);
  return lookup;
}

async function findSessionAccount(db: Db, request: FastifyRequest, config: AdminSessionConfig): Promise<AdminSession | null> {
  const value = request.cookies[SESSION_COOKIE];
  if (!value) return null;
  const lookupDigest = hmacToken(value, config.SESSION_SECRET_BASE64);
  const indexed = await db.query(
    `select s.id, s.account_id, s.session_hash, s.reauthenticated_at, a.username, a.role
       from admin_session s
       join admin_account a on a.id=s.account_id
      where s.lookup_digest=$1 and s.expires_at > now() and s.revoked_at is null and a.active is true
        and s.session_epoch=a.session_epoch`,
    [lookupDigest]
  );
  if (indexed.rowCount && await argon2.verify(String(indexed.rows[0].session_hash), value)) {
    return {
      accountId: String(indexed.rows[0].account_id),
      accountName: String(indexed.rows[0].username),
      sessionId: String(indexed.rows[0].id),
      role: ADMIN_ROLES.includes(indexed.rows[0].role as AdminRole) ? indexed.rows[0].role as AdminRole : "OWNER",
      reauthenticatedAt: indexed.rows[0].reauthenticated_at
        ? new Date(indexed.rows[0].reauthenticated_at as string | Date).toISOString()
        : new Date().toISOString()
    };
  }
  return null;
}

export function requireCsrf(request: FastifyRequest): boolean {
  const cookie = request.cookies[CSRF_COOKIE];
  const header = request.headers["x-csrf-token"];
  return Boolean(cookie && header && cookie === header);
}

export async function getLoginLockState(db: Db, request: FastifyRequest, username: string, config: AdminSessionConfig): Promise<{ blocked: boolean; retryAfterSeconds: number }> {
  const keys = loginThrottleKeys(request, username, config);
  const result = await db.query(
    `select max(greatest(0, ceil(extract(epoch from (locked_until-now()))))::int) as retry_after_seconds
       from admin_login_throttle
      where attempt_key = any($1::bytea[])
        and locked_until > now()`,
    [keys.map((key) => key.value)]
  );
  const retryAfterSeconds = Number(result.rows[0]?.retry_after_seconds ?? 0);
  return { blocked: retryAfterSeconds > 0, retryAfterSeconds };
}

export async function recordLoginFailure(db: Db, request: FastifyRequest, username: string, config: AdminSessionConfig): Promise<void> {
  await tx(db, async (client) => {
    for (const key of loginThrottleKeys(request, username, config)) {
      await client.query("select pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'),0))", [key.value]);
      const result = await client.query(
        "select failure_count,last_failed_at from admin_login_throttle where attempt_key=$1 for update",
        [key.value]
      );
      const now = Date.now();
      const lastFailedAt = result.rows[0]?.last_failed_at ? new Date(result.rows[0].last_failed_at).getTime() : 0;
      const count = !result.rowCount || lastFailedAt < now - LOGIN_ATTEMPT_WINDOW_MS
        ? 1
        : Number(result.rows[0].failure_count) + 1;
      const threshold = key.scope === "ip" ? 8 : key.scope === "account" ? 5 : 3;
      const lockSteps = Math.max(0, count - threshold);
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
        [key.value, count, lockDurationMs ? new Date(now + lockDurationMs) : null]
      );
    }
  });
}

export async function clearLoginFailures(db: Db, request: FastifyRequest, username: string, config: AdminSessionConfig): Promise<void> {
  const keys = loginThrottleKeys(request, username, config).filter((key) => key.scope !== "ip");
  await db.query("delete from admin_login_throttle where attempt_key = any($1::bytea[])", [keys.map((key) => key.value)]);
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

function buildMfaEnrollmentToken(
  request: FastifyRequest,
  config: AdminSessionConfig,
  account: { id: string; sessionEpoch: string; username: string },
  secret: string
): { enrollmentToken: string; expiresAt: string; otpauthUri: string } {
  const expiresAt = new Date(Date.now() + MFA_ENROLLMENT_MS).toISOString();
  const issuer = "KCML";
  return {
    enrollmentToken: signAdminToken({
      purpose: "mfa_enrollment",
      accountId: account.id,
      sessionEpoch: account.sessionEpoch,
      expiresAt,
      uaDigest: userAgentDigest(request, config.SESSION_SECRET_BASE64),
      secret,
      username: account.username
    }, config.SESSION_SECRET_BASE64),
    expiresAt,
    otpauthUri: authenticator.keyuri(account.username, issuer, secret)
  };
}

async function requireAdminReauthentication(
  db: Db,
  config: AdminReauthConfig,
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
  return authenticator.check(totp, decryptMfaSecret(String(account.rows[0].mfa_secret), config.MFA_ENCRYPTION_KEY_BASE64, {
    allowLegacyPlaintext: config.MFA_ALLOW_PLAINTEXT_LEGACY,
    subjectId: accountId,
    purpose: "admin_totp"
  }));
}

async function runServerTest(db: Db, serverId: string, correlationId: string, actorId: string): Promise<{
  ok: boolean;
  status: "PASSED" | "EXPECTED_RESULT_MISMATCH" | "FAILED";
  correlationId: string;
  latencyMs: number;
  activeRevisionId: string;
  manifestDigest: string;
  checkpoints: Array<{
    key: "contract" | "input_validation" | "runtime_lease" | "handler_run" | "output_validation" | "result_match" | "activation";
    label: string;
    description: string;
    status: "PENDING" | "PASSED" | "FAILED" | "SKIPPED";
    detail?: string;
    durationMs?: number;
  }>;
  errorCode?: string;
  errorMessage?: string;
  failedCheckpointKey?: "contract" | "input_validation" | "runtime_lease" | "handler_run" | "output_validation" | "result_match" | "activation";
  output?: unknown;
}> {
  const checkpoints: Array<{
    key: "contract" | "input_validation" | "runtime_lease" | "handler_run" | "output_validation" | "result_match" | "activation";
    label: string;
    description: string;
    status: "PENDING" | "PASSED" | "FAILED" | "SKIPPED";
    detail?: string;
    durationMs?: number;
  }> = [
    { key: "contract", label: "Připravuji testovací kontrakt", description: "Načítám aktivní revizi, kontrakt a bezpečnostní režim testu.", status: "PENDING" },
    { key: "input_validation", label: "Validuji bezpečný vstup", description: "Ověřuji safe input proti registrovanému vstupnímu schématu.", status: "PENDING" },
    { key: "runtime_lease", label: "Rezervuji runtime", description: "Získávám execution lease, aby test běžel izolovaně a bez kolize.", status: "PENDING" },
    { key: "handler_run", label: "Spouštím handler", description: "Volám registrovaný handler a sleduji timeout i runtime logy.", status: "PENDING" },
    { key: "output_validation", label: "Validuji výstup", description: "Kontroluji limit velikosti odpovědi a výstupní schema.", status: "PENDING" },
    { key: "result_match", label: "Porovnávám expected result", description: "Vyhodnocuji, zda výsledek odpovídá zaregistrovanému očekávání.", status: "PENDING" },
    { key: "activation", label: "Uzavírám výsledek", description: "Zapisuji audit a případně povyšuji server z TRIAL do ACTIVE.", status: "PENDING" }
  ];
  const markCheckpoint = (
    key: typeof checkpoints[number]["key"],
    status: typeof checkpoints[number]["status"],
    detail?: string,
    durationMs?: number
  ): void => {
    const checkpoint = checkpoints.find((item) => item.key === key);
    if (!checkpoint) return;
    checkpoint.status = status;
    if (detail) checkpoint.detail = detail;
    if (durationMs !== undefined) checkpoint.durationMs = durationMs;
  };
  const server = await getServerById(db, serverId);
  if (!server) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  if (!server.enabled || !["TRIAL", "ACTIVE"].includes(server.registrationState)) {
    throw Object.assign(new Error("server_disabled"), { statusCode: 409 });
  }
  const recertification = evaluateRecertification({
    activeRevisionId: server.activeRevisionId,
    validationState: server.registrationValidationState,
    approvedAt: server.reviewApprovedAt,
    reviewDueAt: server.reviewDueAt,
    reviewIntervalDays: server.reviewIntervalDays
  });
  if (!recertification.canActivate) throw Object.assign(new Error(recertification.reason ?? "recertification_blocks_test"), { statusCode: 409 });
  if (!server.monitoringEnabled || !server.monitoringProfileDigest) throw Object.assign(new Error("active_monitoring_profile_required"), { statusCode: 409 });
  await appendAudit(db, {
    eventType: "mcp_server.test.started",
    actorType: "admin",
    actorId,
    objectType: "mcp_server",
    objectId: serverId,
    after: { activeRevisionId: server.activeRevisionId },
    correlationId
  });
  const started = Date.now();
  let leaseId = "";
  let failedCheckpointKey: typeof checkpoints[number]["key"] | undefined;
  try {
    let checkpointStarted = Date.now();
    const manifestResult = await db.query(
    `select manifest
       from registration_revision
      where id=$2
        and server_id=$1
        and active=true`,
    [serverId, server.activeRevisionId]
  );
    if (!manifestResult.rowCount) throw Object.assign(new Error("manifest_not_found"), { statusCode: 404 });
    const parsed = registrationManifestSchema.safeParse(manifestResult.rows[0].manifest);
    if (!parsed.success) throw Object.assign(new Error("manifest_test_contract_missing"), { statusCode: 409 });
    if (server.effectClass !== "READ_ONLY" && !["SANDBOX", "COMPENSATED"].includes(parsed.data.testContract.executionMode ?? "")) {
      throw Object.assign(new Error("unsafe_write_test_contract"), { statusCode: 409 });
    }
    if (parsed.data.testContract.executionMode === "COMPENSATED" && server.shutdownPolicy !== "COMPENSATE") {
      throw Object.assign(new Error("test_compensation_policy_mismatch"), { statusCode: 409 });
    }
    markCheckpoint("contract", "PASSED", `Revize ${server.activeRevisionId} je připravena pro safe test.`, Date.now() - checkpointStarted);
    checkpointStarted = Date.now();
    const validateInput = compileSchemaValidator(server.inputSchema);
    if (!validateInput(parsed.data.testContract.safeInput)) {
      throw Object.assign(new Error("manifest_safe_input_schema_failed"), { statusCode: 409, issues: validateInput.errors ?? [] });
    }
    markCheckpoint("input_validation", "PASSED", "Safe input odpovídá vstupnímu schématu.", Date.now() - checkpointStarted);
    checkpointStarted = Date.now();
    const handler = getHandler(server);
    if (!handler) throw Object.assign(new Error("handler_unavailable"), { statusCode: 503 });
    leaseId = await acquireServerExecutionLease(db, server);
    markCheckpoint("runtime_lease", "PASSED", "Runtime lease byl úspěšně přidělen.", Date.now() - checkpointStarted);
    checkpointStarted = Date.now();
    const output = await invokeWithDeadline(server.timeoutMs, server.shutdownPolicy, (signal) => handler.invoke(parsed.data.testContract.safeInput, {
        correlationId,
        server,
        signal,
        logger: {
          info: async (fields, message) => {
            const safeFields = redact(fields);
            const safeMessage = String(redact(message ?? "admin.test.info")).slice(0, 160);
            await db.query(
              `insert into runtime_log_event(server_id,level,event_name,fields,correlation_id,image_digest)
               values ($1,'info',$2,$3,$4,$5)`,
              [server.id, safeMessage, JSON.stringify(safeFields), correlationId, server.imageDigest]
            );
          },
          error: async (fields, message) => {
            const safeFields = redact(fields);
            const safeMessage = String(redact(message ?? "admin.test.error")).slice(0, 160);
            await db.query(
              `insert into runtime_log_event(server_id,level,event_name,fields,correlation_id,image_digest)
               values ($1,'error',$2,$3,$4,$5)`,
              [server.id, safeMessage, JSON.stringify(safeFields), correlationId, server.imageDigest]
            );
          }
        }
      }));
    markCheckpoint("handler_run", "PASSED", "Handler dokončil běh bez timeoutu.", Date.now() - checkpointStarted);
    checkpointStarted = Date.now();
    serializeWithinLimit(output, server.responseMaxBytes, "worker_response_too_large");
    const validateOutput = compileSchemaValidator(server.outputSchema);
    if (!validateOutput(output)) {
      throw Object.assign(new Error("output_schema_failed"), { statusCode: 409, issues: validateOutput.errors ?? [] });
    }
    markCheckpoint("output_validation", "PASSED", "Výstup odpovídá registrovanému výstupnímu schématu.", Date.now() - checkpointStarted);
    checkpointStarted = Date.now();
    const latencyMs = Date.now() - started;
    const ok = matchesExpectedResult(output, parsed.data.testContract.expectedResult);
    if (!ok) {
      markCheckpoint("result_match", "FAILED", "Výstup neodpovídá zaregistrovanému expected result.", Date.now() - checkpointStarted);
      failedCheckpointKey = "result_match";
    } else {
      markCheckpoint("result_match", "PASSED", "Výsledek odpovídá očekávanému kontraktu.", Date.now() - checkpointStarted);
    }
    checkpointStarted = Date.now();
    await appendAudit(db, {
      eventType: ok ? "mcp_server.test.passed" : "mcp_server.test.failed",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      after: { latencyMs, correlationId, ok, activeRevisionId: server.activeRevisionId },
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
      markCheckpoint("activation", "PASSED", "Server byl po úspěšném testu povýšen z TRIAL do ACTIVE.", Date.now() - checkpointStarted);
    } else if (ok) {
      markCheckpoint("activation", "SKIPPED", "Server už byl v ACTIVE; aktivace se znovu neprovádí.");
    } else {
      markCheckpoint("activation", "SKIPPED", "Aktivace se neprovádí, protože expected result nesouhlasí.");
    }
    return {
      ok,
      status: ok ? "PASSED" : "EXPECTED_RESULT_MISMATCH",
      correlationId,
      latencyMs,
      activeRevisionId: server.activeRevisionId!,
      manifestDigest: server.manifestDigest,
      checkpoints,
      failedCheckpointKey,
      output: redact(output)
    };
  } catch (error) {
    const latencyMs = Date.now() - started;
    const errorCode = error instanceof Error ? error.message : "test_failed";
    failedCheckpointKey = failedCheckpointKey
      ?? (["manifest_not_found", "manifest_test_contract_missing", "unsafe_write_test_contract", "test_compensation_policy_mismatch"].includes(errorCode)
        ? "contract"
        : errorCode === "manifest_safe_input_schema_failed"
          ? "input_validation"
          : ["handler_unavailable", "concurrency_limit_exceeded"].includes(errorCode)
            ? "runtime_lease"
            : ["handler_timeout"].includes(errorCode)
              ? "handler_run"
              : ["output_schema_failed", "worker_response_too_large"].includes(errorCode)
                ? "output_validation"
                : "handler_run");
    markCheckpoint(failedCheckpointKey, "FAILED", errorCode, Math.max(1, latencyMs));
    for (const checkpoint of checkpoints) {
      if (checkpoint.status === "PENDING" && checkpoint.key !== failedCheckpointKey) checkpoint.status = "SKIPPED";
    }
    await appendAudit(db, {
      eventType: "mcp_server.test.failed",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      after: {
        latencyMs,
        correlationId,
        ok: false,
        activeRevisionId: server.activeRevisionId,
        error: errorCode
      },
      correlationId
    });
    return {
      ok: false,
      status: "FAILED",
      correlationId,
      latencyMs,
      activeRevisionId: server.activeRevisionId!,
      manifestDigest: server.manifestDigest,
      checkpoints,
      errorCode,
      errorMessage: errorCode,
      failedCheckpointKey
    };
  } finally {
    if (leaseId) await releaseServerExecutionLease(db, leaseId);
  }
}

async function getMonitoringProfile(db: Db, serverId: string): Promise<{ enabled: boolean; version: number; profile: Record<string, unknown> }> {
  const result = await db.query("select enabled,profile,version from monitoring_profile where server_id=$1", [serverId]);
  if (result.rowCount) {
    const profile = monitoringPolicySchema.safeParse(result.rows[0].profile);
    return {
      enabled: Boolean(result.rows[0].enabled),
      version: Number(result.rows[0].version ?? 0),
      profile: (profile.success ? profile.data : result.rows[0].profile) as Record<string, unknown>
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
    version: 0,
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
): Promise<{ enabled: boolean; version: number; profile: Record<string, unknown> }> {
  const parsed = monitoringProfileUpdateSchema.parse(input);
  return tx(db, async (client) => {
    const server = await client.query("select id,code,registration_state,active_revision_id from mcp_server where id=$1 for update", [serverId]);
    if (!server.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (["ACTIVE", "TRIAL"].includes(String(server.rows[0].registration_state))) {
      throw Object.assign(new Error("monitoring_revision_required"), { statusCode: 409 });
    }
    const current = await client.query("select enabled,profile,version from monitoring_profile where server_id=$1 for update", [serverId]);
    const currentVersion = current.rowCount ? Number(current.rows[0].version ?? 0) : 0;
    if (currentVersion !== parsed.expectedVersion) throw Object.assign(new Error("monitoring_profile_version_conflict"), { statusCode: 409 });
    await client.query(
      `insert into monitoring_profile(server_id,profile,enabled,registration_revision_id,profile_digest,next_probe_at,version)
       values ($1,$2,$3,$4,$5,now(),1)
       on conflict (server_id) do update
         set profile=excluded.profile,
             enabled=excluded.enabled,
             registration_revision_id=excluded.registration_revision_id,
             profile_digest=excluded.profile_digest,
             next_probe_at=now(),
             version=monitoring_profile.version+1,
             updated_at=now()`,
      [serverId, parsed.profile, parsed.enabled, server.rows[0].active_revision_id, digestCanonicalJson(parsed.profile)]
    );
    await appendAudit(client, {
      eventType: "monitoring_profile.updated",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      before: current.rowCount ? { enabled: current.rows[0].enabled, profile: current.rows[0].profile, version: currentVersion } : null,
      after: { code: server.rows[0].code, enabled: parsed.enabled, profile: parsed.profile, version: currentVersion + 1 },
      correlationId
    });
    return { enabled: parsed.enabled, profile: parsed.profile, version: currentVersion + 1 };
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
  const nextSessionEpoch = randomUUID();
  await tx(db, async (client) => {
    await client.query("update admin_account set password_hash=$2, password_changed_at=now(), session_epoch=$3 where id=$1", [session.accountId, nextHash, nextSessionEpoch]);
    await client.query("update admin_session set revoked_at=now() where account_id=$1 and id<>$2 and revoked_at is null", [session.accountId, session.sessionId]);
    await client.query("update admin_session set session_epoch=$2 where id=$1 and revoked_at is null", [session.sessionId, nextSessionEpoch]);
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

async function revokeOwnAdminSession(db: Db, session: AdminSession, targetSessionId: string, correlationId: string): Promise<boolean> {
  return tx(db, async (client) => {
    const revoked = await client.query(
      `update admin_session set revoked_at=now()
        where id=$1 and account_id=$2 and revoked_at is null
        returning id`,
      [targetSessionId, session.accountId]
    );
    if (!revoked.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await appendAudit(client, {
      eventType: "admin.session.revoked",
      actorType: "admin",
      actorId: session.accountId,
      objectType: "admin_session",
      objectId: targetSessionId,
      after: { current: targetSessionId === session.sessionId },
      correlationId
    });
    return targetSessionId === session.sessionId;
  });
}

async function revokeAllAdminSessions(db: Db, session: AdminSession, correlationId: string): Promise<void> {
  await tx(db, async (client) => {
    await client.query("update admin_account set session_epoch=gen_random_uuid(),updated_at=now() where id=$1", [session.accountId]);
    await client.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [session.accountId]);
    await appendAudit(client, {
      eventType: "admin.sessions.revoked_all",
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
  deploymentManaged: boolean;
  passwordChangedAt: string | null;
  mfaEnabled: boolean;
  createdAt: string;
  activeSessionCount: number;
  recoveryCodeCount: number;
  current: boolean;
  role: AdminRole;
  active: boolean;
}>> {
  const result = await db.query(
    `select a.id, a.username, a.password_changed_at, a.mfa_enabled, a.created_at, a.role, a.active,
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
    deploymentManaged: false,
    passwordChangedAt: row.password_changed_at ? String(row.password_changed_at) : null,
    mfaEnabled: Boolean(row.mfa_enabled),
    createdAt: String(row.created_at),
    activeSessionCount: Number(row.active_session_count),
    recoveryCodeCount: Number(row.recovery_code_count),
    current: String(row.id) === currentAccountId,
    role: ADMIN_ROLES.includes(row.role as AdminRole) ? row.role as AdminRole : "ADMIN",
    active: Boolean(row.active)
  }));
}

async function createAdminAccount(
  db: Db,
  actorId: string,
  correlationId: string,
  input: unknown
): Promise<void> {
  const parsed = adminAccountCreateSchema.parse(input);
  const passwordHash = await argon2.hash(parsed.password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  await tx(db, async (client) => {
    const inserted = await client.query(
      `insert into admin_account(username,password_hash,password_changed_at,mfa_enabled,mfa_secret,role,active,activated_at)
       values ($1,$2,now(),$3,$4,$5,true,now())
       returning id,username,role`,
      [parsed.username, passwordHash, false, null, parsed.role]
    );
    await appendAudit(client, {
      eventType: "admin.account.created",
      actorType: "admin",
      actorId,
      objectType: "admin_account",
      objectId: String(inserted.rows[0].id),
      after: { username: inserted.rows[0].username, role: inserted.rows[0].role, active: true, mfaEnabled: false },
      correlationId
    });
  });
}

async function setManagedAdminPassword(db: Db, actorId: string, correlationId: string, accountId: string, nextPassword: string, deploymentManagedUsername: string): Promise<void> {
  if (nextPassword.length < 12) throw Object.assign(new Error("weak_password"), { statusCode: 400 });
  const nextHash = await argon2.hash(nextPassword, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  const nextSessionEpoch = randomUUID();
  await tx(db, async (client) => {
    const account = await client.query("select username from admin_account where id=$1 for update", [accountId]);
    if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (String(account.rows[0].username) === deploymentManagedUsername) {
      throw Object.assign(new Error("admin_password_deployment_managed"), { statusCode: 409 });
    }
    const updated = await client.query(
      "update admin_account set password_hash=$2, password_changed_at=now(), session_epoch=$3 where id=$1 returning username",
      [accountId, nextHash, nextSessionEpoch]
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
  const nextSessionEpoch = randomUUID();
  await tx(db, async (client) => {
    const account = await client.query("select username from admin_account where id=$1 for update", [accountId]);
    if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (String(account.rows[0].username) === deploymentManagedUsername) {
      throw Object.assign(new Error("admin_mfa_deployment_managed"), { statusCode: 409 });
    }
    const storedSecret = parsed.enabled
      ? encryptMfaSecret(trimmed, encryptionKey, { subjectId: accountId, purpose: "admin_totp" })
      : null;
    const updated = await client.query(
      "update admin_account set mfa_enabled=$2, mfa_secret=$3, session_epoch=$4 where id=$1 returning username",
      [accountId, parsed.enabled, storedSecret, nextSessionEpoch]
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
    await client.query("update admin_account set session_epoch=$2,updated_at=now() where id=$1", [accountId, randomUUID()]);
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

async function getBootstrapRequired(db: Db): Promise<boolean> {
  const result = await db.query(
    `select coalesce((select completed from admin_bootstrap_state where singleton=true),false) as completed,
            exists(select 1 from admin_account where active=true and password_hash is not null and role='OWNER') as owner_ready`
  );
  return !result.rows[0]?.completed && !result.rows[0]?.owner_ready;
}

function bootstrapRequestAllowed(request: FastifyRequest, configuredSecret: string | undefined, submittedSecret: string | undefined): boolean {
  if (["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(request.ip)) return true;
  if (!configuredSecret || !submittedSecret) return false;
  const expected = Buffer.from(configuredSecret);
  const actual = Buffer.from(submittedSecret);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

async function bootstrapAdmin(db: Db, correlationId: string, input: z.infer<typeof adminBootstrapSchema>): Promise<{ recoveryCodes: string[] }> {
  const passwordHash = await argon2.hash(input.password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  await tx(db, async (client) => {
    const state = await client.query("select completed from admin_bootstrap_state where singleton=true for update");
    if (!state.rowCount || Boolean(state.rows[0].completed)) throw Object.assign(new Error("bootstrap_completed"), { statusCode: 409 });
    const existingOwner = await client.query("select 1 from admin_account where active=true and password_hash is not null and role='OWNER' for update");
    if (existingOwner.rowCount) throw Object.assign(new Error("bootstrap_completed"), { statusCode: 409 });
    const account = await client.query(
      `insert into admin_account(username,password_hash,password_changed_at,mfa_enabled,role,active,activated_at)
       values ($1,$2,now(),false,'OWNER',true,now())
       on conflict (username) do update
         set password_hash=excluded.password_hash,password_changed_at=now(),mfa_enabled=false,mfa_secret=null,
             role='OWNER',active=true,activated_at=now(),updated_at=now()
       where admin_account.password_hash is null and admin_account.active is false
       returning id,username`,
      [input.username, passwordHash]
    );
    if (!account.rowCount) throw Object.assign(new Error("bootstrap_username_unavailable"), { statusCode: 409 });
    const accountId = String(account.rows[0].id);
    await client.query(
      "update admin_bootstrap_state set completed=true,completed_at=now(),completed_by=$1,updated_at=now() where singleton=true and completed=false",
      [accountId]
    );
    await appendAudit(client, {
      eventType: "admin.bootstrap.completed",
      actorType: "admin",
      actorId: accountId,
      objectType: "admin_account",
      objectId: accountId,
      after: { username: account.rows[0].username, role: "OWNER", mfaEnabled: false },
      correlationId
    });
  });
  return { recoveryCodes: [] };
}

async function updateAdminAccount(db: Db, actorId: string, correlationId: string, accountId: string, input: unknown): Promise<void> {
  const parsed = adminAccountUpdateSchema.parse(input);
  await tx(db, async (client) => {
    const current = await client.query("select username,role,active from admin_account where id=$1 for update", [accountId]);
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const before = current.rows[0];
    const nextRole = parsed.role ?? String(before.role) as AdminRole;
    const nextActive = parsed.active ?? Boolean(before.active);
    const updated = await client.query(
      "update admin_account set role=$2,active=$3,updated_at=now() where id=$1 returning username,role,active",
      [accountId, nextRole, nextActive]
    );
    if (!nextActive || nextRole !== String(before.role)) {
      await client.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [accountId]);
    }
    await appendAudit(client, {
      eventType: "admin.account.updated",
      actorType: "admin",
      actorId,
      objectType: "admin_account",
      objectId: accountId,
      before: { username: before.username, role: before.role, active: before.active },
      after: { username: updated.rows[0].username, role: updated.rows[0].role, active: updated.rows[0].active },
      correlationId
    });
  });
}

export function registerAdminRoutes(app: FastifyInstance, db: Db, config: AdminRoutesConfig): void {
  const dummyPasswordHash = argon2.hash(randomBytes(32), { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  app.addHook("preHandler", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST || !request.url.startsWith("/api/")) return;
    const path = request.url.split("?")[0] ?? request.url;
    if (["HEAD", "OPTIONS"].includes(request.method) || path === "/api/session") return;
    if (request.method === "GET") {
      const session = await sessionAccount(db, request, config);
      if (!session || session.role !== "AUDITOR") return;
      const auditorReadable = ["/api/audit", "/api/monitoring", "/api/readiness", "/api/admin-security", "/api/mcp-servers", "/api/components"];
      if (!auditorReadable.some((prefix) => path.startsWith(prefix))) return sendError(reply, 403, "admin_role_forbidden");
      return;
    }
    if (["/api/login", "/api/login/mfa", "/api/logout", "/api/bootstrap", "/api/reauth", "/api/admin-password"].includes(path)) return;
    const session = await sessionAccount(db, request, config);
    if (!session) return;
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden");
    if (path.startsWith("/api/admin-accounts") && session.role !== "OWNER") {
      return sendError(reply, 403, "owner_role_required");
    }
    if (Date.now() - new Date(session.reauthenticatedAt).getTime() > RECENT_REAUTH_MS) {
      return sendError(reply, 428, "reauthentication_required", "Recent authentication is required");
    }
  });

  app.get("/api/session", async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    return {
      authenticated: Boolean(session),
      account: session?.accountName ?? null,
      role: session?.role ?? null,
      bootstrapRequired: session ? false : await getBootstrapRequired(db)
    };
  });

  app.post("/api/bootstrap", {
    config: { rateLimit: { max: 5, timeWindow: "15 minutes", groupId: "admin-bootstrap" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    try {
      const parsed = adminBootstrapSchema.parse(request.body);
      if (!bootstrapRequestAllowed(request, config.ADMIN_BOOTSTRAP_SECRET, parsed.bootstrapSecret)) {
        return sendError(reply, 403, "bootstrap_access_denied", undefined, correlationId);
      }
      return await bootstrapAdmin(db, correlationId, parsed);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return sendError(reply, 400, "bootstrap_input_invalid", undefined, correlationId);
      }
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "bootstrap_failed", undefined, correlationId);
    }
  });

  app.get("/api/admin-security", {
    config: { rateLimit: { max: 60, timeWindow: "1 minute", groupId: "admin-security-read" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    const account = await db.query(
      "select username,role,active,password_changed_at,mfa_enabled from admin_account where id=$1",
      [session.accountId]
    );
    const sessions = await listAdminSessions(db, session.accountId, session.sessionId);
    return {
      username: String(account.rows[0].username),
      role: String(account.rows[0].role),
      active: Boolean(account.rows[0].active),
      deploymentManaged: isDeploymentManagedAdmin(String(account.rows[0].username), config),
      mfaEnabled: Boolean(account.rows[0].mfa_enabled),
      passwordChangedAt: account.rows[0].password_changed_at ? String(account.rows[0].password_changed_at) : null,
      sessions
    };
  });

  app.get("/api/admin-accounts", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role !== "OWNER") return sendError(reply, 403, "owner_role_required", undefined, correlationId);
    const accounts = await listAdminAccounts(db, session.accountId);
    return {
      accounts: accounts.map((account) => ({
        ...account,
        deploymentManaged: isDeploymentManagedAdmin(account.username, config)
      }))
    };
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

  app.put("/api/operational-config/domain", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    try {
      const parsed = domainConfigUpdateSchema.parse(request.body);
      return await updateDomainConfiguration(db, session.accountId, correlationId, parsed.baseDomain, parsed.expectedVersions);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.put("/api/operational-config/:key", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { key } = request.params as { key: string };
    try {
      const parsed = operationalConfigUpdateSchema.parse(request.body);
      if (key === "mfaEncryptionKey") {
        return await rotateMfaEncryptionKey(db, config, session.accountId, correlationId, parsed.value, parsed.expectedVersion);
      }
      await updateOperationalConfig(db, config, session.accountId, correlationId, key, parsed.value, parsed.expectedVersion);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/secrets", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    return { secrets: await listSecrets(db) };
  });

  app.post("/api/secrets", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    try {
      const parsed = secretCreateSchema.parse(request.body);
      return { secret: await createSecret(db, config, session.accountId, correlationId, parsed) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secrets/:id/rotate", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretRotateSchema.parse(request.body);
      return { secret: await rotateSecret(db, config, session.accountId, correlationId, id, parsed) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secrets/:id/delete", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretDeleteSchema.parse(request.body);
      await deleteSecret(db, session.accountId, correlationId, id, parsed.expectedVersion);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secrets/:id/status", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretStatusSchema.parse(request.body);
      return { secret: await setSecretStatus(db, session.accountId, correlationId, id, parsed.expectedVersion, parsed.status) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secrets/:id/restore", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretDeleteSchema.parse(request.body);
      return { secret: await restoreSecret(db, session.accountId, correlationId, id, parsed.expectedVersion) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.get("/api/secrets/:id/versions", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    const { id } = request.params as { id: string };
    return { versions: await listSecretVersions(db, id) };
  });

  app.get("/api/secrets/:id/grants", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    const { id } = request.params as { id: string };
    return { grants: await listSecretGrants(db, id) };
  });

  app.post("/api/secrets/:id/grants", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretGrantSchema.parse(request.body);
      return { grants: await grantSecret(db, session.accountId, correlationId, id, parsed) };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secret-grants/:id/revoke", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      await revokeSecretGrant(db, session.accountId, correlationId, id);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secrets/:id/reveal-grants", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute", groupId: "secret-reveal-grant" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretRevealGrantSchema.parse(request.body);
      return await createRevealGrant(db, config, session.accountId, correlationId, id, { ...parsed, sessionId: session.sessionId });
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secrets/:id/reveal", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute", groupId: "secret-reveal-consume" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretRevealConsumeSchema.parse(request.body);
      const revealed = await consumeRevealGrant(db, config, session.accountId, session.sessionId, correlationId, id, parsed.revealGrantId);
      return reply.header("cache-control", "no-store").send(revealed);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/secrets/:id/reveal-events", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (session.role === "AUDITOR") return sendError(reply, 403, "admin_role_forbidden", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      const parsed = secretRevealUiEventSchema.parse(request.body);
      await auditRevealUiEvent(db, session.accountId, session.sessionId, correlationId, id, parsed);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/login", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute", groupId: "admin-login" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const body = request.body as { username?: string; password?: string };
    const throttle = await getLoginLockState(db, request, body.username ?? "", config);
    if (throttle.blocked) {
      reply.header("retry-after", String(throttle.retryAfterSeconds));
      await appendAudit(db, { eventType: "admin.login.rate_limited", actorType: "admin", actorId: body.username ?? null, correlationId });
      return sendError(reply, 429, "login_rate_limited", "Too many login attempts", correlationId);
    }
    const loginUsername = normalizedLoginUsername(body.username ?? "");
    const result = await db.query("select * from admin_account where username=$1", [loginUsername]);
    const account = result.rows[0] as Record<string, unknown> | undefined;
    const accountEligible = Boolean(account?.active) && account?.activated_at !== null;
    const passwordHash = accountEligible && typeof account?.password_hash === "string" ? account.password_hash : await dummyPasswordHash;
    const passwordOk = await argon2.verify(passwordHash, canonicalAdminPassword(body.password ?? ""));
    if (!account) {
      await recordLoginFailure(db, request, loginUsername, config);
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: loginUsername || null, after: loginFailureAuditAfter("account_not_found", body, loginUsername), correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    if (!accountEligible) {
      await recordLoginFailure(db, request, loginUsername, config);
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: loginUsername || null, objectType: "admin_account", objectId: String(account.id), after: loginFailureAuditAfter("account_inactive", body, loginUsername), correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    if (!account.password_hash) {
      await recordLoginFailure(db, request, loginUsername, config);
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: loginUsername || null, objectType: "admin_account", objectId: String(account.id), after: loginFailureAuditAfter("password_hash_missing", body, loginUsername), correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    if (!passwordOk) {
      await recordLoginFailure(db, request, loginUsername, config);
      await appendAudit(db, { eventType: "admin.login.failed", actorType: "admin", actorId: loginUsername || null, objectType: "admin_account", objectId: String(account.id), after: loginFailureAuditAfter("password_mismatch", body, loginUsername), correlationId });
      return sendError(reply, 401, "invalid_login", "Invalid credentials", correlationId);
    }
    await clearLoginFailures(db, request, loginUsername, config);
    if (account.mfa_enabled && !trustedDeviceMatches(request, config.SESSION_SECRET_BASE64, { id: String(account.id), session_epoch: String(account.session_epoch) })) {
      const challenge = issueLoginChallenge(reply, request, config.SESSION_SECRET_BASE64, {
        id: String(account.id),
        session_epoch: String(account.session_epoch),
        username: String(account.username)
      });
      await appendAudit(db, { eventType: "admin.login.password_verified", actorType: "admin", actorId: String(account.id), correlationId });
      return {
        ok: false,
        mfaRequired: true,
        challengeExpiresAt: challenge.expiresAt,
        trustedDeviceWindowHours: Math.floor(MFA_TRUST_WINDOW_MS / (60 * 60 * 1000))
      };
    }
    clearLoginChallenge(reply);
    const created = await createAdminSession(db, reply, request, config, {
      id: account.id,
      session_epoch: account.session_epoch
    });
    await appendAudit(db, { eventType: "admin.login.succeeded", actorType: "admin", actorId: String(account.id), correlationId });
    return { ok: true, csrfToken: created.csrfToken, trustedDeviceExpiresAt: created.trustedDeviceExpiresAt };
  });

  app.post("/api/login/mfa", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute", groupId: "admin-login-mfa" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const challenge = verifyAdminToken(request.cookies[LOGIN_CHALLENGE_COOKIE], config.SESSION_SECRET_BASE64);
    if (!challenge || challenge.purpose !== "login_challenge" || challenge.uaDigest !== userAgentDigest(request, config.SESSION_SECRET_BASE64)) {
      clearLoginChallenge(reply);
      return sendError(reply, 401, "mfa_challenge_required", "MFA challenge is required", correlationId);
    }
    const body = request.body as { code?: string; recoveryCode?: string };
    const result = await db.query("select id, username, mfa_enabled, mfa_secret, session_epoch from admin_account where id=$1 and active=true and activated_at is not null", [challenge.accountId]);
    const account = result.rows[0] as Record<string, unknown> | undefined;
    if (!account || !account.mfa_enabled || String(account.session_epoch) !== challenge.sessionEpoch) {
      clearLoginChallenge(reply);
      return sendError(reply, 401, "mfa_challenge_required", "MFA challenge is required", correlationId);
    }
    const decryptedMfaSecret = decryptMfaSecret(typeof account.mfa_secret === "string" ? account.mfa_secret : "", config.MFA_ENCRYPTION_KEY_BASE64, {
      allowLegacyPlaintext: config.MFA_ALLOW_PLAINTEXT_LEGACY,
      subjectId: String(account.id),
      purpose: "admin_totp"
    });
    const code = typeof body.code === "string" ? body.code.trim() : "";
    const recoveryCode = typeof body.recoveryCode === "string" ? body.recoveryCode.trim() : code;
    const totpOk = authenticator.check(code, decryptedMfaSecret);
    const recoveryOk = !totpOk ? await consumeRecoveryCode(db, String(account.id), recoveryCode) : false;
    if (!totpOk && !recoveryOk) {
      await appendAudit(db, { eventType: "admin.login.mfa_failed", actorType: "admin", actorId: String(account.id), correlationId });
      return sendError(reply, 401, "invalid_mfa_code", "Invalid MFA code", correlationId);
    }
    clearLoginChallenge(reply);
    const created = await createAdminSession(db, reply, request, config, {
      id: account.id,
      session_epoch: account.session_epoch
    }, true);
    await appendAudit(db, { eventType: "admin.login.succeeded", actorType: "admin", actorId: String(account.id), correlationId });
    if (recoveryOk) {
      await appendAudit(db, { eventType: "admin.login.recovery_code_used", actorType: "admin", actorId: String(account.id), objectType: "admin_account", objectId: String(account.id), correlationId });
    }
    return { ok: true, csrfToken: created.csrfToken, trustedDeviceExpiresAt: created.trustedDeviceExpiresAt };
  });

  app.post("/api/logout", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute", groupId: "admin-session-write" } }
  }, async (request, reply) => {
    const session = await sessionAccount(db, request, config);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed");
    if (session) await db.query("update admin_session set revoked_at=now() where id=$1 and revoked_at is null", [session.sessionId]);
    reply.clearCookie(SESSION_COOKIE, { path: "/" });
    reply.clearCookie(CSRF_COOKIE, { path: "/" });
    clearTrustedDeviceCookie(reply);
    return { ok: true };
  });

  app.post("/api/reauth", {
    config: { rateLimit: { max: 5, timeWindow: "1 minute", groupId: "admin-reauth" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const body = request.body && typeof request.body === "object" ? request.body as Record<string, unknown> : {};
    if (!await requireAdminReauthentication(db, config, session.accountId, body)) {
      return sendError(reply, 401, "reauthentication_failed", undefined, correlationId);
    }
    await tx(db, async (client) => {
      await client.query("update admin_session set reauthenticated_at=now() where id=$1 and revoked_at is null", [session.sessionId]);
      await appendAudit(client, { eventType: "admin.reauthenticated", actorType: "admin", actorId: session.accountId, objectType: "admin_session", objectId: session.sessionId, correlationId });
    });
    return { ok: true, validForSeconds: Math.floor(RECENT_REAUTH_MS / 1000) };
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

  app.post("/api/admin-mfa/enrollment/start", {
    config: { rateLimit: { max: 5, timeWindow: "10 minutes", groupId: "admin-mfa-enrollment-start" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const account = await db.query("select username,mfa_enabled,session_epoch from admin_account where id=$1", [session.accountId]);
    if (!account.rowCount) return sendError(reply, 404, "not_found", undefined, correlationId);
    if (isDeploymentManagedAdmin(String(account.rows[0].username), config)) {
      return sendError(reply, 409, "admin_mfa_deployment_managed", undefined, correlationId);
    }
    const secret = authenticator.generateSecret();
    const enrollment = buildMfaEnrollmentToken(request, config, {
      id: session.accountId,
      sessionEpoch: String(account.rows[0].session_epoch),
      username: String(account.rows[0].username)
    }, secret);
    return {
      ok: true,
      mfaEnabled: Boolean(account.rows[0].mfa_enabled),
      enrollmentToken: enrollment.enrollmentToken,
      otpauthUri: enrollment.otpauthUri,
      manualSecret: secret,
      expiresAt: enrollment.expiresAt
    };
  });

  app.post("/api/admin-mfa/enrollment/verify", {
    config: { rateLimit: { max: 10, timeWindow: "10 minutes", groupId: "admin-mfa-enrollment-verify" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const parsed = adminMfaEnrollmentVerifySchema.safeParse(request.body);
    if (!parsed.success) return sendError(reply, 400, "invalid_mfa_enrollment", undefined, correlationId);
    const enrollment = verifyAdminToken(parsed.data.enrollmentToken, config.SESSION_SECRET_BASE64);
    if (!enrollment || enrollment.purpose !== "mfa_enrollment" || enrollment.accountId !== session.accountId || enrollment.uaDigest !== userAgentDigest(request, config.SESSION_SECRET_BASE64) || !enrollment.secret) {
      return sendError(reply, 400, "invalid_mfa_enrollment", undefined, correlationId);
    }
    if (!authenticator.check(parsed.data.code, enrollment.secret)) {
      return sendError(reply, 401, "invalid_mfa_code", undefined, correlationId);
    }
    const recoveryCodes = Array.from({ length: 8 }, generateRecoveryCode);
    const recoveryHashes = await Promise.all(recoveryCodes.map((code) => argon2.hash(code, { type: argon2.argon2id, memoryCost: 32768, timeCost: 2, parallelism: 1 })));
    const nextSessionEpoch = randomUUID();
    await tx(db, async (client) => {
      const account = await client.query("select username,session_epoch from admin_account where id=$1 for update", [session.accountId]);
      if (!account.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
      if (String(account.rows[0].session_epoch) !== enrollment.sessionEpoch) throw Object.assign(new Error("invalid_mfa_enrollment"), { statusCode: 400 });
      const enrollmentSecret = enrollment.secret;
      if (!enrollmentSecret) throw Object.assign(new Error("invalid_mfa_enrollment"), { statusCode: 400 });
      const encrypted = encryptMfaSecret(enrollmentSecret, config.MFA_ENCRYPTION_KEY_BASE64, { subjectId: session.accountId, purpose: "admin_totp" });
      await client.query("update admin_account set mfa_enabled=true,mfa_secret=$2,session_epoch=$3,updated_at=now() where id=$1", [session.accountId, encrypted, nextSessionEpoch]);
      await client.query("update admin_recovery_code set consumed_at=coalesce(consumed_at, now()) where account_id=$1", [session.accountId]);
      for (const hash of recoveryHashes) {
        await client.query("insert into admin_recovery_code(account_id,code_hash) values ($1,$2)", [session.accountId, hash]);
      }
      await client.query("update admin_session set revoked_at=now() where account_id=$1 and id<>$2 and revoked_at is null", [session.accountId, session.sessionId]);
      await client.query("update admin_session set session_epoch=$2,reauthenticated_at=now() where id=$1 and revoked_at is null", [session.sessionId, nextSessionEpoch]);
      await appendAudit(client, {
        eventType: "admin.mfa.enabled",
        actorType: "admin",
        actorId: session.accountId,
        objectType: "admin_account",
        objectId: session.accountId,
        after: { recoveryCodeCount: recoveryCodes.length },
        correlationId
      });
    });
    setTrustedDeviceCookie(reply, request, config.SESSION_SECRET_BASE64, { id: session.accountId, session_epoch: nextSessionEpoch });
    return { ok: true, recoveryCodes };
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

  app.post("/api/admin-sessions/:id/revoke", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    try {
      const revokedCurrent = await revokeOwnAdminSession(db, session, (request.params as { id: string }).id, correlationId);
      if (revokedCurrent) {
        reply.clearCookie(SESSION_COOKIE, { path: "/" });
        reply.clearCookie(CSRF_COOKIE, { path: "/" });
      }
      return { ok: true, revokedCurrent };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.post("/api/admin-sessions/revoke-all", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    await revokeAllAdminSessions(db, session, correlationId);
    reply.clearCookie(SESSION_COOKIE, { path: "/" });
    reply.clearCookie(CSRF_COOKIE, { path: "/" });
    return { ok: true };
  });

  app.post("/api/admin-accounts", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    try {
      await createAdminAccount(db, session.accountId, correlationId, request.body);
      return { ok: true };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 500), error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
    }
  });

  app.patch("/api/admin-accounts/:id", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    try {
      await updateAdminAccount(db, session.accountId, correlationId, id, request.body);
      return { ok: true };
    } catch (error) {
      const lastOwner = error instanceof Error && error.message.includes("last_owner_required");
      return sendError(reply, lastOwner ? 409 : Number((error as { statusCode?: number }).statusCode ?? 500), lastOwner ? "last_owner_required" : error instanceof Error ? error.message : "operation_failed", undefined, correlationId);
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

  app.post("/api/mcp-servers/:id/monitoring-profile/preview", async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    try {
      const parsed = monitoringProfileUpdateSchema.parse(request.body);
      const intervals = Object.values(parsed.profile.probeIntervals);
      return {
        valid: true,
        profileDigest: digestCanonicalJson(parsed.profile),
        minimumProbeIntervalSeconds: Math.min(...intervals),
        estimatedDailyProbeCount: Math.ceil(intervals.reduce((total, seconds) => total + 86_400 / seconds, 0)),
        alertRuleCount: parsed.profile.alertRules.length,
        retentionDays: parsed.profile.retentionDays
      };
    } catch (error) {
      return sendError(reply, 400, "monitoring_profile_invalid", error instanceof Error ? error.message : undefined, correlationId);
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

  app.post("/api/mcp-servers/:id/delete", {
    config: { rateLimit: { max: 3, timeWindow: "10 minutes", groupId: "mcp-server-delete" } }
  }, async (request, reply) => {
    const correlationId = randomUUID();
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found", undefined, correlationId);
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized", undefined, correlationId);
    if (!requireCsrf(request)) return sendError(reply, 403, "csrf_failed", undefined, correlationId);
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const confirmedCode = typeof body.confirmedCode === "string" ? body.confirmedCode.trim() : "";
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    if (reason.length < 10) return sendError(reply, 400, "invalid_delete_request", undefined, correlationId);
    if (!await requireAdminReauthentication(db, config, session.accountId, body)) {
      return sendError(reply, 403, "reauthentication_failed", undefined, correlationId);
    }
    try {
      const server = await db.query("select code from mcp_server where id=$1", [id]);
      if (!server.rowCount) return sendError(reply, 404, "not_found", undefined, correlationId);
      if (confirmedCode !== String(server.rows[0].code)) return sendError(reply, 409, "confirmation_code_mismatch", undefined, correlationId);
      await deleteRegisteredServer(db, id, session.accountId, correlationId, reason);
      return { ok: true, deletedServerId: id };
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
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    try {
      const query = parseAuditQuery(request.query);
      const where = buildAuditWhere(query);
      const values = [...where.values, query.limit + 1];
      const result = await db.query(
        `select id,event_type,actor_type,actor_id,object_type,object_id,correlation_id,created_at,before_json,after_json,
                chain_sequence,encode(prev_hash,'hex') as prev_hash_hex,encode(event_hash,'hex') as event_hash_hex
           from audit_event
          where ${where.sql}
          order by id desc
          limit $${values.length}`,
        values
      );
      const events = result.rows.slice(0, query.limit).map((row) => sanitizeAuditRow(row, false));
      const lastId = Number(events[events.length - 1]?.id ?? 0);
      return { events, nextCursor: result.rows.length > query.limit && lastId ? encodeAuditCursor(lastId) : null };
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "audit_query_invalid");
    }
  });

  app.get("/api/audit/events/:id", {
    config: { rateLimit: { max: 60, timeWindow: "1 minute", groupId: "admin-audit-read" } }
  }, async (request, reply) => {
    if (hostOf(request.headers.host) !== config.ADMIN_HOST) return sendError(reply, 404, "not_found");
    const session = await sessionAccount(db, request, config);
    if (!session) return sendError(reply, 401, "unauthorized");
    const id = Number((request.params as { id: string }).id);
    if (!Number.isSafeInteger(id) || id < 1) return sendError(reply, 400, "audit_event_id_invalid");
    const result = await db.query(
      `select id,event_type,actor_type,actor_id,object_type,object_id,correlation_id,created_at,before_json,after_json,
              chain_sequence,encode(prev_hash,'hex') as prev_hash_hex,encode(event_hash,'hex') as event_hash_hex
         from audit_event where id=$1`,
      [id]
    );
    if (!result.rowCount) return sendError(reply, 404, "not_found");
    return { event: sanitizeAuditRow(result.rows[0]) };
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
    let query: ReturnType<typeof parseAuditQuery>;
    try {
      query = parseAuditQuery(request.query);
    } catch (error) {
      return sendError(reply, Number((error as { statusCode?: number }).statusCode ?? 400), error instanceof Error ? error.message : "audit_query_invalid");
    }
    const exportLimit = 10_000;
    const pageSize = 500;
    async function* streamExport() {
      yield `${JSON.stringify({ exportedAt: new Date().toISOString(), filters: { ...query, cursor: undefined, cursorId: undefined } }).slice(0, -1)},"events":[`;
      let lastId = 0;
      let eventCount = 0;
      let first = true;
      let truncated = false;
      while (eventCount < exportLimit) {
        const where = buildAuditWhere({ ...query, cursorId: lastId || null }, "ASC");
        const requested = Math.min(pageSize, exportLimit - eventCount);
        const values = [...where.values, requested + 1];
        const result = await db.query(
          `select id,event_type,actor_type,actor_id,object_type,object_id,correlation_id,created_at,before_json,after_json,
                  chain_sequence,encode(prev_hash,'hex') as prev_hash_hex,encode(event_hash,'hex') as event_hash_hex
             from audit_event where ${where.sql} order by id asc limit $${values.length}`,
          values
        );
        const page = result.rows.slice(0, requested);
        const hasMore = result.rows.length > requested;
        for (const row of page) {
          yield `${first ? "" : ","}${JSON.stringify(sanitizeAuditRow(row))}`;
          first = false;
          eventCount += 1;
          lastId = Number(row.id);
        }
        if (!hasMore || page.length === 0) break;
        if (eventCount >= exportLimit) truncated = true;
      }
      yield `],"eventCount":${eventCount},"truncated":${truncated}}`;
    }
    return reply
      .type("application/json; charset=utf-8")
      .header("content-disposition", "attachment; filename=\"audit-export.json\"")
      .header("cache-control", "no-store")
      .send(Readable.from(streamExport(), { objectMode: false }));
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
