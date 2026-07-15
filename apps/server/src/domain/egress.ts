import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { fingerprintSecret, hmacToken } from "../security/secrets.js";

const EPHEMERAL_PREFIX = "kce2_";
type Queryable = Pick<Db, "query">;

export type ValidatedEgressCapability = {
  jobId: string | null;
  serverId: string | null;
  managedServiceId: string | null;
  allowlist: string[];
  purpose: string;
  correlationId: string | null;
};

export async function createEgressCapability(db: Queryable, config: AppConfig, jobId: string, allowlist: string[]): Promise<string | null> {
  await db.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where job_id=$1 and revoked_at is null", [jobId]);
  if (allowlist.length === 0) return null;
  const token = `kce_${randomBytes(64).toString("base64url")}`;
  await db.query(
    `insert into egress_capability(lookup_digest,fingerprint,job_id,allowlist,expires_at)
     values ($1,$2,$3,$4,now()+interval '30 days')`,
    [hmacToken(token, config.EGRESS_CAPABILITY_HMAC_KEY_BASE64), fingerprintSecret(token), jobId, JSON.stringify(allowlist)]
  );
  return token;
}

export async function attachEgressCapabilityToServer(db: Queryable, jobId: string, serverId: string): Promise<void> {
  await db.query(
    `update egress_capability
        set server_id=$2,
            expires_at=greatest(expires_at, now()+interval '3650 days')
      where job_id=$1 and revoked_at is null`,
    [jobId, serverId]
  );
}

export async function revokeEgressCapabilities(db: Queryable, jobId: string): Promise<void> {
  await db.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where job_id=$1", [jobId]);
}

export function createEphemeralEgressCapability(config: AppConfig, params: {
  allowlist: string[];
  managedServiceId?: string | null;
  correlationId?: string | null;
  purpose: string;
  ttlSeconds: number;
}): string {
  const payload = Buffer.from(JSON.stringify({
    v: 1,
    allowlist: params.allowlist,
    managedServiceId: params.managedServiceId ?? null,
    correlationId: params.correlationId ?? null,
    purpose: params.purpose,
    exp: Date.now() + Math.max(5, params.ttlSeconds) * 1000
  })).toString("base64url");
  const signature = createHmac("sha256", config.EGRESS_CAPABILITY_HMAC_KEY_BASE64).update(payload).digest("base64url");
  return `${EPHEMERAL_PREFIX}${payload}.${signature}`;
}

function validateEphemeralEgressCapability(config: AppConfig, token: string): ValidatedEgressCapability {
  const encoded = token.slice(EPHEMERAL_PREFIX.length);
  const separator = encoded.lastIndexOf(".");
  if (separator <= 0) throw new Error("invalid_egress_capability");
  const payload = encoded.slice(0, separator);
  const signature = encoded.slice(separator + 1);
  const expected = createHmac("sha256", config.EGRESS_CAPABILITY_HMAC_KEY_BASE64).update(payload).digest("base64url");
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length || !timingSafeEqual(actualBuffer, expectedBuffer)) {
    throw new Error("invalid_egress_capability");
  }
  const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
    v?: number;
    allowlist?: unknown;
    managedServiceId?: unknown;
    correlationId?: unknown;
    purpose?: unknown;
    exp?: unknown;
  };
  if (parsed.v !== 1 || !Array.isArray(parsed.allowlist) || typeof parsed.purpose !== "string") throw new Error("invalid_egress_capability");
  const expiresAt = Number(parsed.exp);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new Error("invalid_egress_capability");
  return {
    jobId: null,
    serverId: null,
    managedServiceId: typeof parsed.managedServiceId === "string" ? parsed.managedServiceId : null,
    allowlist: parsed.allowlist.filter((entry): entry is string => typeof entry === "string"),
    purpose: parsed.purpose,
    correlationId: typeof parsed.correlationId === "string" ? parsed.correlationId : null
  };
}

export async function validateEgressCapability(db: Queryable, config: AppConfig, token: string): Promise<ValidatedEgressCapability> {
  if (token.startsWith(EPHEMERAL_PREFIX)) return validateEphemeralEgressCapability(config, token);
  const digest = hmacToken(token, config.EGRESS_CAPABILITY_HMAC_KEY_BASE64);
  const result = await db.query(
    `update egress_capability ec
        set last_used_at=now()
       from onboarding_job oj
      where ec.lookup_digest=$1 and ec.job_id=oj.id
        and ec.revoked_at is null and ec.expires_at>now()
        and oj.state not in ('FAILED','QUARANTINED','CANCELLED')
      returning ec.job_id,ec.server_id,ec.allowlist`,
    [digest]
  );
  if (!result.rowCount) throw new Error("invalid_egress_capability");
  return {
    jobId: String(result.rows[0].job_id),
    serverId: result.rows[0].server_id ? String(result.rows[0].server_id) : null,
    managedServiceId: null,
    allowlist: result.rows[0].allowlist as string[],
    purpose: "legacy.onboarding",
    correlationId: null
  };
}
