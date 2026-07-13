import { randomBytes } from "node:crypto";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { fingerprintSecret, hmacToken } from "../security/secrets.js";

export async function createEgressCapability(db: Db, config: AppConfig, jobId: string, allowlist: string[]): Promise<string | null> {
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

export async function attachEgressCapabilityToServer(db: Db, jobId: string, serverId: string): Promise<void> {
  await db.query("update egress_capability set server_id=$2 where job_id=$1 and revoked_at is null", [jobId, serverId]);
}

export async function revokeEgressCapabilities(db: Db, jobId: string): Promise<void> {
  await db.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where job_id=$1", [jobId]);
}

export async function validateEgressCapability(db: Db, config: AppConfig, token: string): Promise<{ jobId: string; serverId: string | null; allowlist: string[] }> {
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
    allowlist: result.rows[0].allowlist as string[]
  };
}
