import type { Db } from "../db.js";
import { hmacToken, issueOpaqueSecret, hashPasswordLikeSecret, verifyPasswordLikeSecret, fingerprintSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { resourceFor } from "./catalog.js";

export type KajaCredentialSummary = {
  id: string;
  publicId: string;
  label: string;
  fingerprint: string;
  active: boolean;
  revokedAt: string | null;
  deletedAt: string | null;
  createdAt: string;
  permissionCount: number;
  activeAccessTokenCount: number;
  lastTokenIssuedAt: string | null;
  lastTokenExpiresAt: string | null;
};

export async function createKajaCredential(db: Db, actorId: string, correlationId: string, label: string): Promise<{ publicId: string; label: string; clientSecret: string; fingerprint: string }> {
  const secret = issueOpaqueSecret();
  const hash = await hashPasswordLikeSecret(secret.value);
  const result = await db.query("select nextval('kaja_number_seq') as number");
  const publicId = `Kaja${String(Number(result.rows[0].number)).padStart(4, "0")}`;
  const inserted = await db.query(
    "insert into kaja_credential(public_id, label, secret_hash, secret_fingerprint) values ($1,$2,$3,$4) returning id",
    [publicId, label, hash, secret.fingerprint]
  );
  await appendAudit(db, {
    eventType: "kaja.created",
    actorType: "admin",
    actorId,
    objectType: "kaja_credential",
    objectId: inserted.rows[0].id,
    after: { publicId, label, fingerprint: secret.fingerprint },
    correlationId
  });
  return { publicId, label, clientSecret: secret.value, fingerprint: secret.fingerprint };
}

export async function listKajaCredentials(db: Db): Promise<KajaCredentialSummary[]> {
  const result = await db.query(`
    select
      kc.id,
      kc.public_id,
      kc.label,
      kc.secret_fingerprint,
      kc.active,
      kc.revoked_at,
      kc.deleted_at,
      kc.created_at,
      count(distinct kp.id) filter (where kp.revoked_at is null) as permission_count,
      count(distinct at.lookup_digest) filter (where at.revoked_at is null and at.expires_at > now()) as active_access_token_count,
      max(at.issued_at) as last_token_issued_at,
      max(at.expires_at) as last_token_expires_at
    from kaja_credential kc
    left join kaja_permission kp on kp.credential_id = kc.id
    left join access_token at on at.credential_id = kc.id
    where kc.deleted_at is null
    group by kc.id
    order by kc.created_at desc
  `);
  return result.rows.map((row) => ({
    id: String(row.id),
    publicId: String(row.public_id),
    label: String(row.label),
    fingerprint: String(row.secret_fingerprint),
    active: Boolean(row.active),
    revokedAt: row.revoked_at ? String(row.revoked_at) : null,
    deletedAt: row.deleted_at ? String(row.deleted_at) : null,
    createdAt: String(row.created_at),
    permissionCount: Number(row.permission_count),
    activeAccessTokenCount: Number(row.active_access_token_count),
    lastTokenIssuedAt: row.last_token_issued_at ? String(row.last_token_issued_at) : null,
    lastTokenExpiresAt: row.last_token_expires_at ? String(row.last_token_expires_at) : null
  }));
}

export async function issueAccessToken(db: Db, params: {
  clientId: string;
  clientSecret: string;
  resource: string;
  hmacKey: Buffer;
  keyId: string;
  correlationId: string;
}): Promise<{ access_token: string; token_type: "Bearer"; expires_in: number; scope: string }> {
  const credentialResult = await db.query("select * from kaja_credential where public_id=$1 and deleted_at is null", [params.clientId]);
  if (!credentialResult.rowCount) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
  const credential = credentialResult.rows[0];
  if (!credential.active || credential.revoked_at) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
  const verified = await verifyPasswordLikeSecret(String(credential.secret_hash), params.clientSecret);
  if (!verified) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });

  const serverResult = await db.query("select id, code, hostname, enabled, registration_state, revocation_epoch from mcp_server where $1 = ('https://' || hostname || '/mcp')", [params.resource]);
  if (!serverResult.rowCount) throw Object.assign(new Error("invalid_resource"), { statusCode: 400 });
  const server = serverResult.rows[0];
  if (!server.enabled || !["ACTIVE", "TRIAL"].includes(String(server.registration_state))) {
    throw Object.assign(new Error("resource_unavailable"), { statusCode: 503 });
  }
  const permission = await db.query(
    "select 1 from kaja_permission where credential_id=$1 and server_id=$2 and revoked_at is null",
    [credential.id, server.id]
  );
  if (!permission.rowCount) throw Object.assign(new Error("insufficient_scope"), { statusCode: 403 });

  const token = issueOpaqueSecret();
  const ttlSeconds = 15 * 60;
  const digest = hmacToken(token.value, params.hmacKey);
  await db.query(
    `insert into access_token
      (lookup_digest, key_id, fingerprint, credential_id, server_id, audience, expires_at, credential_revocation_epoch, server_revocation_epoch)
     values ($1,$2,$3,$4,$5,$6, now() + ($7 || ' seconds')::interval, $8, $9)`,
    [digest, params.keyId, token.fingerprint, credential.id, server.id, params.resource, ttlSeconds, credential.revocation_epoch, server.revocation_epoch]
  );
  await appendAudit(db, {
    eventType: "access_token.issued",
    actorType: "kaja",
    actorId: credential.id,
    objectType: "mcp_server",
    objectId: server.id,
    after: { resource: params.resource, fingerprint: token.fingerprint, expiresIn: ttlSeconds },
    correlationId: params.correlationId
  });
  return { access_token: token.value, token_type: "Bearer", expires_in: ttlSeconds, scope: `mcp:${server.code}` };
}

export async function validateBearer(db: Db, token: string, hostname: string, hmacKey: Buffer): Promise<{ credentialId: string; serverId: string; code: string; toolName: string }> {
  const digest = hmacToken(token, hmacKey);
  const resource = resourceFor(hostname);
  const result = await db.query(
    `select at.credential_id, at.server_id, ms.code, ms.tool_name
       from access_token at
       join kaja_credential kc on kc.id=at.credential_id
       join mcp_server ms on ms.id=at.server_id
      where at.lookup_digest=$1
        and at.audience=$2
        and at.expires_at > now()
        and at.revoked_at is null
        and kc.active is true
        and kc.revoked_at is null
        and at.credential_revocation_epoch = kc.revocation_epoch
        and at.server_revocation_epoch = ms.revocation_epoch
        and ms.enabled is true
        and ms.registration_state in ('ACTIVE','TRIAL')`,
    [digest, resource]
  );
  if (!result.rowCount) throw Object.assign(new Error("invalid_token"), { statusCode: 401, fingerprint: fingerprintSecret(token) });
  return {
    credentialId: result.rows[0].credential_id,
    serverId: result.rows[0].server_id,
    code: result.rows[0].code,
    toolName: result.rows[0].tool_name
  };
}
