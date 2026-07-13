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
  updatedAt: string;
  expiresAt: string | null;
  permissionCount: number;
  activeAccessTokenCount: number;
  lastTokenIssuedAt: string | null;
  lastTokenExpiresAt: string | null;
};

export type KajaPermissionSummary = {
  serverId: string;
  code: string;
  hostname: string;
  displayName: string;
  granted: boolean;
  accessLevel: "READ" | "EXECUTE" | "MANAGE" | null;
  grantedAt: string | null;
};

export type KajaPermissionInput = {
  serverId: string;
  accessLevel: "READ" | "EXECUTE" | "MANAGE";
};

export async function createKajaCredential(
  db: Db,
  actorId: string,
  correlationId: string,
  label: string,
  expiresAt: string | null
): Promise<{ publicId: string; label: string; clientSecret: string; fingerprint: string; expiresAt: string | null }> {
  const secret = issueOpaqueSecret();
  const hash = await hashPasswordLikeSecret(secret.value);
  const result = await db.query("select nextval('kaja_number_seq') as number");
  const publicId = `Kaja${String(Number(result.rows[0].number)).padStart(4, "0")}`;
  const inserted = await db.query(
    "insert into kaja_credential(public_id, label, secret_hash, secret_fingerprint, expires_at) values ($1,$2,$3,$4,$5) returning id, expires_at",
    [publicId, label, hash, secret.fingerprint, expiresAt]
  );
  await appendAudit(db, {
    eventType: "kaja.created",
    actorType: "admin",
    actorId,
    objectType: "kaja_credential",
    objectId: inserted.rows[0].id,
    after: { publicId, label, fingerprint: secret.fingerprint, expiresAt },
    correlationId
  });
  return {
    publicId,
    label,
    clientSecret: secret.value,
    fingerprint: secret.fingerprint,
    expiresAt: inserted.rows[0].expires_at ? String(inserted.rows[0].expires_at) : null
  };
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
      kc.updated_at,
      kc.expires_at,
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
    updatedAt: String(row.updated_at),
    expiresAt: row.expires_at ? String(row.expires_at) : null,
    permissionCount: Number(row.permission_count),
    activeAccessTokenCount: Number(row.active_access_token_count),
    lastTokenIssuedAt: row.last_token_issued_at ? String(row.last_token_issued_at) : null,
    lastTokenExpiresAt: row.last_token_expires_at ? String(row.last_token_expires_at) : null
  }));
}

export async function revokeKajaCredential(db: Db, actorId: string, correlationId: string, credentialId: string): Promise<void> {
  const result = await db.query(
    `update kaja_credential
        set active=false,
            revoked_at=coalesce(revoked_at, now()),
            revocation_epoch=gen_random_uuid()
      where id=$1 and deleted_at is null
      returning id, public_id, label`,
    [credentialId]
  );
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  await db.query("update kaja_permission set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  await db.query("update access_token set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  await appendAudit(db, {
    eventType: "kaja.revoked",
    actorType: "admin",
    actorId,
    objectType: "kaja_credential",
    objectId: credentialId,
    after: { publicId: result.rows[0].public_id, label: result.rows[0].label },
    correlationId
  });
}

export async function deleteKajaCredential(db: Db, actorId: string, correlationId: string, credentialId: string): Promise<void> {
  const result = await db.query(
    `update kaja_credential
        set active=false,
            revoked_at=coalesce(revoked_at, now()),
            deleted_at=coalesce(deleted_at, now()),
            revocation_epoch=gen_random_uuid()
      where id=$1 and deleted_at is null
      returning id, public_id, label`,
    [credentialId]
  );
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  await db.query("update kaja_permission set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  await db.query("update access_token set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  await appendAudit(db, {
    eventType: "kaja.deleted",
    actorType: "admin",
    actorId,
    objectType: "kaja_credential",
    objectId: credentialId,
    after: { publicId: result.rows[0].public_id, label: result.rows[0].label },
    correlationId
  });
}

export async function listKajaPermissions(db: Db, credentialId: string): Promise<KajaPermissionSummary[]> {
  const credential = await db.query("select 1 from kaja_credential where id=$1 and deleted_at is null", [credentialId]);
  if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const result = await db.query(`
    select
      ms.id as server_id,
      ms.code,
      ms.hostname,
      ms.display_name,
      kp.access_level,
      kp.granted_at,
      (kp.id is not null and kp.revoked_at is null) as granted
    from mcp_server ms
    left join kaja_permission kp on kp.server_id = ms.id and kp.credential_id = $1
    order by ms.kcml_number asc
  `, [credentialId]);
  return result.rows.map((row) => ({
    serverId: String(row.server_id),
    code: String(row.code),
    hostname: String(row.hostname),
    displayName: String(row.display_name),
    granted: Boolean(row.granted),
    accessLevel: row.access_level ? row.access_level as KajaPermissionSummary["accessLevel"] : null,
    grantedAt: row.granted_at ? String(row.granted_at) : null
  }));
}

export async function replaceKajaPermissions(db: Db, actorId: string, correlationId: string, credentialId: string, permissions: KajaPermissionInput[]): Promise<void> {
  const credential = await db.query("select id, public_id from kaja_credential where id=$1 and deleted_at is null and revoked_at is null and active is true", [credentialId]);
  if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const previousResult = await db.query(
    "select server_id,access_level from kaja_permission where credential_id=$1 and revoked_at is null",
    [credentialId]
  );
  const previousExecutable = new Set(
    previousResult.rows
      .filter((row) => ["EXECUTE", "MANAGE"].includes(String(row.access_level)))
      .map((row) => String(row.server_id))
  );
  const byServer = new Map<string, KajaPermissionInput>();
  for (const permission of permissions) byServer.set(permission.serverId, permission);
  const normalized = Array.from(byServer.values());
  const serverIds = normalized.map((permission) => permission.serverId);
  if (serverIds.length) {
    const validServers = await db.query("select id from mcp_server where id = any($1::uuid[])", [serverIds]);
    if (validServers.rowCount !== serverIds.length) throw Object.assign(new Error("invalid_server"), { statusCode: 400 });
  }
  await db.query("update kaja_permission set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  for (const permission of normalized) {
    await db.query(
      `insert into kaja_permission(credential_id, server_id, access_level, revoked_at)
       values ($1,$2,$3,null)
       on conflict (credential_id, server_id) do update set revoked_at=null, granted_at=now(), access_level=excluded.access_level`,
      [credentialId, permission.serverId, permission.accessLevel]
    );
  }
  const currentExecutable = new Set(
    normalized
      .filter((permission) => ["EXECUTE", "MANAGE"].includes(permission.accessLevel))
      .map((permission) => permission.serverId)
  );
  const removedExecutable = [...previousExecutable].filter((serverId) => !currentExecutable.has(serverId));
  if (removedExecutable.length) {
    await db.query(
      "update access_token set revoked_at=coalesce(revoked_at,now()) where credential_id=$1 and server_id=any($2::uuid[])",
      [credentialId, removedExecutable]
    );
    for (const serverId of removedExecutable) {
      await appendAudit(db, {
        eventType: "permission.revoked",
        actorType: "admin",
        actorId,
        objectType: "mcp_server",
        objectId: serverId,
        after: { credentialId },
        correlationId
      });
    }
  }
  for (const permission of normalized) {
    if (!previousExecutable.has(permission.serverId) && currentExecutable.has(permission.serverId)) {
      await appendAudit(db, {
        eventType: "permission.granted",
        actorType: "admin",
        actorId,
        objectType: "mcp_server",
        objectId: permission.serverId,
        after: { credentialId, accessLevel: permission.accessLevel },
        correlationId
      });
    }
  }
  await appendAudit(db, {
    eventType: "kaja.permissions.updated",
    actorType: "admin",
    actorId,
    objectType: "kaja_credential",
    objectId: credentialId,
    after: { publicId: credential.rows[0].public_id, permissions: normalized },
    correlationId
  });
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
  if (!credential.active || credential.revoked_at || (credential.expires_at && new Date(String(credential.expires_at)).getTime() <= Date.now())) {
    throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
  }
  const verified = await verifyPasswordLikeSecret(String(credential.secret_hash), params.clientSecret);
  if (!verified) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });

  const serverResult = await db.query("select id, code, hostname, enabled, registration_state, revocation_epoch from mcp_server where $1 = ('https://' || hostname || '/mcp')", [params.resource]);
  if (!serverResult.rowCount) throw Object.assign(new Error("invalid_resource"), { statusCode: 400 });
  const server = serverResult.rows[0];
  if (!server.enabled || !["ACTIVE", "TRIAL"].includes(String(server.registration_state))) {
    throw Object.assign(new Error("resource_unavailable"), { statusCode: 503 });
  }
  const permission = await db.query(
    "select 1 from kaja_permission where credential_id=$1 and server_id=$2 and revoked_at is null and access_level in ('EXECUTE','MANAGE')",
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
        and kc.deleted_at is null
        and (kc.expires_at is null or kc.expires_at > now())
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
