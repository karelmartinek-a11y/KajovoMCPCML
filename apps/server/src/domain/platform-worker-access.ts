import type { AppServerConfig, WorkerConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { decryptVaultSecret, encryptVaultSecret, hmacToken, issueOpaqueSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { authorizeComponentCall, type ComponentAuthorizationDecision } from "./component-auth.js";

const SETTING_KEY = "platform-worker-access-token";
type AccessConfig = Pick<AppServerConfig, "ACCESS_TOKEN_HMAC_KEY_BASE64" | "ACCESS_TOKEN_HMAC_KEY_ID" | "CONFIG_VAULT_MASTER_KEY_BASE64" | "CONFIG_VAULT_MASTER_KEY_ID">;
type WorkerAccessConfig = Pick<WorkerConfig, "ACCESS_TOKEN_HMAC_KEY_BASE64" | "CONFIG_VAULT_MASTER_KEY_BASE64" | "CONFIG_VAULT_MASTER_KEY_ID">;

export async function getPlatformWorkerAccessStatus(db: Db): Promise<Record<string, unknown>> {
  const result = await db.query(`
    select identity.fingerprint,identity.rotated_at,identity.updated_at,token.revoked_at,token.last_used_at,
           principal.public_id,principal.status
      from platform_worker_access_identity identity
      join principal on principal.id=identity.principal_id
      left join principal_access_token token on token.id=identity.access_token_id
     where identity.singleton is true`);
  const row = result.rows[0] ?? {};
  return {
    configured: Boolean(row.fingerprint) && !row.revoked_at,
    fingerprint: row.fingerprint ?? null,
    principalPublicId: row.public_id ?? "KCML-PLATFORM-WORKER",
    principalStatus: row.status ?? "UNAVAILABLE",
    rotatedAt: row.rotated_at ?? null,
    lastUsedAt: row.last_used_at ?? null,
    revokedAt: row.revoked_at ?? null
  };
}

export async function rotatePlatformWorkerAccessToken(db: Db, config: AccessConfig, params: {
  actorId: string;
  correlationId: string;
}): Promise<{ status: Record<string, unknown>; accessToken: { token: string; fingerprint: string } }> {
  const issued = issueOpaqueSecret();
  await tx(db, async (client) => {
    const identity = await client.query(`
      select identity.*,principal.policy_epoch,principal.revocation_epoch,principal.status
        from platform_worker_access_identity identity
        join principal on principal.id=identity.principal_id
       where identity.singleton is true for update of identity,principal`);
    if (!identity.rowCount || identity.rows[0].status !== "ACTIVE") {
      throw Object.assign(new Error("platform_worker_principal_unavailable"), { statusCode: 503 });
    }
    if (identity.rows[0].access_token_id) {
      await client.query(
        "update principal_access_token set revoked_at=coalesce(revoked_at,now()),rotated_at=now(),rotation_reason='ADMIN_ROTATE' where id=$1",
        [identity.rows[0].access_token_id]
      );
    }
    const inserted = await client.query(`
      insert into principal_access_token(
        lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,
        issued_policy_epoch,issued_revocation_epoch,expires_at,handed_off_at
      ) values ($1,$2,$3,$4,null,'*',array['*'],$5,$6,'infinity',now()) returning id`,
      [hmacToken(issued.value, config.ACCESS_TOKEN_HMAC_KEY_BASE64), config.ACCESS_TOKEN_HMAC_KEY_ID, issued.fingerprint,
        identity.rows[0].principal_id, identity.rows[0].policy_epoch, identity.rows[0].revocation_epoch]
    );
    const ciphertext = encryptVaultSecret(issued.value, config.CONFIG_VAULT_MASTER_KEY_BASE64, {
      keyId: config.CONFIG_VAULT_MASTER_KEY_ID,
      settingKey: SETTING_KEY
    });
    await client.query(`
      update platform_worker_access_identity
         set access_token_id=$1,token_ciphertext=$2,key_id=$3,fingerprint=$4,rotated_by=$5,rotated_at=now(),updated_at=now()
       where singleton is true`,
      [inserted.rows[0].id, ciphertext, config.CONFIG_VAULT_MASTER_KEY_ID, issued.fingerprint, params.actorId]
    );
    await appendAudit(client, {
      eventType: "platform_worker.access_token.rotated", actorType: "admin", actorId: params.actorId,
      objectType: "principal_access_token", objectId: String(inserted.rows[0].id),
      after: { fingerprint: issued.fingerprint, principalPublicId: "KCML-PLATFORM-WORKER", expiresAt: "infinity" },
      correlationId: params.correlationId
    });
  });
  return { status: await getPlatformWorkerAccessStatus(db), accessToken: { token: issued.value, fingerprint: issued.fingerprint } };
}

async function loadPlatformWorkerToken(db: Db, config: WorkerAccessConfig): Promise<string> {
  const result = await db.query(`
    select identity.token_ciphertext,identity.key_id,token.revoked_at,principal.status
      from platform_worker_access_identity identity
      join principal on principal.id=identity.principal_id
      join principal_access_token token on token.id=identity.access_token_id
     where identity.singleton is true`);
  if (!result.rowCount || result.rows[0].revoked_at || result.rows[0].status !== "ACTIVE") {
    throw new Error("platform_worker_access_token_unavailable");
  }
  return decryptVaultSecret(String(result.rows[0].token_ciphertext), new Map([
    [String(result.rows[0].key_id), config.CONFIG_VAULT_MASTER_KEY_BASE64]
  ]), SETTING_KEY);
}

export async function authorizePlatformWorkerCall(db: Db, config: WorkerAccessConfig, params: {
  hostname: string;
  scope: string;
  route: string;
  correlationId: string;
}): Promise<{ token: string; decision: ComponentAuthorizationDecision }> {
  const token = await loadPlatformWorkerToken(db, config);
  const decision = await authorizeComponentCall(db, {
    token,
    audience: `https://${params.hostname}`,
    host: params.hostname,
    scope: params.scope,
    route: params.route,
    hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
    correlationId: params.correlationId
  });
  if (!decision.allow) throw new Error(`platform_worker_authorization_${decision.reasonCode}`);
  return { token, decision };
}
